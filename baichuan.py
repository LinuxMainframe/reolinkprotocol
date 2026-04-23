#!/usr/bin/env python3
"""
login.py
========

:author: Aidan A. Bradley
:date: April 20th, 2026

The Baichuan protocol is a proprietary communication and authorization protocol
developed by Baichuan SoC Company for their ARM-based camera systems. It has
not been publicly documented by ReoLink or Baichuan.

This protocol was initially reverse-engineered by George Hilliard
(a.k.a. *thirtythreeforty* on GitHub) and then extensively developed into
**NeoLink** (current maintainer: Andrew W. King, a.k.a. *quantumentangledandy*).
This module is an independent Python implementation — not a port of NeoLink —
built from protocol documentation, community research, and inspection of the
``reolink_aio`` library.  It is intended as the foundation of a dedicated
streaming library for Reolink cameras.

**What this module adds over the original wire layer**

The initial version of this file handled raw frame construction and socket I/O
in a synchronous, function-only style.  This revision merges in the session
lifecycle work needed to complete the authentication handshake, drawing on the
``reolink_aio`` implementation as a reference.  The following were added:

* ``EncType`` — enumeration of the three protocol-defined encryption levels.
* ``SessionConfig`` — a frozen, slot-based configuration struct that records
  the caller's encryption preferences before any network activity begins.
* ``SessionState`` — a mutable, slot-based struct that accumulates connection
  state as the handshake progresses.  ``__slots__`` is used deliberately to
  keep per-instance memory tight; when running sixteen concurrent camera
  sessions the overhead of a conventional ``__dict__``-backed object multiplies
  noticeably.
* AES-128-CFB helpers (``aes_encrypt`` / ``aes_decrypt``) and the key-derivation
  function that produces the per-session AES key from the nonce.
* Credential-hashing utilities matching the modern firmware convention observed
  in ``reolink_aio``.
* Async equivalents of the synchronous socket helpers, built on
  ``asyncio.StreamReader`` / ``asyncio.StreamWriter``.
* A complete async session lifecycle: ``connect``, ``get_nonce``, ``login``,
  ``close``.

**Encryption negotiation**

The protocol uses a capability-advertisement model rather than a command-response
negotiation.  The client declares its maximum supported level in the ``encrypt``
field of the nonce request; the camera replies with the level it will actually
use.  This module defaults to advertising full AES capability.  If the camera
replies that it has chosen BC, the session falls back gracefully.  Unencrypted
sessions are rejected by default and can only be permitted by explicit
``SessionConfig`` override.

**AES key derivation — unresolved case-sensitivity**

The AES key is the first 16 characters of the MD5 hex digest of
``nonce + "-" + password``.  Community documentation specifies *uppercase* hex;
``reolink_aio`` internally uses whatever its ``md5_str_modern`` helper returns,
which is likely lowercase.  These produce different 16-byte keys for the same
inputs.  The correct variant must be verified empirically against a real camera.
Both are derived below and the session stores the result of whichever path is
chosen at construction time.  See ``derive_aes_key`` for details.

**Background / Motivation**

The impetus for this module came from repeated failed attempts to use the
built-in RTSP/RTMP streams.  Artifacting, image columnation, I-frame issues,
improper buffering, and colour shifts made those streams unusable for a live
outdoor activity feed.  Switching to NeoLink yielded a dramatic quality increase
at low CPU/GPU cost.  However, NeoLink struggled with multiple concurrent
high-resolution streams — even on a machine with an RTX 4060, a 4.5 GHz AMD
CPU, and 30 GB of RAM.  Increasing I-frame intervals and raising resolution/fps
caused a buffer runaway, with RAM allocation creeping up rapidly.  Partitioning
cameras across multiple NeoLink instances and coupling MediaMTX helped stabilise
things somewhat, but the added chain reduced overall reliability.  NeoLink's
buffer management was the clear bottleneck.

None of this diminishes NeoLink's achievement.  It is an incredible piece of
work, and the community around it provided the examples and insight needed to
understand and reason about the Baichuan stream chain.  This module stands on
that foundation.
"""

import asyncio
import hashlib
import socket
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Union, Optional

try:
    from Cryptodome.Cipher import AES as _AES
except ImportError:
    from Crypto.Cipher import AES as _AES


# ============================================================================
#  CONSTANTS
# ============================================================================
#
#  All integer constants are written in standard (big-endian-readable) form,
#  e.g. 0x6514 rather than 0x1465.  When building wire messages they are
#  explicitly serialised as little-endian, so callers never have to reason
#  about byte order until the moment a header is assembled.
# ============================================================================

MAGIC: int = 0x0ABCDEF0
"""
Magic number that opens every Baichuan frame (client ↔ device).

Serialised as little-endian it becomes ``f0 de bc 0a`` on the wire.  A
separate magic ``a0 cd ed 0f`` exists for device-to-device traffic (e.g. NVR
↔ IPC); that path is out of scope for a client library.
"""

PORT: int = 9000
"""
Default TCP port for the Baichuan protocol.

ReoLink cameras listen on port 9000 by default.  Pass an explicit port where
accepted if the camera has been reconfigured.
"""

RECV_TIMEOUT: float = 15.0
"""
Socket receive timeout in seconds for the synchronous helpers.

The async helpers use ``asyncio`` timeouts at the call site instead.
"""

AES_IV: bytes = b"0123456789abcdef"
"""
Fixed 16-byte initialisation vector used by all AES-128-CFB sessions.

This value is hardcoded in the Baichuan protocol and is identical across every
known ReoLink device.  A new cipher object is created per encrypt/decrypt call
(each message is an independent CFB stream starting from this IV), which is
the correct interpretation of how the protocol applies AES.
"""

XML_KEY: bytes = bytes([0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF])
"""
8-byte rotating XOR key used by the BC cipher.

**Do not modify.**  This key is identical across every known ReoLink device;
changing it will break decryption of all camera responses.
"""

HEADER_LENGTHS: dict[int, int] = {
    0x6514: 20,   # Legacy  — nonce / login request  (client → camera)
    0x6614: 20,   # Legacy  — nonce response          (camera → client)
    0x6414: 24,   # Modern  — standard command / login
    0x6482: 24,   # Modern  — file download variant
    0x0000: 24,   # Modern  — alternate command variant (seen in some firmware)
    0x0146: 24,   # Modern  — additional known variant
}
"""
Mapping of message-class integers to their header sizes in bytes.

* **20 bytes** — legacy classes:
  ``MAGIC(4) + cmd_id(4) + msg_len(4) + mess_id(4) + encrypt(2) + class(2)``

* **24 bytes** — modern classes (append a 4-byte payload-offset field):
  ``MAGIC(4) + cmd_id(4) + msg_len(4) + mess_id(4) + status(2) + class(2) + offset(4)``

Note that at offset 16 the legacy layout has an ``encrypt`` field while the
modern layout has a ``status`` field.  They occupy the same bytes; the
interpretation depends on whether the message is a client request (legacy +
encrypt) or a camera response (modern + status).
"""

# Baichuan function codes (cmd_id field, offset 4 in the header).
CMD_LOGIN:  int = 1    # GetNonce request *and* modern LoginUser — same code, different stage.
CMD_VIDEO:  int = 3    # Request/receive video stream data.
CMD_LOGOUT: int = 2    # Graceful session termination.

# Encryption advertisement byte sent by the client in the legacy-header encrypt field.
# Byte layout: [level_byte][0xDC].  0xDC signals "capability ceiling"; the camera
# replies with 0xDD to indicate its chosen level.  The value 0x12 is what
# reolink_aio sends and has been verified to work across multiple firmware versions.
# If you need to force AES negotiation, try b'\x02\xdc' or b'\x03\xdc' and
# observe the camera's response byte at header offset 16.
ENCRYPT_ADV_DEFAULT: bytes = b'\x12\xdc'

# The ch_id used for host-level (non-NVR-channel) commands.  This byte is
# placed at the start of the 4-byte mess_id field and doubles as the enc_offset
# for outgoing BC-encrypted payloads.
CH_ID_HOST: int = 0xFA   # 250 decimal — conventional host/client channel.


# ============================================================================
#  ENUMERATIONS
# ============================================================================

class EncType(IntEnum):
    """
    Protocol-defined encryption levels.

    The values map directly to the level nibble in the Baichuan encrypt field:

    * ``NONE`` (0) — plaintext, no obfuscation.  Present in very old firmware.
    * ``BC``   (1) — simple rotating XOR cipher using ``XML_KEY``.
    * ``AES``  (2) — AES-128-CFB with a per-session derived key and fixed IV.

    A value of 3 is also defined by the protocol to indicate that the *client*
    supports AES, but it is an advertisement level rather than an operational
    mode; the camera never reports 3 in its reply.
    """
    NONE = 0
    BC   = 1
    AES  = 2


# ============================================================================
#  SESSION DATA STRUCTURES
# ============================================================================

@dataclass(frozen=True, slots=True)
class SessionConfig:
    """
    Immutable per-session preferences set by the caller before connecting.

    Frozen so it can be safely shared across coroutines without copying.
    ``__slots__`` keeps the struct compact.

    Attributes:
        preferred_enc: The highest encryption level the client will attempt to
            negotiate.  Defaults to ``EncType.AES``; use ``EncType.BC`` for
            cameras known not to support AES.
        allow_bc_fallback: If ``True`` and the camera replies that it chose BC
            when AES was requested, the session continues under BC rather than
            raising.  Useful for mixed-firmware deployments.
        reject_plaintext: If ``True``, a camera that replies with
            ``EncType.NONE`` causes ``login`` to raise ``EncryptionError``
            rather than proceeding unencrypted.  Strongly recommended.
        aes_key_uppercase: Controls whether the AES key is derived from the
            *uppercase* hex digest of the MD5 hash (``True``) or the lowercase
            digest (``False``).  Protocol documentation specifies uppercase;
            ``reolink_aio`` appears to use lowercase.  The correct value for
            your specific firmware version must be determined empirically —
            a wrong value here produces a plausible-looking session that silently
            fails at the camera's decrypt stage.  See ``derive_aes_key``.
    """
    preferred_enc:     EncType = EncType.AES
    allow_bc_fallback: bool    = True
    reject_plaintext:  bool    = True
    aes_key_uppercase: bool    = True   # Set False if login 401s with AES.


@dataclass(slots=True)
class SessionState:
    """
    Mutable state accumulated during and after the Baichuan login handshake.

    Intentionally a plain data struct; behaviour lives in module-level
    functions rather than methods.  This keeps lifecycle explicit and avoids
    the resource-management ambiguity that comes with objects whose destructor
    timing is unclear.

    Fields that are ``None`` before login completes are marked in the
    attribute docstrings.  Callers should not read stream-phase fields until
    ``logged_in`` is ``True``.

    Attributes:
        host:           Camera IP address or hostname.
        port:           TCP port (default ``PORT``).
        reader:         asyncio read handle; ``None`` until ``connect`` runs.
        writer:         asyncio write handle; ``None`` until ``connect`` runs.
        mess_id:        24-bit rolling sequence counter.  Wraps at 2²⁴.
                        Incremented once per outgoing message.
        nonce:          Nonce string received from the camera; empty until
                        ``get_nonce`` completes.
        negotiated_enc: Encryption level the camera chose; ``None`` until the
                        nonce response is parsed.
        aes_key:        16-byte AES key derived after nonce receipt; ``None``
                        unless ``negotiated_enc`` is ``EncType.AES``.
        logged_in:      ``True`` after a successful ``login`` call.
        ch_id:          Channel identifier byte prepended to the mess_id field.
                        ``CH_ID_HOST`` for single-camera devices; set to the
                        NVR channel number (1-indexed) for multi-channel units.
    """
    host:           str
    port:           int                       = PORT
    reader:         asyncio.StreamReader|None = field(default=None)
    writer:         asyncio.StreamWriter|None = field(default=None)
    mess_id:        int                       = 0
    nonce:          str                       = ""
    negotiated_enc: EncType|None              = None
    aes_key:        bytes|None                = None
    logged_in:      bool                      = False
    ch_id:          int                       = CH_ID_HOST


# ============================================================================
#  AES HELPERS
# ============================================================================

def aes_encrypt(key: bytes, data: bytes) -> bytes:
    """
    Encrypt *data* with AES-128-CFB using the Baichuan fixed IV.

    A fresh cipher object is created on every call.  This is correct because
    the protocol starts each message's CFB stream from the same fixed IV; there
    is no running state carried across messages.

    Args:
        key:  16-byte AES key, typically produced by ``derive_aes_key``.
        data: Plaintext bytes to encrypt (null-terminated XML payload).

    Returns:
        Ciphertext of the same length as *data*.

    Raises:
        ValueError: If *key* is not exactly 16 bytes.
    """
    if len(key) != 16:
        raise ValueError(f"AES key must be 16 bytes, got {len(key)}.")
    cipher = _AES.new(key, _AES.MODE_CFB, iv=AES_IV, segment_size=128)
    return cipher.encrypt(data)


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """
    Decrypt *data* with AES-128-CFB using the Baichuan fixed IV.

    Mirror of ``aes_encrypt``; same fresh-cipher-per-call contract.

    Args:
        key:  16-byte AES key.
        data: Ciphertext bytes to decrypt.

    Returns:
        Plaintext of the same length as *data*.

    Raises:
        ValueError: If *key* is not exactly 16 bytes.
    """
    if len(key) != 16:
        raise ValueError(f"AES key must be 16 bytes, got {len(key)}.")
    cipher = _AES.new(key, _AES.MODE_CFB, iv=AES_IV, segment_size=128)
    return cipher.decrypt(data)


# ============================================================================
#  BC (XOR) CIPHER
# ============================================================================

def bc_decrypt(enc_offset: int, data: bytes) -> bytes:
    """
    Decrypt (or encrypt) a Baichuan XOR-obfuscated payload.

    The BC cipher is a symmetric byte-level XOR using a rotating 8-byte
    key (``XML_KEY``) combined with a single offset byte derived from the
    message header.  Because XOR is its own inverse, the same function handles
    both directions.

    **Algorithm** — for each byte at index *i* in *data*:

    .. code-block:: text

        key_byte  = XML_KEY[(i + enc_offset) % 8]
        result[i] = data[i] ^ key_byte ^ offset_byte

    where ``offset_byte = enc_offset & 0xFF``.

    Args:
        enc_offset: Least-significant byte of the 4-byte ``mess_id`` field at
            offset 0x0C in the received header (i.e. ``header[12]``).  For
            outgoing messages this is the ``ch_id`` byte placed at the start
            of the same field.
        data: Raw bytes to decrypt (or encrypt).

    Returns:
        Transformed bytes of the same length as *data*.
    """
    offset_byte = enc_offset & 0xFF
    result      = bytearray(len(data))
    for i, byte in enumerate(data):
        key_byte  = XML_KEY[(i + enc_offset) % 8]
        result[i] = byte ^ key_byte ^ offset_byte
    return bytes(result)


# ============================================================================
#  SESSION-LEVEL ENCRYPTION DISPATCH
# ============================================================================

def session_encrypt(session: SessionState, data: bytes) -> bytes:
    """
    Encrypt *data* using whichever cipher the session negotiated.

    For BC the enc_offset is ``session.ch_id``, which is the byte placed at
    the start of the outgoing mess_id field — so the outgoing encrypt offset
    and the outgoing mess_id header byte are always consistent.

    For AES, ``session.aes_key`` must already be populated (i.e. the nonce
    step must have completed).

    Args:
        session: Live session whose ``negotiated_enc`` has been set.
        data:    Plaintext payload bytes (null-terminated XML).

    Returns:
        Encrypted bytes ready to attach to the outgoing header.

    Raises:
        RuntimeError: If ``negotiated_enc`` has not been set (handshake
            incomplete) or is ``EncType.NONE`` (plaintext, which should have
            been rejected by ``login``).
    """
    enc = session.negotiated_enc
    if enc is None:
        raise RuntimeError("Encryption not yet negotiated — handshake incomplete.")
    if enc == EncType.AES:
        if session.aes_key is None:
            raise RuntimeError("AES negotiated but aes_key is not set.")
        return aes_encrypt(session.aes_key, data)
    if enc == EncType.BC:
        return bc_decrypt(session.ch_id, data)   # XOR is its own inverse.
    raise RuntimeError(f"Plaintext sessions are not supported (enc={enc}).")


def session_decrypt(session: SessionState, data: bytes, enc_offset: int) -> bytes:
    """
    Decrypt *data* using whichever cipher the session negotiated.

    For BC, the enc_offset must be read from the *received* header
    (``header[12]``), not from the session's ``ch_id``, because the camera
    may choose a different offset value than the client does.

    For AES the enc_offset is ignored; decryption uses only the session key.

    Args:
        session:    Live session whose ``negotiated_enc`` has been set.
        data:       Encrypted payload bytes as received from the camera.
        enc_offset: Byte 0 of the 4-byte mess_id field in the received header
            (``header[12]``).  Used for BC decryption; ignored for AES.

    Returns:
        Decrypted bytes.

    Raises:
        RuntimeError: Same conditions as ``session_encrypt``.
    """
    enc = session.negotiated_enc
    if enc is None:
        raise RuntimeError("Encryption not yet negotiated — handshake incomplete.")
    if enc == EncType.AES:
        if session.aes_key is None:
            raise RuntimeError("AES negotiated but aes_key is not set.")
        return aes_decrypt(session.aes_key, data)
    if enc == EncType.BC:
        return bc_decrypt(enc_offset, data)
    raise RuntimeError(f"Plaintext sessions are not supported (enc={enc}).")


# ============================================================================
#  KEY DERIVATION AND CREDENTIAL HASHING
# ============================================================================

def derive_aes_key(nonce: str, password: str, uppercase: bool = True) -> bytes:
    """
    Derive the 16-byte per-session AES key from the nonce and plain password.

    The key material is ``nonce + "-" + password``.  Its MD5 hex digest is
    taken (32 hex characters), the first 16 characters are sliced, and those
    characters are encoded as ASCII bytes to form the 16-byte key.

    **Case sensitivity warning:** Protocol documentation specifies *uppercase*
    hex (``uppercase=True``); ``reolink_aio`` appears to use lowercase.  These
    produce different keys from the same input.  If AES login returns a 401 or
    a garbled response, swap this flag and retry.

    Args:
        nonce:     The nonce string extracted from the camera's nonce response.
        password:  Plain-text camera password (not pre-hashed).
        uppercase: If ``True``, take the first 16 characters of the uppercase
            hex digest.  If ``False``, use the lowercase digest.  Default
            ``True`` per protocol specification.

    Returns:
        16-byte AES key, ASCII-encoded hex slice of the MD5 digest.
    """
    key_material = f"{nonce}-{password}"
    digest       = hashlib.md5(key_material.encode("utf-8")).hexdigest()
    if uppercase:
        digest = digest.upper()
    return digest[:16].encode("ascii")


def hash_credential(value: str, nonce: str) -> str:
    """
    Produce the nonce-mixed MD5 hex digest used in the LoginUser XML payload.

    The modern firmware convention (observed in ``reolink_aio``) is to hash
    ``value + nonce`` rather than ``value`` alone.  This binds the credential
    hash to the specific nonce issued for this session, preventing replay of
    a captured login message.

    Args:
        value: Plain-text username or password.
        nonce: The nonce string received from the camera.

    Returns:
        32-character lowercase hex MD5 digest of ``value + nonce``.
    """
    return hashlib.md5(f"{value}{nonce}".encode("utf-8")).hexdigest()


# ============================================================================
#  PAYLOAD BUILDERS
# ============================================================================

def build_get_nonce_payload() -> bytes:
    """
    Build the minimal XML body sent with the nonce request.

    This is the first payload the client sends.  The camera decrypts the
    body (if it is encrypted at all — older firmware sends plain text), parses
    the ``<GetNonce/>`` element, and replies with a ``<nonce>`` element in a
    BC-encrypted response.

    An alternative documented in the community notes is to send *only* the
    20-byte header with no body (``msg_len = 0``).  Both approaches have been
    observed to work; the XML-body variant is used here because it was verified
    against the target hardware.

    Returns:
        UTF-8 encoded, null-terminated XML bytes.
    """
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<body>\n'
        '<GetNonce/>\n'
        '</body>'
    )
    return xml.encode("utf-8") + b"\x00"


def build_login_xml(username_hash: str, password_hash: str) -> bytes:
    """
    Build the LoginUser XML payload sent in the modern (stage-two) login.

    The ``userName`` and ``password`` fields contain the nonce-mixed MD5
    hashes produced by ``hash_credential``, *not* the plain-text credentials
    and *not* the AES key material.  The AES key is derived separately and
    used only to *encrypt this payload* before transmission.

    The ``LoginNet`` block is included because firmware expects it alongside
    ``LoginUser``; omitting it causes some versions to reject the login or
    return incomplete device info.

    Args:
        username_hash: MD5 hex digest of ``username + nonce``.
        password_hash: MD5 hex digest of ``password + nonce``.

    Returns:
        UTF-8 encoded, null-terminated XML bytes ready for encryption.
    """
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<body>\n'
        '<LoginUser version="1.1">\n'
        f'<userName>{username_hash}</userName>\n'
        f'<password>{password_hash}</password>\n'
        '<userVer>1</userVer>\n'
        '</LoginUser>\n'
        '<LoginNet version="1.1">\n'
        '<type>LAN</type>\n'
        '<udpPort>0</udpPort>\n'
        '</LoginNet>\n'
        '</body>'
    )
    return xml.encode("utf-8") + b"\x00"


# ============================================================================
#  HEADER HELPERS
# ============================================================================

def get_header_size(message_class: Union[int, bytes]) -> int:
    """
    Look up the total header size in bytes for a given message class.

    Accepts the class as either a plain integer (e.g. ``0x6514``) or as a
    raw little-endian ``bytes`` object straight off the wire (e.g.
    ``b'\\x14\\x65'``).  Both forms are normalised before the lookup.

    Args:
        message_class: Message class as ``int`` or little-endian ``bytes``.

    Returns:
        Header size in bytes (``20`` or ``24``).

    Raises:
        ValueError: If *message_class* is not in ``HEADER_LENGTHS``.
        TypeError:  If *message_class* is neither ``int`` nor ``bytes``.
    """
    if isinstance(message_class, bytes):
        message_class = int.from_bytes(message_class, "little")
    elif not isinstance(message_class, int):
        raise TypeError(
            f"message_class must be int or bytes, got {type(message_class).__name__}"
        )
    try:
        return HEADER_LENGTHS[message_class]
    except KeyError:
        raise ValueError(
            f"Unrecognised message class 0x{message_class:04X} — "
            f"not in HEADER_LENGTHS."
        )


# ============================================================================
#  HEADER BUILDER
# ============================================================================

def build_header(
    cmd_id:         int,
    payload_len:    int,
    message_class:  int,
    ch_id:          int   = CH_ID_HOST,
    mess_id:        int   = 0,
    encrypt:        bytes = ENCRYPT_ADV_DEFAULT,
    status:         int   = 0,
    payload_offset: int   = 0,
) -> bytes:
    """
    Assemble a complete Baichuan message header.

    Header size (20 or 24 bytes) is determined automatically from
    *message_class* via ``HEADER_LENGTHS``.

    **Legacy header layout (20 bytes):**

    .. code-block:: text

        Offset  Size  Field
        ------  ----  -----
         0       4    Magic         (little-endian 0x0ABCDEF0 → f0 de bc 0a)
         4       4    cmd_id        (little-endian uint32 — Baichuan function code)
         8       4    payload_len   (little-endian uint32)
        12       4    mess_id       (ch_id[1] + mess_id[3], little-endian)
        16       2    encrypt       (capability advertisement, e.g. 12 dc)
        18       2    message_class (little-endian uint16)

    **Modern header layout (24 bytes):**

    .. code-block:: text

        Offset  Size  Field
        ------  ----  -----
         0–15         (same as legacy)
        16       2    status        (0x0000 in requests; HTTP-style code in replies)
        18       2    message_class (little-endian uint16)
        20       4    payload_offset (little-endian uint32)

    In modern headers the ``encrypt`` argument is ignored because the status
    field occupies the same two bytes.

    Args:
        cmd_id:         Baichuan function code (e.g. ``CMD_LOGIN``, ``CMD_VIDEO``).
        payload_len:    Byte length of the payload that follows this header.
        message_class:  Integer class determining header size and layout.
        ch_id:          Channel-ID byte; ``CH_ID_HOST`` for single-camera devices.
            Also used as ``enc_offset`` when BC-encrypting the outgoing payload.
        mess_id:        24-bit sequence counter (wraps at 2²⁴).  Use
            ``next_mess_id(session)`` to obtain and advance the counter.
        encrypt:        2-byte advertisement written into legacy headers only.
        status:         2-byte status written into modern headers only.
        payload_offset: Byte position where binary data begins within the
            payload.  Zero for pure XML messages.

    Returns:
        Packed header bytes, 20 or 24 bytes long.
    """
    header_len = HEADER_LENGTHS.get(message_class, 20)

    magic_bytes   = MAGIC.to_bytes(4, "little")
    cmd_id_bytes  = cmd_id.to_bytes(4, "little")
    msglen_bytes  = payload_len.to_bytes(4, "little")
    # The 4-byte mess_id field: [ch_id (1 byte)] + [mess_id (3 bytes)].
    messid_bytes  = ch_id.to_bytes(1, "little") + mess_id.to_bytes(3, "little")
    mclass_bytes  = message_class.to_bytes(2, "little")

    if header_len == 20:
        return (magic_bytes + cmd_id_bytes + msglen_bytes +
                messid_bytes + encrypt + mclass_bytes)
    else:
        status_bytes = status.to_bytes(2, "little")
        poffs_bytes  = payload_offset.to_bytes(4, "little")
        return (magic_bytes + cmd_id_bytes + msglen_bytes +
                messid_bytes + status_bytes + mclass_bytes + poffs_bytes)


# ============================================================================
#  SYNCHRONOUS SOCKET HELPERS  (retained for testing and non-async contexts)
# ============================================================================

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly *n* bytes from a blocking socket, looping until complete.

    A single ``recv()`` call is not guaranteed to return all requested bytes;
    the OS may fragment delivery.  This helper retries until the full count
    arrives, which is a prerequisite for correct Baichuan framing.

    Args:
        sock: Connected blocking TCP socket.
        n:    Exact number of bytes to read.

    Returns:
        ``bytes`` of length exactly *n*.

    Raises:
        ConnectionError: If the socket closes before *n* bytes arrive.
    """
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(
                f"Socket closed after {len(data)} of {n} expected bytes."
            )
        data += chunk
    return data


def recv_response(sock: socket.socket) -> tuple[bytes, bytes] | tuple[None, None]:
    """
    Read a complete Baichuan message (header + payload) from a blocking socket.

    Reads in three stages: the fixed minimum header (20 bytes), an optional
    4-byte modern extension, and the variable-length payload.

    Args:
        sock: Connected TCP socket positioned at the start of a Baichuan frame.

    Returns:
        ``(header_bytes, payload_bytes)`` on success, or ``(None, None)`` on
        connection error or timeout.
    """
    try:
        header = recv_exact(sock, 20)
    except (ConnectionError, socket.timeout):
        return None, None

    mclass     = struct.unpack_from("<H", header, 18)[0]
    header_len = HEADER_LENGTHS.get(mclass, 20)

    if header_len > 20:
        try:
            header += recv_exact(sock, header_len - 20)
        except (ConnectionError, socket.timeout):
            return None, None

    msg_len = struct.unpack_from("<I", header, 8)[0]
    if msg_len > 0:
        try:
            payload = recv_exact(sock, msg_len)
        except (ConnectionError, socket.timeout):
            return None, None
    else:
        payload = b""

    return header, payload


# ============================================================================
#  ASYNCHRONOUS SOCKET HELPERS
# ============================================================================

async def async_recv_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """
    Async equivalent of ``recv_exact`` using ``asyncio.StreamReader``.

    ``StreamReader.readexactly`` handles the fragmentation loop internally and
    raises ``asyncio.IncompleteReadError`` if the connection closes before *n*
    bytes arrive.  That error is normalised here into a ``ConnectionError`` for
    consistency with the synchronous helper.

    Args:
        reader: asyncio stream reader attached to a connected socket.
        n:      Exact number of bytes to read.

    Returns:
        ``bytes`` of length exactly *n*.

    Raises:
        ConnectionError: If the connection closes prematurely.
    """
    try:
        return await reader.readexactly(n)
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError(
            f"Connection closed after {len(exc.partial)} of {n} expected bytes."
        ) from exc


async def async_recv_response(
    reader: asyncio.StreamReader,
) -> tuple[bytes, bytes] | tuple[None, None]:
    """
    Async equivalent of ``recv_response`` using ``asyncio.StreamReader``.

    Performs the same three-stage read (minimum header → optional extension →
    payload) as the synchronous version but yields control to the event loop
    during each I/O wait.

    Args:
        reader: asyncio stream reader positioned at the start of a frame.

    Returns:
        ``(header_bytes, payload_bytes)`` on success, or ``(None, None)`` on
        connection error.
    """
    try:
        header = await async_recv_exact(reader, 20)
    except ConnectionError:
        return None, None

    mclass     = struct.unpack_from("<H", header, 18)[0]
    header_len = HEADER_LENGTHS.get(mclass, 20)

    if header_len > 20:
        try:
            header += await async_recv_exact(reader, header_len - 20)
        except ConnectionError:
            return None, None

    msg_len = struct.unpack_from("<I", header, 8)[0]
    if msg_len > 0:
        try:
            payload = await async_recv_exact(reader, msg_len)
        except ConnectionError:
            return None, None
    else:
        payload = b""

    return header, payload


# ============================================================================
#  SESSION COUNTER HELPER
# ============================================================================

def next_mess_id(session: SessionState) -> int:
    """
    Advance the session's 24-bit sequence counter and return the new value.

    The counter wraps at 2²⁴ (16 777 216).  It occupies the upper three bytes
    of the 4-byte mess_id header field; the lower byte is always ``ch_id``.
    Callers should call this once per outgoing message and pass the result to
    ``build_header``.

    Args:
        session: Live session whose counter will be mutated.

    Returns:
        The new sequence number (1 on the first call, wrapping after 2²⁴ − 1).
    """
    session.mess_id = (session.mess_id + 1) % 0x1000000
    return session.mess_id


# ============================================================================
#  SESSION LIFECYCLE
# ============================================================================

async def connect(host: str, port: int = PORT) -> SessionState:
    """
    Open a TCP connection to the camera and return an uninitialised session.

    This only establishes the transport layer.  No authentication has occurred;
    ``nonce``, ``negotiated_enc``, and ``aes_key`` are all unset.  Call
    ``login`` (which calls ``get_nonce`` internally) to complete the handshake.

    Args:
        host: Camera IP address or hostname.
        port: TCP port (default ``PORT`` = 9000).

    Returns:
        A ``SessionState`` with ``reader`` and ``writer`` populated.

    Raises:
        OSError: If the TCP connection cannot be established.
    """
    reader, writer = await asyncio.open_connection(host, port)
    return SessionState(host=host, port=port, reader=reader, writer=writer)


async def get_nonce(session: SessionState, config: SessionConfig) -> str:
    """
    Send the GetNonce request and parse the camera's nonce response.

    This is stage one of the two-stage handshake.  The function:

    1. Builds and sends the legacy GetNonce message.
    2. Reads the camera's response and extracts the ``<nonce>`` value.
    3. Records the encryption level the camera chose (from the response's
       encrypt/dd byte) in ``session.negotiated_enc``.
    4. If AES was negotiated, derives ``session.aes_key`` immediately so it is
       available for the subsequent ``login`` call.

    **Encryption negotiation at this stage:**  The client advertises its
    ceiling in the ``encrypt`` field of the outgoing header.  The first byte
    of the camera's ``encrypt`` field in the response is the chosen level.
    Byte value ``0x01`` = BC; ``0x02`` = AES.  The second byte changes from
    ``0xDC`` (client capability) to ``0xDD`` (camera choice).

    Args:
        session: Connected but unauthenticated session.
        config:  Preferences governing encryption negotiation.

    Returns:
        The nonce string extracted from the camera response.

    Raises:
        ConnectionError:    If the socket closes during the exchange.
        ValueError:         If the nonce element is absent in the XML.
        EncryptionError:    If the camera's chosen level is plaintext and
            ``config.reject_plaintext`` is ``True``, or if BC was chosen when
            the config does not permit fallback.
        RuntimeError:       If the response message class is unrecognised.
    """
    assert session.reader is not None and session.writer is not None, (
        "Session not connected — call connect() first."
    )

    # The encrypt advertisement byte b'\x12\xdc' is required here.  The protocol
    # specification implies b'\x02\xdc' (AES capability) or b'\x03\xdc' should
    # work, but the camera firmware silently discards the GetNonce message for any
    # value other than 0x12 in the first byte.  The meaning of 0x12 in this context
    # is not documented; it is a magic value observed in reolink_aio and verified
    # against multiple firmware versions.  Do not derive this from preferred_enc.
    payload = build_get_nonce_payload()
    header  = build_header(
        cmd_id        = CMD_LOGIN,
        payload_len   = len(payload),
        message_class = 0x6514,
        ch_id         = session.ch_id,
        mess_id       = next_mess_id(session),
        encrypt       = ENCRYPT_ADV_DEFAULT,   # b'\x12\xdc' — empirically required.
    )
    session.writer.write(header + payload)
    await session.writer.drain()

    # Read the response — payload is BC-encrypted in all observed firmware.
    resp_header, resp_payload = await async_recv_response(session.reader)
    if resp_header is None:
        raise ConnectionError(f"No response to GetNonce from {session.host}.")

    # Parse the negotiated encryption level from the camera's response.
    # At offset 16 in the legacy response header: [level_byte][0xDD].
    # 0x01 = BC chosen; 0x02 = AES chosen; 0x00 = plaintext (reject).
    resp_enc_byte  = resp_header[16]
    negotiated_raw = resp_enc_byte & 0x0F   # Lower nibble is the level.
    try:
        negotiated = EncType(negotiated_raw)
    except ValueError:
        negotiated = EncType.BC   # Treat unknown values as BC (conservative).

    if negotiated == EncType.NONE and config.reject_plaintext:
        raise RuntimeError(
            f"Camera {session.host} chose plaintext (EncType.NONE) "
            "and reject_plaintext is True."
        )
    if negotiated == EncType.BC and config.preferred_enc == EncType.AES and not config.allow_bc_fallback:
        raise RuntimeError(
            f"Camera {session.host} chose BC when AES was requested "
            "and allow_bc_fallback is False."
        )

    session.negotiated_enc = negotiated

    # Decrypt the nonce response payload.
    # The nonce response is BC-encrypted regardless of the negotiated session
    # encryption.  The enc_offset for decryption is header[12] (the first byte
    # of the mess_id field in the *response* header).
    enc_offset = resp_header[12]
    if resp_payload.startswith(b"<?xml"):
        xml_bytes = resp_payload   # Plaintext — older firmware.
    else:
        xml_bytes = bc_decrypt(enc_offset, resp_payload)

    xml_str = xml_bytes.rstrip(b"\x00").decode("utf-8")

    # Extract the nonce element.
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        raise ValueError(
            f"Camera {session.host}: failed to parse nonce response XML: {exc}\n"
            f"Raw decrypted: {xml_str!r}"
        ) from exc

    nonce_el = root.find(".//nonce")
    if nonce_el is None or not nonce_el.text:
        raise ValueError(
            f"Camera {session.host}: <nonce> element missing in response:\n{xml_str}"
        )

    session.nonce = nonce_el.text.strip()

    # Derive the AES key now regardless of negotiation outcome.  If the camera
    # chose BC this time, having the key ready means an AES retry is cheap.
    # The uppercase flag is the empirically uncertain parameter — see
    # SessionConfig.aes_key_uppercase and derive_aes_key for details.
    session.aes_key = derive_aes_key(
        session.nonce,
        "",   # Password is not available here; caller must call login() next.
        uppercase=config.aes_key_uppercase,
    )
    # aes_key will be re-derived with the real password inside login().

    return session.nonce


async def login(
    session:  SessionState,
    username: str,
    password: str,
    config:   SessionConfig,
) -> dict:
    """
    Perform the complete two-stage Baichuan login handshake.

    Calls ``get_nonce`` internally if the nonce has not yet been obtained, so
    callers only need to call this function directly.

    **Stage 1** — ``get_nonce``: sends a legacy GetNonce message, receives the
    nonce, negotiates encryption level, and derives the AES key if applicable.

    **Stage 2** — modern login: builds the LoginUser XML with nonce-mixed
    credential hashes, encrypts it with the negotiated cipher, and sends it
    under a modern (24-byte) header.  Parses the 200/400/401 response and
    returns the device information block.

    Args:
        session:  Connected but unauthenticated ``SessionState``.
        username: Plain-text camera username.
        password: Plain-text camera password.
        config:   Encryption preferences.

    Returns:
        A dict of device info fields extracted from the camera's login response
        (model, firmware version, channel count, etc.).  Keys depend on what
        the specific firmware includes in its ``DeviceInfo`` block.

    Raises:
        ConnectionError:    If the socket closes at any point.
        PermissionError:    If the camera returns a 401 (bad credentials).
        RuntimeError:       On unexpected response codes or structural errors.
    """
    # Stage 1 — nonce.
    if not session.nonce:
        await get_nonce(session, config)

    print(f"Session Nonce: {session.nonce}")
    # Re-derive the AES key now that we have the real password.
    session.aes_key = derive_aes_key(
        session.nonce,
        password,
        uppercase=config.aes_key_uppercase,
    )
    print(f"Session AES Key:{session.aes_key}")

    # Build the credential hashes.  Modern firmware convention (reolink_aio):
    # userName = MD5(username + nonce),  password = MD5(password + nonce).
    user_hash = hash_credential(username, session.nonce)
    pass_hash = hash_credential(password, session.nonce)
    xml_body  = build_login_xml(user_hash, pass_hash)
    print(f"XML BODY DATA: {xml_body}")

    # Encrypt the login payload with the negotiated cipher.
    encrypted_body = bc_decrypt(session.ch_id, xml_body)

    # Stage 2 — send modern login (class 0x6414, 24-byte header).
    header = build_header(
        cmd_id         = CMD_LOGIN,
        payload_len    = len(encrypted_body),
        message_class  = 0x6414,
        ch_id          = session.ch_id,
        mess_id        = next_mess_id(session),
        payload_offset = 0,
    )

    print(f"Stage 2 Header build: {header}")

    assert session.writer is not None
    session.writer.write(header + encrypted_body)
    await session.writer.drain()

    # Read the login response.
    resp_header, resp_payload = await async_recv_response(session.reader)
    if resp_header is None:
        raise ConnectionError(
            f"No response to login from {session.host}."
        )
    print(f"Response Header : {resp_header}")
    # The modern response header has a status code at offset 16.
    # c8 00 = 200 OK; 90 01 = 400 Bad Request; 91 01 = 401 Unauthorised.
    status_code = struct.unpack_from("<H", resp_header, 16)[0]
    print(f"Status Code: {status_code}")
    if status_code == 0x0190:   # 400
        raise RuntimeError(
            f"Camera {session.host}: login returned 400 Bad Request."
        )
    if status_code == 0x0191:   # 401
        raise PermissionError(
            f"Camera {session.host}: login returned 401 Unauthorised — "
            "check username and password."
        )
    if status_code != 0x00C8:   # anything other than 200
        raise RuntimeError(
            f"Camera {session.host}: unexpected login status 0x{status_code:04X}."
        )

    session.logged_in = True

    # Decrypt and parse the device-info response.
    enc_offset  = resp_header[12]
    xml_bytes = bc_decrypt(enc_offset, resp_payload)
    xml_str     = xml_bytes.rstrip(b"\x00").decode("utf-8")

    device_info: dict = {}
    try:
        root    = ET.fromstring(xml_str)
        dev_el  = root.find(".//DeviceInfo")
        if dev_el is not None:
            for child in dev_el:
                if child.text:
                    device_info[child.tag] = child.text.strip()
    except ET.ParseError:
        # Non-fatal — the session is authenticated; info parsing is best-effort.
        pass

    return device_info


async def close(session: SessionState) -> None:
    """
    Send a logout message and close the TCP connection cleanly.

    Best-effort: if the socket is already closed the function returns without
    raising.  The session's ``logged_in`` flag is cleared regardless of
    network outcome.

    Args:
        session: The session to terminate.
    """
    session.logged_in = False

    if session.writer is None:
        return

    # Attempt a graceful logout if the session authenticated successfully.
    try:
        header = build_header(
            cmd_id        = CMD_LOGOUT,
            payload_len   = 0,
            message_class = 0x6414,
            ch_id         = session.ch_id,
            mess_id       = next_mess_id(session),
        )
        session.writer.write(header)
        await session.writer.drain()
    except OSError:
        pass   # Socket may already be gone; ignore.

    try:
        session.writer.close()
        await session.writer.wait_closed()
    except OSError:
        pass

    session.reader = None
    session.writer = None


# ============================================================================
#  QUICK TEST / EXAMPLE
# ============================================================================

if __name__ == "__main__":
    import sys

    CAMERA_IP = "192.168.1.220"
    USERNAME  = "admin"
    PASSWORD  = "Outback59!"       # Replace with real password before testing.

    async def _test() -> None:
        cfg     = SessionConfig(
            preferred_enc     = EncType.AES,
            allow_bc_fallback = True,
            reject_plaintext  = True,
            aes_key_uppercase = True,   # Flip to False if AES login returns 401.
        )
        session = await connect(CAMERA_IP)
        print(f"Connected to {CAMERA_IP}:{PORT}")

        try:
            device_info = await login(session, USERNAME, PASSWORD, cfg)
        except PermissionError as exc:
            print(f"Authentication failed: {exc}")
            await close(session)
            sys.exit(1)
        except RuntimeError as exc:
            print(f"Login error: {exc}")
            await close(session)
            sys.exit(1)

        print(f"Negotiated encryption : {session.negotiated_enc.name}")
        print(f"Nonce                 : {session.nonce}")
        print(f"Logged in             : {session.logged_in}")
        print("Device info:")
        for k, v in device_info.items():
            print(f"  {k}: {v}")

        await close(session)
        print("Session closed.")

    asyncio.run(_test())