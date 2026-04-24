#!/usr/bin/env python3
"""
baichuan.py
===========

:author: Aidan A. Bradley
:date: April 23rd, 2026

The Baichuan protocol is a proprietary communication and authorization protocol
developed by Baichuan SoC Company for their ARM-based camera systems.  The main
protocol has not been publicly discussed or disseminated in any form by ReoLink
or Baichuan (the company).

This protocol was initially reverse-engineered by George Hilliard
(a.k.a. *thirtythreeforty* on GitHub), and then extensively polished into a
full-fledged program known as **NeoLink**.  The project's current maintainer is
Andrew W. King (a.k.a. *quantumentangledandy* on GitHub).  Although the project
has grown dusty, this Python system is intended as a complete rewrite of the
NeoLink codebase — not to mimic or recreate it, but to build a base library
with extensive commentary.

The exact mechanisms implemented here were determined through extensive testing
and by reading disparate documentation from the original authors and the
community surrounding NeoLink, as well as some code evaluated inside the
``reolink_aio`` Python module.  Although ``reolink_aio`` exists and works, this
module aims to be more focused on building a dedicated streaming library for
ReoLink cameras, much in the way NeoLink was originally aiming to.

**Background / Motivation**

The impetus for this module came from repeated failed attempts to use the
built-in RTSP/RTMP streams.  Artifacting, image columnation, I-frame issues,
improper buffering, color shifts, and other anomalies made those streams
unusable for a live outdoor activity feed.  Switching to NeoLink yielded a
dramatic quality increase at low CPU/GPU cost.  However, NeoLink struggled with
multiple concurrent high-resolution streams — even on a machine with an
RTX 4070, a 4.5 GHz AMD CPU, and 32 GB of RAM.  Increasing I-frame intervals
(x2, x4) and raising resolution/fps caused a buffer runaway, with RAM
allocation creeping up rapidly.  Partitioning cameras across multiple NeoLink
instances and coupling MediaMTX helped stabilize things somewhat, but the
added chain and complexity reduced overall reliability — particularly when
approaching the limits of older Proliant Gen7/8 server NICs used for ingest.
Switching to direct desktop ingest showed no improvement; NeoLink's buffer
management was the clear bottleneck.

None of this diminishes NeoLink's achievement.  It is an incredible piece of
work, and the community around it provided the examples and insight needed to
understand and reason about Baichuan stream chains.  This module stands on that
foundation.

**Verified handshake sequence** (confirmed against Duo 3 PoE firmware)

  Stage 1 — GetNonce
    Client sends: legacy header (0x6514, 20 bytes) + GetNonce XML payload.
    Camera sends: legacy header (0x6614, 20 bytes) + BC-encrypted Encryption
    XML.  The Encryption XML contains ``<type>`` (login encryption method) and
    ``<nonce>`` (the session nonce string).  The ``<type>`` field drives login
    path selection in Stage 2.

  Stage 2 — Login (BC XOR path, ``<type>md5``)
    Client sends: modern header (0x6414, 24 bytes) + BC-encrypted LoginUser XML.
    Credentials: MD5(value + nonce)[:31].upper() — 31 hex chars, not 32.
    Camera sends: modern header (0x0000, 24 bytes, status=200) + BC-encrypted
    DeviceInfo and StreamInfoList XML.

  Stage 2 — Login (AES path, ``<type>aes``)
    Client sends: modern header (0x6414, 24 bytes) + AES-128-CFB-encrypted
    LoginUser XML.  Credentials are plain MD5(value).hexdigest() — no nonce
    mixing, lowercase, all 32 chars.  AES key: MD5(nonce + "-" + password)[:16].
    Camera sends: same response structure as BC path.

    .. warning::

        The AES login path is implemented from the community protocol
        specification but has not yet been verified empirically against
        RLC-810A or RLC-1212A hardware.  It will be validated and corrected
        before the Session layer is built on top of this module.

  Stage 3 — Stream
    Client sends: modern header (cmd_id=3) + BC-encrypted Preview XML.
    Camera sends: one of three acknowledgement forms depending on firmware:

    * **XML ack** (older firmware): ``<Extension>`` block with
      ``<binaryData>1</binaryData>``, then binary stream frames begin.
    * **Bare 200 OK** (Duo 3 PoE, confirmed): class-0x0000 modern header,
      status=200, zero-length payload; binary stream frames begin immediately.
    * **Implicit ack** (some variants): a non-XML payload on a 200 response;
      the first media frame arrives as the ack response body and has already
      been consumed from the socket before ``request_stream()`` returns.

**Key implementation notes**

- The login response uses message class 0x0000 (a 24-byte modern header).
  Any ``HEADER_LENGTHS`` table that omits 0x0000 will misread the response,
  prepending 4 rogue payload-offset bytes to the payload and producing garbled
  output.  This was the final bug resolved before a working login was achieved.

- BC credential hashes are MD5(value + nonce) truncated to 31 hex characters
  (uppercase).  The protocol allocates a 32-byte field with a null terminator;
  byte 32 is always zero and is never compared by the camera firmware.

- AES credential hashes are plain MD5(value).hexdigest() — no nonce mixing,
  lowercase, all 32 characters.  The nonce appears only in AES key derivation,
  not in the credential fields themselves.

- BC encryption uses CH_ID (0xFA for host-level commands) as the enc_offset
  for all outgoing payloads.  The camera echoes this byte at header[12] in
  its responses, which is the correct offset to pass to ``bc_crypt()`` for
  decryption.

- All multi-byte integers on the wire are little-endian, consistent with the
  ARM architecture of the underlying Baichuan SoC.

- The encryption advertisement byte in the GetNonce header must be 0x12
  (i.e. ``b'\\x12\\xdc'``).  Other values cause the camera to silently discard
  the message with no response.  The meaning of 0x12 is not documented in any
  public specification; it is an empirically required magic value.

**Camera model heterogeneity**

The production deployment covers five distinct Reolink models.  Two fields
from ``DeviceInfo`` are critical for geometry-correct decoding at the layers
above the wire:

* ``bino_type`` — non-zero for dual-sensor (Duo series) cameras.  The Session
  layer must propagate this to the Stream Pipe layer so consumers receive
  correct panoramic geometry metadata.
* ``need_rotate`` — ``1`` on Duo 3 PoE (confirmed), indicating the encoded
  frame data is rotated 90° relative to the declared display dimensions.
  Downstream decoders that ignore this produce the columnation artefacts
  observed in naive RTSP pipelines.

+----------------+---------+-------------------------------------------+
| Model          | Count   | Notes                                     |
+================+=========+===========================================+
| RLC-810A       | 4       | Single sensor, 8 MP                       |
| RLC-1212A      | 3       | Single sensor, 12 MP                      |
| Duo 2 PoE      | 1       | Dual sensor panoramic                     |
| Duo 2V PoE     | 3       | Dual sensor, vertical orientation         |
| Duo 3 PoE      | 4       | Dual sensor, needRotate=1 (confirmed)     |
+----------------+---------+-------------------------------------------+

**Module structure**

This module is the complete Serial Layer (wire communication layer).  It is
organised into ten sections:

  1. Protocol constants — wire values, command IDs, cipher constants
  2. BC cipher           — ``bc_crypt`` (symmetric XOR, str/bytes input,
                           validated offset)
  3. AES cipher          — ``derive_aes_key``, ``aes_encrypt``,
                           ``aes_decrypt``
  4. Header construction — ``build_header``
  5. Socket I/O          — ``recv_exact``, ``recv_frame``, ``parse_header``
  6. Credential helpers  — ``hash_credential`` (BC XOR path),
                           ``hash_credential_plain`` (AES path)
  7. Payload builders    — ``build_get_nonce_payload``,
                           ``build_login_payload``,
                           ``build_aes_login_payload``,
                           ``build_preview_payload``
  8. Data model          — ``DeviceInfo``, ``EncodeTable``, ``StreamInfo``,
                           ``LoginResponse``, ``Session``
  9. Session lifecycle   — ``open_session``, ``get_nonce``, ``login``,
                           ``request_stream``, ``close_session``
  10. High-level API     — ``BaichuanSession`` context manager with
                           ``connect()`` for single-call authentication
"""

import hashlib
import logging
import socket
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional, Union

# AES is required for cameras that negotiate the AES login path (enc_type "aes").
# PyCryptodome is the maintained fork; pycrypto is the legacy fallback.
# Install with: pip install pycryptodome
# BC XOR login (the path verified on all currently tested cameras) is not affected
# if this import fails; the ImportError surfaces only when aes_encrypt/aes_decrypt
# are actually called.
try:
    from Cryptodome.Cipher import AES as _AES
except ImportError:
    try:
        from Crypto.Cipher import AES as _AES  # type: ignore[no-redef]
    except ImportError:
        _AES = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


# ============================================================================
#  1. PROTOCOL CONSTANTS
# ============================================================================
#
#  All integer constants are written in standard (big-endian-readable) form,
#  e.g. 0x6514 rather than 0x1465.  When building wire messages they are
#  explicitly serialised as little-endian, so callers never have to reason
#  about byte order until the moment a header is assembled.
# ============================================================================

MAGIC: int = 0x0ABCDEF0
"""
Magic number that opens every Baichuan frame.

Serialised as little-endian it becomes the byte sequence ``f0 de bc 0a`` on
the wire.  A separate magic value (``a0 cd ed 0f``) exists for NVR-to-IPC
internal traffic and is not relevant for client implementations.  This value
is fixed across all known ReoLink/Baichuan devices.
"""

PORT: int = 9000
"""
Default TCP port for the Baichuan protocol.

ReoLink cameras listen on port 9000 out of the box.  This can be changed from
the camera's network settings, in which case pass the custom port explicitly
wherever a port argument is accepted.
"""

RECV_TIMEOUT: float = 15.0
"""
Socket receive timeout in seconds.

How long the library will block waiting for data before raising a timeout
error.  Increase on high-latency or heavily loaded networks; decrease for
faster failure detection in managed reconnect loops at the Session layer.
"""

XML_KEY: bytes = bytes([0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF])
"""
8-byte rotating XOR key used to obfuscate XML payloads (BC encryption).

**Do not modify.**  This key is identical across every known ReoLink device;
changing it will break decryption of all camera responses.
"""

AES_IV: bytes = b"0123456789abcdef"
"""
Fixed 16-byte AES initialisation vector used for the AES-128-CFB login path.

Hardcoded by the protocol specification.  The IV does not change between
sessions; only the derived AES key changes (incorporating the session nonce).
"""

HEADER_LENGTHS: dict[int, int] = {
    0x6514: 20,   # Legacy  — client GetNonce request
    0x6614: 20,   # Legacy  — camera nonce response (no payload-offset field)
    0x6414: 24,   # Modern  — client login / command (includes payload-offset)
    0x0000: 24,   # Modern  — camera login response (status at offset 16)
    0x6482: 24,   # Modern  — file download variant
    0x0146: 24,   # Modern  — alternate command variant
}
"""
Mapping of message-class integers to their corresponding header sizes in bytes.

Baichuan headers come in two sizes:

* **20 bytes** — legacy classes (nonce exchange, older firmware).  Layout::

      MAGIC(4) + cmd_id(4) + msg_len(4) + mess_id(4) + encrypt(2) + class(2)

* **24 bytes** — modern classes (login, commands, camera responses).  Same
  layout plus::

      … + payload_offset(4)

  The ``encrypt`` field in legacy client headers and the ``status`` field in
  modern camera response headers occupy the same two bytes at offset 16 —
  they serve different roles depending on message direction and class.

.. warning::

    ``0x0000`` **must** be present in this table.  Without it, ``recv_frame``
    reads only 20 bytes for the login response header.  The 4-byte
    payload-offset field is then prepended to the payload, producing garbled
    XML.  This was the final bug resolved before a successful login was
    achieved.

Keys are message-class integers in standard (big-endian-readable) notation.
"""

# Baichuan command IDs — placed in the cmd_id field (offset 4) of every header.
CMD_LOGIN:  int = 1
"""Command ID for GetNonce requests and Login messages."""
CMD_LOGOUT: int = 2
"""Command ID for the session logout message."""
CMD_VIDEO:  int = 3
"""Command ID for Preview (stream start) requests."""

# Encryption advertisement bytes for the GetNonce legacy (20-byte) header.
# 0x12 at offset 16 is an empirically required magic value.  Other values
# (0x01, 0x02, 0x03) cause the camera to silently discard the frame.
ENCRYPT_ADV: bytes = b'\x12\xdc'
"""
Encryption advertisement bytes for the GetNonce legacy (20-byte) header.

Placed at offset 16 (the ``encrypt`` field).  ``0x12`` is an empirically
required magic value whose meaning is undocumented in any public specification.
``0xdc`` is the "unknown" second byte observed in community implementations.
Do not change without testing against physical hardware.
"""

CH_ID_HOST: int = 0xFA
"""
Host-level channel identifier.

Placed as the first byte of the 4-byte ``mess_id`` field (offset 12) in every
outgoing header.  Also used as the ``enc_offset`` parameter when BC-encrypting
outgoing payloads, because the camera reads this same byte from the received
header to determine the decryption offset for its responses.
"""

# Encryption type strings returned in the camera's <type> element (GetNonce
# response).  These drive login path selection in login().
ENC_TYPE_MD5: str = "md5"
"""
Nonce response encryption type indicating the BC XOR login path.

When the camera's ``<Encryption>`` response contains ``<type>md5</type>``,
login credentials are hashed as MD5(value + nonce)[:31].upper() and the
payload is BC XOR encrypted.  This is the path verified against all currently
tested cameras (Duo 3 PoE, confirmed working).
"""

ENC_TYPE_AES: str = "aes"
"""
Nonce response encryption type indicating the AES-128-CFB login path.

When the camera returns ``<type>aes</type>``, credentials are plain
MD5(value).hexdigest() (no nonce mixing), and the LoginUser payload is
AES-128-CFB encrypted with a nonce-derived key.

.. warning::

    This path is implemented from the community protocol specification but has
    not been verified against RLC-810A or RLC-1212A hardware.  The ``authMode``
    field in ``DeviceInfo`` (expected non-zero for AES cameras) will be used
    for post-login verification once testing is possible.
"""


# ============================================================================
#  2. BC CIPHER
# ============================================================================

def bc_crypt(enc_offset: int, data: Union[str, bytes]) -> bytes:
    """
    Apply the Baichuan XOR cipher to *data*.

    The BC cipher is symmetric — the same function handles both encryption
    of outgoing payloads and decryption of incoming payloads.

    **Algorithm:**

    For each byte at index *i* in *data*:

    .. code-block:: text

        key_byte  = XML_KEY[(enc_offset + i) % 8]
        result[i] = data[i] ^ key_byte ^ (enc_offset & 0xFF)

    where ``offset_byte = enc_offset & 0xFF``.

    **Direction guide:**

    * **Outgoing** (client → camera): pass ``session.ch_id`` as *enc_offset*.
      The camera reads the ch_id byte from the received header to derive the
      same offset for decryption.
    * **Incoming** (camera → client): pass ``header[12]`` (the first byte of
      the camera's ``mess_id`` field) as *enc_offset*.

    Args:
        enc_offset: Byte-range offset in [0, 255].  Used as both the
            key-rotation seed and the per-byte XOR mask.  Values outside this
            range raise ``ValueError``; the protocol provides only one byte for
            this field and silent masking would hide bugs.
        data: Raw bytes or UTF-8 string to transform.  Strings are encoded to
            UTF-8 before processing.

    Returns:
        Transformed bytes of the same length as the input.

    Raises:
        ValueError: If *enc_offset* is outside [0, 255].
        TypeError:  If *data* is neither ``str`` nor ``bytes``/``bytearray``.
    """
    if not (0 <= enc_offset <= 255):
        raise ValueError(
            f"BC cipher enc_offset must be in [0, 255], got {enc_offset}."
        )
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(
            f"bc_crypt expects str or bytes, got {type(data).__name__}."
        )

    offset_byte = enc_offset & 0xFF
    result      = bytearray(len(data))
    for i, byte in enumerate(data):
        key_byte  = XML_KEY[(enc_offset + i) % 8]
        result[i] = byte ^ key_byte ^ offset_byte
    return bytes(result)


# ============================================================================
#  3. AES CIPHER
# ============================================================================

def derive_aes_key(nonce: str, password: str) -> bytes:
    """
    Derive the 16-byte AES-128 key for the AES login path.

    Key derivation formula (from community protocol specification)::

        key_material = nonce + "-" + password
        key = MD5(key_material).hexdigest()[:16].encode("ascii")

    The hyphen separator is literal and required.  The result is the first
    16 characters of the hex digest encoded as ASCII bytes, yielding a
    128-bit (16-byte) key.

    Args:
        nonce:    Session nonce string from the GetNonce response.
        password: Plain-text camera password.

    Returns:
        16-byte AES key.

    Example:
        If ``nonce = "abc123"`` and ``password = "secret"``::

            key_material = "abc123-secret"
            key = MD5("abc123-secret").hexdigest()[:16].encode("ascii")
    """
    key_material = f"{nonce}-{password}"
    return hashlib.md5(key_material.encode("utf-8")).hexdigest()[:16].encode("ascii")


def aes_encrypt(key: bytes, plaintext: Union[str, bytes]) -> bytes:
    """
    Encrypt *plaintext* with AES-128-CFB using the fixed protocol IV.

    The Baichuan AES path uses AES-128 in CFB mode with 128-bit feedback
    (CFB128) and the fixed IV ``AES_IV`` (``b"0123456789abcdef"``).  The key
    must be derived via ``derive_aes_key()`` for each session.

    Args:
        key:       16-byte AES key from ``derive_aes_key()``.
        plaintext: Data to encrypt.  Strings are UTF-8 encoded before
                   encryption.

    Returns:
        AES-128-CFB128 ciphertext bytes of the same length as the input.

    Raises:
        RuntimeError: If pycryptodome (or pycrypto) is not installed.
            Install with: ``pip install pycryptodome``
    """
    if _AES is None:
        raise RuntimeError(
            "AES login path requires pycryptodome.  "
            "Install with: pip install pycryptodome"
        )
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    cipher = _AES.new(key, _AES.MODE_CFB, iv=AES_IV, segment_size=128)
    return cipher.encrypt(plaintext)


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt *ciphertext* with AES-128-CFB using the fixed protocol IV.

    Inverse of ``aes_encrypt()``.  Uses the same key, IV, and mode.  Camera
    responses under the AES path are decrypted with this function using the
    same derived key that encrypted the login payload.

    Args:
        key:        16-byte AES key from ``derive_aes_key()``.
        ciphertext: Encrypted bytes from the camera.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        RuntimeError: If pycryptodome (or pycrypto) is not installed.
    """
    if _AES is None:
        raise RuntimeError(
            "AES login path requires pycryptodome.  "
            "Install with: pip install pycryptodome"
        )
    cipher = _AES.new(key, _AES.MODE_CFB, iv=AES_IV, segment_size=128)
    return cipher.decrypt(ciphertext)


# ============================================================================
#  4. HEADER CONSTRUCTION
# ============================================================================

def build_header(
    cmd_id:         int,
    payload_len:    int,
    message_class:  int,
    ch_id:          int   = CH_ID_HOST,
    mess_id:        int   = 0,
    encrypt:        bytes = ENCRYPT_ADV,
    status:         int   = 0,
    payload_offset: int   = 0,
) -> bytes:
    """
    Build a Baichuan message header.

    The header size (20 or 24 bytes) is determined automatically from
    *message_class* using ``HEADER_LENGTHS``.

    **Legacy layout** (20 bytes, classes 0x6514 / 0x6614)::

        Offset  Bytes  Field
          0       4    Magic (LE: f0 de bc 0a)
          4       4    cmd_id         (LE uint32)
          8       4    payload_len    (LE uint32)
         12       4    mess_id        ([ch_id:1][mess_id:3], LE)
         16       2    encrypt        (capability advertisement)
         18       2    message_class  (LE uint16)

    **Modern layout** (24 bytes, classes 0x6414 / 0x0000 / etc.)::

        Offset  Bytes  Field
          0–17         (same as legacy)
         16       2    status         (0x0000 in all client requests)
         18       2    message_class  (LE uint16)
         20       4    payload_offset (LE uint32)

    Note on offsets 16–17: these bytes hold ``encrypt`` in legacy headers and
    ``status`` in modern headers.  The *encrypt* argument is unused for modern
    classes; the *status* argument is unused for legacy classes.

    Args:
        cmd_id:         Baichuan function code (``CMD_LOGIN``, etc.).
        payload_len:    Byte length of the payload that follows this header.
        message_class:  Selects the header layout and total byte size.
        ch_id:          Channel identifier byte.  ``CH_ID_HOST`` (0xFA) for
                        all single-camera host-level commands.  Also used as
                        the BC ``enc_offset`` for the accompanying payload, so
                        it must match whatever was passed to ``bc_crypt()``.
        mess_id:        24-bit rolling sequence counter.  Increment once per
                        outgoing message via ``next_mess_id()``.
        encrypt:        2-byte advertisement at offset 16 in legacy headers.
                        Defaults to ``ENCRYPT_ADV`` (``b'\\x12\\xdc'``).
        status:         2-byte status at offset 16 in modern headers.  Always
                        0 in client requests.
        payload_offset: Byte position within the payload where binary data
                        begins.  Zero for all pure XML messages.

    Returns:
        Packed header bytes (20 or 24 bytes).
    """
    header_len  = HEADER_LENGTHS.get(message_class, 20)
    magic_bytes = MAGIC.to_bytes(4, "little")
    cmd_bytes   = cmd_id.to_bytes(4, "little")
    plen_bytes  = payload_len.to_bytes(4, "little")
    # mess_id field: [ch_id (1 byte)] + [mess_id (3 bytes, LE)]
    mid_bytes   = ch_id.to_bytes(1, "little") + mess_id.to_bytes(3, "little")
    cls_bytes   = message_class.to_bytes(2, "little")

    if header_len == 20:
        return magic_bytes + cmd_bytes + plen_bytes + mid_bytes + encrypt + cls_bytes

    status_bytes = status.to_bytes(2, "little")
    poff_bytes   = payload_offset.to_bytes(4, "little")
    return (
        magic_bytes + cmd_bytes + plen_bytes + mid_bytes
        + status_bytes + cls_bytes + poff_bytes
    )


# ============================================================================
#  5. SOCKET I/O
# ============================================================================

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly *n* bytes from a blocking socket, looping until satisfied.

    A single ``recv()`` call is not guaranteed to return the requested number
    of bytes — particularly on congested or high-latency network paths.  This
    helper accumulates chunks until the full count is satisfied, making it
    safe to use as the primitive for all framed protocol reads.

    Args:
        sock: Connected blocking socket.
        n:    Exact number of bytes to read.

    Returns:
        ``bytes`` of length exactly *n*.

    Raises:
        ConnectionError: If the remote end closes the connection before *n*
            bytes have arrived.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"Socket closed after {len(buf)} of {n} expected bytes."
            )
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> tuple[bytes, bytes]:
    """
    Read one complete Baichuan frame (header + payload) from *sock*.

    Reads in three stages:

    1. **Minimum header** — 20 bytes, present in every message class.
    2. **Header extension** — an additional 4 bytes for modern (24-byte)
       classes, determined by the message-class field at offset 18.
    3. **Payload** — ``msg_len`` bytes as reported at offset 8 in the header.

    Args:
        sock: Connected TCP socket positioned at the start of a Baichuan frame.

    Returns:
        ``(header_bytes, payload_bytes)`` on success.
        ``(b"", b"")`` if the connection closes cleanly at the header stage
        or a timeout occurs at the header stage — the caller should treat this
        as a normal disconnection signal.

    Raises:
        ConnectionError: If the connection drops mid-frame (after the header
            has been at least partially received).
    """
    # Stage 1: Minimum header.  A clean close or timeout here is treated as a
    # normal disconnection rather than an error.
    try:
        header = recv_exact(sock, 20)
    except (ConnectionError, socket.timeout):
        return b"", b""

    # Stage 2: Check the message-class field (offset 18, LE uint16) to decide
    # whether a 4-byte modern header extension is present.
    mclass     = struct.unpack_from("<H", header, 18)[0]
    header_len = HEADER_LENGTHS.get(mclass, 20)

    if header_len > 20:
        header += recv_exact(sock, header_len - 20)

    # Stage 3: Variable-length payload.
    msg_len = struct.unpack_from("<I", header, 8)[0]
    payload = recv_exact(sock, msg_len) if msg_len > 0 else b""

    return header, payload


def parse_header(header: bytes) -> dict:
    """
    Decode a raw Baichuan header into a named-field dictionary.

    Works for both 20-byte (legacy) and 24-byte (modern) headers.  Fields
    present only in modern headers are ``None`` for legacy headers.

    Args:
        header: Raw header bytes as returned by ``recv_frame()``.  Must be
                at least 20 bytes; 24 bytes expected for modern classes.

    Returns:
        Dictionary with the following keys:

        ``magic`` (int)
            The 4-byte magic number (should always equal ``MAGIC``).
        ``cmd_id`` (int)
            Baichuan command ID.
        ``msg_len`` (int)
            Byte length of the payload that follows.
        ``ch_id`` (int)
            First byte of the mess_id field (offset 12).  Used as the BC
            ``enc_offset`` when decrypting the accompanying payload.
        ``mess_id`` (int)
            24-bit rolling sequence counter (bytes 13–15, LE).
        ``enc_or_status`` (bytes)
            Raw 2 bytes at offset 16 — ``encrypt`` field in legacy client
            headers; ``status`` field in modern camera response headers.
        ``message_class`` (int)
            Message class identifier (offset 18, LE uint16).
        ``status_code`` (int)
            Bytes 16–17 interpreted as LE uint16.  Meaningful in modern
            camera responses: 0x00C8 = 200 OK, 0x0191 = 401 Unauthorized,
            0x0190 = 400 Bad Request.
        ``payload_offset`` (int or None)
            Byte offset where binary data begins within the payload.  Present
            only in 24-byte modern headers; ``None`` for 20-byte legacy headers.
    """
    mclass = struct.unpack_from("<H", header, 18)[0]
    return {
        "magic":          struct.unpack_from("<I", header, 0)[0],
        "cmd_id":         struct.unpack_from("<I", header, 4)[0],
        "msg_len":        struct.unpack_from("<I", header, 8)[0],
        "ch_id":          header[12],
        "mess_id":        int.from_bytes(header[13:16], "little"),
        "enc_or_status":  header[16:18],
        "message_class":  mclass,
        "status_code":    struct.unpack_from("<H", header, 16)[0],
        "payload_offset": struct.unpack_from("<I", header, 20)[0]
                          if len(header) >= 24 else None,
    }


# ============================================================================
#  6. CREDENTIAL HELPERS
# ============================================================================

def hash_credential(value: str, nonce: str) -> str:
    """
    Produce the nonce-mixed credential hash for the BC XOR login path.

    Used when the camera's GetNonce response contains ``<type>md5</type>``.

    **Formula:** ``MD5(value + nonce)[:31].upper()``

    The camera allocates a 32-byte field with a null terminator in the
    LoginUser XML; only 31 characters are ever compared by the firmware.
    Truncating to 31 is correct protocol behaviour, not a truncation error.

    Args:
        value: Plain-text username or password.
        nonce: Session nonce string from the GetNonce response.

    Returns:
        31-character uppercase hex string.
    """
    return hashlib.md5(
        f"{value}{nonce}".encode("utf-8")
    ).hexdigest()[:31].upper()


def hash_credential_plain(value: str) -> str:
    """
    Produce the plain MD5 credential hash for the AES login path.

    Used when the camera's GetNonce response contains ``<type>aes</type>``.
    Unlike the BC path, there is no nonce mixing — the nonce appears only in
    the AES key derivation (``derive_aes_key()``), not in the credential hash.

    **Formula:** ``MD5(value).hexdigest()``  (32 chars, lowercase)

    Args:
        value: Plain-text username or password.

    Returns:
        32-character lowercase hex string.

    .. warning::

        Unverified against physical hardware.  Derived from the community
        protocol specification.  Test against an RLC-810A or RLC-1212A
        before relying on this in production.
    """
    return hashlib.md5(value.encode("utf-8")).hexdigest()


# ============================================================================
#  7. PAYLOAD BUILDERS
# ============================================================================

def build_get_nonce_payload() -> bytes:
    """
    Build the minimal XML payload used to request an authentication nonce.

    This is the very first message sent to a camera after the TCP connection
    is established.  The body contains a single self-closing ``<GetNonce/>``
    element.  The camera responds with an ``<Encryption>`` block containing
    ``<type>`` (the login encryption method the camera expects) and ``<nonce>``
    (the session nonce string used in credential hashing or AES key derivation).

    Returns:
        UTF-8 encoded, null-terminated XML bytes ready to be appended to a
        legacy (0x6514) header.
    """
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<body>\n'
        '<GetNonce/>\n'
        '</body>'
    )
    return xml.encode("utf-8") + b"\x00"


def build_login_payload(username_hash: str, password_hash: str) -> bytes:
    """
    Build the LoginUser XML payload for the BC XOR login path.

    Used when the nonce response advertises ``<type>md5</type>``.  The
    credential fields carry nonce-mixed MD5 hashes produced by
    ``hash_credential()``.

    The ``LoginNet`` block is required — some firmware versions silently
    reject logins that omit it, even though the block content (LAN / UDP
    port 0) carries no meaningful information for a standard client session.

    Args:
        username_hash: 31-char uppercase hex from ``hash_credential()``.
        password_hash: 31-char uppercase hex from ``hash_credential()``.

    Returns:
        UTF-8 encoded, null-terminated XML bytes ready for BC encryption
        and appending to a modern (0x6414) header.
    """
    xml = (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
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


def build_aes_login_payload(username: str, password: str) -> bytes:
    """
    Build the LoginUser XML payload for the AES login path.

    Used when the nonce response advertises ``<type>aes</type>``.  Unlike the
    BC path, credentials here are plain MD5 hashes with no nonce mixing —
    the nonce appears only in the AES key derivation via ``derive_aes_key()``.

    This payload is passed to ``aes_encrypt()`` before transmission.  The AES
    key is derived separately: ``aes_key = derive_aes_key(nonce, password)``.

    Args:
        username: Plain-text camera username.
        password: Plain-text camera password.

    Returns:
        UTF-8 encoded, null-terminated XML bytes (containing plain MD5 hashes)
        ready for AES encryption and appending to a modern (0x6414) header.

    .. warning::

        Unverified against physical hardware.  See ``ENC_TYPE_AES`` for the
        full caveat.
    """
    user_hash = hash_credential_plain(username)
    pass_hash = hash_credential_plain(password)
    xml = (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<body>\n'
        '<LoginUser version="1.1">\n'
        f'<userName>{user_hash}</userName>\n'
        f'<password>{pass_hash}</password>\n'
        '<userVer>1</userVer>\n'
        '</LoginUser>\n'
        '<LoginNet version="1.1">\n'
        '<type>LAN</type>\n'
        '<udpPort>0</udpPort>\n'
        '</LoginNet>\n'
        '</body>'
    )
    return xml.encode("utf-8") + b"\x00"


def build_preview_payload(
    channel_id:  int = 0,
    handle:      int = 0,
    stream_type: str = "mainStream",
) -> bytes:
    """
    Build the Preview XML payload to request a video stream.

    After a successful login, the client sends this payload with ``CMD_VIDEO``
    to ask the camera to begin streaming.  The camera responds with an
    acknowledgement (XML, bare 200 OK, or implicit first frame — see
    ``request_stream()`` for the full taxonomy), after which all subsequent
    frames on the connection carry raw Baichuan-framed media packet data.

    Args:
        channel_id:  Camera channel index.  Always 0 for single-sensor
                     devices.  NVR channels are 0-indexed per the NVR's
                     channel list.
        handle:      Stream handle.  Must be unique across concurrent streams
                     on the same authenticated session.  Use 0 for single-
                     stream cases.  If the camera returns 400 on a fresh
                     connection, try handle=1 — a stale server-side stream
                     slot from a previous crashed session may be occupying
                     handle=0.
        stream_type: ``"mainStream"`` (full resolution, default) or
                     ``"subStream"`` (reduced resolution).  Production use
                     always selects ``"mainStream"``; ``"subStream"`` is
                     available for diagnostic or low-bandwidth scenarios.

    Returns:
        UTF-8 encoded, null-terminated XML bytes ready for BC encryption
        and appending to a modern (0x6414) header.
    """
    xml = (
        '<?xml version="1.0" encoding="UTF-8" ?>\n'
        '<body>\n'
        '<Preview version="1.1">\n'
        f'<channelId>{channel_id}</channelId>\n'
        f'<handle>{handle}</handle>\n'
        f'<streamType>{stream_type}</streamType>\n'
        '</Preview>\n'
        '</body>'
    )
    return xml.encode("utf-8") + b"\x00"


# ============================================================================
#  8. DATA MODEL
# ============================================================================

@dataclass
class DeviceInfo:
    """
    Scalar fields from the ``<DeviceInfo>`` block in the login response.

    A representative subset of wire fields is typed explicitly; all remaining
    fields land in ``extras`` so no wire data is ever silently dropped as
    firmware versions add new elements.

    Two fields carry geometry metadata that must be propagated to the Session
    and Stream Pipe layers:

    * ``bino_type`` — non-zero for dual-sensor (Duo series) cameras.  Consumers
      need to know the frame is a side-by-side panoramic stitch.
    * ``need_rotate`` — ``1`` on Duo 3 PoE (confirmed), meaning the encoded
      frame data is rotated 90° relative to the declared display dimensions.
      Decoders that ignore this produce the columnation artefacts observed in
      naive RTSP pipelines.

    ``auth_mode`` is expected to be non-zero on cameras that negotiate the AES
    login path, and may be used for post-login sanity checking once the AES
    path is verified against hardware.
    """
    firm_version:    str  = ""
    type:            str  = ""    # "ipc" / "nvr"
    type_info:       str  = ""    # "IPC"
    channel_num:     int  = 0
    audio_num:       int  = 0
    sd_card:         int  = 0
    soft_ver:        str  = ""
    hard_ver:        str  = ""
    language:        str  = ""
    norm:            str  = ""    # "NTSC" / "PAL"
    ptz_mode:        str  = ""
    bino_type:       int  = 0     # 0 = single sensor; non-zero = Duo series
    need_rotate:     int  = 0     # 1 = frame is 90° rotated; propagate upward
    auth_mode:       int  = 0     # 0 = BC XOR; non-zero expected for AES cameras
    resolution_name: str  = ""
    width:           int  = 0
    height:          int  = 0
    extras:          dict = field(default_factory=dict)

    @classmethod
    def from_element(cls, el: ET.Element) -> "DeviceInfo":
        """
        Parse a ``<DeviceInfo>`` XML element into a ``DeviceInfo`` instance.

        Unknown child elements are collected into ``extras`` rather than
        discarded, ensuring no wire data is silently lost as firmware adds
        new fields.

        Args:
            el: The ``<DeviceInfo>`` ``xml.etree.ElementTree.Element``.

        Returns:
            Populated ``DeviceInfo`` instance.
        """
        def _int(tag: str, default: int = 0) -> int:
            node = el.find(tag)
            try:
                return int(node.text.strip()) if node is not None and node.text else default
            except ValueError:
                return default

        def _str(tag: str) -> str:
            node = el.find(tag)
            return node.text.strip() if node is not None and node.text else ""

        # Tags handled by the typed fields above; everything else goes to extras.
        known = {
            "firmVersion", "type", "typeInfo", "channelNum", "audioNum",
            "sdCard", "softVer", "hardVer", "language", "norm", "ptzMode",
            "binoType", "needRotate", "authMode",
        }
        extras: dict = {}
        for child in el:
            if child.tag not in known and child.tag != "resolution":
                text = child.text.strip() if child.text else ""
                if text:
                    extras[child.tag] = text

        res_el = el.find("resolution")
        return cls(
            firm_version    = _str("firmVersion"),
            type            = _str("type"),
            type_info       = _str("typeInfo"),
            channel_num     = _int("channelNum"),
            audio_num       = _int("audioNum"),
            sd_card         = _int("sdCard"),
            soft_ver        = _str("softVer"),
            hard_ver        = _str("hardVer"),
            language        = _str("language"),
            norm            = _str("norm"),
            ptz_mode        = _str("ptzMode"),
            bino_type       = _int("binoType"),
            need_rotate     = _int("needRotate"),
            auth_mode       = _int("authMode"),
            resolution_name = res_el.findtext("resolutionName", "").strip()
                              if res_el is not None else "",
            width           = int(res_el.findtext("width",  "0") or 0)
                              if res_el is not None else 0,
            height          = int(res_el.findtext("height", "0") or 0)
                              if res_el is not None else 0,
            extras          = extras,
        )

    def summary(self) -> str:
        """Return a compact single-line human-readable summary."""
        return (
            f"{self.type_info or self.type}  fw={self.firm_version}"
            f"  res={self.resolution_name or f'{self.width}x{self.height}'}"
            f"  ch={self.channel_num}  norm={self.norm}"
            f"  bino={self.bino_type}  rotate={self.need_rotate}"
        )


@dataclass
class EncodeTable:
    """
    One ``<encodeTable>`` entry from the login response stream info block.

    Represents the encoding capabilities for a single stream type (main or
    sub) on a given channel: resolution, default and available framerate
    options, default and available bitrate options, and GOP interval.

    The ``default_gop`` field is the camera's configured I-frame interval in
    seconds.  Production cameras run at ``default_gop=1`` after the tuning
    documented in the ops reference, giving a maximum GOP size of
    ``default_framerate × default_gop`` frames — the recovery window for the
    Flow Control layer above.
    """
    stream_type:       str       = ""
    width:             int       = 0
    height:            int       = 0
    default_framerate: int       = 0
    default_bitrate:   int       = 0       # kbps
    framerate_table:   list[int] = field(default_factory=list)
    bitrate_table:     list[int] = field(default_factory=list)
    default_gop:       int       = 0       # seconds

    @classmethod
    def from_element(cls, el: ET.Element) -> "EncodeTable":
        """
        Parse an ``<encodeTable>`` XML element into an ``EncodeTable`` instance.

        Args:
            el: The ``<encodeTable>`` ``xml.etree.ElementTree.Element``.

        Returns:
            Populated ``EncodeTable`` instance.
        """
        def _int(tag: str) -> int:
            node = el.find(tag)
            try:
                return int(node.text.strip()) if node is not None and node.text else 0
            except ValueError:
                return 0

        def _intlist(tag: str) -> list[int]:
            node = el.find(tag)
            if node is None or not node.text:
                return []
            try:
                return [int(x) for x in node.text.strip().split(",") if x.strip()]
            except ValueError:
                return []

        res_el = el.find("resolution")
        return cls(
            stream_type       = (el.findtext("type") or "").strip(),
            width             = int(res_el.findtext("width",  "0") or 0)
                                if res_el is not None else 0,
            height            = int(res_el.findtext("height", "0") or 0)
                                if res_el is not None else 0,
            default_framerate = _int("defaultFramerate"),
            default_bitrate   = _int("defaultBitrate"),
            framerate_table   = _intlist("framerateTable"),
            bitrate_table     = _intlist("bitrateTable"),
            default_gop       = _int("defaultGop"),
        )

    def summary(self) -> str:
        """Return a formatted multi-line human-readable summary."""
        fps_str  = "/".join(str(f) for f in self.framerate_table)
        kbps_str = "/".join(str(b) for b in self.bitrate_table)
        return (
            f"  [{self.stream_type}]  {self.width}x{self.height}"
            f"  default {self.default_framerate}fps @ {self.default_bitrate}kbps"
            f"  gop={self.default_gop}s\n"
            f"    fps options : {fps_str}\n"
            f"    kbps options: {kbps_str}"
        )


@dataclass
class StreamInfo:
    """
    One ``<StreamInfo>`` block from the login response.

    Contains the channel bit-mask and one or more ``EncodeTable`` entries
    describing the available encoding configurations for that channel.

    The login response may include multiple ``StreamInfo`` blocks when the
    camera supports different resolution profiles.  For example, the Duo 3
    reports both the full-stitch 7680×2160 and the active-crop 4096×1152
    profiles as separate ``StreamInfo`` entries with independent GOP and
    bitrate tables.
    """
    channel_bits:  int               = 0
    encode_tables: list[EncodeTable] = field(default_factory=list)

    @classmethod
    def from_element(cls, el: ET.Element) -> "StreamInfo":
        """
        Parse a ``<StreamInfo>`` XML element into a ``StreamInfo`` instance.

        Args:
            el: The ``<StreamInfo>`` ``xml.etree.ElementTree.Element``.

        Returns:
            Populated ``StreamInfo`` instance.
        """
        try:
            channel_bits = int(el.findtext("channelBits", "0") or 0)
        except ValueError:
            channel_bits = 0
        tables = [EncodeTable.from_element(t) for t in el.findall("encodeTable")]
        return cls(channel_bits=channel_bits, encode_tables=tables)

    def summary(self) -> str:
        """Return a formatted multi-line human-readable summary."""
        lines = [f"  channelBits={self.channel_bits}"]
        for t in self.encode_tables:
            lines.append(t.summary())
        return "\n".join(lines)


@dataclass
class LoginResponse:
    """
    Parsed result of a successful camera login.

    Carries the structured ``DeviceInfo`` and ``StreamInfoList`` from the
    login response XML.  Previously these were flattened into a plain dict
    which silently overwrote repeated tags (``width``, ``height``, ``type``,
    etc. were each clobbered multiple times across ``StreamInfo`` blocks).
    The typed dataclass structure here ensures no wire data is lost.

    This object is stored on ``Session.login_response`` and is the primary
    data source for the Session layer when it needs camera metadata — geometry,
    codec capabilities, auth mode — to drive reconnect or stream management.
    """
    device_info:      Optional[DeviceInfo] = None
    stream_info_list: list[StreamInfo]     = field(default_factory=list)

    @classmethod
    def from_xml(cls, xml_str: str) -> "LoginResponse":
        """
        Parse the login response XML body into a ``LoginResponse``.

        The response body contains one ``<DeviceInfo>`` element and one
        ``<StreamInfoList>`` element (with one or more ``<StreamInfo>``
        children).  A parse error returns an empty ``LoginResponse`` rather
        than raising — the session is authenticated regardless of whether
        the device info parses cleanly.

        Args:
            xml_str: Decrypted, null-stripped, UTF-8 decoded XML string.

        Returns:
            ``LoginResponse`` instance.  Fields may be ``None`` or empty if
            the XML was absent or malformed.
        """
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError:
            return cls()

        device_info: Optional[DeviceInfo] = None
        dev_el = root.find(".//DeviceInfo")
        if dev_el is not None:
            device_info = DeviceInfo.from_element(dev_el)

        stream_info_list: list[StreamInfo] = []
        sil_el = root.find(".//StreamInfoList")
        if sil_el is not None:
            stream_info_list = [
                StreamInfo.from_element(si)
                for si in sil_el.findall("StreamInfo")
            ]

        return cls(device_info=device_info, stream_info_list=stream_info_list)

    def dump(self) -> str:
        """Return a formatted multi-line summary of all device and stream info."""
        lines: list[str] = []

        if self.device_info:
            di = self.device_info
            lines.append("── Device Info " + "─" * 50)
            lines.append(f"  Type         : {di.type_info or di.type}")
            lines.append(f"  Firmware     : {di.firm_version}")
            lines.append(
                f"  Resolution   : {di.resolution_name or f'{di.width}x{di.height}'}"
            )
            lines.append(f"  Channels     : {di.channel_num}  (audio: {di.audio_num})")
            lines.append(f"  Norm / Lang  : {di.norm} / {di.language}")
            lines.append(f"  PTZ mode     : {di.ptz_mode}")
            lines.append(
                f"  Bino type    : {di.bino_type}"
                + ("  (dual sensor)" if di.bino_type else "  (single sensor)")
            )
            lines.append(
                f"  Needs rotate : "
                + ("yes — frame data is 90° rotated" if di.need_rotate else "no")
            )
            lines.append(f"  SD card      : {'yes' if di.sd_card else 'no'}")
            lines.append(f"  softVer      : {di.soft_ver}  hardVer: {di.hard_ver}")
            lines.append(
                f"  authMode     : {di.auth_mode}"
                + ("  (BC XOR)" if di.auth_mode == 0 else "  (AES — unverified)")
            )
            if di.extras:
                lines.append("  extras:")
                for k, v in di.extras.items():
                    lines.append(f"    {k}: {v}")

        if self.stream_info_list:
            lines.append("")
            lines.append("── Stream Info " + "─" * 50)
            for idx, si in enumerate(self.stream_info_list):
                lines.append(f"  StreamInfo [{idx}]  channelBits={si.channel_bits}")
                for tbl in si.encode_tables:
                    lines.append(tbl.summary())

        return "\n".join(lines)


# ============================================================================
#  SESSION STATE
# ============================================================================

@dataclass(slots=True)
class Session:
    """
    All mutable state for one active Baichuan camera wire session.

    This is a plain data container; all protocol behaviour lives in the
    module-level functions in Section 9 below.  ``__slots__`` keeps per-
    instance memory tight — important when managing 16 concurrent camera
    sessions within the ~43 MB per-camera budget derived from production
    tuning.

    The ``enc_type`` field is populated by ``get_nonce()`` from the camera's
    ``<type>`` element and drives ``login()``'s path selection.  It defaults
    to ``ENC_TYPE_MD5`` (BC XOR) since that is the path verified against all
    currently tested hardware.

    Attributes:
        host:           Camera IP address or hostname.
        port:           TCP port (default ``PORT`` = 9000).
        sock:           Connected blocking socket.  ``None`` before
                        ``open_session()`` and after ``close_session()``.
        ch_id:          Channel byte at the start of the mess_id field (offset
                        12 in every header).  Also used as the BC enc_offset
                        for all outgoing payloads.  ``CH_ID_HOST`` (0xFA) for
                        single-camera host-level commands.
        mess_id:        24-bit rolling sequence counter, incremented per
                        outgoing message via ``next_mess_id()``.
        nonce:          Session nonce from the camera's GetNonce response.
                        Empty string before ``get_nonce()`` is called.
        enc_type:       Encryption type advertised by the camera in the
                        ``<type>`` element of the GetNonce response.  Drives
                        login path selection: ``ENC_TYPE_MD5`` → BC XOR,
                        ``ENC_TYPE_AES`` → AES-128-CFB.
        logged_in:      ``True`` after a successful ``login()`` call.
                        Cleared immediately by ``close_session()``.
        login_response: Structured device and stream info from the login
                        response.  ``None`` before ``login()`` completes.
    """
    host:           str
    port:           int                     = PORT
    sock:           Optional[socket.socket] = field(default=None)
    ch_id:          int                     = CH_ID_HOST
    mess_id:        int                     = 0
    nonce:          str                     = ""
    enc_type:       str                     = ENC_TYPE_MD5
    logged_in:      bool                    = False
    login_response: Optional[LoginResponse] = field(default=None)


def next_mess_id(session: Session) -> int:
    """
    Increment the session's rolling mess_id counter and return the new value.

    The counter wraps at 2²⁴ (16 777 216) to stay within the 3-byte wire
    field.  Call this exactly once per outgoing message and pass the result
    to ``build_header()``.

    Args:
        session: Live session to mutate.

    Returns:
        New 24-bit sequence number.
    """
    session.mess_id = (session.mess_id + 1) % 0x1000000
    return session.mess_id


# ============================================================================
#  9. SESSION LIFECYCLE
# ============================================================================

def open_session(host: str, port: int = PORT) -> Session:
    """
    Open a TCP connection to a camera and return an uninitialised session.

    No protocol messages are exchanged.  Call ``get_nonce()`` followed by
    ``login()``, or use the high-level ``BaichuanSession.connect()`` which
    handles both in a single call.

    Args:
        host: Camera IP address or hostname.
        port: TCP port (default 9000).

    Returns:
        ``Session`` with ``sock`` populated and all protocol fields at their
        defaults.

    Raises:
        OSError: If the TCP connection cannot be established.  Common causes:
            camera offline, wrong IP, firewall, or a port conflict with a
            running NeoLink instance already holding the camera's stream slot.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(RECV_TIMEOUT)
    sock.connect((host, port))
    return Session(host=host, port=port, sock=sock)


def get_nonce(session: Session) -> str:
    """
    Stage 1 — Send a GetNonce request and extract the session nonce.

    Also parses the ``<type>`` field from the camera's ``<Encryption>``
    response and stores it in ``session.enc_type``, driving login path
    selection in ``login()``:

    * ``ENC_TYPE_MD5`` (``"md5"``) → BC XOR login path.
    * ``ENC_TYPE_AES`` (``"aes"``) → AES-128-CFB login path.

    Populates ``session.nonce`` and ``session.enc_type`` on success.

    Args:
        session: Connected but unauthenticated session (``sock`` not ``None``).

    Returns:
        The nonce string extracted from the camera response.

    Raises:
        AssertionError:  If ``session.sock`` is ``None``.
        ConnectionError: If no response is received.
        ValueError:      If the ``<nonce>`` element is absent in the response.
        RuntimeError:    If the response cannot be decrypted or parsed.
    """
    assert session.sock is not None, (
        "Session socket is None — call open_session() first."
    )

    payload = build_get_nonce_payload()
    header  = build_header(
        cmd_id        = CMD_LOGIN,
        payload_len   = len(payload),
        message_class = 0x6514,
        ch_id         = session.ch_id,
        mess_id       = next_mess_id(session),
        encrypt       = ENCRYPT_ADV,
    )
    session.sock.sendall(header + payload)
    logger.debug("[nonce] GetNonce sent (%d bytes total)", len(header) + len(payload))

    resp_header, resp_payload = recv_frame(session.sock)
    if not resp_header:
        raise ConnectionError(f"No response to GetNonce from {session.host}.")

    enc_offset = resp_header[12]
    logger.debug(
        "[nonce] response: class=0x%04x  enc_offs=0x%02x  len=%d",
        struct.unpack_from("<H", resp_header, 18)[0],
        enc_offset,
        len(resp_payload),
    )

    # Nonce response is BC-encrypted.  Plaintext fallback handles older firmware
    # that skips encryption on the nonce response.
    xml_bytes = (
        resp_payload if resp_payload.startswith(b"<?xml")
        else bc_crypt(enc_offset, resp_payload)
    )
    xml_str = xml_bytes.rstrip(b"\x00").decode("utf-8")
    logger.debug("[nonce] XML:\n%s", xml_str)

    try:
        root     = ET.fromstring(xml_str)
        nonce_el = root.find(".//nonce")
        if nonce_el is None or not nonce_el.text:
            raise ValueError(f"<nonce> element missing in response:\n{xml_str}")
        session.nonce = nonce_el.text.strip()

        # Parse <type> to determine login path.  Default to "md5" (BC XOR)
        # if the element is absent — all currently verified cameras return it,
        # but defensive defaulting prevents a crash on unexpected firmware.
        type_el = root.find(".//type")
        if type_el is not None and type_el.text:
            session.enc_type = type_el.text.strip().lower()
        else:
            session.enc_type = ENC_TYPE_MD5
            logger.debug(
                "[nonce] <type> element absent; defaulting to '%s'",
                ENC_TYPE_MD5,
            )

    except ET.ParseError as exc:
        raise RuntimeError(
            f"Failed to parse nonce response XML: {exc}\nRaw: {xml_str!r}"
        ) from exc

    logger.debug(
        "[nonce] nonce: %s  enc_type: %s", session.nonce, session.enc_type
    )
    return session.nonce


def login(session: Session, username: str, password: str) -> LoginResponse:
    """
    Stage 2 — Authenticate with the camera.

    Calls ``get_nonce()`` automatically if the nonce has not yet been
    obtained.  Dispatches to the BC XOR or AES login path based on
    ``session.enc_type`` populated during the nonce exchange.

    **BC XOR path** (``enc_type == "md5"``, all verified cameras):
    Credentials are hashed as MD5(value + nonce)[:31].upper() and the
    LoginUser XML is BC-encrypted with ``session.ch_id`` as enc_offset.

    **AES path** (``enc_type == "aes"``, unverified against hardware):
    Credentials are plain MD5(value).hexdigest() (no nonce mixing).  The
    AES key is derived as MD5(nonce + "-" + password)[:16] and the LoginUser
    XML is AES-128-CFB encrypted.

    On success, ``session.logged_in`` is set to ``True`` and
    ``session.login_response`` is populated with the structured device and
    stream info.

    Args:
        session:  Connected session (nonce may or may not be pre-fetched).
        username: Plain-text camera username.
        password: Plain-text camera password.

    Returns:
        ``LoginResponse`` with ``device_info`` and ``stream_info_list``.

    Raises:
        ConnectionError: Socket closed during the exchange.
        PermissionError: Camera returned HTTP 401 (wrong credentials).
        RuntimeError:    400 Bad Request, unexpected status code, or unknown
                         ``enc_type`` value in the session.
    """
    if not session.nonce:
        get_nonce(session)

    # ── BC XOR path ─────────────────────────────────────────────────────────
    if session.enc_type == ENC_TYPE_MD5:
        user_hash = hash_credential(username, session.nonce)
        pass_hash = hash_credential(password, session.nonce)
        logger.debug("[login] BC XOR path  user_hash=%s", user_hash)
        logger.debug("[login] pass_hash: %s", pass_hash)

        xml_payload = build_login_payload(user_hash, pass_hash)
        logger.debug(
            "[login] login XML:\n%s", xml_payload.rstrip(b"\x00").decode("utf-8")
        )
        enc_payload = bc_crypt(session.ch_id, xml_payload)

    # ── AES path ─────────────────────────────────────────────────────────────
    elif session.enc_type == ENC_TYPE_AES:
        logger.debug(
            "[login] AES path (UNVERIFIED against hardware, enc_type=%s)",
            session.enc_type,
        )
        aes_key     = derive_aes_key(session.nonce, password)
        xml_payload = build_aes_login_payload(username, password)
        logger.debug(
            "[login] login XML:\n%s", xml_payload.rstrip(b"\x00").decode("utf-8")
        )
        enc_payload = aes_encrypt(aes_key, xml_payload)

    # ── Unknown enc_type ─────────────────────────────────────────────────────
    else:
        raise RuntimeError(
            f"{session.host}: Unknown enc_type '{session.enc_type}' received "
            f"in nonce response.  Expected '{ENC_TYPE_MD5}' or '{ENC_TYPE_AES}'."
        )

    header = build_header(
        cmd_id        = CMD_LOGIN,
        payload_len   = len(enc_payload),
        message_class = 0x6414,
        ch_id         = session.ch_id,
        mess_id       = next_mess_id(session),
    )
    logger.debug("[login] header      : %s", header.hex())
    logger.debug("[login] enc payload : %s...", enc_payload[:32].hex())
    logger.debug(
        "[login] sending login (%d bytes total)", len(header) + len(enc_payload)
    )
    session.sock.sendall(header + enc_payload)

    resp_header, resp_payload = recv_frame(session.sock)
    if not resp_header:
        raise ConnectionError(f"No response to login from {session.host}.")

    fields      = parse_header(resp_header)
    status_code = fields["status_code"]
    logger.debug(
        "[login] response: class=0x%04x  len=%d  enc_offs=0x%02x  status=0x%04x",
        fields["message_class"], fields["msg_len"], fields["ch_id"], status_code,
    )
    logger.debug("[login] raw header: %s", resp_header.hex())

    if status_code == 0x0191:     # 401 Unauthorized
        raise PermissionError(
            f"{session.host}: Login returned 401 — check credentials."
        )
    if status_code == 0x0190:     # 400 Bad Request
        raise RuntimeError(
            f"{session.host}: Login returned 400 Bad Request.  "
            f"If this follows a fresh connect, the camera may already be "
            f"streaming to another client (e.g. a running NeoLink instance). "
            f"Stop that client before connecting."
        )
    if status_code != 0x00C8:     # anything other than 200 OK
        raise RuntimeError(
            f"{session.host}: Unexpected login status 0x{status_code:04X}."
        )

    session.logged_in = True

    # Decrypt the login response using the camera's ch_id byte as enc_offset.
    # The camera BC-encrypts its response payload regardless of which login
    # path was used for the request — this is consistent across both paths.
    enc_offset = fields["ch_id"]
    xml_bytes  = bc_crypt(enc_offset, resp_payload)
    xml_str    = xml_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")
    logger.debug("[login] response XML:\n%s", xml_str)

    session.login_response = LoginResponse.from_xml(xml_str)
    return session.login_response


def request_stream(
    session:     Session,
    channel_id:  int = 0,
    handle:      int = 0,
    stream_type: str = "mainStream",
) -> bool:
    """
    Stage 3 — Send a Preview request to start the video stream.

    After a successful call, the TCP connection enters binary stream mode.
    All subsequent ``recv_frame()`` calls on ``session.sock`` return raw
    Baichuan-framed media packets rather than XML messages.

    **Observed acknowledgement forms** (all result in ``True`` return):

    * **XML ack** (older firmware): camera sends an ``<Extension>`` block with
      ``<binaryData>1</binaryData>``, then switches to binary frame mode.
    * **Bare 200 OK** (Duo 3 PoE, confirmed): class-0x0000 modern header with
      status=200 and zero-length payload; binary frames arrive immediately
      on the next ``recv_frame()`` call.
    * **Implicit ack** (some firmware variants): a non-XML payload on a 200
      response — the camera skipped the XML ack entirely.  The first media
      frame has already been consumed from the socket and is not recoverable.
      The caller's frame loop will pick up from the second frame onward.

    **400 Bad Request** on the stream request is almost always a resource
    conflict — the camera already has an active stream client (typically a
    running NeoLink instance on CT102).  Stop the relevant group before
    testing::

        systemctl stop neolink-groupN   # on CT102

    Args:
        session:     Authenticated session (``session.logged_in`` must be
                     ``True``).
        channel_id:  Camera channel index.  Always 0 for single-camera
                     devices.  NVR channels are 0-indexed.
        handle:      Stream handle.  Use 0 for single-stream cases.  Try 1 if
                     the camera returns 400 on a fresh session — a stale
                     server-side slot from a previous crash may hold handle=0.
        stream_type: ``"mainStream"`` (default, full resolution) or
                     ``"subStream"`` (reduced resolution).

    Returns:
        ``True`` if the camera acknowledged the stream request.

    Raises:
        RuntimeError:    Session not authenticated, or non-200 ack status.
        ConnectionError: No response received.
    """
    if not session.logged_in:
        raise RuntimeError("Cannot request stream: session is not logged in.")

    xml_payload = build_preview_payload(channel_id, handle, stream_type)
    logger.debug(
        "[stream] preview XML:\n%s", xml_payload.rstrip(b"\x00").decode("utf-8")
    )
    enc_payload = bc_crypt(session.ch_id, xml_payload)

    header = build_header(
        cmd_id        = CMD_VIDEO,
        payload_len   = len(enc_payload),
        message_class = 0x6414,
        ch_id         = session.ch_id,
        mess_id       = next_mess_id(session),
    )
    logger.debug(
        "[stream] sending Preview (%d bytes total)", len(header) + len(enc_payload)
    )
    session.sock.sendall(header + enc_payload)

    resp_header, resp_payload = recv_frame(session.sock)
    if not resp_header:
        raise ConnectionError(f"No response to stream request from {session.host}.")

    fields      = parse_header(resp_header)
    enc_offset  = fields["ch_id"]
    status_code = fields["status_code"]
    logger.debug(
        "[stream] ack: class=0x%04x  status=0x%04x  enc_offs=0x%02x  payload=%d bytes",
        fields["message_class"], status_code, enc_offset, len(resp_payload),
    )

    # ── Bare 200 OK with no payload ──────────────────────────────────────────
    # Confirmed on Duo 3 PoE: class-0x0000, status=0x00C8, msg_len=0.
    if not resp_payload:
        if status_code == 0x00C8:
            logger.debug("[stream] bare 200 OK ack (no payload) — stream is live")
            return True
        raise RuntimeError(
            f"{session.host}: Stream request returned empty payload with "
            f"non-200 status 0x{status_code:04X}."
        )

    # ── XML ack or implicit media-frame ack ──────────────────────────────────
    # Attempt BC decrypt and XML parse.  If the result is non-XML on a 200
    # response, the camera skipped the XML ack and the first media frame has
    # already been consumed from the socket — treat it as an implicit ack.
    xml_bytes = (
        resp_payload if resp_payload.startswith(b"<?xml")
        else bc_crypt(enc_offset, resp_payload)
    )
    xml_str = xml_bytes.rstrip(b"\x00").decode("utf-8", errors="replace")

    try:
        root  = ET.fromstring(xml_str)
        bd_el = root.find(".//binaryData")
        if bd_el is not None and bd_el.text == "1":
            logger.debug("[stream] XML ack confirmed binaryData=1")
            return True
        raise RuntimeError(
            f"{session.host}: Unexpected binaryData value "
            f"'{bd_el.text if bd_el is not None else '<missing>'}' "
            f"in stream acknowledgement:\n{xml_str}"
        )
    except ET.ParseError:
        if status_code == 0x00C8:
            logger.debug(
                "[stream] non-XML payload on 200 response "
                "(class=0x%04x  enc_offs=0x%02x  %d bytes) — "
                "implicit stream-start ack; first frame already consumed",
                fields["message_class"], enc_offset, len(resp_payload),
            )
            return True
        raise RuntimeError(
            f"{session.host}: Non-XML stream ack with non-200 status "
            f"0x{status_code:04X}\n"
            f"class=0x{fields['message_class']:04x}  "
            f"enc_offset=0x{enc_offset:02x}  "
            f"payload={len(resp_payload)} bytes\n"
            f"raw (first 64 bytes):       {resp_payload[:64].hex()}\n"
            f"decrypted (first 64 bytes): {xml_bytes[:64]!r}"
        )


def close_session(session: Session) -> None:
    """
    Send a logout frame and close the TCP socket.

    Best-effort: network errors during logout are silently ignored since the
    socket is closed regardless.  ``session.logged_in`` is cleared before the
    logout frame is sent so that concurrent code sees the session as inactive
    immediately.

    Args:
        session: Session to terminate.  Safe to call on an already-closed
                 session (``session.sock is None``).
    """
    session.logged_in = False

    if session.sock is None:
        return

    try:
        header = build_header(
            cmd_id        = CMD_LOGOUT,
            payload_len   = 0,
            message_class = 0x6414,
            ch_id         = session.ch_id,
            mess_id       = next_mess_id(session),
        )
        session.sock.sendall(header)
    except OSError:
        pass    # Camera may already have dropped the connection.

    try:
        session.sock.close()
    except OSError:
        pass

    session.sock = None


# ============================================================================
#  10. HIGH-LEVEL API
# ============================================================================

class BaichuanSession:
    """
    Context manager for a complete Baichuan camera wire session.

    Guarantees socket closure on ``__exit__`` regardless of exceptions.
    The raw ``Session`` dataclass is available as ``.session`` for callers
    that need direct access to wire-level fields (nonce, enc_type, mess_id,
    sock).

    This class is the primary interface for the Session layer above the wire.
    It exposes the full three-stage handshake as individual methods and as the
    single-call ``connect()`` convenience wrapper.

    **Typical usage (single call):**

    .. code-block:: python

        with BaichuanSession("192.168.1.220") as bc:
            response = bc.connect("admin", "password")
            print(response.dump())

            if bc.request_stream():
                header, payload = recv_frame(bc.session.sock)

    **Step-by-step usage** (when nonce or enc_type is needed before login):

    .. code-block:: python

        with BaichuanSession("192.168.1.220") as bc:
            nonce = bc.get_nonce()
            print(f"Nonce: {nonce}  enc_type: {bc.session.enc_type}")
            response = bc.login("admin", "password")

    .. note::

        If CT102 (NeoLink) is running and already holds the stream slot for a
        camera, ``request_stream()`` will receive a 400 response.  Stop the
        relevant NeoLink group on CT102 before running standalone tests::

            systemctl stop neolink-groupN
    """

    def __init__(self, host: str, port: int = PORT) -> None:
        self._host    = host
        self._port    = port
        self.session: Optional[Session] = None

    # ------------------------------------------------------------------
    # Context manager protocol
    # ------------------------------------------------------------------

    def __enter__(self) -> "BaichuanSession":
        self.session = open_session(self._host, self._port)
        return self

    def __exit__(self, *_) -> None:
        if self.session is not None:
            close_session(self.session)

    # ------------------------------------------------------------------
    # Stage wrappers
    # ------------------------------------------------------------------

    def get_nonce(self) -> str:
        """
        Stage 1: negotiate session nonce and determine encryption type.

        Populates ``session.nonce`` and ``session.enc_type``.
        See module-level ``get_nonce()`` for full documentation.
        """
        assert self.session is not None
        return get_nonce(self.session)

    def login(self, username: str, password: str) -> LoginResponse:
        """
        Stage 2: authenticate using the enc_type negotiated in Stage 1.

        Calls ``get_nonce()`` automatically if not already done.
        See module-level ``login()`` for full documentation.
        """
        assert self.session is not None
        return login(self.session, username, password)

    def connect(self, username: str, password: str) -> LoginResponse:
        """
        Single-call convenience: Stage 1 (GetNonce) + Stage 2 (Login).

        Equivalent to::

            bc.get_nonce()
            return bc.login(username, password)

        Args:
            username: Plain-text camera username.
            password: Plain-text camera password.

        Returns:
            ``LoginResponse`` with populated ``device_info`` and
            ``stream_info_list``.
        """
        assert self.session is not None
        get_nonce(self.session)
        return login(self.session, username, password)

    def request_stream(
        self,
        channel_id:  int = 0,
        handle:      int = 0,
        stream_type: str = "mainStream",
    ) -> bool:
        """
        Stage 3: request video stream.

        See module-level ``request_stream()`` for full documentation,
        including 400 conflict resolution and the three acknowledgement forms.
        """
        assert self.session is not None
        return request_stream(self.session, channel_id, handle, stream_type)

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def device_info(self) -> Optional[DeviceInfo]:
        """Shortcut to ``session.login_response.device_info``."""
        if self.session and self.session.login_response:
            return self.session.login_response.device_info
        return None

    @property
    def stream_info_list(self) -> list[StreamInfo]:
        """Shortcut to ``session.login_response.stream_info_list``."""
        if self.session and self.session.login_response:
            return self.session.login_response.stream_info_list
        return []


# ============================================================================
#  QUICK TEST
# ============================================================================

if __name__ == "__main__":
    import sys

    # ── Logging ─────────────────────────────────────────────────────────────
    # When run directly, enable DEBUG so every wire exchange is visible.
    # When imported as a library, the caller controls verbosity via the
    # standard logging hierarchy; no output appears unless they add a handler.
    logging.basicConfig(
        level  = logging.DEBUG,
        format = "%(message)s",
    )

    # ── Configuration ────────────────────────────────────────────────────────
    # F2DORITOS — Duo 3 PoE at 192.168.1.220.
    # Stop neolink-group2 on CT102 before running if NeoLink is active;
    # otherwise the stream request will receive a 400 (slot already held).
    CAMERA_IP = "REDACTED"
    USERNAME  = "REDACTED"
    PASSWORD  = "REDACTED"

    print(f"Connecting to {CAMERA_IP}:{PORT} ...")

    with BaichuanSession(CAMERA_IP) as bc:

        # ── Stage 1 + 2: nonce negotiation + login ───────────────────────
        try:
            response = bc.connect(USERNAME, PASSWORD)
        except PermissionError as exc:
            print(f"\nAuthentication failed: {exc}")
            sys.exit(1)
        except (ConnectionError, RuntimeError) as exc:
            print(f"\nLogin error: {exc}")
            sys.exit(1)

        print(f"\nLogged in.")
        print(f"  Nonce    : {bc.session.nonce}")
        print(f"  enc_type : {bc.session.enc_type}")
        print()
        print(response.dump())

        # ── Stage 3: stream request ───────────────────────────────────────
        try:
            streaming = bc.request_stream(channel_id=0, stream_type="mainStream")
        except RuntimeError as exc:
            print(f"\nStream request failed: {exc}")
            sys.exit(1)

        print(f"\nStream acknowledged: {streaming}")

        # ── Raw frame read loop ───────────────────────────────────────────
        # Once the stream is live, every recv_frame() call returns a
        # Baichuan-framed media packet.  The inner media header structure
        # (codec, timestamp, frame type) will be parsed by the Stream Pipe
        # layer above; here we just print the outer wire header fields.
        if streaming:
            print("\nReading first 5 media frames ...\n")
            assert bc.session.sock is not None
            for i in range(5):
                frame_header, frame_payload = recv_frame(bc.session.sock)
                if not frame_header:
                    print("Connection closed by camera.")
                    break
                fields = parse_header(frame_header)
                print(
                    f"  Frame {i + 1}: "
                    f"class=0x{fields['message_class']:04x}  "
                    f"cmd_id={fields['cmd_id']}  "
                    f"payload={fields['msg_len']} bytes  "
                    f"enc_offs=0x{fields['ch_id']:02x}"
                )

    print("\nSession closed.")