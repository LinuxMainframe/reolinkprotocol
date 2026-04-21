#!/usr/bin/env python3

"""
Baichuan.py
===========

:author: Aidan A. Bradley
:date: April 20th, 2026

The Baichuan protocol is a proprietary communication and authorization protocol
developed by Baichuan SoC Company for their ARM-based camera systems. The main
protocol has not been publicly discussed or disseminated in any form by ReoLink
or Baichuan (the company).

This protocol was initially reverse-engineered by George Hilliard
(a.k.a. *thirtythreeforty* on GitHub), and then extensively polished into a
full-fledged program known as **NeoLink**. The project's current maintainer is
Andrew W. King (a.k.a. *quantumentangledandy* on GitHub). Although the project
has grown dusty, this Python system is intended as a complete rewrite of the
NeoLink codebase — not to mimic or recreate it, but to build a base library
with extensive commentary.

The exact mechanisms implemented here were determined through extensive testing
and by reading disparate documentation from the original authors and the
community surrounding NeoLink, as well as some code evaluated inside the
``reolink_aio`` Python module. Although ``reolink_aio`` exists and works, this
module aims to be more focused on building a dedicated streaming library for
ReoLink cameras, much in the way NeoLink was originally aiming to.

**Background / Motivation**

The impetus for this module came from repeated failed attempts to use the
built-in RTSP/RTMP streams. Artifacting, image columnation, I-frame issues,
improper buffering, color shifts, and other anomalies made those streams
unusable for a live outdoor activity feed. Switching to NeoLink yielded a
dramatic quality increase at low CPU/GPU cost. However, NeoLink struggled with
multiple concurrent high-resolution streams — even on a machine with an
RTX 4070, a 4.5 GHz AMD CPU, and 32 GB of RAM. Increasing I-frame intervals
(x2, x4) and raising resolution/fps caused a buffer runaway, with RAM
allocation creeping up rapidly. Partitioning cameras across multiple NeoLink
instances and coupling MediaMTX helped stabilize things somewhat, but the
added chain and complexity reduced overall reliability — particularly when
approaching the limits of older Proliant Gen7/8 server NICs used for ingest.
Switching to direct desktop ingest showed no improvement; NeoLink's buffer
management was the clear bottleneck.

None of this diminishes NeoLink's achievement. It is an incredible piece of
work, and the community around it provided the examples and insight needed to
understand and reason about Baichuan stream chains. This module stands on that
foundation.
"""

import hashlib
import socket
import struct
import xml.etree.ElementTree as ET
from typing import Union, Optional

try:
    from Cryptodome.Cipher import AES
except ImportError:
    from Crypto.Cipher import AES


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
Magic number that opens every Baichuan frame.

Serialised as little-endian it becomes the byte sequence ``f0 de bc 0a`` on
the wire.  This value is fixed across all known ReoLink/Baichuan devices; it
should only be changed if you are deliberately impersonating a non-client
device.
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

How long the library will wait for data before raising a timeout error.
Increase this on high-latency or heavily loaded networks; decrease it if you
need faster failure detection.
"""

XML_KEY: bytes = bytes([0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF])
"""
8-byte rotating XOR key used to obfuscate XML payloads (BC encryption).

**Do not modify.**  This key is identical across every known ReoLink device;
changing it will break decryption of all camera responses.
"""

HEADER_LENGTHS: dict[int, int] = {
    0x6514: 20,   # Legacy — nonce request  (client → camera)
    0x6614: 20,   # Legacy — nonce response (camera → client, no payload-offset field)
    0x6414: 24,   # Modern — standard command/login (includes 4-byte payload-offset field)
    0x6482: 24,   # Modern — file download variant
    0x0146: 24,   # Modern — alternate command variant
}
"""
Mapping of message-class integers to their corresponding header sizes in bytes.

Baichuan headers come in two sizes:

* **20 bytes** — legacy classes used during nonce exchange and on older
  firmware.  The layout is:
  ``MAGIC(4) + cmd_id(4) + msg_len(4) + mess_id(4) + encrypt(2) + class(2)``

* **24 bytes** — modern classes used for AES-encrypted login and most
  subsequent commands.  The layout appends a 4-byte payload-offset field:
  ``MAGIC(4) + cmd_id(4) + msg_len(4) + mess_id(4) + status(2) + class(2) + payload_offset(4)``

Keys are message-class integers in standard (big-endian-readable) form.
"""


# ============================================================================
#  BC (XOR) DECRYPT
# ============================================================================

def bc_decrypt(enc_offset: int, data: bytes) -> bytes:
    """
    Decrypt (or encrypt) a Baichuan XOR-obfuscated payload.

    The BC cipher is a simple symmetric byte-level XOR using a rotating 8-byte
    key (``XML_KEY``) combined with a single offset byte derived from the
    message header.  Because XOR is its own inverse, the same function handles
    both directions.

    **Algorithm:**

    For each byte at index *i* in *data*:

    .. code-block:: text

        key_byte    = XML_KEY[(i + enc_offset) % 8]
        result[i]   = data[i] ^ key_byte ^ offset_byte

    where ``offset_byte = enc_offset & 0xFF``.

    Args:
        enc_offset: The least-significant byte of the 4-byte ``mess_id`` field
            found at offset ``0x0C`` in the received header.  It doubles as
            both the key-rotation seed and the per-byte XOR mask.
        data: Raw bytes to decrypt (or encrypt).

    Returns:
        Transformed bytes of the same length as *data*.
    """
    offset_byte = enc_offset & 0xFF
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        key_byte  = XML_KEY[(i + enc_offset) % 8]
        result[i] = byte ^ key_byte ^ offset_byte
    return bytes(result)


# ============================================================================
#  PAYLOAD BUILDERS
# ============================================================================

def build_get_nonce_payload() -> bytes:
    """
    Build the minimal XML payload used to request an authentication nonce.

    This is the very first message sent to a camera.  The body contains a
    single self-closing ``<GetNonce/>`` element; the camera responds with an
    ``<Encryption>`` block containing the nonce string needed for the login
    step.

    The payload is always null-terminated (``\\x00``) as required by the
    Baichuan framing convention.

    Returns:
        UTF-8 encoded, null-terminated XML bytes ready to append to a header.
    """
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<body>\n<GetNonce/>\n</body>'
    return xml.encode('utf-8') + b'\x00'


# ============================================================================
#  HEADER HELPERS
# ============================================================================

def get_header_size(message_class: Union[int, bytes]) -> int:
    """
    Look up the total header size in bytes for a given message class.

    Accepts the class as either a plain integer (e.g. ``0x6514``) or as a
    raw little-endian ``bytes`` object straight off the wire (e.g.
    ``b'\\x14\\x65'``).  Both forms are normalised to a big-endian-readable
    integer before the lookup, so callers do not need to pre-convert.

    Args:
        message_class: Message class identifier as an ``int`` **or** a
            little-endian ``bytes`` value read directly from a header.

    Returns:
        Header size in bytes (either ``20`` or ``24``).

    Raises:
        ValueError: If *message_class* is not present in :data:`HEADER_LENGTHS`.
        TypeError: If *message_class* is neither ``int`` nor ``bytes``.
    """
    if isinstance(message_class, bytes):
        # Wire format is little-endian; convert to the same big-endian-readable
        # integer form used as keys in HEADER_LENGTHS (e.g. b'\x14\x65' → 0x6514).
        message_class = int.from_bytes(message_class, 'little')
    elif not isinstance(message_class, int):
        raise TypeError(
            f"message_class must be int or bytes, got {type(message_class).__name__}"
        )

    try:
        return HEADER_LENGTHS[message_class]
    except KeyError:
        raise ValueError(
            f"Unrecognized message class: 0x{message_class:04X} — "
            f"not found in HEADER_LENGTHS."
        )


# ============================================================================
#  HEADER BUILDER
# ============================================================================

def build_header(
    cmd_id: int,
    payload_len: int,
    message_class: int,
    channel_id: int = 0xFA,
    mess_id: int = 0,
    encrypt: bytes = b'\x12\xdc',
    status: int = 0,
    payload_offset: int = 0,
) -> bytes:
    """
    Assemble a complete Baichuan message header.

    The header size (20 or 24 bytes) is determined automatically from
    *message_class* via :data:`HEADER_LENGTHS`.

    **Legacy header layout (20 bytes):**

    .. code-block:: text

        Offset  Size  Field
        ------  ----  -----
         0       4    Magic (little-endian 0x0ABCDEF0 → f0 de bc 0a)
         4       4    cmd_id        (little-endian uint32)
         8       4    payload_len   (little-endian uint32)
        12       4    mess_id       (channel_id[1] + mess_id[3], little-endian)
        16       2    encrypt       (e.g. 0x12dc for BC-XOR, 0x02dc for AES)
        18       2    message_class (little-endian uint16)

    **Modern header layout (24 bytes):**

    .. code-block:: text

        Offset  Size  Field
        ------  ----  -----
         0–15         (same as legacy)
        16       2    status        (0x0000 for requests)
        18       2    message_class (little-endian uint16)
        20       4    payload_offset (little-endian uint32)

    Note that modern headers replace the ``encrypt`` field with a ``status``
    field at the same offset.  The ``encrypt`` argument is therefore ignored
    for modern message classes.

    Args:
        cmd_id: Command sequence number, incremented with each message sent
            during a session (start at ``1``).
        payload_len: Byte length of the payload that immediately follows this
            header on the wire.
        message_class: Integer message class (e.g. ``0x6514``, ``0x6414``).
            Determines header size and whether legacy or modern layout is used.
        channel_id: Single-byte client channel identifier.  ``0xFA`` (250) is
            the conventional host/client value.
        mess_id: 24-bit message identifier packed into the upper three bytes of
            the ``mess_id`` field.  Typically ``0`` for initial requests.
        encrypt: 2-byte encryption-type field written into legacy headers only.
            ``b'\\x12\\xdc'`` signals BC-XOR obfuscation;
            ``b'\\x02\\xdc'`` signals AES-CFB encryption.
        status: 2-byte status field written into modern headers only.
            Always ``0`` for client requests; cameras echo a status code in
            their responses.
        payload_offset: Byte offset within the payload at which binary (non-XML)
            data begins.  ``0`` for purely XML payloads, non-zero for mixed
            binary frames (modern headers only).

    Returns:
        Packed header bytes, either 20 or 24 bytes long.
    """
    header_len = HEADER_LENGTHS.get(message_class, 20)

    # All multi-byte integers are serialised as little-endian on the wire.
    magic_bytes    = MAGIC.to_bytes(4, 'little')
    cmd_id_bytes   = cmd_id.to_bytes(4, 'little')
    msg_len_bytes  = payload_len.to_bytes(4, 'little')
    # mess_id is a 4-byte field: [channel_id (1 byte)] + [mess_id (3 bytes)]
    mess_id_bytes  = channel_id.to_bytes(1, 'little') + mess_id.to_bytes(3, 'little')
    mclass_bytes   = message_class.to_bytes(2, 'little')

    if header_len == 20:
        # Legacy: encrypt field at bytes 16–17, class at 18–19.
        return (magic_bytes + cmd_id_bytes + msg_len_bytes +
                mess_id_bytes + encrypt + mclass_bytes)
    else:
        # Modern: status field at bytes 16–17, class at 18–19, offset at 20–23.
        status_bytes = status.to_bytes(2, 'little')
        poffs_bytes  = payload_offset.to_bytes(4, 'little')
        return (magic_bytes + cmd_id_bytes + msg_len_bytes +
                mess_id_bytes + status_bytes + mclass_bytes + poffs_bytes)


# ============================================================================
#  SOCKET HELPERS
# ============================================================================

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Read exactly *n* bytes from a socket, looping until all bytes arrive.

    A single ``sock.recv()`` call is not guaranteed to return all requested
    bytes — the OS may deliver them in fragments.  This helper loops until the
    full count is satisfied, which is essential for correct Baichuan framing.

    Args:
        sock: Connected TCP socket to read from.
        n: Exact number of bytes to read.

    Returns:
        A ``bytes`` object of length exactly *n*.

    Raises:
        ConnectionError: If the socket is closed before all *n* bytes arrive.
    """
    data = b''
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
    Read a complete Baichuan message (header + payload) from the socket.

    The function reads in three stages:

    1. **Minimum header** — always 20 bytes, common to every message class.
    2. **Header extension** — an additional 4 bytes for modern (24-byte) classes,
       determined by inspecting the message-class field at offset 18.
    3. **Payload** — ``msg_len`` bytes as reported in the header at offset 8.

    Args:
        sock: Connected TCP socket positioned at the start of a Baichuan frame.

    Returns:
        ``(header_bytes, payload_bytes)`` on success, or ``(None, None)`` if
        any stage encounters a connection error or timeout.
    """
    # Stage 1: Read the 20-byte minimum header present in every message class.
    try:
        header = recv_exact(sock, 20)
    except (ConnectionError, socket.timeout):
        return None, None

    # Stage 2: Check the message-class field (offset 18, little-endian uint16)
    # to decide whether a 4-byte extension is needed for modern headers.
    mclass     = struct.unpack_from('<H', header, 18)[0]
    header_len = HEADER_LENGTHS.get(mclass, 20)

    if header_len > 20:
        try:
            header += recv_exact(sock, header_len - 20)
        except (ConnectionError, socket.timeout):
            return None, None

    # Stage 3: Read the variable-length payload indicated at offset 8.
    msg_len = struct.unpack_from('<I', header, 8)[0]
    if msg_len > 0:
        try:
            payload = recv_exact(sock, msg_len)
        except (ConnectionError, socket.timeout):
            return None, None
    else:
        payload = b''

    return header, payload


# ============================================================================
#  QUICK TEST / EXAMPLE
# ============================================================================

if __name__ == "__main__":
    # Build and send a GetNonce request, then decode the camera's response.
    nonce_payload = build_get_nonce_payload()
    hdr           = build_header(
        cmd_id=1,
        payload_len=len(nonce_payload),
        message_class=0x6514,
    )
    message = hdr + nonce_payload

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(RECV_TIMEOUT)
        sock.connect(('192.168.1.220', PORT))
        sock.sendall(message)

        resp_header, resp_payload = recv_response(sock)

        if resp_header is None:
            print("No response received — connection failed or timed out.")
        else:
            mclass   = struct.unpack_from('<H', resp_header, 18)[0]
            msg_len  = struct.unpack_from('<I', resp_header, 8)[0]
            enc_offs = resp_header[12]
            print(f"Response: class=0x{mclass:04x}, len={msg_len}, enc_offs=0x{enc_offs:02x}")

            if msg_len == 0:
                print("Empty payload — camera rejected the request.")
            else:
                # Decrypt the payload if it is not already plain XML.
                if resp_payload.startswith(b'<?xml'):
                    xml_bytes = resp_payload
                else:
                    xml_bytes = bc_decrypt(enc_offs, resp_payload)

                xml_str = xml_bytes.rstrip(b'\x00').decode('utf-8')
                print("Payload XML:\n" + xml_str)

                # Extract and display the nonce.
                try:
                    root     = ET.fromstring(xml_str)
                    nonce_el = root.find('.//nonce')
                    if nonce_el is not None and nonce_el.text:
                        print(f"SUCCESS: Nonce = {nonce_el.text.strip()}")
                    else:
                        print("No <nonce> element found in response.")
                except ET.ParseError as e:
                    print(f"XML parse error: {e}")