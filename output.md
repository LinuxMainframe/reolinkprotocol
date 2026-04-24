```python
#!/usr/bin/env python3
"""
baichuan.py
===========

:author: Aidan A. Bradley
:date: April 23th, 2026

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

**Module structure**

This module is organised into seven layers:

  1. Constants & cipher   — wire constants, ``bc_crypt``
  2. Header I/O           — ``build_header``, ``recv_frame``, ``parse_header``
  3. Credential helpers   — ``hash_credential``
  4. Payload builders     — ``build_get_nonce_payload``, ``build_login_payload``,
                            ``build_preview_payload``
  5. Data model           — ``DeviceInfo``, ``EncodeTable``, ``StreamInfo``,
                            ``LoginResponse``, ``Session``
  6. Session lifecycle    — ``open_session``, ``get_nonce``, ``login``,
                            ``request_stream``, ``close_session``
  7. High-level API       — ``BaichuanSession`` context manager with
                            ``connect()`` for single-call authentication
"""

import hashlib
import logging
import socket
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================================
#  PROTOCOL CONSTANTS
# ============================================================================

MAGIC: int = 0x0ABCDEF0
"""Magic number present at the start of every Baichuan frame (LE: f0 de bc 0a)."""

PORT: int = 9000
"""Default TCP port.  Cameras listen here unless explicitly reconfigured."""

RECV_TIMEOUT: float = 15.0
"""Socket receive timeout in seconds for blocking I/O operations."""

XML_KEY: bytes = bytes([0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF])
"""8-byte rotating XOR key for the BC cipher.  Identical across all known devices."""

AES_IV: bytes = b"0123456789abcdef"
"""Fixed 16-byte AES IV.  Used if AES negotiation is ever implemented."""

HEADER_LENGTHS: dict[int, int] = {
    0x6514: 20,   # Legacy  — client GetNonce request
    0x6614: 20,   # Legacy  — camera nonce response
    0x6414: 24,   # Modern  — client login / command
    0x0000: 24,   # Modern  — camera login response (status at offset 16)
    0x6482: 24,   # Modern  — file download
    0x0146: 24,   # Modern  — alternate command variant
}
"""
Message-class → header-length mapping.

Legacy (20 bytes):  MAGIC(4) + cmd_id(4) + msg_len(4) + mess_id(4) + encrypt(2) + class(2)
Modern (24 bytes):  … + payload_offset(4)

Critically, 0x0000 must be present here.  Without it the 4-byte payload-offset
field of the login response is prepended to the payload, producing garbled XML.
"""

CMD_LOGIN:  int = 1
CMD_LOGOUT: int = 2
CMD_VIDEO:  int = 3

# 0x12 is the empirically required encryption-advertisement byte for GetNonce.
# Other values cause the camera to silently discard the frame.
ENCRYPT_ADV: bytes = b'\x12\xdc'

CH_ID_HOST: int = 0xFA
"""Host-level channel ID; used as BC enc_offset for all outgoing payloads."""


# ============================================================================
#  BC CIPHER
# ============================================================================

def bc_crypt(enc_offset: int, data: bytes) -> bytes:
    """
    Apply the Baichuan XOR cipher to *data* (symmetric — same function for
    encryption and decryption).

    For each byte at index ``i``:
        key_byte  = XML_KEY[(enc_offset + i) % 8]
        result[i] = data[i] ^ key_byte ^ (enc_offset & 0xFF)

    Args:
        enc_offset: ``header[12]`` for incoming frames; ``ch_id`` for outgoing.
        data:       Bytes to transform.

    Returns:
        Transformed bytes of identical length.
    """
    offset_byte = enc_offset & 0xFF
    result      = bytearray(len(data))
    for i, byte in enumerate(data):
        key_byte  = XML_KEY[(enc_offset + i) % 8]
        result[i] = byte ^ key_byte ^ offset_byte
    return bytes(result)


# ============================================================================
#  HEADER CONSTRUCTION
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
    Build a Baichuan message header (20 or 24 bytes, determined by *message_class*).

    Legacy layout (20 bytes)::
        0   4   Magic
        4   4   cmd_id
        8   4   payload_len
        12  4   mess_id  ([ch_id:1][mess_id:3])
        16  2   encrypt  (capability advertisement)
        18  2   message_class

    Modern layout (24 bytes) appends::
        20  4   payload_offset
    """
    header_len  = HEADER_LENGTHS.get(message_class, 20)
    magic_bytes = MAGIC.to_bytes(4, "little")
    cmd_bytes   = cmd_id.to_bytes(4, "little")
    plen_bytes  = payload_len.to_bytes(4, "little")
    mid_bytes   = ch_id.to_bytes(1, "little") + mess_id.to_bytes(3, "little")
    cls_bytes   = message_class.to_bytes(2, "little")

    if header_len == 20:
        return magic_bytes + cmd_bytes + plen_bytes + mid_bytes + encrypt + cls_bytes

    status_bytes = status.to_bytes(2, "little")
    poff_bytes   = payload_offset.to_bytes(4, "little")
    return magic_bytes + cmd_bytes + plen_bytes + mid_bytes + status_bytes + cls_bytes + poff_bytes


# ============================================================================
#  SOCKET I/O
# ============================================================================

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly *n* bytes from a blocking socket, looping as necessary."""
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

    Returns:
        ``(header_bytes, payload_bytes)`` or ``(b"", b"")`` on clean close.
    """
    try:
        header = recv_exact(sock, 20)
    except ConnectionError:
        return b"", b""

    mclass     = struct.unpack_from("<H", header, 18)[0]
    header_len = HEADER_LENGTHS.get(mclass, 20)

    if header_len > 20:
        header += recv_exact(sock, header_len - 20)

    msg_len = struct.unpack_from("<I", header, 8)[0]
    payload = recv_exact(sock, msg_len) if msg_len > 0 else b""
    return header, payload


def parse_header(header: bytes) -> dict:
    """
    Decode a raw Baichuan header into a named-field dictionary.

    Keys: ``magic``, ``cmd_id``, ``msg_len``, ``ch_id``, ``mess_id``,
    ``enc_or_status``, ``message_class``, ``status_code``, ``payload_offset``.
    ``payload_offset`` is ``None`` for 20-byte (legacy) headers.
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
        "payload_offset": struct.unpack_from("<I", header, 20)[0] if len(header) >= 24 else None,
    }


# ============================================================================
#  CREDENTIAL HELPERS
# ============================================================================

def hash_credential(value: str, nonce: str) -> str:
    """
    Produce the nonce-mixed credential hash for LoginUser XML.

    Formula: MD5(value + nonce)[:31].upper()

    The camera allocates a 32-byte field with a null terminator; only 31
    characters are ever compared, making truncation to 31 correct behaviour.
    """
    return hashlib.md5(f"{value}{nonce}".encode("utf-8")).hexdigest()[:31].upper()


# ============================================================================
#  XML PAYLOAD BUILDERS
# ============================================================================

def build_get_nonce_payload() -> bytes:
    """Return the UTF-8 + null-terminated GetNonce XML payload."""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<body>\n'
        '<GetNonce/>\n'
        '</body>'
    )
    return xml.encode("utf-8") + b"\x00"


def build_login_payload(username_hash: str, password_hash: str) -> bytes:
    """
    Build the LoginUser XML payload for the modern login stage.

    The ``LoginNet`` block is required — some firmware versions reject logins
    that omit it.
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


def build_preview_payload(
    channel_id:  int = 0,
    handle:      int = 0,
    stream_type: str = "mainStream",
) -> bytes:
    """Build the Preview XML payload to initiate a video stream."""
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
#  DATA MODEL
# ============================================================================

@dataclass
class DeviceInfo:
    """
    Scalar fields from the ``<DeviceInfo>`` block in the login response.

    Only a representative subset is typed explicitly; everything else lands
    in ``extras`` so no wire data is silently dropped.
    """
    firm_version:    str  = ""
    type:            str  = ""   # "ipc" / "nvr"
    type_info:       str  = ""   # "IPC"
    channel_num:     int  = 0
    audio_num:       int  = 0
    sd_card:         int  = 0
    soft_ver:        str  = ""
    hard_ver:        str  = ""
    language:        str  = ""
    norm:            str  = ""   # "NTSC" / "PAL"
    ptz_mode:        str  = ""
    bino_type:       int  = 0
    need_rotate:     int  = 0
    auth_mode:       int  = 0
    resolution_name: str  = ""
    width:           int  = 0
    height:          int  = 0
    extras:          dict = field(default_factory=dict)

    @classmethod
    def from_element(cls, el: ET.Element) -> "DeviceInfo":
        """Parse a ``<DeviceInfo>`` XML element into a ``DeviceInfo`` instance."""
        def _int(tag: str, default: int = 0) -> int:
            node = el.find(tag)
            try:
                return int(node.text.strip()) if node is not None and node.text else default
            except ValueError:
                return default

        def _str(tag: str) -> str:
            node = el.find(tag)
            return node.text.strip() if node is not None and node.text else ""

        # Known scalar fields
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
            resolution_name = res_el.findtext("resolutionName", "").strip() if res_el is not None else "",
            width           = int(res_el.findtext("width", "0") or 0)  if res_el is not None else 0,
            height          = int(res_el.findtext("height", "0") or 0) if res_el is not None else 0,
            extras          = extras,
        )

    def summary(self) -> str:
        """Return a compact, human-readable summary string."""
        return (
            f"{self.type_info or self.type}  fw={self.firm_version}"
            f"  res={self.resolution_name or f'{self.width}x{self.height}'}"
            f"  ch={self.channel_num}  norm={self.norm}"
            f"  lang={self.language}"
        )


@dataclass
class EncodeTable:
    """One ``<encodeTable>`` entry: stream type, resolution, rate & bitrate caps."""
    stream_type:       str       = ""
    width:             int       = 0
    height:            int       = 0
    default_framerate: int       = 0
    default_bitrate:   int       = 0
    framerate_table:   list[int] = field(default_factory=list)
    bitrate_table:     list[int] = field(default_factory=list)
    default_gop:       int       = 0

    @classmethod
    def from_element(cls, el: ET.Element) -> "EncodeTable":
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
            width             = int(res_el.findtext("width", "0") or 0)  if res_el is not None else 0,
            height            = int(res_el.findtext("height", "0") or 0) if res_el is not None else 0,
            default_framerate = _int("defaultFramerate"),
            default_bitrate   = _int("defaultBitrate"),
            framerate_table   = _intlist("framerateTable"),
            bitrate_table     = _intlist("bitrateTable"),
            default_gop       = _int("defaultGop"),
        )

    def summary(self) -> str:
        fps_str  = "/".join(str(f) for f in self.framerate_table)
        kbps_str = "/".join(str(b) for b in self.bitrate_table)
        return (
            f"  [{self.stream_type}]  {self.width}x{self.height}"
            f"  default {self.default_framerate}fps @ {self.default_bitrate}kbps"
            f"  gop={self.default_gop}\n"
            f"    fps options : {fps_str}\n"
            f"    kbps options: {kbps_str}"
        )


@dataclass
class StreamInfo:
    """One ``<StreamInfo>`` block: channel bits + one or more encode tables."""
    channel_bits:  int               = 0
    encode_tables: list[EncodeTable] = field(default_factory=list)

    @classmethod
    def from_element(cls, el: ET.Element) -> "StreamInfo":
        try:
            channel_bits = int(el.findtext("channelBits", "0") or 0)
        except ValueError:
            channel_bits = 0
        tables = [EncodeTable.from_element(t) for t in el.findall("encodeTable")]
        return cls(channel_bits=channel_bits, encode_tables=tables)

    def summary(self) -> str:
        lines = [f"  channelBits={self.channel_bits}"]
        for t in self.encode_tables:
            lines.append(t.summary())
        return "\n".join(lines)


@dataclass
class LoginResponse:
    """
    Parsed result of a successful login exchange.

    ``device_info`` and ``stream_info_list`` come from the login response XML.
    Previously these were smashed into a flat dict; now they are properly
    structured so nothing is silently overwritten.
    """
    device_info:      Optional[DeviceInfo]  = None
    stream_info_list: list[StreamInfo]      = field(default_factory=list)

    @classmethod
    def from_xml(cls, xml_str: str) -> "LoginResponse":
        """
        Parse the login response XML into a ``LoginResponse``.

        The response body contains one ``<DeviceInfo>`` and one
        ``<StreamInfoList>`` (with one or more ``<StreamInfo>`` children).
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
        """Return a formatted multi-line summary of device and stream info."""
        lines: list[str] = []

        if self.device_info:
            di = self.device_info
            lines.append("── Device Info " + "─" * 50)
            lines.append(f"  Type         : {di.type_info or di.type}")
            lines.append(f"  Firmware     : {di.firm_version}")
            lines.append(f"  Resolution   : {di.resolution_name or f'{di.width}x{di.height}'}")
            lines.append(f"  Channels     : {di.channel_num}  (audio: {di.audio_num})")
            lines.append(f"  Norm / Lang  : {di.norm} / {di.language}")
            lines.append(f"  PTZ mode     : {di.ptz_mode}")
            lines.append(f"  SD card      : {'yes' if di.sd_card else 'no'}")
            lines.append(f"  Needs rotate : {'yes' if di.need_rotate else 'no'}")
            lines.append(f"  softVer      : {di.soft_ver}  hardVer: {di.hard_ver}")
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
    All mutable state for one authenticated Baichuan camera session.

    ``login_response`` replaces the old flat ``device_info`` dict and carries
    the full ``DeviceInfo`` + ``StreamInfoList`` in structured form.
    """
    host:           str
    port:           int                      = PORT
    sock:           Optional[socket.socket]  = field(default=None)
    ch_id:          int                      = CH_ID_HOST
    mess_id:        int                      = 0
    nonce:          str                      = ""
    logged_in:      bool                     = False
    login_response: Optional[LoginResponse]  = field(default=None)


def next_mess_id(session: Session) -> int:
    """Increment and return the session's rolling 24-bit sequence counter."""
    session.mess_id = (session.mess_id + 1) % 0x1000000
    return session.mess_id


# ============================================================================
#  SESSION LIFECYCLE
# ============================================================================

def open_session(host: str, port: int = PORT) -> Session:
    """
    Open a TCP connection and return an uninitialised ``Session``.

    No protocol messages are sent.  Call ``get_nonce()`` + ``login()``, or
    use the high-level ``BaichuanSession.connect()`` which does both.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(RECV_TIMEOUT)
    sock.connect((host, port))
    return Session(host=host, port=port, sock=sock)


def get_nonce(session: Session) -> str:
    """
    Stage 1 — Send a GetNonce request and extract the nonce from the response.

    Populates ``session.nonce`` and returns it.

    Raises:
        ConnectionError: No response received.
        ValueError:      ``<nonce>`` element absent in the response XML.
        RuntimeError:    Decryption or parse failure.
    """
    assert session.sock is not None, "Session not connected."

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
        struct.unpack_from("<H", resp_header, 18)[0], enc_offset, len(resp_payload),
    )

    xml_bytes  = (
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
    except ET.ParseError as exc:
        raise RuntimeError(
            f"Failed to parse nonce response XML: {exc}\nRaw: {xml_str!r}"
        ) from exc

    logger.debug("[nonce] nonce: %s", session.nonce)
    return session.nonce


def login(session: Session, username: str, password: str) -> LoginResponse:
    """
    Stage 2 — Authenticate with the camera.

    Calls ``get_nonce()`` automatically if the nonce has not yet been obtained.
    On success, ``session.logged_in`` is set to ``True`` and
    ``session.login_response`` is populated with structured device and stream
    info.

    Returns:
        ``LoginResponse`` with ``device_info`` and ``stream_info_list`` fields.

    Raises:
        ConnectionError: Socket closed during the exchange.
        PermissionError: Camera returned HTTP 401.
        RuntimeError:    Unexpected status codes or structural errors.
    """
    if not session.nonce:
        get_nonce(session)

    user_hash   = hash_credential(username, session.nonce)
    pass_hash   = hash_credential(password, session.nonce)
    logger.debug("[login] user_hash: %s", user_hash)
    logger.debug("[login] pass_hash: %s", pass_hash)

    xml_payload = build_login_payload(user_hash, pass_hash)
    logger.debug("[login] login XML:\n%s", xml_payload.rstrip(b"\x00").decode("utf-8"))

    enc_payload = bc_crypt(session.ch_id, xml_payload)

    header = build_header(
        cmd_id        = CMD_LOGIN,
        payload_len   = len(enc_payload),
        message_class = 0x6414,
        ch_id         = session.ch_id,
        mess_id       = next_mess_id(session),
    )
    logger.debug("[login] header      : %s", header.hex())
    logger.debug("[login] enc payload : %s...", enc_payload[:32].hex())
    logger.debug("[login] sending login (%d bytes total)", len(header) + len(enc_payload))
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

    if status_code == 0x0191:   # 401
        raise PermissionError(
            f"{session.host}: Login returned 401 — check credentials."
        )
    if status_code == 0x0190:   # 400
        raise RuntimeError(f"{session.host}: Login returned 400 Bad Request.")
    if status_code != 0x00C8:   # not 200
        raise RuntimeError(
            f"{session.host}: Unexpected login status 0x{status_code:04X}."
        )

    session.logged_in = True

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

    After calling this the connection enters binary stream mode.  All
    subsequent ``recv_frame()`` calls return raw media packets.

    The camera may acknowledge the stream request in one of two ways:

    * **XML ack** (older firmware): sends an ``<Extension>`` block containing
      ``<binaryData>1</binaryData>`` before switching to binary mode.
    * **Bare 200 OK** (Duo 3 and some other models): sends a class-0x0000
      header with status=200 and an empty payload, then immediately starts
      streaming.  No XML is ever sent.

    Both forms are handled here; ``True`` is returned in either case.

    Returns:
        ``True`` if the camera acknowledged the stream request.

    Raises:
        RuntimeError:    Session not authenticated, or unexpected response.
        ConnectionError: No response received.
    """
    if not session.logged_in:
        raise RuntimeError("Cannot request stream: session is not logged in.")

    xml_payload = build_preview_payload(channel_id, handle, stream_type)
    logger.debug("[stream] preview XML:\n%s", xml_payload.rstrip(b"\x00").decode("utf-8"))
    enc_payload = bc_crypt(session.ch_id, xml_payload)

    header = build_header(
        cmd_id        = CMD_VIDEO,
        payload_len   = len(enc_payload),
        message_class = 0x6414,
        ch_id         = session.ch_id,
        mess_id       = next_mess_id(session),
    )
    logger.debug("[stream] sending Preview (%d bytes total)", len(header) + len(enc_payload))
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

    # ── Bare 200 OK with no payload ──────────────────────────────────────
    # Some firmware versions (confirmed on Duo 3 PoE) send a class-0x0000
    # header with status=200 and msg_len=0 as the entire acknowledgement.
    if not resp_payload:
        if status_code == 0x00C8:   # 200 OK
            logger.debug("[stream] bare 200 OK ack (no payload) — stream is live")
            return True
        raise RuntimeError(
            f"{session.host}: Stream request returned empty payload with "
            f"status 0x{status_code:04X} (expected 0x00C8)."
        )

    # ── XML acknowledgement ──────────────────────────────────────────────
    # Attempt to decrypt and parse.  If decryption produces non-XML (e.g.
    # this firmware skips the ack and the first frame landed here), fall
    # back to accepting any 200 response as an implicit stream-start.
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
        # Non-XML payload on a 200 response: the camera skipped the XML ack
        # and sent the first media frame directly.  Accept 200 as success.
        if status_code == 0x00C8:
            logger.debug(
                "[stream] non-XML payload on 200 response "
                "(class=0x%04x  enc_offs=0x%02x  %d bytes) — "
                "treating as implicit stream-start ack; "
                "first frame may already be buffered",
                fields["message_class"], enc_offset, len(resp_payload),
            )
            return True
        raise RuntimeError(
            f"{session.host}: Non-XML stream ack with unexpected status "
            f"0x{status_code:04X}\n"
            f"class=0x{fields['message_class']:04x}  "
            f"enc_offset=0x{enc_offset:02x}  "
            f"payload={len(resp_payload)} bytes\n"
            f"raw (first 64): {resp_payload[:64].hex()}\n"
            f"decrypted (first 64): {xml_bytes[:64]!r}"
        )


def close_session(session: Session) -> None:
    """
    Send a logout frame and close the TCP socket.

    Best-effort: network errors during logout are ignored since the socket is
    closed regardless.  ``session.logged_in`` is cleared first.
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
        pass

    try:
        session.sock.close()
    except OSError:
        pass

    session.sock = None


# ============================================================================
#  HIGH-LEVEL CONTEXT MANAGER
# ============================================================================

class BaichuanSession:
    """
    Context manager for a Baichuan camera session.

    Guarantees socket closure on exit regardless of exceptions.  The raw
    ``Session`` dataclass is available as ``.session`` for callers that need
    direct access to sequence counters, nonce, or socket.

    Typical usage::

        with BaichuanSession("192.168.1.220") as bc:
            response = bc.connect("admin", "secret")
            print(response.dump())

            if bc.request_stream():
                header, payload = recv_frame(bc.session.sock)

    Or step-by-step if you need the nonce before calling login::

        with BaichuanSession("192.168.1.220") as bc:
            nonce = bc.get_nonce()
            response = bc.login("admin", "secret")
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
    # Convenience wrappers
    # ------------------------------------------------------------------

    def get_nonce(self) -> str:
        """Stage 1: negotiate session nonce.  See ``get_nonce()``."""
        assert self.session is not None
        return get_nonce(self.session)

    def login(self, username: str, password: str) -> LoginResponse:
        """
        Stage 2: authenticate.  Calls ``get_nonce()`` first if needed.
        See ``login()`` for full docs.
        """
        assert self.session is not None
        return login(self.session, username, password)

    def connect(self, username: str, password: str) -> LoginResponse:
        """
        Single-call convenience: run the full nonce → login negotiation.

        Equivalent to::

            bc.get_nonce()
            return bc.login(username, password)

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
        """Stage 3: request video stream.  See ``request_stream()``."""
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

    logging.basicConfig(
        level   = logging.DEBUG,
        format  = "%(message)s",
    )

    CAMERA_IP = "192.168.0.220"
    USERNAME  = "admin"
    PASSWORD  = "Outback59!"

    print(f"Connecting to {CAMERA_IP}:{PORT} ...")

    with BaichuanSession(CAMERA_IP) as bc:
        try:
            response = bc.connect(USERNAME, PASSWORD)
        except PermissionError as exc:
            print(f"Authentication failed: {exc}")
            sys.exit(1)
        except (ConnectionError, RuntimeError) as exc:
            print(f"Login error: {exc}")
            sys.exit(1)

        print(f"\nLogged in.  Nonce: {bc.session.nonce}")
        print()
        print(response.dump())

        streaming = bc.request_stream(channel_id=0, stream_type="mainStream")
        print(f"\nStream acknowledged: {streaming}")

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
                    f"  Frame {i+1}: "
                    f"class=0x{fields['message_class']:04x}  "
                    f"cmd_id={fields['cmd_id']}  "
                    f"payload={fields['msg_len']} bytes"
                )

    print("\nSession closed.")

```

```console
Connecting to 192.168.0.220:9000 ...
[nonce] GetNonce sent (86 bytes total)
[nonce] response: class=0x6614  enc_offs=0xfa  len=158
[nonce] XML:
<?xml version="1.0" encoding="UTF-8" ?>
<body>
<Encryption version="1.1">
<type>md5</type>
<nonce>REDACTED</nonce>
</Encryption>
</body>

[nonce] nonce: REDACTED
[login] user_hash: REDACTED
[login] pass_hash: REDACTED
[login] login XML:
<?xml version="1.0" encoding="UTF-8" ?>
<body>
<LoginUser version="1.1">
<userName>REDACTED</userName>
<password>REDACTED</password>
<userVer>1</userVer>
</LoginUser>
<LoginNet version="1.1">
<type>LAN</type>
<udpPort>0</udpPort>
</LoginNet>
</body>
[login] header      : f0debc0a0100000028010000fa0200000000146400000000
[login] enc payload : REDACTED...
[login] sending login (320 bytes total)
[login] response: class=0x0000  len=4007  enc_offs=0xfa  status=0x00c8
[login] raw header: f0debc0a01000000a70f0000fa020000c800000000000000
[login] response XML:
<?xml version="1.0" encoding="UTF-8" ?>
<body>
<DeviceInfo version="1.1">
<firmVersion>57945531888563</firmVersion>
<IOInputPortNum>0</IOInputPortNum>
<IOOutputPortNum>0</IOOutputPortNum>
<diskNum>0</diskNum>
<type>ipc</type>
<channelNum>1</channelNum>
<audioNum>1</audioNum>
<ipChannel>0</ipChannel>
<analogChnNum>1</analogChnNum>
<resolution>
<resolutionName>4512*2512</resolutionName>
<width>4512</width>
<height>2512</height>
</resolution>
<secretCode>REDACTED</secretCode>
<language>English</language>
<sdCard>1</sdCard>
<ptzMode>none</ptzMode>
<typeInfo>IPC</typeInfo>
<softVer>50397401</softVer>
<hardVer>0</hardVer>
<panelVer>0</panelVer>
<hdChannel1>0</hdChannel1>
<hdChannel2>0</hdChannel2>
<hdChannel3>0</hdChannel3>
<hdChannel4>0</hdChannel4>
<norm>NTSC</norm>
<osdFormat>MDY</osdFormat>
<B485>0</B485>
<supportAutoUpdate>0</supportAutoUpdate>
<userVer>1</userVer>
<FrameworkVer>1</FrameworkVer>
<authMode>0</authMode>
<binoType>0</binoType>
</DeviceInfo>
<StreamInfoList version="1.1">
<StreamInfo>
<channelBits>1</channelBits>
<encodeTable>
<type>mainStream</type>
<resolution>
<width>4512</width>
<height>2512</height>
</resolution>
<defaultFramerate>20</defaultFramerate>
<defaultBitrate>8192</defaultBitrate>
<framerateTable>20,18,16,15,12,10,8,6,4,2</framerateTable>
<bitrateTable>3072,4096,5120,6144,7168,8192,9216,10240</bitrateTable>
<defaultGop>2</defaultGop>
</encodeTable>
<encodeTable>
<type>subStream</type>
<resolution>
<width>896</width>
<height>512</height>
</resolution>
<defaultFramerate>10</defaultFramerate>
<defaultBitrate>1024</defaultBitrate>
<framerateTable>20,15,10,7,4</framerateTable>
<bitrateTable>128,256,384,512,768,1024,1228</bitrateTable>
<defaultGop>4</defaultGop>
</encodeTable>
</StreamInfo>
<StreamInfo>
<channelBits>1</channelBits>
<encodeTable>
<type>mainStream</type>
<resolution>
<width>3840</width>
<height>2160</height>
</resolution>
<defaultFramerate>25</defaultFramerate>
<defaultBitrate>8192</defaultBitrate>
<framerateTable>25,22,20,18,16,15,12,10,8,6,4,2</framerateTable>
<bitrateTable>4096,5120,6144,7168,8192</bitrateTable>
<defaultGop>2</defaultGop>
</encodeTable>
<encodeTable>
<type>subStream</type>
<resolution>
<width>896</width>
<height>512</height>
</resolution>
<defaultFramerate>10</defaultFramerate>
<defaultBitrate>1024</defaultBitrate>
<framerateTable>20,15,10,7,4</framerateTable>
<bitrateTable>128,256,384,512,768,1024,1228</bitrateTable>
<defaultGop>4</defaultGop>
</encodeTable>
</StreamInfo>
<StreamInfo>
<channelBits>1</channelBits>
<encodeTable>
<type>mainStream</type>
<resolution>
<width>2560</width>
<height>1440</height>
</resolution>
<defaultFramerate>25</defaultFramerate>
<defaultBitrate>8192</defaultBitrate>
<framerateTable>25,22,20,18,16,15,12,10,8,6,4,2</framerateTable>
<bitrateTable>1024,1536,2048,3072,4096,5120,6144,7168,8192</bitrateTable>
<defaultGop>2</defaultGop>
</encodeTable>
<encodeTable>
<type>subStream</type>
<resolution>
<width>896</width>
<height>512</height>
</resolution>
<defaultFramerate>10</defaultFramerate>
<defaultBitrate>1024</defaultBitrate>
<framerateTable>20,15,10,7,4</framerateTable>
<bitrateTable>128,256,384,512,768,1024,1228</bitrateTable>
<defaultGop>4</defaultGop>
</encodeTable>
</StreamInfo>
<StreamInfo>
<channelBits>1</channelBits>
<encodeTable>
<type>mainStream</type>
<resolution>
<width>2304</width>
<height>1296</height>
</resolution>
<defaultFramerate>25</defaultFramerate>
<defaultBitrate>8192</defaultBitrate>
<framerateTable>25,22,20,18,16,15,12,10,8,6,4,2</framerateTable>
<bitrateTable>1024,1536,2048,3072,4096,5120,6144,7168,8192</bitrateTable>
<defaultGop>2</defaultGop>
</encodeTable>
<encodeTable>
<type>subStream</type>
<resolution>
<width>896</width>
<height>512</height>
</resolution>
<defaultFramerate>10</defaultFramerate>
<defaultBitrate>1024</defaultBitrate>
<framerateTable>20,15,10,7,4</framerateTable>
<bitrateTable>128,256,384,512,768,1024,1228</bitrateTable>
<defaultGop>4</defaultGop>
</encodeTable>
</StreamInfo>
</StreamInfoList>
</body>


Logged in.  Nonce: 69eade3c-VTW7RJf40PElhYnawAxi

── Device Info ──────────────────────────────────────────────────
  Type         : IPC
  Firmware     : 57945531888563
  Resolution   : 4512*2512
  Channels     : 1  (audio: 1)
  Norm / Lang  : NTSC / English
  PTZ mode     : none
  SD card      : yes
  Needs rotate : no
  softVer      : 50397401  hardVer: 0
  extras:
    IOInputPortNum: 0
    IOOutputPortNum: 0
    diskNum: 0
    ipChannel: 0
    analogChnNum: 1
    secretCode: REDACTED
    panelVer: 0
    hdChannel1: 0
    hdChannel2: 0
    hdChannel3: 0
    hdChannel4: 0
    osdFormat: MDY
    B485: 0
    supportAutoUpdate: 0
    userVer: 1
    FrameworkVer: 1

── Stream Info ──────────────────────────────────────────────────
  StreamInfo [0]  channelBits=1
  [mainStream]  4512x2512  default 20fps @ 8192kbps  gop=2
    fps options : 20/18/16/15/12/10/8/6/4/2
    kbps options: 3072/4096/5120/6144/7168/8192/9216/10240
  [subStream]  896x512  default 10fps @ 1024kbps  gop=4
    fps options : 20/15/10/7/4
    kbps options: 128/256/384/512/768/1024/1228
  StreamInfo [1]  channelBits=1
  [mainStream]  3840x2160  default 25fps @ 8192kbps  gop=2
    fps options : 25/22/20/18/16/15/12/10/8/6/4/2
    kbps options: 4096/5120/6144/7168/8192
  [subStream]  896x512  default 10fps @ 1024kbps  gop=4
    fps options : 20/15/10/7/4
    kbps options: 128/256/384/512/768/1024/1228
  StreamInfo [2]  channelBits=1
  [mainStream]  2560x1440  default 25fps @ 8192kbps  gop=2
    fps options : 25/22/20/18/16/15/12/10/8/6/4/2
    kbps options: 1024/1536/2048/3072/4096/5120/6144/7168/8192
  [subStream]  896x512  default 10fps @ 1024kbps  gop=4
    fps options : 20/15/10/7/4
    kbps options: 128/256/384/512/768/1024/1228
  StreamInfo [3]  channelBits=1
  [mainStream]  2304x1296  default 25fps @ 8192kbps  gop=2
    fps options : 25/22/20/18/16/15/12/10/8/6/4/2
    kbps options: 1024/1536/2048/3072/4096/5120/6144/7168/8192
  [subStream]  896x512  default 10fps @ 1024kbps  gop=4
    fps options : 20/15/10/7/4
    kbps options: 128/256/384/512/768/1024/1228
[stream] preview XML:
<?xml version="1.0" encoding="UTF-8" ?>
<body>
<Preview version="1.1">
<channelId>0</channelId>
<handle>0</handle>
<streamType>mainStream</streamType>
</Preview>
</body>
[stream] sending Preview (194 bytes total)
[stream] ack: class=0x0000  status=0x0190  enc_offs=0xfa  payload=0 bytes
Traceback (most recent call last):
  File "/home/user/Documents/code/baichuanpython/login5.py", line 1037, in <module>
    streaming = bc.request_stream(channel_id=0, stream_type="mainStream")
  File "/home/user/Documents/code/baichuanpython/login5.py", line 984, in request_stream
    return request_stream(self.session, channel_id, handle, stream_type)
  File "/home/user/Documents/code/baichuanpython/login5.py", line 816, in request_stream
    raise RuntimeError(
    ...<2 lines>...
    )
RuntimeError: 192.168.0.220: Stream request returned empty payload with status 0x0190 (expected 0x00C8).
```