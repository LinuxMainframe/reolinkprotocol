#!/usr/bin/env python3

"""
Baichuan.py_old

Aidan A. Bradley

This was my first attempt at reconstructing the system. Didnt work, but got some testing notes that allowed me to figure out my
first successful nonce request and parsing.

April 17th 2026
"""


import hashlib
import struct
import socket
import xml.etree.ElementTree as ET


# <+ -- MAIN CONSTANTS -- +>
MAGIC = 0x0ABCDEF0
PORT = 9000
RECV_TIMEOUT = 15.0

# <+ -- XOR KEY -- +>
XML_KEY = bytes([0x1F,0x2D,0x3C,0x4B,0x5A,0x69,0x78,0xFF])

# <+ -- MESSAGE CLASS AND SUBSEQUENT HEADER SIZE MAP -- +>
HEADER_LENGTHS = {
    0x6514: 20, # LEGACY
    0x6614: 20, # MODERN (no payload offset
    0x6414: 24, # MODERN (with payload offset)
    0x6482: 24, # MODERN (file download)
    0x0000: 24, # MODERN
}

# -----------------------------
# BAICHUAN DECRYPTION FUNCTION
# -----------------------------
def bc_crypt(enc_offset: int, data: bytes) -> bytes:
    """
    """
    offset_byte = enc_offset & 0xFF
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        key_byte = XML_KEY[(i + enc_offset) % 8]
        result[i] = byte ^ key_byte ^ offset_byte
    return bytes(result)

# -----------------------------
#   HEADER BUILDING FUNCTIONS
# -----------------------------
def legacy_header(msg_id: int = 1, payload_len : int = 1836) -> bytes:
    """
    Build a 20-byte legacy header
    Structure: magic(I), id(I), len(I), enc_offs(I), enc_flag(B), unk(B), msgclass(H)
    enc_offs = 0x01000000, little-endian->bytes: 00 00 00 01
        byte12=channel_id=0x00, byte13=stream_id=0x00
        byte14=unknown=0x00,    byte15=msg_handle=0x01
    """

    magic    = int(MAGIC)
    offs     = int(0x01000000) # msg_handle=0x01, channel=0, stream=0
    enc      = int(0x01)       # BC encryption or lower, no auth yet
    unknown  = int(0xDC)       # client sending code, 0xDC, whereas camera replies with 0xdd
    mclass   = int(0x6514)     # we use the legacy class first
    # TOTAL OF 20 BYTES FOR LEGACY

    return struct.pack('<IIIIBBH', magic, msg_id, payload_len, offs, enc, unknown, mclass)

def modern_header(msg_id: int = 1, payload_len : int = 0, status : int = 0x0000, mclass : int = 0x6414, poffs : int = 0) -> bytes:
    """
    Build a 24-byte modern header
    Structure: magic(I), id(I), len(I), enc_offs(I), status(H), mclass(H), poffs(I)
    enc_offs, same as legacy
    """

    magic = MAGIC
    offs = 0x01000000     # Message handle = 1
    return struct.pack('<IIIIHHI', magic, msg_id, payload_len, offs, status, mclass, poffs)

# ----------------------------
#        LOGIN HANDLERS
# ----------------------------
def legacy_login(username : str, password : str) -> bytes:
    """
    Step 0: Ask for nonce
    Body = MD5(Username)[32bytes] + MD5(password)[32bytes] + zeros

    Some firmware requires the even older methods where the MD5 payload is sent as hex-digested
    instead of the raw digested form. If so, just swap the hashlib.md5()
    """

    user_hash = hashlib.md5(username.encode()).hexdigest().encode('ascii')
    pass_hash = hashlib.md5(password.encode()).hexdigest().encode('ascii')

    # 32s code for the hashlib.pack('...') autopads anyremaining bytes that the hashes dont fill
    payload = struct.pack('32s32s', user_hash, pass_hash)
    payload += b'\x00' * (1836 - len(payload)) # pad to the final size of 0x072C (=1836 Bytes)

    header = legacy_header(msg_id=1, payload_len=len(payload))
    return header + payload

def modern_login(username : str, password : str) -> bytes:
    """
    Step 1: Switch to XML
    Credentials are now hex-digested MD5 hashes instead of binary from step 0
    The nonce from step 1 IS NOT mixed into credentials here; its only for negotiating
    to switch to AES encryption, which are not (yet) doing
    """

    user_hash = hashlib.md5(username.encode()).hexdigest() # 32-char HEX
    pass_hash = hashlib.md5(password.encode()).hexdigest() # 32-char HEX

    xml_body = (
        '<? xml version="1.0" encoding="UTF-8" ?>\n'
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

    payload = xml_body.encode('utf-8') + b'\x00'
    header = modern_header(msg_id=1, payload_len=len(payload))
    return header + payload

# ---------------------------
#      SOCKET I/O HELPERS
# ---------------------------
def recv_exact(sock: socket.socket, n : int) -> bytes:
    """
    Read exactly n bytes from socket, handling partial reads.
    """
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Socket closed before all bytes received")
        data += chunk
    return data

def recv_bc_message(sock: socket.socket) -> bytes:
    """
    Read an entire BC message from socket
    1.) Read bytes (minimum header)
    2.) Decide header size from message class
    3.) Read remaining header bytes if needed
    4.) Read msg_leng body bytes
    """

    data = recv_exact(sock, 20)

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != MAGIC and magic != 0x0FEDCBA0:
        raise ValueError(f"Invalid magic: {magic:#010x} -- expected {MAGIC:#010x}")

    mclass = struct.unpack_from('<H', data, 18)[0]
    header_len = HEADER_LENGTHS.get(mclass, 20)

    if header_len == 24:
        data += recv_exact(sock, 4)

    msg_len = struct.unpack_from('<I', data, 8)[0]

    if msg_len > 0:
        data += recv_exact(sock, msg_len)

    return data

def parse_bc_header(data : bytes) -> dict:
    magic, msg_id, msg_len, enc_offs_raw = struct.unpack_from('<IIII', data, 0)
    mclass = struct.unpack_from('<H', data, 18)[0]
    header_len = HEADER_LENGTHS.get(mclass, 20)

    result = {
        'magic' : magic,
        'msg_id' : msg_id,
        'msg_len' : msg_len,
        'enc_offs' : data[12], 
        'channel_id' : data[12],
        'stream_id' : data[13],
        'msg_handle' : data[15], # Usually byte 15 in this protocol
        'mclass' : mclass,
        'header_len' : header_len,
    }

    if header_len == 24:
        result['status'] = struct.unpack_from('<H', data, 16)[0]
        result['poffs'] = struct.unpack_from('<I', data, 20)[0]
    else:
        result['status'] = struct.unpack_from('<H', data, 16)[0] # Even legacy has status here
        result['poffs'] = 0

    return result

def try_decode_body(enc_offset : int, body : bytes) -> str | None:
    """
    Try to decode body as XML, handling three cases (taken from Lua dissector from git /thirtythreeforty/NeoLink
        1.) Plaintext XML (starts with '<?xml')
        2.) BC XOR encrypted XML (XOR decrypt, then check for '<?xml')
        3.) Binary data (returns None)
    """

    if not body:
        return None

    if body[:5] == b'<?xml':
        return body.rstrip(b'\x00').decode('utf-8', errors='replace')

    decrypted = bc_crypt(enc_offset, body)
    if decrypted[:5] == b'<?xml':
        return decrypted.rstrip(b'\x00').decode('utf-8', errors='replace')

    return None

# ---------------------------
#      FULL HANDSHAKE
#   CHOREOGRAPHER FUNCTION
# ---------------------------
def login(ip : str, username : str, password : str, port : int = PORT) -> bool:
    """
    Perform the full two-step BC protocol
    Returns True on success, False on failure.
    """

    print(f"\n{'='*60}")
    print(f"Connecting to {ip}:{port}")
    print(f"{'='*60}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(RECV_TIMEOUT)
        sock.connect((ip, port))
        print(f"[+] Connected!")

        msg = legacy_login(username, password)
        print(f"Sending legacy login attempt: ({len(msg)} bytes)")
        print(f"    Header hex: {msg[:20].hex(' ')}")
        sock.sendall(msg)

        # Read and parse
        #raw = recv_bc_message(sock)
        sock.settimeout(3.0)
        try:
            peek = sock.recv(4096)
            print(f"RAW RESPONSE: ({len(peek)} bytes): {peek.hex(' ')}")
        except socket.timeout:
            print("NO RESPONSE!")
        raw = None
        hdr = parse_bc_header(raw)
        body = raw[hdr['header_len']:]

        print(f"    -> Received response! ({len(raw)} bytes)")
        xml_text = try_decode_body(hdr['enc_offs'], body)
        if xml_text:
            print(f"\n RESPONSE XML: \n{xml_text}")
        else:
            print(f"\n RESPONSE BODY (hex, first 64 bytes):\n{body[:64].hex(' ')}")

        nonce = None
        if xml_text:
            try:
                clean_xml = xml_text.split('\x00')[0].strip()
                root = ET.fromstring(clean_xml)
                nonce_el = root.find('.//nonce')
                if nonce_el is not None:
                    nonce = nonce_el.text.strip()
                    print(f"\n[+] Got Nonce!: {nonce}")
            except ET.ParseError as e:
                print(f"[!] ERROR: XML parse error: {e}")

        if nonce is None:
            if hdr.get('status') == 0xC800 or hdr.get('status') == 200:
                print("[i] Legacy Camera (no nonce step) - check XML for device info")
                return True
            else:
                print("[!] No nonce detected, and no success status, LOGIN FAILED!")
                return False

        msg2 = modern_login(username, password)
        print("\n[i] Sending modern login ({len(msg2)} bytes)")
        print("    Header hex: {msg2[:24].hex(' ')}")
        sock.sendall(msg2)

        raw2 = recv_bc_message(sock)
        hdr2 = parse_bc_header(raw2)
        body2 = raw2[hdr2['header_len']:]

        print(f"\n[!] Got response!: ({len(raw2)} bytes)")

        status_ok = hdr2.get('status') in (0x00C8, 0xC800, 200)

        xml_text2 = try_decode_body(hdr2['enc_offs'], body2)
        if xml_test2:
            print(f"\n[i] Response XML:\n{xml_test2}")
            try:
                clean_xml2 = xml_text2.split('\x00')[0].strip()
                root = ET.fromstring(clean_xml2)

                fw = root2.find('.//firmVersion')
                type = root2.find('.//type')
                ch = root2.find('.//channelNum')
            except ET.ParseError as e:
                pass

        else:
            print(f"[i] Response Body: {body2[:64].hex(' ')}")

        if status_ok:
            print("\n[!] Login Successful!")
            return True
        else:
            print("FAILED TO LOGIN!")
            return False

if __name__ == "__main__":
    CAMERA_IP = '192.168.xxx.yyy'
    USERNAME = '<redacted>'
    PASSWORD = '<redacted>'

    success = login(CAMERA_IP, USERNAME, PASSWORD)
    print(success)
