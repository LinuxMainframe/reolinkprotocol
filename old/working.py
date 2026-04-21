#!/usr/bin/env python3
"""
Minimal GetNonce test matching reolink_aio header structure.
"""
"""
Baichuan.py_old2

Aidan A. Bradley

This worked, but was very minimal. Was able to use this and some of my notes to build the current version.

April 18th 2026
"""

import socket
import struct
import xml.etree.ElementTree as ET

CAMERA_IP = "192.168.xxx.yyy"
PORT = 9000
TIMEOUT = 5.0

# Constants from reolink_aio
MAGIC = bytes.fromhex("f0debc0a")
BC_KEY = bytes([0x1F, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0xFF])

def bc_decrypt(enc_offset, data):
    offset_byte = enc_offset & 0xFF
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        key_byte = BC_KEY[(i + enc_offset) % 8]
        result[i] = byte ^ key_byte ^ offset_byte
    return bytes(result)

def build_get_nonce_payload():
    # Minimal XML exactly as used in working libraries
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<body>\n<GetNonce/>\n</body>'
    return xml.encode('utf-8') + b'\x00'

def build_header(cmd_id: int, payload_len: int, message_class: str) -> bytes:
    """Build header exactly as reolink_aio does."""
    cmd_id_bytes = cmd_id.to_bytes(4, byteorder='little')
    mess_len_bytes = payload_len.to_bytes(4, byteorder='little')
    # ch_id=250 (host), mess_id=0 for initial request
    ch_id = 250
    mess_id = 0
    mess_id_bytes = ch_id.to_bytes(1, byteorder='little') + mess_id.to_bytes(3, byteorder='little')
    
    if message_class == "1465":  # Legacy / Nonce request
        # From reolink_aio: encrypt = "12dc", header = MAGIC + cmd_id + mess_len + mess_id + encrypt + message_class
        encrypt = bytes.fromhex("12dc")
        return MAGIC + cmd_id_bytes + mess_len_bytes + mess_id_bytes + encrypt + bytes.fromhex(message_class)
    else:
        # Modern header (not needed for this test)
        status_code = bytes.fromhex("0000")
        payload_offset_bytes = (0).to_bytes(4, byteorder='little')
        return MAGIC + cmd_id_bytes + mess_len_bytes + mess_id_bytes + status_code + bytes.fromhex(message_class) + payload_offset_bytes

def recv_response(sock):
    # Read first 20 bytes (minimum header)
    header = sock.recv(20)
    if len(header) < 20:
        return None, None
    mclass = struct.unpack_from('<H', header, 18)[0]
    # Modern header (24 bytes) if mclass in (0x6414, 0x6482, 0x0146)
    if mclass in (0x6414, 0x6482, 0x0146):
        header += sock.recv(4)
    msg_len = struct.unpack_from('<I', header, 8)[0]
    payload = sock.recv(msg_len) if msg_len > 0 else b''
    return header, payload

def main():
    payload = build_get_nonce_payload()
    # Use message_class "1465" (string, not integer) as per reolink_aio
    header = build_header(cmd_id=1, payload_len=len(payload), message_class="1465")
    
    print(f"Connecting to {CAMERA_IP}:{PORT}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect((CAMERA_IP, PORT))
        print("Sending GetNonce request...")
        print(f"Header: {header.hex(' ')}")
        sock.sendall(header + payload)
        
        resp_header, resp_payload = recv_response(sock)
        if resp_header is None:
            print("No response.")
            return
        
        mclass = struct.unpack_from('<H', resp_header, 18)[0]
        msg_len = struct.unpack_from('<I', resp_header, 8)[0]
        enc_offs = resp_header[12]
        print(f"Response: class=0x{mclass:04x}, len={msg_len}, enc_offs=0x{enc_offs:02x}")
        
        if msg_len == 0:
            print("Empty payload. Camera rejected.")
            return
        
        # Decrypt (BC XOR)
        if resp_payload.startswith(b'<?xml'):
            xml_bytes = resp_payload
        else:
            xml_bytes = bc_decrypt(enc_offs, resp_payload)
        
        xml_str = xml_bytes.rstrip(b'\x00').decode('utf-8')
        print("Payload XML:\n" + xml_str)
        
        # Extract nonce
        try:
            root = ET.fromstring(xml_str)
            nonce_el = root.find('.//nonce')
            if nonce_el is not None and nonce_el.text:
                print(f"SUCCESS: Nonce = {nonce_el.text.strip()}")
            else:
                print("No <nonce> element found.")
        except ET.ParseError as e:
            print(f"XML parse error: {e}")

if __name__ == "__main__":
    main()
