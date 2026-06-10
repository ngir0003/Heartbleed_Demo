# Heartbleed Demo — CVE-2014-0160

Interactive educational demonstration of the Heartbleed vulnerability for COMP3781 Cybersecurity, Flinders University.

## Architecture

| Container | Role | Port |
|-----------|------|------|
| `server` | SecureBank — Flask login app behind **stunnel** using **OpenSSL 1.0.1f** (vulnerable, compiled from source) | HTTP :4000 · HTTPS :4001 |
| `hacker` | Attacker console — sends malformed heartbeat, shows memory dump and stolen cookies | :4002 |
| `dashboard` | Overview — explains the attack, links to all roles, references | :4003 |

All containers share a private Docker network (`heartbleed-net`). The hacker container reaches the server at `server:443` internally.

## Requirements

- **Docker Desktop** (Mac, Windows) or **Docker Engine + Compose plugin** (Linux)
- No other dependencies — everything is compiled inside Docker during the build

### Supported platforms

| Platform | Status |
|----------|--------|
| Linux x86-64 | Native |
| Linux ARM64 (e.g. Raspberry Pi 4, AWS Graviton) | Native |
| macOS Intel | Native |
| macOS Apple Silicon (M1/M2/M3) | Native |
| Windows x86-64 (Docker Desktop) | Native |
| Windows ARM (Docker Desktop) | Native |

OpenSSL 1.0.1f is compiled from source for whatever CPU architecture you run on — no pre-built 2014 binaries required.

## Quick Start

```bash
cd Heartbleed_Demo
docker compose up --build
```

The first build compiles OpenSSL 1.0.1f and stunnel from source — allow **5–10 minutes**. Subsequent starts reuse the cached layers and are instant.

| URL | What you will see |
|-----|-------------------|
| http://localhost:4003 | Demo overview and explanation |
| https://localhost:4001 | SecureBank login (accept the self-signed certificate warning) |
| http://localhost:4002 | Attacker console |

## Demo Walkthrough

### Step 1 — Victim logs in
1. Open **https://localhost:4001** in your browser.
2. Accept the self-signed certificate warning.
3. Log in with `alice` / `password123` (or `bob` / `securepass`).
4. Keep this tab open — your session cookie is now in server process memory.

### Step 2 — Launch the exploit
1. Open **http://localhost:4002** in a second tab.
2. Review the malformed heartbeat packet visualiser — hover over each byte for a description.
3. Click **LAUNCH EXPLOIT**.

The hacker container sends a TLS heartbeat to `server:443` containing **1 byte of actual payload** but a claimed length of 16,384 bytes (`0x4000`). OpenSSL trusts the claimed length without validating it against the real record size. The `memcpy` call copies our 1 byte of payload and then blindly reads 16,383 more bytes from adjacent heap memory into the response.

### Step 3 — Read the memory dump
The raw bytes returned by the server are displayed in hex and ASCII. Any `session=` cookie values found in the dump appear in the **Session Tokens Stolen** banner.

### Step 4 — Hijack the session
1. Copy the stolen token from the banner.
2. In the victim's browser tab open DevTools (`F12`) → **Application** → **Cookies** → select `localhost`.
3. Double-click the `session` cookie value, paste the stolen token, press Enter.
4. Reload the page — you are now logged in as the victim with no password.

> You may need to click **LAUNCH EXPLOIT** several times. Whether the victim's cookie appears in a given memory dump depends on heap layout — this reflects the real behaviour of the vulnerability.

## Why This Works — Root Cause

The OpenSSL heartbeat handler reads a 2-byte claimed payload length from the client message and passes it directly to `memcpy` without checking it against the actual record length:

```c
n2s(p, payload);               // attacker sets payload = 0x4000 (16384)
bp = OPENSSL_malloc(payload);
memcpy(bp, pl, payload);       // copies 16384 bytes — most of which are NOT ours
```

The one-line fix in OpenSSL 1.0.1g adds a bounds check:

```c
if (1 + 2 + payload + 16 > s->s3->rrec.length)
    return 0;
```

## How the Server Is Built

The server container uses a two-stage Docker build:

1. **Builder stage** — downloads and compiles OpenSSL 1.0.1f from source (openssl.org permanent archive), then compiles stunnel 5.56 linked against that library.
2. **Runtime stage** — copies only the compiled artifacts (libssl, libcrypto, stunnel binary) into a clean Ubuntu 22.04 image alongside Python 3 + Flask.

stunnel listens on port 443 using the vulnerable OpenSSL and proxies traffic to Flask on port 80. The heartbleed exploit targets the stunnel TLS layer directly.

## Vulnerability Detection

Systems can be scanned for this vulnerability using:
- **Nmap**: `nmap -p 443 --script ssl-heartbleed <target>`
- **Metasploit**: `auxiliary/scanner/ssl/openssl_heartbleed`

## Mitigation

- Upgrade OpenSSL to version 1.0.1g or later
- Revoke and reissue all TLS certificates after patching
- Require all users to change passwords
- Deploy IDS rules (e.g. Snort) to flag heartbeat requests claiming oversized payloads

## Stopping the Demo

```bash
docker compose down
```

## References

1. "Heartbleed Bug," *heartbleed.com*, 2014. https://heartbleed.com
2. CISA, "OpenSSL 'Heartbleed' Vulnerability (CVE-2014-0160)," Apr. 2014. https://www.cisa.gov/news-events/alerts/2014/04/08/openssl-heartbleed-vulnerability-cve-2014-0160
3. CERT/CC, "Vulnerability Note VU#720951," *kb.cert.org*. https://www.kb.cert.org/vuls/id/720951
4. Canada Revenue Agency, "Internal Audit — Cyber Security," *canada.ca*, 2016.
5. Cloudflare, "Staying Ahead of OpenSSL Vulnerabilities," *The Cloudflare Blog*, Apr. 7, 2014. https://blog.cloudflare.com/staying-ahead-of-openssl-vulnerabilities/
6. Shodan, "Facet Analysis: CVE-2014-0160," *shodan.io*, 2026.
7. OWASP, "Cyber Defense Framework," *owasp.org*, 2023. https://owasp.org/www-project-cyber-defense-framework/
8. Snort, "Network Intrusion Detection & Prevention System," *snort.org*. https://www.snort.org/

## Project Team — COMP3781 2026

Colin Chen · Bailey Boyd · Samuel Ngiri · Lachlan Gill
