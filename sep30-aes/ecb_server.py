#!/usr/bin/env python3
"""
ECB oracle challenge server  --  Security I, Fall 26, Columbia

It answers one question, over and over:

    give me some bytes P, and I return   AES-128-ECB( KEY,  P || FLAG )

KEY is random and fresh every time the server starts; you never see it.
FLAG is read from the environment (default is a placeholder).  Your job,
as the attacker, is to recover FLAG using only the ciphertexts.

Talk to it (prefix is hex):

    curl 'http://165.22.35.184:54321/oracle?prefix='                 # just FLAG, encrypted
    curl 'http://165.22.35.184:54321/oracle?prefix=4141414141'       # "AAAAA" || FLAG
"""
import os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ----------------------------------------------------------------- AES-128 (ECB)
def _xt(a):
    a <<= 1
    return a ^ 0x11b if a & 0x100 else a
def _mul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        a = _xt(a); b >>= 1
    return r
_INV = [0]*256
for _a in range(1, 256):
    for _b in range(1, 256):
        if _mul(_a, _b) == 1: _INV[_a] = _b; break
def _sb(x):
    b = _INV[x]; r = 0x63
    for i in range(5): r ^= ((b << i) | (b >> (8 - i))) & 0xff
    return r
SBOX = [_sb(x) for x in range(256)]
RCON = [1, 2, 4, 8, 16, 32, 64, 128, 0x1b, 0x36]
def _expand(key):
    w = [list(key[4*i:4*i+4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]; t = [SBOX[b] for b in t]; t[0] ^= RCON[i//4 - 1]
        w.append([a ^ b for a, b in zip(w[i-4], t)])
    return [sum(w[4*r:4*r+4], []) for r in range(11)]
def _enc_block(pt, K):
    s = [a ^ b for a, b in zip(pt, K[0])]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[4*((i//4 + i%4) % 4) + i%4] for i in range(16)]     # ShiftRows
        if r < 10:                                                  # MixColumns
            n = []
            for c in range(4):
                a = s[4*c:4*c+4]
                n += [_mul(a[0],2)^_mul(a[1],3)^a[2]^a[3],
                      a[0]^_mul(a[1],2)^_mul(a[2],3)^a[3],
                      a[0]^a[1]^_mul(a[2],2)^_mul(a[3],3),
                      _mul(a[0],3)^a[1]^a[2]^_mul(a[3],2)]
            s = n
        s = [a ^ b for a, b in zip(s, K[r])]
    return bytes(s)
def _pad(m):
    n = 16 - len(m) % 16
    return m + bytes([n]) * n
def ecb_encrypt(data, key):
    K = _expand(key)
    d = _pad(data)
    return b''.join(_enc_block(d[i:i+16], K) for i in range(0, len(d), 16))

# ----------------------------------------------------------------- the oracle
KEY  = os.urandom(16)
FLAG = os.environ.get("FLAG", "flag{replace_me_with_a_real_flag}").encode()
LIMIT = threading.BoundedSemaphore(30)         # at most 30 in flight at once

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass            # quiet
    def _send(self, code, body, ctype="text/plain"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/help"):
            self._send(200, __doc__)
            return
        if u.path != "/oracle":
            self._send(404, "try /oracle?prefix=<hex>\n")
            return
        q = parse_qs(u.query)
        prefix_hex = (q.get("prefix", [""])[0]).strip()
        try:
            prefix = bytes.fromhex(prefix_hex) if prefix_hex else b""
        except ValueError:
            self._send(400, "prefix must be hex\n")
            return
        with LIMIT:                            # cap concurrency at 30
            ct = ecb_encrypt(prefix + FLAG, KEY)
        self._send(200, ct.hex() + "\n")

def main():
    port = int(os.environ.get("PORT", "54321"))
    host = os.environ.get("HOST", "0.0.0.0")
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"ECB oracle listening on http://{host}:{port}/oracle?prefix=<hex>", file=sys.stderr)
    print(f"(flag is {len(FLAG)} bytes; up to 30 concurrent requests)", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()

if __name__ == "__main__":
    main()
