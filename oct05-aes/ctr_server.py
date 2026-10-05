#!/usr/bin/env python3
"""
CTR nonce-reuse challenge server  --  Security I, Fall 26, Columbia

Two endpoints, both CTR mode under the SAME key and the SAME nonce:

    GET /token                 -> CTR-encrypt(SECRET) as hex          (the message to crack)
    GET /encrypt?msg=<hex>     -> CTR-encrypt(your bytes) as hex      (your own encryptions)

Reusing one (key, nonce) pair means both calls XOR the plaintext with the
SAME keystream. Encrypt something you know, and the keystream falls out;
XOR it into the token to read SECRET. Goal: recover SECRET. No key needed.
"""
import os, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# shared AES-128 core (embedded verbatim into each server so they stay standalone)
def _xt(a):
    a<<=1; return a^0x11b if a&0x100 else a
def _mul(a,b):
    r=0
    while b:
        if b&1: r^=a
        a=_xt(a); b>>=1
    return r
_INV=[0]*256
for _a in range(1,256):
    for _b in range(1,256):
        if _mul(_a,_b)==1: _INV[_a]=_b; break
def _sb(x):
    b=_INV[x]; r=0x63
    for i in range(5): r^=((b<<i)|(b>>(8-i)))&0xff
    return r
SBOX=[_sb(x) for x in range(256)]
ISBOX=[0]*256
for i,v in enumerate(SBOX): ISBOX[v]=i
RCON=[1,2,4,8,16,32,64,128,0x1b,0x36]
def _expand(key):
    w=[list(key[4*i:4*i+4]) for i in range(4)]
    for i in range(4,44):
        t=list(w[i-1])
        if i%4==0:
            t=t[1:]+t[:1]; t=[SBOX[b] for b in t]; t[0]^=RCON[i//4-1]
        w.append([a^b for a,b in zip(w[i-4],t)])
    return [sum(w[4*r:4*r+4],[]) for r in range(11)]
def enc_block(pt,K):
    s=[a^b for a,b in zip(pt,K[0])]
    for r in range(1,11):
        s=[SBOX[b] for b in s]
        s=[s[4*((i//4+i%4)%4)+i%4] for i in range(16)]
        if r<10:
            n=[]
            for c in range(4):
                a=s[4*c:4*c+4]
                n+=[_mul(a[0],2)^_mul(a[1],3)^a[2]^a[3],a[0]^_mul(a[1],2)^_mul(a[2],3)^a[3],a[0]^a[1]^_mul(a[2],2)^_mul(a[3],3),_mul(a[0],3)^a[1]^a[2]^_mul(a[3],2)]
            s=n
        s=[a^b for a,b in zip(s,K[r])]
    return bytes(s)
def dec_block(ct,K):
    def ishift(s): return [s[4*((i//4-i%4)%4)+i%4] for i in range(16)]
    def imix(s):
        o=[]
        for c in range(4):
            a=s[4*c:4*c+4]
            o+=[_mul(a[0],14)^_mul(a[1],11)^_mul(a[2],13)^_mul(a[3],9),_mul(a[0],9)^_mul(a[1],14)^_mul(a[2],11)^_mul(a[3],13),_mul(a[0],13)^_mul(a[1],9)^_mul(a[2],14)^_mul(a[3],11),_mul(a[0],11)^_mul(a[1],13)^_mul(a[2],9)^_mul(a[3],14)]
        return o
    s=[a^b for a,b in zip(ct,K[10])]
    for r in range(9,0,-1):
        s=ishift(s); s=[ISBOX[b] for b in s]; s=[a^b for a,b in zip(s,K[r])]; s=imix(s)
    s=ishift(s); s=[ISBOX[b] for b in s]; s=[a^b for a,b in zip(s,K[0])]
    return bytes(s)

KEY   = os.urandom(16)
_K    = _expand(KEY)
NONCE = os.urandom(8)                       # fixed for the whole run -- the bug
SECRET = os.environ.get("FLAG", "flag{ctr_nonce_reuse_default}").encode()

def keystream(n):
    out = b""
    ctr = 0
    while len(out) < n:
        out += enc_block(NONCE + ctr.to_bytes(8, "big"), _K)
        ctr += 1
    return out[:n]
def ctr(data):
    ks = keystream(len(data))
    return bytes(a ^ b for a, b in zip(data, ks))

TOKEN = ctr(SECRET)
LIMIT = threading.BoundedSemaphore(90)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/help"): self._s(200, __doc__); return
        if u.path == "/token": self._s(200, TOKEN.hex() + "\n"); return
        if u.path == "/encrypt":
            hx = parse_qs(u.query).get("msg", [""])[0].strip()
            try: msg = bytes.fromhex(hx) if hx else b""
            except ValueError: self._s(400, "msg must be hex\n"); return
            with LIMIT:
                out = ctr(msg)
            self._s(200, out.hex() + "\n"); return
        self._s(404, "try /token or /encrypt?msg=<hex>\n")

def main():
    port = int(os.environ.get("PORT", "54323")); host = os.environ.get("HOST", "0.0.0.0")
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((host, port), H)
    print(f"CTR nonce-reuse on http://{host}:{port}/  (/token, /encrypt?msg=hex)", file=sys.stderr)
    print(f"(secret is {len(SECRET)} bytes; up to 30 concurrent)", file=sys.stderr)
    try: srv.serve_forever()
    except KeyboardInterrupt: srv.shutdown()

if __name__ == "__main__": main()
