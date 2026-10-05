#!/usr/bin/env python3
"""
Double-encryption (meet-in-the-middle) challenge server  --  Security I, Fall 26, Columbia

The secret is encrypted TWICE with two independent keys:

    C = AES(k2, AES(k1, P))          # ECB, one AES-128 block at a time

To keep it runnable, each key has only 20 bits of entropy, laid out as a
16-byte AES-128 key:  KEY = 13 zero bytes || 3-byte value, with value < 2**20.
Brute-forcing BOTH keys is 2**20 * 2**20 = 2**40 -- hopeless. But you do not
have to. Goal: recover the two keys from the known pair, then decrypt SECRET.

Two endpoints:

    GET /aes.py      ->   AES-128 in pure Python, ready to import:
                          make_key(v), encrypt(key, block), decrypt(key, block)
    GET /challenge   ->   the hex values (labeled), the whole challenge:
        known_plaintext   = P    (a fixed, public 16-byte block)
        known_plaintext2  = P2   (a second known block, to rule out false hits)
        known_ciphertext  = C  = AES(k2, AES(k1, P))
        known_ciphertext2 = C2 = AES(k2, AES(k1, P2))
        secret_ciphertext = AES(k2, AES(k1, .)) over PKCS#7-padded SECRET, ECB
"""
import os, sys, threading, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# shared AES-128 core (embedded verbatim, identical to the other mode-CTF servers)
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
# ---------------------------------------------------------------------------
KEYBITS = int(os.environ.get("KEYBITS", "20"))
assert 1 <= KEYBITS <= 24, "KEYBITS must be 1..24 (3-byte value field)"

def aes_key(val):
    """A 16-byte AES-128 key carrying `val` bits of entropy: 13 zero bytes then
    a 3-byte big-endian value.  Students are told this exact format."""
    return bytes(13) + val.to_bytes(3, "big")

def pkcs7(b, bs=16):
    n = bs - (len(b) % bs)
    return b + bytes([n]) * n

# two independent keys, fresh every run
_k1 = int.from_bytes(os.urandom(3), "big") % (1 << KEYBITS)
_k2 = int.from_bytes(os.urandom(3), "big") % (1 << KEYBITS)
_K1 = _expand(aes_key(_k1))
_K2 = _expand(aes_key(_k2))

def enc2(block):                                   # C = AES(k2, AES(k1, block))
    return enc_block(enc_block(block, _K1), _K2)

def enc2_ecb(data):
    return b"".join(enc2(data[i:i+16]) for i in range(0, len(data), 16))

# a fixed, public known plaintext, plus a second block to rule out false hits
P  = b"COMSW4181-MITM!!"                            # exactly 16 bytes
P2 = b"double.encrypt00"                            # exactly 16 bytes
assert len(P) == 16 and len(P2) == 16

C  = enc2(P)
C2 = enc2(P2)
SECRET = os.environ.get("FLAG", "flag{mitm_double_enc_default}").encode()
CSTAR  = enc2_ecb(pkcs7(SECRET))

CHALLENGE = (
    "known_plaintext   = " + P.hex()   + "\n"
    "known_plaintext2  = " + P2.hex()  + "\n"
    "known_ciphertext  = " + C.hex()   + "\n"
    "known_ciphertext2 = " + C2.hex()  + "\n"
    "secret_ciphertext = " + CSTAR.hex() + "\n"
    "# key format: AES-128 key = 13 zero bytes || 3-byte value, value < 2**%d\n" % KEYBITS +
    "# C = AES(k2, AES(k1, P)); secret is PKCS#7-padded then ECB double-encrypted\n"
)

# /aes.py: the AES core above, cut out of this very file, plus a small API
_src = open(os.path.abspath(__file__)).read()
_core = re.search(r"(# shared AES-128 core.*?)\n# -{20,}", _src, re.S).group(1)
AES_PY = (
    '"""AES-128, pure Python (the same code the CTF #4 server runs).\n\n'
    '    from aes import make_key, encrypt, decrypt\n'
    '    k = make_key(12345)            # 13 zero bytes || 3-byte value\n'
    '    c = encrypt(k, p)              # p: exactly 16 bytes\n'
    '    assert decrypt(k, c) == p\n\n'
    'Each call expands the key; in a hot loop over one key, call\n'
    'expand_key(k) once and use enc_block(block, K) / dec_block(block, K).\n'
    '"""\n'
    + _core + "\n\n"
    "def expand_key(key):\n"
    "    assert len(key) == 16, 'AES-128 key is 16 bytes'\n"
    "    return _expand(key)\n\n"
    "def make_key(v):\n"
    "    \"\"\"The CTF #4 key format: 13 zero bytes, then v as 3 big-endian bytes.\"\"\"\n"
    "    return bytes(13) + v.to_bytes(3, 'big')\n\n"
    "def encrypt(key, block):\n"
    "    assert len(block) == 16, 'one AES block is 16 bytes'\n"
    "    return enc_block(block, _expand(key))\n\n"
    "def decrypt(key, block):\n"
    "    assert len(block) == 16, 'one AES block is 16 bytes'\n"
    "    return dec_block(block, _expand(key))\n\n"
    "if __name__ == '__main__':          # FIPS-197 test vector\n"
    "    k = bytes(range(16)); p = bytes.fromhex('00112233445566778899aabbccddeeff')\n"
    "    c = encrypt(k, p)\n"
    "    assert c.hex() == '69c4e0d86a7b0430d8cdb78070b4c55a' and decrypt(k, c) == p\n"
    "    print('aes.py OK')\n"
)

LIMIT = threading.BoundedSemaphore(90)

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/help"): self._s(200, __doc__); return
        if u.path == "/aes.py":
            with LIMIT:
                self._s(200, AES_PY); return
        if u.path == "/challenge":
            with LIMIT:
                self._s(200, CHALLENGE); return
        self._s(404, "try /challenge or /aes.py\n")

def main():
    port = int(os.environ.get("PORT", "54324")); host = os.environ.get("HOST", "0.0.0.0")
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((host, port), H)
    print(f"double-encryption MITM on http://{host}:{port}/  (/challenge, /aes.py)  KEYBITS={KEYBITS}", file=sys.stderr)
    try: srv.serve_forever()
    except KeyboardInterrupt: pass

if __name__ == "__main__":
    main()
