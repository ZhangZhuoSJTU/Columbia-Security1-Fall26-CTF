#!/usr/bin/env python3
"""
IND-CPA distinguishing-game challenge server  --  Security I, Fall 26, Columbia

You play the IND-CPA game against a scheme we built, and you must WIN it:
not once by luck, but 20 times in a row.

The scheme (public, as it should be):

    AES-128-CBC with PKCS#7 padding. Every reply is  IV || C  as hex.
    The IV of your FIRST message in a game is random. After that, the IV of
    each message is the LAST CIPHERTEXT BLOCK of the previous message in the
    same game (this is how TLS 1.0 chained its IVs). So the same message
    encrypts to different bytes every time -- it is NOT deterministic.

Three game endpoints. Add  &s=<any id you pick>  to every request so you keep your
own game (without it the game is keyed to your IP, which breaks on shared NAT):

    GET /encrypt?msg=<hex>&s=ID             -> IV || E(your bytes)       (the CPA oracle)
    GET /challenge?m0=<hex>&m1=<hex>&s=ID   -> IV || E(m_b), b a fresh secret bit
                                               (m0 and m1 must have the same length)
    GET /guess?b=<0|1>&s=ID                 -> checks your guess for the last challenge
    GET /source                             -> this server's full source code

A correct guess grows your streak by one; a wrong guess resets it to 0.
A streak of 20 returns the flag. A blind guesser has a 2**-20 chance, about
one in a million, so you need an attack, not luck. Goal: write a program
that reaches streak 20 and prints the flag.
"""
import os, sys, time, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

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

KEY = os.urandom(16)
_K  = _expand(KEY)
SECRET = os.environ.get("FLAG", "flag{cpa_chained_iv_default}").encode()
TARGET = 20                                  # consecutive correct guesses to win
MAXLEN = 256                                 # bytes per message

def _pad(msg):                               # PKCS#7 to a 16-byte boundary
    n = 16 - (len(msg) % 16)
    return msg + bytes([n]) * n

def cbc(iv, msg):                            # AES-128-CBC, returns IV || C
    data = _pad(msg)
    out, prev = b"", iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
        prev = enc_block(blk, _K)
        out += prev
    return iv + out

# per-player game state: sid -> {"streak": int, "b": int|None, "iv": bytes, "seen": float}
GAMES = {}
GLOCK = threading.Lock()
LIMIT = threading.BoundedSemaphore(90)

def _sid(u, handler):
    s = parse_qs(u.query).get("s", [""])[0].strip()
    return s[:64] if s else "ip:" + handler.client_address[0]

def _game(sid):
    g = GAMES.get(sid)
    if g is None:
        if len(GAMES) > 5000:                # drop the oldest if the table grows
            old = min(GAMES, key=lambda k: GAMES[k]["seen"])
            GAMES.pop(old, None)
        g = {"streak": 0, "b": None, "iv": os.urandom(16), "seen": time.time()}
        GAMES[sid] = g
    g["seen"] = time.time()
    return g

def _encrypt_in_game(g, msg):
    """CBC with the chained IV: this message's IV is the previous ciphertext's last block."""
    out = cbc(g["iv"], msg)
    g["iv"] = out[-16:]                      # the bug: the next IV is public before it is used
    return out

def _hex_arg(q, name):
    hx = q.get(name, [""])[0].strip()
    msg = bytes.fromhex(hx) if hx else b""   # may raise ValueError
    return msg

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _s(self, code, body):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code); self.send_header("Content-Type","text/plain")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query)
        if u.path in ("/", "/help"):
            self._s(200, __doc__); return

        if u.path == "/source":              # the key and flag are never in the file
            with open(os.path.abspath(__file__), "rb") as f:
                self._s(200, f.read())
            return

        if u.path == "/encrypt":
            try: msg = _hex_arg(q, "msg")
            except ValueError: self._s(400, "msg must be hex\n"); return
            if not msg or len(msg) > MAXLEN:
                self._s(400, f"msg must be 1..{MAXLEN} bytes of hex\n"); return
            sid = _sid(u, self)
            with LIMIT, GLOCK:
                out = _encrypt_in_game(_game(sid), msg)
            self._s(200, out.hex() + "\n"); return

        if u.path == "/challenge":
            try: m0, m1 = _hex_arg(q, "m0"), _hex_arg(q, "m1")
            except ValueError: self._s(400, "m0 and m1 must be hex\n"); return
            if not m0 or not m1 or len(m0) > MAXLEN or len(m1) > MAXLEN:
                self._s(400, f"m0 and m1 must each be 1..{MAXLEN} bytes of hex\n"); return
            if len(m0) != len(m1):
                self._s(400, "m0 and m1 must have the same length\n"); return
            sid = _sid(u, self)
            with LIMIT, GLOCK:
                g = _game(sid)
                g["b"] = int.from_bytes(os.urandom(1), "big") & 1   # fresh secret bit
                out = _encrypt_in_game(g, m0 if g["b"] == 0 else m1)
            self._s(200, out.hex() + "\n"); return

        if u.path == "/guess":
            raw = q.get("b", [""])[0].strip()
            if raw not in ("0", "1"):
                self._s(400, "b must be 0 or 1\n"); return
            guess = int(raw); sid = _sid(u, self)
            with GLOCK:
                g = _game(sid)
                if g["b"] is None:
                    self._s(409, "no pending challenge; call /challenge first\n"); return
                correct = (guess == g["b"])
                g["b"] = None                         # one guess per challenge
                if correct:
                    g["streak"] += 1
                    if g["streak"] >= TARGET:
                        g["streak"] = 0
                        self._s(200, "correct -- streak %d/%d reached! %s\n"
                                % (TARGET, TARGET, SECRET.decode())); return
                    msg = "correct -- streak %d/%d\n" % (g["streak"], TARGET)
                else:
                    g["streak"] = 0
                    msg = "wrong -- streak reset to 0/%d\n" % TARGET
            self._s(200, msg); return

        self._s(404, "try /help, /encrypt?msg=hex, /challenge?m0=hex&m1=hex, /guess?b=0|1  (all with &s=ID), /source\n")

def main():
    port = int(os.environ.get("PORT", "54325")); host = os.environ.get("HOST", "0.0.0.0")
    ThreadingHTTPServer.daemon_threads = True
    srv = ThreadingHTTPServer((host, port), H)
    print(f"IND-CPA game on http://{host}:{port}/  (/encrypt, /challenge, /guess, /source)", file=sys.stderr)
    print(f"(win = {TARGET} correct in a row; CBC with a chained, predictable IV)", file=sys.stderr)
    try: srv.serve_forever()
    except KeyboardInterrupt: srv.shutdown()

if __name__ == "__main__": main()
