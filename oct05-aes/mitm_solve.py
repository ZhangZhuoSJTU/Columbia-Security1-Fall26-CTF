#!/usr/bin/env python3
"""
Reference solver for the double-encryption CTF (meet-in-the-middle).  PRIVATE.
    python3 mitm_solve.py http://localhost:54324
Recovers (k1, k2) from the known pair, then decrypts the secret.
"""
import sys, re, urllib.request

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
def aes_key(val): return bytes(13) + val.to_bytes(3, "big")

def fetch(base):
    return urllib.request.urlopen(base.rstrip("/") + "/challenge", timeout=15).read().decode()

def parse(txt):
    d = {}
    for line in txt.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1); d[k.strip()] = v.strip()
    kb = int(re.search(r"2\*\*(\d+)", txt).group(1))
    return d, kb

def mitm(P, C, P2, C2, kb):
    N = 1 << kb
    table = {}
    for k1 in range(N):                       # build from the left: E_k1(P)
        table[enc_block(P, _expand(aes_key(k1)))] = k1
    for k2 in range(N):                       # meet from the right: D_k2(C)
        k1 = table.get(dec_block(C, _expand(aes_key(k2))))
        if k1 is not None:
            K1, K2 = _expand(aes_key(k1)), _expand(aes_key(k2))
            if enc_block(enc_block(P2, K1), K2) == C2:   # confirm on 2nd pair
                return k1, k2
    return None

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:54324"
    d, kb = parse(fetch(base))
    P  = bytes.fromhex(d["known_plaintext"]);   P2 = bytes.fromhex(d["known_plaintext2"])
    C  = bytes.fromhex(d["known_ciphertext"]);  C2 = bytes.fromhex(d["known_ciphertext2"])
    CS = bytes.fromhex(d["secret_ciphertext"])
    res = mitm(P, C, P2, C2, kb)
    if not res:
        print("no key pair found"); return 1
    k1, k2 = res
    K1, K2 = _expand(aes_key(k1)), _expand(aes_key(k2))
    pt = b"".join(dec_block(dec_block(CS[i:i+16], K2), K1) for i in range(0, len(CS), 16))
    pt = pt[:-pt[-1]]
    print(f"k1 = {k1}  k2 = {k2}  (KEYBITS={kb})")
    print("flag =", pt.decode(errors="replace"))
    return 0

if __name__ == "__main__":
    sys.exit(main())
