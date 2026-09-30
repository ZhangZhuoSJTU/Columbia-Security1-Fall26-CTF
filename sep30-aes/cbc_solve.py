#!/usr/bin/env python3
"""
CBC padding-oracle solution.  NOT for the repo.

    python3 cbc_solve.py http://localhost:54322

Fetch the token (IV || C1 || C2 || ...). For each ciphertext block C_i, use
the padding oracle on a forged [C'_prev || C_i] to recover the intermediate
state D_K(C_i) one byte at a time, then XOR with the real previous block to
get the plaintext. Standard padding-oracle attack; no key needed.
"""
import sys, urllib.request, concurrent.futures as cf

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:54322"
BS = 16

def get(path):
    for _ in range(5):
        try:
            with urllib.request.urlopen(f"{BASE}{path}", timeout=10) as r:
                return r.read().decode().strip()
        except Exception as e:
            last = e
    raise last

def valid(ct: bytes) -> bool:
    return get("/verify?ct=" + ct.hex()) == "valid"

def recover_block(prev: bytes, cur: bytes) -> bytes:
    """Recover the 16 intermediate bytes I = D_K(cur)."""
    inter = bytearray(16)
    for pad in range(1, 17):
        pos = BS - pad
        # build the suffix of the forged previous block that yields padding=pad
        suffix = bytes(inter[k] ^ pad for k in range(pos + 1, BS))
        # find the byte at pos that makes valid padding
        def test(g):
            forged = bytes(16 - pad) + bytes([g]) + suffix
            return g, valid(forged + cur)
        hit = None
        with cf.ThreadPoolExecutor(max_workers=30) as ex:
            for g, ok in ex.map(test, range(256)):
                if ok:
                    # guard against the false hit where existing bytes already pad
                    forged = bytes(16 - pad) + bytes([g]) + suffix
                    if pad == 1:
                        # confirm by flipping the second-last byte
                        f2 = bytearray(forged); f2[BS-2] ^= 0xff
                        if not valid(bytes(f2) + cur):
                            continue
                    hit = g
        inter[pos] = hit ^ pad
    return bytes(inter)

def main():
    token = bytes.fromhex(get("/token"))
    iv, ct = token[:BS], token[BS:]
    blocks = [iv] + [ct[i:i+BS] for i in range(0, len(ct), BS)]
    pt = b""
    for i in range(1, len(blocks)):
        inter = recover_block(blocks[i-1], blocks[i])
        pt += bytes(a ^ b for a, b in zip(inter, blocks[i-1]))
        print(f"\r[*] {pt}", end="", flush=True)
    # strip PKCS#7
    pad = pt[-1]
    print(f"\n[+] recovered: {pt[:-pad].decode(errors='replace')}")

if __name__ == "__main__":
    main()
