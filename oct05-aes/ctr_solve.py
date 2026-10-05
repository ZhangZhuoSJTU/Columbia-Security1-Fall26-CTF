#!/usr/bin/env python3
"""
CTR nonce-reuse solution.  NOT for the repo.

    python3 ctr_solve.py http://localhost:54323

The /encrypt endpoint reuses the same keystream as /token. Encrypt a run of
zero bytes as long as the token: the ciphertext of zeros IS the keystream.
XOR it into the token to recover SECRET.
"""
import sys, urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:54323"
def get(path):
    for _ in range(5):
        try:
            with urllib.request.urlopen(f"{BASE}{path}", timeout=10) as r:
                return r.read().decode().strip()
        except Exception as e:
            last = e
    raise last

def main():
    token = bytes.fromhex(get("/token"))
    zeros = "00" * len(token)                       # encrypt zeros of the same length
    keystream = bytes.fromhex(get("/encrypt?msg=" + zeros))
    secret = bytes(a ^ b for a, b in zip(token, keystream))
    print("[+] recovered:", secret.decode(errors="replace"))

if __name__ == "__main__":
    main()
