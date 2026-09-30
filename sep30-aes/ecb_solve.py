#!/usr/bin/env python3
"""
Solution to the byte-at-a-time ECB CTF.  NOT part of the course repo.

    python3 solve.py http://localhost:54321

Idea: the server returns AES-ECB(KEY, our_prefix || FLAG).  ECB encrypts
each 16-byte block on its own and deterministically, so if we choose a
prefix that leaves exactly ONE unknown flag byte at the end of a block,
we can brute-force that byte (<=256 tries) by matching ciphertext blocks.
Slide the window and the whole flag falls out.
"""
import sys, urllib.request, concurrent.futures as cf

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:54321"

def oracle(prefix: bytes) -> bytes:
    url = f"{BASE}/oracle?prefix={prefix.hex()}"
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return bytes.fromhex(r.read().decode().strip())
        except Exception:
            if attempt == 4:
                raise
    

BS = 16
def block(ct, i): return ct[i*BS:(i+1)*BS]

def flag_len():
    base = len(oracle(b""))
    for i in range(1, BS + 1):
        n = len(oracle(b"A" * i))
        if n > base:
            return base - i          # base = padded len; subtract the pad we added
    return base

def main():
    n = flag_len()
    print(f"[*] flag is {n} bytes")
    known = b""
    for i in range(n):
        pad = b"A" * (BS - 1 - (i % BS))
        blk = (len(pad) + len(known)) // BS
        target = block(oracle(pad), blk)
        # try all 256 candidates for the next byte, in parallel
        def try_byte(g):
            guess = pad + known + bytes([g])
            return g, block(oracle(guess), blk)
        found = None
        with cf.ThreadPoolExecutor(max_workers=30) as ex:
            for g, cblk in ex.map(try_byte, range(256)):
                if cblk == target:
                    found = g
        if found is None:
            break                    # ran into padding; done
        known += bytes([found])
        print(f"\r[*] {known.decode(errors='replace')}", end="", flush=True)
    print(f"\n[+] recovered: {known.decode(errors='replace')}")

if __name__ == "__main__":
    main()
