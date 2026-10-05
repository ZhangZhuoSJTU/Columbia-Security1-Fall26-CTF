#!/usr/bin/env python3
"""
IND-CPA game solution (chained-IV CBC).  NOT for the repo.

    python3 cpa_solve.py http://localhost:54325

The scheme is randomized, but the IV of the next message is the last block of
the previous ciphertext, which the server just handed us. So we always know
the IV before it is used. CBC's first block is E_K(m[0:16] XOR IV), so:

  1. once:  send msg = IV_next  -> first block of the reply is E_K(0), call it T
  2. each round: m0 = IV_next (so m0 XOR IV_next = 0), m1 = anything else of
     the same length. The challenge's first block equals T exactly when b = 0.

Twenty rounds, twenty correct guesses, flag. This is the BEAST-style
predictable-IV break from the "IV must be unpredictable" slide.
"""
import sys, random, urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:54325"
SID  = "solve-%012x" % random.getrandbits(48)

def get(path):
    url = f"{BASE}{path}&s={SID}"
    last = None
    for _ in range(5):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return bytes.fromhex(r.read().decode().strip().split()[0]) if "/guess" not in path \
                       else r.read().decode().strip()
        except Exception as e:
            last = e
    raise last

def get_text(path):
    url = f"{BASE}{path}&s={SID}"
    with urllib.request.urlopen(url, timeout=10) as r:
        return r.read().decode().strip()

def main():
    # step 0: any message, just to learn the chain. reply = IV || C ; next IV = C[-16:]
    r = get("/encrypt?msg=" + "00" * 16)
    iv_next = r[-16:]

    # step 1: learn T = E_K(0) by making the first block's input zero
    r = get("/encrypt?msg=" + iv_next.hex())
    assert r[:16] == iv_next, "IV prediction failed"
    T = r[16:32]
    iv_next = r[-16:]
    print("[*] T = E_K(0) =", T.hex())

    # step 2: play
    while True:
        m0 = iv_next                                   # m0 XOR IV = 0  -> first block = T if b = 0
        m1 = bytes([x ^ 0xff for x in iv_next])        # anything else, same length
        r = get(f"/challenge?m0={m0.hex()}&m1={m1.hex()}")
        assert r[:16] == iv_next, "IV prediction failed"
        b = 0 if r[16:32] == T else 1
        iv_next = r[-16:]
        res = get_text("/guess?b=%d" % b)
        print("[*]", res)
        if "flag{" in res or "reached" in res:
            break

if __name__ == "__main__":
    main()
