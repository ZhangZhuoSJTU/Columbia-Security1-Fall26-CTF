# CTF #4 — Double encryption, meet-in-the-middle

**Topic:** Double AES meet-in-the-middle
**Lecture:** https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-2des-ctf
**Files:** `mitm_server.py` (challenge), `mitm_solve.py` (intended solution)

If one key is good, two should be better, right? This server encrypts the secret
twice, `C = AES(k2, AES(k1, P))`, with two independent keys. To keep things
runnable, each key has only 20 bits of entropy. It is still a 16-byte AES-128
key, but 13 of those bytes are zero. You get a known plaintext/ciphertext pair
(plus a second pair to double-check with) and the double-encrypted secret.
Guessing both keys at once means 2^20 × 2^20 = 2^40 tries. That's hopeless in
Python.

You don't have to guess both at once, because the middle value can be reached
from both ends. Encrypt `P` under every possible `k1` and store each result in
a table, mapped back to its key. Then decrypt `C` under every possible `k2` and
look each result up. A hit means `AES(k1, P) == AES⁻¹(k2, C)`, so the two halves
meet in the middle and you have a candidate `(k1, k2)`. Check it against the
second known pair to rule out a false match, then decrypt the secret block by
block.

That's about 2^20 + 2^20 AES calls plus a table of 2^20 entries. It takes
minutes instead of centuries. The general lesson is that double encryption with
two n-bit keys gives you roughly n+1 bits of security, not 2n, as long as you
can afford the memory. That's why 2DES was never used and the world went
straight to 3DES.
