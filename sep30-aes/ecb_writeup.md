# CTF #1 — ECB byte-at-a-time

**Topic:** AES-ECB byte oracle
**Lecture:** https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-ecb-ctf
**Files:** `ecb_server.py` (challenge), `ecb_solve.py` (intended solution)

The server does something that looks harmless: you hand it some bytes, and it
hands back the encryption of *your bytes followed by the secret flag*, all under
AES in ECB mode. The key never leaves the server. So how do you read the flag?

The trick is that ECB is a lookup table in disguise. It chops the message into
16-byte blocks and encrypts each one independently, so the *same* plaintext block
always produces the *same* ciphertext block. That determinism is the whole game.

Feed it exactly 15 bytes of filler. Now the first ciphertext block covers your 15
bytes plus the very first byte of the flag, which you don't know yet. But you can
just try all 256 possibilities: send "15 filler bytes + one guess" and see which
guess reproduces that block. When it matches, you've learned the flag's first
byte. Shift the window by one, and repeat. The flag falls out one letter at a
time. No key, no math, just the fact that ECB can't keep a secret about which
blocks are equal.
