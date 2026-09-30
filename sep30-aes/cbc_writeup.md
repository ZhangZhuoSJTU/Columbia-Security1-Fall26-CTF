# CTF #2 — CBC padding oracle

**Topic:** AES-CBC padding oracle
**Lecture:** https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-cbc-ctf
**Files:** `cbc_server.py` (challenge), `cbc_solve.py` (intended solution)

This one is sneakier, because the server barely tells you anything. You get a
token (an IV plus the CBC-encrypted secret), and a `/verify` endpoint that
answers a single yes/no question: does this ciphertext decrypt to something with
valid PKCS#7 padding? That's it. One bit of information. It feels like nothing.

But that one bit is enough to recover the entire secret without the key. In CBC,
each plaintext byte is the decrypted block XOR'd with the previous ciphertext
block, and the previous block is under your control. So you forge a previous
block and tamper with its last byte until the server says "valid" — which almost
always means you've forced the last decrypted byte to be `0x01`, a legal
one-byte pad. From that success you can algebra out the real intermediate value,
and then the real plaintext byte.

Then you go for a two-byte pad (`0x02 0x02`), then three, and so on, peeling off
one byte per position, block by block, all the way back through the message. The
server thinks it's just checking padding. It's actually reading you the secret,
one reluctant bit at a time. The lesson: never let an error message (or a timing
difference, or *any* observable difference) leak whether padding was correct.
