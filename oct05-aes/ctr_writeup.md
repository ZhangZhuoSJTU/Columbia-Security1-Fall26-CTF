# CTF #3 — CTR nonce reuse

**Topic:** AES-CTR nonce reuse
**Lecture:** https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-ctr-ctf
**Files:** `ctr_server.py` (challenge), `ctr_solve.py` (intended solution)

CTR mode turns AES into a stream cipher. It encrypts a counter (a nonce plus a
block number) to get a keystream, then XORs that keystream with your message.
The server gives you two things: `/token`, which is the secret encrypted this
way, and `/encrypt`, which encrypts whatever bytes you send. Both use the same
key. They also use the same nonce, and that's the bug.

A nonce is supposed to be used once. The same (key, nonce) pair always gives the
same keystream, so the token and every one of your encryptions get XOR'd with
the exact same bytes. If you know a plaintext and see its ciphertext, XORing the
two gives you the keystream back. The easiest known plaintext is all zeros: ask
`/encrypt` for a run of `00` bytes as long as the token, and the reply *is* the
keystream.

XOR that keystream into the token and the secret comes out. One request, no key,
no brute force. AES itself was never broken. CTR is only as good as its promise
never to repeat a keystream, and this server broke that promise. The lesson: a
CTR nonce (or a stream cipher's IV) must never repeat under the same key. Reusing
it gives you the classic "two-time pad."
