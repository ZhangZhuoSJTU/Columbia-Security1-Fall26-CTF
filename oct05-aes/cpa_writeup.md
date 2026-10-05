# CTF #5 — IND-CPA with a chained IV

**Topic:** CBC predictable IV (IND-CPA game)
**Lecture:** https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-cpa-ctf
**Files:** `cpa_server.py` (challenge), `cpa_solve.py` (intended solution)

This time you don't recover a secret directly. You have to *win the IND-CPA game*.
You pick two messages `m0` and `m1` of the same length. The server flips a coin,
encrypts one of them, and you guess which. One correct guess could be luck, so
you need 20 in a row. A blind guesser manages that about once in a million
tries. You also get an encryption oracle, `/encrypt`, for free.

The scheme looks fine at first. It's AES-CBC, and the same message encrypts to
different bytes every time, so it isn't deterministic like ECB. But look at
where the IV comes from. After the first message, each IV is the *last
ciphertext block of the previous message*. TLS 1.0 did the same thing. That
block was just sent to you, so you always know the next IV before it's used. And
in CBC, the first block of ciphertext is `E_K(m[0:16] XOR IV)`.

So make that XOR come out to zero. Send `/encrypt` a message equal to the next
IV, and the first ciphertext block is `E_K(0)`. Write that down as `T`. In each
round, set `m0` to the IV that's coming next, so `m0 XOR IV = 0`. Set `m1` to
anything else of the same length. If the challenge's first block equals `T`, the
server picked `m0`. Otherwise it picked `m1`. That's twenty correct guesses and
the flag. Randomizing ciphertexts isn't enough for CBC. Its IV has to be
*unpredictable* to an attacker, and this exact predictable-IV flaw is what the
BEAST attack exploited against TLS 1.0.
