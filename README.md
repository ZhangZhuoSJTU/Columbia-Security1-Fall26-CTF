# Security I — In-Class CTF (Fall 2026)

Capture-the-flag challenges for **COMS Security I**, Columbia, Fall 2026.

Each challenge is a small self-contained server tied to a lecture topic. We add
new ones as the course moves forward, so this list grows over the semester. A
solver script lives next to every server for reference (these are *not* meant to
be handed out before the challenge is retired).

## Challenges

| #  | Topic                  | Lecture link                                                                          | Write-up                                    | Files                                               |
|----|------------------------|---------------------------------------------------------------------------------------|---------------------------------------------|-----------------------------------------------------|
| 1  | AES-ECB byte oracle    | [ECB CTF](https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-ecb-ctf)   | [ecb_writeup.md](sep30-aes/ecb_writeup.md)  | `sep30-aes/ecb_server.py`, `sep30-aes/ecb_solve.py` |
| 2  | AES-CBC padding oracle | [CBC CTF](https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-cbc-ctf)   | [cbc_writeup.md](sep30-aes/cbc_writeup.md)  | `sep30-aes/cbc_server.py`, `sep30-aes/cbc_solve.py` |

## Running a challenge

Each server is plain Python 3 with no dependencies (AES is implemented from
scratch inside the file). Set the flag through the environment and run it:

```bash
FLAG='flag{your_flag_here}' python3 sep30-aes/ecb_server.py   # serves on :54321
FLAG='flag{your_flag_here}' python3 sep30-aes/cbc_server.py   # serves on :54322
```

Point the matching solver at it to check the intended solution works:

```bash
python3 sep30-aes/ecb_solve.py http://localhost:54321
python3 sep30-aes/cbc_solve.py http://localhost:54322
```

## Write-ups

Each challenge has its own write-up, kept next to that challenge's server and
solver:

- CTF #1 — ECB byte-at-a-time: [`sep30-aes/ecb_writeup.md`](sep30-aes/ecb_writeup.md)
- CTF #2 — CBC padding oracle: [`sep30-aes/cbc_writeup.md`](sep30-aes/cbc_writeup.md)
