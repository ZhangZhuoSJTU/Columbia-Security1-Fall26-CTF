# Security I: In-Class CTF (Fall 2026)

Capture-the-flag challenges for **[COMS W4181 Security I](https://zzhang.xyz/teaching/security1-fall26/index.html)**, Columbia, Fall 2026.

Each challenge is tied to a lecture topic. We add new ones as the course moves forward, so this list grows over the semester. A solver script lives next to every server for reference.

## Challenges

| #  | Topic                         | Lecture link                                                                           | Write-up                                     | Files                                                 |
|----|-------------------------------|----------------------------------------------------------------------------------------|----------------------------------------------|-------------------------------------------------------|
| 1  | AES-ECB byte oracle           | [ECB CTF](https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-ecb-ctf)    | [ecb_writeup.md](sep30-aes/ecb_writeup.md)   | `sep30-aes/ecb_server.py`, `sep30-aes/ecb_solve.py`   |
| 2  | AES-CBC padding oracle        | [CBC CTF](https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-cbc-ctf)    | [cbc_writeup.md](sep30-aes/cbc_writeup.md)   | `sep30-aes/cbc_server.py`, `sep30-aes/cbc_solve.py`   |
| 3  | AES-CTR nonce reuse           | [CTR CTF](https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-ctr-ctf)    | [ctr_writeup.md](oct05-aes/ctr_writeup.md)   | `oct05-aes/ctr_server.py`, `oct05-aes/ctr_solve.py`   |
| 4  | Double AES meet-in-the-middle | [2DES CTF](https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-2des-ctf)  | [mitm_writeup.md](oct05-aes/mitm_writeup.md) | `oct05-aes/mitm_server.py`, `oct05-aes/mitm_solve.py` |
| 5  | CBC predictable IV (IND-CPA)  | [CPA CTF](https://zzhang.xyz/teaching/security1-fall26/lectures/crypto/#/s-cpa-ctf)    | [cpa_writeup.md](oct05-aes/cpa_writeup.md)   | `oct05-aes/cpa_server.py`, `oct05-aes/cpa_solve.py`   |
