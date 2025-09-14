# addition - Imaginary
## Challenge Info
- Date: 2025
- CTF Name: Imaginary
- Category: pwn
- Difficulty (subjective): easy
- Points: 100
- Provided Files: vuln(ELF)
- tools:
## Brief Description
i love addition
## Initial Analysis
### Environment
``` sh
checksec addition
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code
``` c
void main(void) {
    longlong lVar1;
    longlong lVar2;
    long in_FS_OFFSET;
    char buf [24];
    undefined8 canary;

    canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
    setbuf(stdin,(char *)0x0);
    setbuf(stdout,(char *)0x0);
    setbuf(stderr,(char *)0x0);
    puts("+++++++++++++++++++++++++++");
    puts("    WELCOME TO ADDITION");
    puts("+++++++++++++++++++++++++++");
    do {
    write(1,"add where? ",0xb);
    fgets(buf,0x10,stdin);
    lVar1 = atoll(buf);
    write(1,"add what? ",10);
    fgets(buf,0x10,stdin);
    lVar2 = atoll(buf);
    *(longlong *)(&::buf + lVar1) = lVar2 + *(long *)(&::buf + lVar1); 
    } while (lVar1 != 0x539);
    FUN_001010f0(0);
                    /* WARNING: Bad instruction - Truncating control flow here */
    halt_baddata();
}
```
``` asm
   0x00005555555552eb <+258>:   mov    QWORD PTR [rbp-0x28],rax
   0x00005555555552ef <+262>:   lea    rdx,[rip+0x2d73]        # 0x555555558069
   0x00005555555552f6 <+269>:   mov    rax,QWORD PTR [rbp-0x30]
   0x00005555555552fa <+273>:   add    rax,rdx
   0x00005555555552fd <+276>:   mov    rcx,QWORD PTR [rax]
   0x0000555555555300 <+279>:   lea    rdx,[rip+0x2d62]        # 0x555555558069
   0x0000555555555307 <+286>:   mov    rax,QWORD PTR [rbp-0x30]
   0x000055555555530b <+290>:   add    rax,rdx
   0x000055555555530e <+293>:   mov    rdx,QWORD PTR [rbp-0x28]
   0x0000555555555312 <+297>:   add    rdx,rcx
   0x0000555555555315 <+300>:   mov    QWORD PTR [rax],rdx
   0x0000555555555318 <+303>:   cmp    QWORD PTR [rbp-0x30],0x539
   0x0000555555555320 <+311>:   je     0x555555555327 <main+318>
   0x0000555555555322 <+313>:   jmp    0x55555555526d <main+132>
   0x0000555555555327 <+318>:   nop
   0x0000555555555328 <+319>:   mov    edi,0x0
   0x000055555555532d <+324>:   call   0x5555555550f0
```
## Vulnerability
### OOB(Out of Bounds)
## Exploit
### Strategy
OOB를 이용해서 `buf` 상위 메모리를 덮어쓸 수 있다. 단, 해당 위치에 존재하는 값과 내가 입력한 값을 더한 값을 덮어쓴다. onegadget을 이용할 경우, 크기가 충분히 크기 때문에 적절한 값을 입력해서 주소를 맞춰야 한다.
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| canary | -0x8 |
| bub | -0x20 |
| lVar2 | -0x28 |
| lVar1 | -x30 |
### payload
``` python
from pwn import *
```
