# Challenge Name - CTF Name
## Challenge Info
- Date: YYYY-MM-DD
- CTF Name:
- Category: pwn
- Difficulty (subjective): easy
- Points:
- Provided Files: welcome(ELF)
- tools:
## Brief Description
Prove that you know how to do pwnable. flag file is in /home/pwn directory.
## Initial Analysis
### Environment
``` sh
checksec welcome
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```
### Code
``` asm
pwndbg> disassemble main
Dump of assembler code for function main:
   0x000000000040073b <+0>:     push   rbp
   0x000000000040073c <+1>:     mov    rbp,rsp
=> 0x000000000040073f <+4>:     sub    rsp,0x30
   0x0000000000400743 <+8>:     mov    eax,0x0
   0x0000000000400748 <+13>:    call   0x4006da <init>
   0x000000000040074d <+18>:    lea    rax,[rbp-0x30]
   0x0000000000400751 <+22>:    mov    edx,0x28
   0x0000000000400756 <+27>:    mov    esi,0x0
   0x000000000040075b <+32>:    mov    rdi,rax
   0x000000000040075e <+35>:    call   0x4005b0 <memset@plt>
   0x0000000000400763 <+40>:    lea    rdi,[rip+0xc2]        # 0x40082c
   0x000000000040076a <+47>:    call   0x400590 <puts@plt>
   0x000000000040076f <+52>:    lea    rax,[rbp-0x30]
   0x0000000000400773 <+56>:    mov    edx,0x40
   0x0000000000400778 <+61>:    mov    rsi,rax
   0x000000000040077b <+64>:    mov    edi,0x0
   0x0000000000400780 <+69>:    mov    eax,0x0
   0x0000000000400785 <+74>:    call   0x4005c0 <read@plt>
   0x000000000040078a <+79>:    mov    eax,0x0
   0x000000000040078f <+84>:    leave
   0x0000000000400790 <+85>:    ret
```
## Vulnerability
### puts
``` asm
0x0000000000400763 <+40>:    lea    rdi,[rip+0xc2]        # 0x40082c
0x000000000040076a <+47>:    call   0x400590 <puts@plt>
```
"Do you know pwnable?"를 출력한다.  
### memset
``` asm
0x000000000040074d <+18>:    lea    rax,[rbp-0x30]
0x0000000000400751 <+22>:    mov    edx,0x28
0x0000000000400756 <+27>:    mov    esi,0x0
0x000000000040075b <+32>:    mov    rdi,rax
0x000000000040075e <+35>:    call   0x4005b0 <memset@plt>
```
rbp-0x30에 위치한 `buf`를 0x28 크기만큼 0으로 초기화 한다.  
### BOF(Buffer Overflow)
``` asm
0x000000000040076f <+52>:    lea    rax,[rbp-0x30]
0x0000000000400773 <+56>:    mov    edx,0x40
0x0000000000400778 <+61>:    mov    rsi,rax
0x000000000040077b <+64>:    mov    edi,0x0
0x0000000000400780 <+69>:    mov    eax,0x0
0x0000000000400785 <+74>:    call   0x4005c0 <read@plt>
```
`buf`의 크기는 0x28인 반면, `read`로 읽어오는 크기는 0x40으로 0x12만큼 초과한다.  
## Exploit
### Strategy
카나리와 PIE가 비활성화 되어있어 BO
### Exploitation Steps
``` sh
pwndbg> plt
Section .plt 0x400580 - 0x4005e0:
0x400590: puts@plt
0x4005a0: system@plt
0x4005b0: memset@plt
0x4005c0: read@plt
0x4005d0: setvbuf@plt
```
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| buf | -0x30 |
### payload
``` python
from pwn import *
```
## Lessons Learned
## Mitigation Strategies(Remediation)