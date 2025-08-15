# Arm Training-v2 - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points:
- Provided Files: Arm Training-v2(ELF)
- tools: gdb(pwndbg), checksec, ROPgadget, ghidra
## Brief Description
셸을 획득하여 /flag를 읽어주세요!
## Initial Analysis
### Environment
``` sh
checksec --file=arm_training-v2
Arch:       arm-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x10000)
Stripped:   No
```
### Code
``` c

```
## Vulnerability
## Exploit
### Strategy
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *
```