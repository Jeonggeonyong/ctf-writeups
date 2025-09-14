# Little ROP - idekCTF
## Challenge Info
- Date: 2025
- CTF Name: idekCTF
- Category: pwn
- Difficulty (subjective): hard
- Points:
- Provided Files: chall(ELF), flag.txt
- tools: gdb(pwndbg), checksec, ROPgadget, ghidra
## Brief Description
No PIE, no canary. Perfect setup for ROP. Show me what you can do!
## Initial Analysis
### Environment
``` sh
checksec --file=chall
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code (ghidra)
``` c
void setup(void) {
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  return;
}

void my_read(int fd,void *buf,size_t cnt) {
  read(fd,buf,cnt);
  return;
}

void vuln(void) {
  undefined buf [32]; // 0x20
  
  my_read(0,buf,0x30);
  return;
}

int main() {
    setup();
    vuln();
    return 0;
}
```
## Vulnerability
### BOF(Buffer Overflow)
``` c
void my_read(int fd,void *buf,size_t cnt) {
  read(fd,buf,cnt);
  return;
}

void vuln(void) {
  undefined buf [32]; // 0x20
  
  my_read(0,buf,0x30);
  return;
}
```
`buf`의 크기가 0x20인 반면에 `read` 함수에서 이를 초과하는 크기를 사용하여 BOF 취약점이 발생한다.  
## Exploit
### Strategy
BOF 취약점과 PIE 및 카나리 방어 기법의 비활성화는 ROP 공격에 있어 최적의 환경이다. 그러나 ASLR은 켜져있는 상태로 예상되며, libc base를 leak하기 위해 필요한 `puts`, `printf`, `write` 함수 등이 존재하지 않는다. PLT를 확인해보면 `read`, `setbuf` 이외에는 libc의 함수를 사용하지 않는다. 또한 ASLR(활성화 가정) + 랜덤 libc 주소인 상황에서 ret2libc는 확률적으로 어렵다. 내가 ghidra에서 놓치고 있는 함수가 있나 더 확인해 봤는데, 찾지 못했다. ASLR도 사실 여러번 반복하면 주소가 중복되는 경우가 생긴다(stack 세그먼트 등의 크기가 유한하기 때문에). brute-force를 활용한 문제일 수도 있다는 생각이 들기도 한다.  
### ROP gagdets
- ret: 0x000000000040101a
- pop rdi; let: 0x000000000002a3e5
- pop rsi; let: 0x000000000002be51
- pop rdx; pop r12; ret: 0x000000000011f497
### Stack Frame of vuln
| Variable Name | Offset from EBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| buf | -0x20 |
### payload
``` python
from pwn import *
```