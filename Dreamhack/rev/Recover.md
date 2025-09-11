# Recover - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: rev
- Difficulty (subjective): easy
- Points: 1
- Provided Files: chall(ELF), encrypted
- tools: Ghidra
## Brief Description
This challenge provides chall binary, along with encrypted file.  
The chall binary encrypts the flag.png file containing the flag, then stores it as an encrypted file.  
Recover flag.png file to get the flag!  
The flag format for this challenge is DH{...}.  
## Initial Analysis
### Code
``` c
undefined8 main(void) {
  size_t sVar1;
  long in_FS_OFFSET;
  byte c;
  int idx;
  undefined *key;
  FILE *fd_flag;
  FILE *fd_encoded;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  key = &DAT_00102004; // 0xde, 0xad, 0xbe, 0xef
  fd_flag = fopen("flag.png","rb");
  if (fd_flag == (FILE *)0x0) {
    puts("fopen() error");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  fd_encoded = fopen("encrypted","wb");
  if (fd_encoded == (FILE *)0x0) {
    puts("fopen() error");
    fclose(fd_flag);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  idx = 0;
  while( true ) {
    sVar1 = fread(&c,1,1,fd_flag);
    if (sVar1 != 1) break;
    c = (c ^ key[idx % 4]) + 0x13;
    fwrite(&c,1,1,fd_encoded);
    idx = idx + 1;
  }
  fclose(fd_flag);
  fclose(fd_encoded);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
`flag.png` 파일의 데이터는 `0xDE`, `0xAD`, `0xBE`, `0xEF`라는 4바이트 키를 반복적으로 XOR 연산한 뒤, 각 바이트에 0x13을 더하는 방식으로 암호화된다. 이 과정을 역순으로 적용하면 원본 `flag.png` 파일을 복원할 수 있다.
## PoC(Poof of Concept)
``` python
key = [0xde, 0xad, 0xbe, 0xef]
with open("encrypted", "rb") as f :
    data = f.read()

result = bytearray()
for i in range(len(data)):
    val = (data[i] - 0x13) & 0xFF # overflow 방지
    val ^= key[i % 4] 
    result.append(val)

with open("flag.png", "wb") as f:
    f.write(result)
```