# flag printer - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: rev
- Difficulty (subjective): easy
- Points: 1 
- Provided Files: flag-printer(ELF)
- tools: Ghidra
## Brief Description
Simple Flag Printer
## Initial Analysis
### Environment
ELF64
### Code
``` c
// main
void main(void) {
  ulong menuNum;
  long in_FS_OFFSET;
  int lowMenuNum;
  undefined4 highMenuNum;
  char buf [72];
  undefined8 canary;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf();
  menu();
  do {
    while( true ) {
      while( true ) {
        printf("> ");
        fgets(buf,0x40,stdin);
        menuNum = getMenuNum(buf); // 입력값 검증 및 메뉴 번호 리턴
        lowMenuNum = (int)menuNum;
        if (lowMenuNum != 2) break;
        help(); // help 기능
      }
      if (lowMenuNum < 3) break;
LAB_00101395:
      puts("Invalid Command!"); // 예외 처리
    }
    highMenuNum = (undefined4)(menuNum >> 0x20);
    if (lowMenuNum == 0) {
      print(highMenuNum); // print 기능
    }
    else {
      if (lowMenuNum != 1) goto LAB_00101395;
      id(highMenuNum); // id 기능
    }
  } while( true );
}
```
사용자에게 다음의 3가지 기능을 제공한다.  
- print
- id
- help

사용자로부터 `print`, `id`, `help` 중에서 입력을 `buf`로 받는다. 이후 `getMenuNum()`에서 입력 값을 검증한 후 메뉴 번호를 받아온다. 받아온 64비트 크기의 메뉴 번호에서 하위 32비트를 기준으로 번호에 맞는 기능(함수)을 동작한다. `print()` 함수의 인자로는 상위 32비트를 전달한다.  
``` c
// print
void print(int highMenuNum) {
  int iVar1;
  char *__filename;
  FILE *__stream;
  
  if (highMenuNum == 0) {
    __filename = "./art";
  }
  else {
    __filename = "./flag";
  }
  __stream = fopen(__filename,"r");
  while( true ) {
    iVar1 = getc(__stream);
    if ((char)iVar1 == -1) break;
    putchar((int)(char)iVar1);
  }
  fclose(__stream);
  putchar(10);
  return;
}
```
전달 받은 메뉴 번호의 상위 32비트가 0이 아니면 FLAG를 출력한다.  
``` c
// getMenuNum
ulong getMenuNum(char *buf) {
  int cmpVal;
  size_t sVar1;
  char *__s1;
  ulong menuNum;
  long in_FS_OFFSET;
  uint switchVal;
  int idx;
  char *token;
  char encoded [5];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  switchVal = 0;
  sVar1 = strcspn(buf,"\n"); // "\n" 문자가 위치한 인덱스 반환
  buf[sVar1] = '\0';
  token = strtok(buf," ");
  do {
    if (token == (char *)0x0) {
      menuNum = (ulong)switchVal << 0x20 | 0xffffffff; // 하위 32비트를 상위 32비트로 이동 후 하위 32비트를 1로 초기화
LAB_00101656:
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return menuNum;
    }
    cmpVal = strcmp(token,"print");
    if (cmpVal == 0) {
      menuNum = (ulong)switchVal << 0x20; // 0으로 초기화
      goto LAB_00101656;
    }
    cmpVal = strcmp(token,"id");
    if (cmpVal == 0) {
      menuNum = (ulong)switchVal << 0x20 | 1; // 1로 초기화
      goto LAB_00101656;
    }
    cmpVal = strcmp(token,"help");
    if (cmpVal == 0) {
      menuNum = (ulong)switchVal << 0x20 | 2; // 2로 초기화
      goto LAB_00101656;
    }
    __s1 = strdup(token); // token 문자열 크기만큼 새로운 동적 메모리 할당 후 token 복사
    idx = 0;
    while (__s1[idx] != '\0') {
      __s1[idx] = __s1[idx] ^ 0x42; // __s1[idx] xor 66로 인코딩
      idx = idx + 1;
    }
    builtin_strncpy(encoded,"&-17",5); // encoded에 "&-17" 복사
    cmpVal = strcmp(__s1,encoded); // 인코딩된 __s1과 "&-17" 비교
    if (cmpVal != 0) {
      free(__s1);
      menuNum = (ulong)switchVal << 0x20 | 0xffffffff;
      goto LAB_00101656;
    }
    switchVal = 1; 
    token = strtok((char *)0x0," "); // 한 번 더 strtok 
    free(__s1);
  } while( true );
}
```
`token`이 NULL이 되면 메뉴 번호의 하위 32비트가 1로 초기화 된다.  
`swutchVal`이 초기화 되는 값(0, 1)에 따라 `main()`에 반환하는 메뉴 상위 32비트가 0 또는 1이 된다. 즉, `1`로 초기화하기 위해서는 `__s1`(사용자 초기 4byte 입력)이 인코딩 과정을 거친 후 `"&-17"`이 되어야 하며, 하위 32비트 또한 `print()`를 트리거 하기 위해 0으로 초기화 되어야 한다.  
## PoC(Poof of Concept)
`"&-17"`는 아스키코드에서 10진수로 변환하면 `38 45 49 55`이 나온다. 여기에 `xor 66` 인코딩을 하면 `100 111 115 117` 즉, `"dosu"`가 나온다. 하위 32비트 또한 `print()` 트리거를 위해서 0으로 초기화 되어야 하기 때문에, 최종 입력은 `"dosu print"`가 된다.  