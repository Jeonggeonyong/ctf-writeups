# dungeon-in-1983 - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: rev
- Difficulty (subjective): easy
- Points: 2
- Provided Files: 
- tools: Ghidra
## Brief Description
Back in 1983, when you only had A and B on your controller...
## Initial Analysis
### main()
``` c
undefined8 main(void) {
  int spellCheck;
  size_t sVar1;
  long in_FS_OFFSET;
  int stage;
  char *str;
  size_t randNum;
  FILE *fd;
  undefined8 monsterName;
  undefined8 local_1a0;
  undefined4 local_198;
  undefined8 local_194;
  undefined8 local_18c;
  undefined4 local_184;
  undefined8 local_180;
  undefined8 local_178;
  undefined4 local_170;
  undefined8 local_16c;
  undefined8 local_164;
  undefined4 local_15c;
  undefined8 local_158;
  undefined8 local_150;
  undefined4 local_148;
  undefined8 local_144;
  undefined8 local_13c;
  undefined4 local_134;
  undefined8 local_130;
  undefined8 local_128;
  undefined4 local_120;
  undefined8 local_11c;
  undefined8 local_114;
  undefined4 local_10c;
  undefined8 local_108;
  undefined8 local_100;
  undefined4 local_f8;
  undefined8 local_f4;
  undefined8 local_ec;
  undefined4 local_e4;
  char buf [201];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  monsterName = 0x6b73696c69736142;
  local_1a0 = 0;
  local_198 = 0;
  local_194 = 0x6172656d696843;
  local_18c = 0;
  local_184 = 0;
  local_180 = 0x6e656b61724b;
  local_178 = 0;
  local_170 = 0;
  local_16c = 0x6e6f67726f47;
  local_164 = 0;
  local_15c = 0;
  local_158 = 0x6f6769646e6557;
  local_150 = 0;
  local_148 = 0;
  local_144 = 0x727561746f6e694d;
  local_13c = 0;
  local_134 = 0;
  local_130 = 0x616874616976654c;
  local_128 = 0x6e;
  local_120 = 0;
  local_11c = 0x6172647948;
  local_114 = 0;
  local_10c = 0;
  local_108 = 0x726f6369746e614d;
  local_100 = 0x65;
  local_f8 = 0;
  local_f4 = 0x636f52;
  local_ec = 0;
  local_e4 = 0;
  setbuf();
  fd = fopen("/dev/urandom","r");
  puts("Welcome to the Dungeon!");
  puts("You have only two buttons: A and B.");
  puts("Each monster requires certain series of key combinations to be defeated, so be careful!") ;
  stage = 0;
  while( true ) {
    if (9 < stage) {
      fclose(fd);
      printf("It\'s dangerous to go alone! Take the flag: ");
      str = (char *)0x0;
      randNum = 0;
      fd = fopen("./flag","r");
      getline(&str,&randNum,fd);
      printf("%s",str);
      free(str);
      fclose(fd);
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    fread(&randNum,8,1,fd);
    printf("[STAGE %2d]: %s\n",(ulong)(stage + 1),(long)&monsterName + (long)stage * 0x14);
    printStats(randNum);
    printf("Cast your spell!: ");
    fgets(buf + 1,200,stdin);
    sVar1 = strlen(buf + 1);
    if (buf[sVar1] == '\n') {
      sVar1 = strlen(buf + 1);
      buf[sVar1] = '\0';
    }
    spellCheck = spell(buf + 1,randNum);
    if (spellCheck == 0) break;
    printf("%s defeated. STAGE %2d cleared!\n",(long)&monsterName + (long)stage * 0x14,
           (ulong)(stage + 1));
    stage = stage + 1;
  }
  puts("You were defeated. Retreat!");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
```
우선 결과적으로 총 10번의 몬스터 사냥에 성공하면 FLAG를 출력한다.  
8byte urand 값을 `printStats` 함수에 전달한다. 이후 사용자에게 `spell`을 입력 받고 해당 값을 `spell()`에 전달한다. `spellCheck`의 결과가 0(false)라면 사냥에 실패, 1(true)라면 사냥에 성공하여 다음 스테이지의 몬스터를 사냥한다.  
### printStats()
``` c
void printStats(ulong randNum) {
  printf("[INFO] HP: %5hu, STR: %5hhu, AGI: %5hhu, VIT: %5hhu, INT: %5hhu, END: %5hhu, DEX: %5hhu\n "
         ,randNum >> 0x30,randNum & 0xff,randNum >> 8 & 0xff,randNum >> 0x10 & 0xff,
         randNum >> 0x18 & 0xff,randNum >> 0x20 & 0xff,randNum >> 0x28 & 0xff);
  return;
}

```
`randNum`의 값을 byte단위로 나누어 스탯이 정해지며, 스탯 별 저장중인 8byte의 위치는 다음과 같다.  
| HP | DEX | END | INT | VIT | AGI | STR |
| --- | --- | --- | --- | --- | --- | --- |
| 2byte | 1byte | 1byte | 1byte | 1byte | 1byte | 1byte |
### spell()
``` c
bool spell(long buf,long randNum) {
  int idx;
  long result;
  bool A;
  bool B;
  
  result = 0;
  A = false;
  B = false;
  idx = 0;
  do {
    if (*(char *)(buf + idx) == '\0') {
      return result == randNum;
    }
    if (*(char *)(buf + idx) == 'A') {
      B = true;
      result = result + 1;
      if (A) {
        puts("A button stucked! Retreat...");
                    /* WARNING: Subroutine does not return */
        exit(-1);
      }
      A = true;
    }
    else {
      if (*(char *)(buf + idx) != 'B') {
        puts("Invalid button!");
                    /* WARNING: Subroutine does not return */
        exit(-1);
      }
      if (!B) {
        puts("Lore says the spell should start with A...");
                    /* WARNING: Subroutine does not return */
        exit(-1);
      }
      result = result << 1;
      A = false;
    }
    idx = idx + 1;
  } while( true );
}
```
`A`와 `B`에 따라 연산되는 `result`값이 `randNum`의 값과 같다면 1(true)를 반환한다.  
즉, 사용자 입력(spell)이 `A`와 `B`로 알맞게 구성되어야 한다. 
### PoC(Poof of Concept)
``` python
from pwn import *

p = remote('host8.dreamhack.games', 9684)

stats = [b'HP:', b'STR:', b'AGI:', b'VIT:', b'INT:', b'END:', b'DEX:']
shift_left = [0x30, 0x0, 0x8, 0x10, 0x18, 0x20, 0x28]

# play game
for i in range(10):
    input_bytes = p.recvline_startswith(b'[INFO] ') # '[INFO] '로 시작하는 라인 받기
    log.info(f'STAGE-[{i+1}]\n{input_bytes.decode()}')
    input_bytes = input_bytes.replace(b'[INFO] ', b'') 
    for s in stats :
        input_bytes = input_bytes.replace(s, b'') 
    targets = [int(v) for v in input_bytes.split(b',')]
    target = 0
    for idx in range(len(targets)) :
        target += targets[idx] << shift_left[idx]

    spell = b''
    while target > 1:
        if target & 1 == 0:
            target >>= 1
            spell += b'B'
        else:
            target -= 1
            spell += b'A'
    
    spell += b'A'
    spell = spell[::-1]
    p.sendline(spell)
    log.info(f'spell: {spell.decode()}')
    log.info('\n')
    
p.recvuntil(b'It\'s dangerous to go alone! Take the flag:')
flag = p.recvline()
log.info(f'FLAG: {flag.decode()}')

# interactive
p.interactive()
```