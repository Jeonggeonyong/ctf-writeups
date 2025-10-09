# Typing Game Goes Hard - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: rev
- Difficulty (subjective): medium
- Points: 3
- Provided Files: dictionary.txt, chall(ELF)
- tools:
## Brief Description
When Typing Game gets harder
## Initial Analysis
### readDictionary
``` c
void readDictionary(void) {
  int cnt;
  FILE *__stream;
  int idx;
  
  idx = 0;
  __stream = fopen("./dictionary.txt","r");
  if (__stream == (FILE *)0x0) {
    puts("fopen() error");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  do {
    cnt = __isoc99_fscanf(__stream,&DAT_00102030,&DICTIONANRY + (long)idx * 0x40);
    idx = idx + 1;
  } while (cnt != -1);
  fclose(__stream);
  return;
}
```
딕셔너리를 저장할 때, 0x40 크기로 나뉘어진 공간에 저장하는 것을 확인할 수 있다.  
### coreFunc
``` c
void coreFunc(void) {
  readDictionary();
  fd_urand = open("/dev/urandom",0);
  read(fd_urand,&uint_rand,4); // get seed
  setUint16Rand(uint_rand & 0xffff);
  printf("Type the following words within %d seconds.\n",0x5a);
  time(&startTime);
  stage = 0;
  do {
    if (1 < stage) {
      printf("You won! flag is ");
      flag();
    }
    puts("----------------------------------------------");
    if (stage == 0) mode = &EASY;
    else mode = &HARD;
    printf("-                 %s MODE                  -\n",mode);
    puts("----------------------------------------------");
    for (idx = 0; idx < 10; idx = idx + 1) {
      chosen = choose();
      target = &DICTIONANRY + (long)(int)(uint)chosen * 0x40;
      word = target;
      if (stage != 0) {
        word = "[REDACTED]";
      }
      printf("Type this word as soon as possible: %s\n",word);
      printf("> ");
      input(buf,0x40);
      time(&endTime);
      timeDiff = difftime(endTime,startTime);
      if ((90.0 < timeDiff) || (iVar1 = strcmp(buf,target), iVar1 != 0)) {
        puts("Wrong or too slow!");
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
    }
    stage = stage + 1;
  } while( true );
}
```
단어 타이핑 게임의 메인 로직은 다음과 같다.  
1. 16 bit 크기의 `seed`를 생성한다.
2. EASY MODE 10번 실행한다.
3. HARD MODE 10번 실행한다. (이때는 문자를 알려주지 않음)
4. 통과 시 FLAG를 출력한다.  

여기서 중요한 점은, 딕셔너리에서 문자를 가져올 때 복잡한 연산을 거치는데, 이때 `seed`가 사용되며 로직은 다음과 같다.  
1. `setUint16Rand()` 함수로 `seed`를 통해 `key`값을 1차적으로 생성한다.
2. `choose()` 함수를 통해 딕셔녀리에서 가져올 문자(index)를 선택한다.
3. `key`는 8번 사용될 때마다 `resetUint16Rand()` 함수를 통해서 초기화한다. (`choose()` 함수 내부)
## PoC(Poof of Concept)
얼핏보면 중간에 연산이 많아 복잡해 보이지만, `key`와 `choson`은 `seed`에 대한 연산을 통해 만들어지며, 연산 자체는 FLAG나 주요 로직에서 큰 의미가 없기 때문에 `추상화`가 가능하다. 즉, 초기 `seed` 값만 알 수 있다면, 다음에 나올 문제를 예측할 수 있고 이를 통해 HARD MODE의 블라인드 게임을 통과할 수 있다. 다행히 `seed`의 크기는 2 byte로 경우의 수가 총 65,536개 뿐이다. 이는 PC로 충분히 연산 가능한 범위기 때문에, brute force로 모든 `seed`에 대해서 연산을 거쳐 나온 단어와 EASY MODE의 첫 번째 단어를 비교하는 것으로 `seed` 값을 유출할 수 있다.  
### payload
``` python
from pwn import *
from ctypes import c_ushort, c_short

p = remote('host1.dreamhack.games', 15096)

# init
DICTIONARY = []
with open('dictionary.txt', 'r') as file :
    lines = file.readlines()
    DICTIONARY = [line.strip() for line in lines]

uint16_rand = [0] * 8
cnt = 0

# def func
def setUint16Rand(seed):
    global uint16_rand, cnt
    uint16_rand[0] = c_ushort(seed).value
    for idx in range(1, 8):
        prev = c_ushort(uint16_rand[idx - 1]).value
        term1 = c_ushort(prev >> 0xe).value
        term2 = c_ushort(term1 ^ prev).value
        term3 = c_ushort(term2 * 0x6c07).value
        new_val = c_ushort(term3 + c_short(idx).value).value
        uint16_rand[idx] = new_val
    cnt = 8

def choose():
    global uint16_rand, cnt
    if cnt > 7:
        resetUint16Rand()
    uVar1 = uint16_rand[cnt]
    cnt += 1
    bVar5 = uVar1 & 0xf
    bVar6 = (uVar1 >> 4) & 0xf
    bVar7 = (uVar1 >> 8) & 0xf
    bVar8 = (uVar1 >> 12) & 0xf
    iVar9  = bVar8 * 2 + bVar7 * 7 + bVar6 * 5 + bVar5 * 3
    iVar10 = bVar8 * 3 + bVar7 * 6 + bVar6 * 7 + bVar5 * 4
    iVar11 = bVar8 * 7 + bVar7 * 4 + bVar6 * 6 + bVar5 * 5
    r1 = iVar11 % 16
    r2 = iVar9  % 16
    r3 = iVar10 % 16
    r4 = (bVar8 * 4 + bVar5 * 2 + bVar6 * 3 + bVar7 * 5) & 0xf
    result = (r1 << 12) | (r4 << 8) | (r3 << 4) | r2
    return c_ushort(result).value

def resetUint16Rand():
    global uint16_rand, cnt

    for idx in range(8):
        next_val = uint16_rand[(idx + 1) % 8]
        curr_val = uint16_rand[idx]
        
        local_10 = c_ushort(((next_val & 0x7fff) | (curr_val & 0x8000)) >> 1).value
        
        if (next_val & 1) != 0:
            local_10 = c_ushort(local_10 ^ 0x9908).value
            
        ahead_val = uint16_rand[(idx + 4) % 8]
        new_val = c_ushort(ahead_val ^ local_10).value
        
        uint16_rand[idx] = new_val
        
    cnt = 0

# uint16_rand seed brute force
log.info("Finding seed by EASY MODE's 1st word...")
p.recvuntil(b"Type this word as soon as possible: ")
first_word = p.recvline().strip().decode()
first_word_index = DICTIONARY.index(first_word)
log.info(f"1st: '{first_word}' (idx: {first_word_index})")

correct_seed = -1
for seed in range(65536): # search 0x0000 ~ 0xffff 
    setUint16Rand(seed)
    predicted_index = choose()
    if predicted_index == first_word_index:
        log.success(f"Found: {hex(seed)}")
        correct_seed = seed
        break

if correct_seed == -1:
    log.error("Not Found.")
    exit()

# play game
log.info("Predict all words...")
predictions = []
setUint16Rand(correct_seed) # 찾은 시드로 PRNG 상태 재초기화
for i in range(20):
    word_index = choose()
    predictions.append(DICTIONARY[word_index])

log.info(f"EASY MODE 단어: {predictions[:10]}")
log.info(f"HARD MODE 단어: {predictions[10:]}")

# EASY MODE clear
log.info("Playing EASY MODE...")
# 1st work -> just send
p.sendlineafter(b"> ", predictions[0].encode())
print('good')
for i in range(1, 10):
    p.sendlineafter(b"> ", predictions[i].encode())
    print('good')

# HARD MODE clear
log.info("Playing HARD MODE...")
for i in range(10):
    p.sendlineafter(b"> ", predictions[10 + i].encode())
    
log.success("Success!")

# interactive
p.interactive()
```