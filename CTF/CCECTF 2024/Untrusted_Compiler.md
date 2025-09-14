# Untrusted Compiler - CCECTF
## Challenge Info
- Date: 2025
- CTF Name: CCECTF
- Category: pwn
- Difficulty (subjective): medium
- Points:
- Provided Files: chall.c
- tools: ghidra
## Brief Description
Do you trust the compiler? nc 43.202.156.51 1337  
## Initial Analysis
### Code
``` c
//gcc -o chall chall.c -no-pie -z relro -O2 -fno-stack-protector

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

uint32_t random_list[10] = {0,};
uint64_t total_random = 0;

void banner()
{
    printf("                        __                                  _ _           \n");
    printf(" _   _ _ __  ___  __ _ / _| ___    ___ ___  _ __ ___  _ __ (_) | ___ _ __ \n");
    printf("| | | | '_ \\/ __|/ _` | |_ / _ \\  / __/ _ \\| '_ ` _ \\| '_ \\| | |/ _ \\ '__|\n");
    printf("| |_| | | | \\__ \\ (_| |  _|  __/ | (_| (_) | | | | | | |_) | | |  __/ |   \n");
    printf(" \\__,_|_| |_|___/\\__,_|_|  \\___|  \\___\\___/|_| |_| |_| .__/|_|_|\\___|_|   \n");
    printf("                                                     |_|                  \n\n");
}

void init(){
    srand(time(NULL));
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
    banner();

    printf("Start setting 10 randoms...\n");

    for(int i = 0; i < 10; i++)
    {
        uint32_t random = rand();
        random_list[i] = random;
        total_random += random;
    }

    printf("done!\n\n");

    printf("Guess the random value XD\n\n");
}

void flush()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void guess()
{
    uint16_t idx = 0;
    uint32_t score_list[10] = {0,};
    uint32_t input_list[10] = {0,};
    uint64_t score_sum = 0;

    while ((random_list[idx] < UINT32_MAX) && (idx < 10)) {
        printf("input %d: ",idx);
        scanf("%d", &input_list[idx]);
        flush();
        if(input_list[idx] == random_list[idx])
            score_list[idx] = random_list[idx];

        score_sum += score_list[idx];
        idx++;
        if(score_sum >= total_random){
    	    return;
    }
  }
}

int main()
{
    init();

    guess();
}
```
### init();
``` c
void init(){
    // rand() 함수의 seed를 time(NULL), 즉 현재 시각으로 설정. 매 실행마다 다른 난수 생성
    srand(time(NULL)); 
    // stdin과 stdout의 버퍼링을 꺼서 입출력이 즉시 처리되도록 설정
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
    banner();

    printf("Start setting 10 randoms...\n");

    // random_list 초기화
    for(int i = 0; i < 10; i++)
    {
        uint32_t random = rand(); // 0 ~ RAND_MAX(32767)
        random_list[i] = random;
        total_random += random;
    }

    printf("done!\n\n");

    printf("Guess the random value XD\n\n");
}
```
전역 변수 `random_list`, `total_random`를 초기화 하는 함수다.  
rand()함수 최대 범위는 0부터 stdlib.h에 정의된 RAND_MAX까지다. RAND_MAX는 0x7fff로 정의된다.  
> [!note] RAND_MAX   
> https://learn.microsoft.com/ko-kr/cpp/c-runtime-library/rand-max?view=msvc-170  
### flush();
``` c
void flush()
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}
```
`scanf()`는 개행 문자 `\n`를 읽지 않고 버퍼에 남겨두는데, 남아 있는 개행 문자(\n)나 다른 쓰레기 문자들을 버퍼에서 제거하는 함수.  
### guess();
``` c
void guess()
{
    uint16_t idx = 0;
    uint32_t score_list[10] = {0,};
    uint32_t input_list[10] = {0,};
    uint64_t score_sum = 0;

    while ((random_list[idx] < UINT32_MAX) && (idx < 10)) { // rand() 함수 최대값은 UINT32_MAX를 넘지 않는다.
        printf("input %d: ",idx);
        scanf("%d", &input_list[idx]);
        flush();
        if(input_list[idx] == random_list[idx])
            score_list[idx] = random_list[idx];

        score_sum += score_list[idx];
        idx++;
        if(score_sum >= total_random){
    	    return;
    }
  }
}
```
최대 10번까지 사용자 입력을 받고 random_list와 비교한다.  
랜덤 값을 맞춘 경우 score_list에 저장 및 score_num에 score_list 값 합산.  
score_sum 값이 total_random 값보다 크거나 같을 경우 바로 return, 그러나 이 부분은 10번 모두 맞춘 후 동작 가능.  
## Vulnerability
### 컴파일 이후 guess() 함수 일부
``` c
do {
if ((&random_list)[i] == -1) {
    return;
}
__printf_chk(1,"input %d: ",i & 0xffffffff);
__isoc99_scanf(&DAT_0040222d,input_list);
do { // flush 함수
    iVar1 = getc(stdin);
    if (iVar1 == 10) break;
} while (iVar1 != -1);
cmp_val = (&random_list)[i];
if (*input_list == cmp_val) {
    *(uint *)(score_list + i * 4) = cmp_val;
}
else {
    cmp_val = *(uint *)(score_list + i * 4);
}
score_sum = score_sum + cmp_val;
i = i + 1;
input_list = input_list + 1;
if (total_random <= score_sum) {
    return;
}
} while( true );
```
컴파일 후 결과를 보면 기존 C 코드의 의도와 달라진 부분이 생긴 것을 확인할 수 있다.  
### 1. while 문 조건 변화
``` c
// 기존 C 코드
while ((random_list[idx] < UINT32_MAX) && (idx < 10))

// 컴파일 후 코드
if ((&random_list)[i] == -1)
```
`(idx < 10)` 부분이 사라졌다. 이로인해 실제로 테스트 해보면 while 문이 10회 이상 반복하는 것을 확인할 수 있다.  
### 2. input_list의 포인터 이동
``` c
// 컴파일 후 코드
input_list = input_list + 1;
```
기존 C 코드에서는 `idx` 변수로 input_list 배열의 요소에 접근했지만, 컴파일 이후 코드를 보면 input_list의 배열 포인터 값을 1 증가(주소 + 4) 시킨다. 이는 1번 while 문 조건 변화와 맞물려 `OOB(Out Of Bounds)` 취약점이 발생한다.  
> [!note] OOB 취약점이란?  
> OOB는 배열이나 버퍼의 경계 밖 메모리에 접근하는 취약점이다. 보통은 인덱스를 잘못 검사하거나 조건문이 없을 때 발생한다. 이에 따른 결과는 배열 밖 메모리를 읽거나 쓸 수 있게 된다.  
## Exploit
### Strategy
해당 문제는 flag 관련 함수나 힌트가 없다. 즉, 목적은 shell을 따는 것이라고 짐작해 볼 수 있다. 또한 `OOB`, `ROP` 취약점은 shell을 따기에 충분한 환경이다.  
``` plain text
ROP 공격을 통한 system("/bin/sh") 호출
```
### ROP(Return Oriented Programming)
ROP는 BOF 같은 취약점을 이용해 함수 호출 대신 짧은 코드 조각(gadget)을 연결해서 원하는 동작을 하는 기술이다. 현대 시스템에서는 `스택 실행이 금지(NX bit)` 되어 있어서 쉘코드를 직접 실행할 수 없다. 따라서 기존 바이너리나 라이브러리에 존재하는 코드 조각(gadget)을 이용해서 원하는 동작을 구현한다. gadget은 ret으로 끝나는 짧은 어셈블리 명령어 조각이다. (예 pop rdi; ret)  
ROP Chain은 여러 gadget을 스택에 쌓아 실행 순서대로 이어 붙인 체인이다. 당연히 체인이 길어질 수록 난이도는 올라간다.  
### Exploitation Steps
``` sh
$ ROPgadget --binary ./untrusted_compiler --re "ret"
Gadgets information
============================================================
0x000000000040101a : ret
```
``` sh
$ ROPgadget --binary ./untrusted_compiler --re "rdi"
Gadgets information
============================================================
0x0000000000401444 : pop rdi ; ret
```
``` sh
$ ROPgadget --binary ./untrusted_compiler --re "pop rsi"
Gadgets information
============================================================
0x0000000000401442 : pop rsi ; pop r15 ; ret
```
``` sh
strings -tx libc.so.6 | grep "/bin/sh"
 18cd57 /bin/sh
```
``` sh
readelf -s libc.so.6 | grep " system@"
  1351: 0000000000045390    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
```
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *


```
## writeup
- https://pdw0412.tistory.com/30
- https://orcinus-orca.tistory.com/279

