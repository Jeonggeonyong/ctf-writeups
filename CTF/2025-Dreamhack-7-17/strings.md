# strings - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: pwn
- Difficulty (subjective): easy/medium/hard
- Points:
- Provided Files:
- tools:
## Brief Description
Give me your strings!
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
``` cpp
#include <bits/stdc++.h>

using namespace std;

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    vector<string> stores(0x10);

    while(true) {
        uint64_t idx;
        string name;

        cout << "Enter store index: ";
        cin >> idx;
        cout << "Enter store name: ";
        cin >> name;

        stores[idx] = name;
    }
}
```
## Vulnerability
### OOB(Out of Bounds)
``` cpp
cout << "Enter store index: ";
cin >> idx;
```
`stores`의 크기는 0x10인 반면, `idx`는 범위에 대한 검증이 없어 OOB 취약점이 발생한다.  
## Exploit
### Strategy
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *
```
### PoC(Poof of Concept)
## Lessons Learned
## Mitigation Strategies(Remediation)