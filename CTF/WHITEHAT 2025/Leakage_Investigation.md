# Challenge Name - CTF Name
## Challenge Info
- Date: YYYY-MM-DD
- CTF Name:
- Category: web/pwn/rev/crypto/forensic/osint/misc
- Difficulty (subjective): easy/medium/hard
- Points:
- Provided Files:
- tools:
## Brief Description
문제 설명  
"LumenGrid Labs" 내부에서 누군가가 신제품에 대한 기밀 정보를 유출한 것을 발견하였습니다.  
의심되는 직원이 사용한 기기에서 네트워크 트래픽 덤프를 추출하였습니다.  
덤프를 분석하여 유출된 정보를 식별해주세요.  
제품명에는 공백 및 특수문자가 포함되지 않습니다.  
Flag format: whitehat2025{ProductName_ReleaseDate}  
Flag Example: whitehat2025{ExampleProduct_2000-01-15}
## Initial Analysis
https://en.wikipedia.org/wiki/Reserved_IP_addresses
198.51.100.23 대역은 테스트 IP 대역 이라는데숭
### Environment
### Code
## Vulnerability
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
## PoC(Poof of Concept)
## Lessons Learned
## Mitigation Strategies(Remediation)