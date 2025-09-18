# Textbook-RSA - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: crypto
- Difficulty (subjective): easy
- Points: 2
- Provided Files: challenge.py
- tools:
## Brief Description
드림이가 비밀 플래그를 가지고 있는 RSA 서버를 운영하고 있습니다. 서버를 공격해 플래그를 탈취해주세요!  
플래그 형식은 DH{...} 입니다.
## Initial Analysis
### Code
``` python
class RSA(object):
    def __init__(self):
        self.p = getStrongPrime(512)
        self.q = getStrongPrime(512)
        self.N = self.p * self.q
        self.e = 0x10001
        self.d = inverse(self.e, self.N - self.p - self.q + 1)

    def encrypt(self, pt):
        return pow(pt, self.e, self.N)

    def decrypt(self, ct):
        return pow(ct, self.d, self.N)
```
서버는 다음 3가지의 기능을 제공한다.  
1. RSA 암호화
2. RSA 복호화
3. N & e & Flag 복호화 정보

서버는 해당 RSA 클래스를 사용하여 암호화 및 복호화를 진행한다. 서버는 암/복호화 횟수에 제한이 없다.  
### 주어진 정보
- FLAG의 암호문: C
- 공개키: (N, e)
- 암호화 함수: C = M^e (mod N)
## PoC(Poof of Concept)
FLAG의 암호문과 공개키를 알고 있고 복호화 요청을 할 수 있으므로, 곱셈 동형성 특성을 통해 CCA(Chosen-Ciphertext Attack) 공격을 시도할 수 있다.  
- CCA1(선택 암호문 공격): 공격자가 암호문을 미리 선택하여 복호화를 요청하고, 그 결과로 얻은 평문을 분석한다. 이후 추가적인 암호문을 선택할 수 없다.
- CCA2(적응형 선택 암호문 공격): 공격자가 복호화 요청으로 암호문을 해독하는 과정 중에도, 목표 암호문을 제외한 새로운 암호문을 계속해서 선택하고 요청할 수 있다.  
### RSA 곱셈 동형성
![](/Resources/images/Textbook-RSA.jpg "곱셈 동형성")
``` plain text
C = M^2 (mod N)

E(2) = 2^e (mod N)

C' = C*E(2) (mod N)

C' = (2*M)^2 (mod N) => C'는 2*M을 암호화한 것과 같다.

P' = D(C')

P' = D(2*M)^ed (mod N) = 2*M (mod N)

M = (P'*1/2) (mod N)
```
### solve.py
``` python
from pwn import *
from Crypto.Util.number import long_to_bytes, inverse

p = remote('host1.dreamhack.games', 16632) 

# get info
p.sendlineafter(b'[3] Get info', b'3')
p.recvuntil(b'N: ')
N = int(p.recvline().strip())
p.recvuntil(b'e: ')
e = int(p.recvline().strip())
p.recvuntil(b'FLAG: ')
FLAG_enc = int(p.recvline().strip())

print(f"[*] N: {N}")
print(f"[*] e: {e}")
print(f"[*] FLAG_enc: {FLAG_enc}")

# 
k = 2
k_enc = pow(k, e, N)
C_prime = (FLAG_enc * k_enc) % N
p.sendlineafter(b'[3] Get info', b'2')
p.sendlineafter(b'(hex): ', hex(C_prime)[2:]) 
M_prime = int(p.recvline().strip())
print(f"[*] Decrypted M': {M_prime}")
k_inv = inverse(k, N)
FLAG_long = (M_prime * k_inv) % N
flag = long_to_bytes(FLAG_long)
print(f"\n[+] FLAG: {flag.decode()}")

p.close()
```
