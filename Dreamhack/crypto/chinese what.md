# chinese what - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: crypto
- Difficulty (subjective): easy
- Points: 1
- Provided Files: prob.py, output.txt
- tools:
## Brief Description
CRT는 rsa에 많이 응용되는 정리입니다.  
간단한 문제를 풀어보며 CRT란 무엇인지 알아보세요.
## Initial Analysis
### prob.py
``` python
from Crypto.Util.number import bytes_to_long, getPrime

flag = bytes_to_long(b'DH{???????????????????????????????????????????????????????}')

p1 = getPrime(420)
p2 = getPrime(420)
p3 = getPrime(420)

print(f'p1 = {p1}')
print(f'p2 = {p2}')
print(f'p3 = {p3}')
print(f'c1 = {flag % p1}')
print(f'c2 = {flag % p2}')
print(f'c3 = {flag % p3}')
```
FLAG를 long 타입으로 변환하여, 420 bit 크기의 무작위 소수 3개를 생성 후, 해당 소수 & FLAG를 소수로 mod 연산한 결과를 출력한다.  
해당 문제는 전형적인 ctr를 이용하는 문제다. ctr의 핵심 원리는 `서로소인 여러 개의 modulus에 대한 나머지가 주어졌을 때, 유일한 해를 modulus들의 곱에 대한 나머지로 구할 수 있다`는 것이다.  
![](/Resources/images/chinese%20what-ctr.jpg "ctr")
## PoC(Poof of Concept)
``` python
def xgcd(a, b): # 확장 유클리드 알고리즘
    if b == 0:
        return a, 1, 0
             
    g, x1, y1 = xgcd(b, a % b)
    x = y1
    y = (g - a * x) // b
    assert a * x + b * y == g

    return g, x, y

def crt(rem, mod): 
    a, b = rem
    p, q = mod
    g, alpha, beta = xgcd(p, q)
    assert g == 1 # 서로소 확인

    c = a * q * beta + b * p * alpha
    final_mod = p * q
    c %= final_mod

    assert c % p == a
    assert c % q == b

    return c, final_mod

def crt_multi(rem, mod):
    c = 0
    final_mod = 1
    for a, p in zip(rem, mod):  
        c, final_mod = crt([c, a], [final_mod, p])

    for a, p in zip(rem, mod):
        assert c % p == a

    return c, final_mod

p1 = 1527207470243143973741530105910986024271649986608148657294882537828034327858594844987775446712917007186537829119357070864918869
p2 = 2019864244456120206428956645997068464122219855220655920467990311571156191223237121636244541173449544034684177250532278907347407
p3 = 1801109020443617827324680638861937237596639325730371475055693399143628803572030079812427637295108153858392360647248339418361407
c1 = 232762450308730030838415167305062079887914561751502831059133765333100914083329837666753704309116795944107100966648563183291808
c2 = 869189375217585206857269997483379374418043159436598804873841035147176525138665409890054486560412505207030359232633223629185304
c3 = 1465704473460472286244828683610388110862719231828602162838215555887249333131331510519650513265133531691347657992103108331793683

flag_num, _ = crt_multi([c1, c2, c3], [p1, p2, p3])
flag_bytes = flag_num.to_bytes((flag_num.bit_length() + 7) // 8, 'big')
print(flag_bytes)

print(xgcd(6, 8))
```
p1과 p2에 대해서 ctr을 진행한 후, 이에 대한 결과를 다시 p3와 ctr을 진행하는 점진적인 방식으로 코드를 작성했다.  