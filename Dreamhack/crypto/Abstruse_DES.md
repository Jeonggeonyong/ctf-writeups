# Abstruse DES - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: crypto
- Difficulty (subjective): easy
- Points: 2
- Provided Files: prob.py, flag
- tools:
## Brief Description
I've heard that DES uses 56-bit key, but it looks like 8-byte for me. Does it imply 1-byte == 7-bit?
## Initial Analysis
### Code
``` py
#!/usr/bin/env python3
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import os


def menu():
    print("1. Encrypt message")
    print("2. Decrypt message")
    print("3. Encrypt flag")
    print("4. Exit")
    print("> ", end="")


if __name__ == "__main__":
    with open("flag", "rb") as f:
        flag = f.read()

    key = os.urandom(8)

    print("DES uses 56bit-length private key. But wait, isn't that 8 byte?")
    cipher = DES.new(key, DES.MODE_ECB)
    while True:
        menu()
        action = int(input())
        if action == 1:
            msg = bytes.fromhex(input("send your message(hex) > "))
            print(f"encrypted message > {cipher.encrypt(pad(msg, 16)).hex()}")

        elif action == 2:
            print("My key is not for sell. I'll give you some dummies instead :>")
            dummy = list(map(int, input().split()))
            assert len(dummy) == 8, "Invalid input!"
            for d in dummy:
                assert 0 < d < 256, "Invalid input!"
            key_dummy = bytes([d ^ k for d, k in zip(dummy, key)])
            cipher_dummy = DES.new(key_dummy, DES.MODE_ECB)
            msg = bytes.fromhex(input("send your message(hex) > "))
            print(f"encrypted message > {cipher_dummy.decrypt(pad(msg, 16)).hex()}")

        elif action == 3:
            print(f"Encrypted flag > {cipher.encrypt(pad(flag, 16)).hex()}")

        elif action == 4:
            print("Good Bye!")
            break

        else:
            print("invalid")
```
DES에 전달한 8byte 키에서 각 바이트의 LSB(bit)를 버리고 남은 7byte를 key로 사용한다.  
`Encrypt message`와 `Encrypt flag` 모두 초기에 전달한 key를 사용하여 암호화 하지만, `Decrypt message`는 `dummy` XOR `key` 연산을 통해 만든 `key_dummy`로 복호화를 수행한다.  
DES에는 보수 속성이 존재하는데, `열쇠를 뒤집고(보수), 내용물도 뒤집어서(보수) 암호화하면, 결과물도 뒤집힌 채로 나온다.`는 특성이 있다. 우리는 암호화된 `flag`를 알고 있고, 기존의 `key`와 XOR 연산을 하는 `dummy` 값을 우리가 원하는 대로 전달할 수 있다. 즉, `Decrypt message` 기능에 암호화된 `flag`를 뒤집어 전달하고, `dummy`를 `255 255 255 255 255 255 255`로 전달하여 `key_dummy`를 기존의 `key`를 뒤집어 사용할 수 있게 되어 최종적으로 뒤집어진 복호화된 `flag`를 획득할 수 있다.  
## PoC
``` py
from pwn import *

p = remote('host1.dreamhack.games', 20165) 

# 암호화된 flag 획득
p.sendlineafter(b"> ", b"3")
p.recvuntil(b"Encrypted flag > ")
encrypted_flag_hex = p.recvline().strip().decode()
log.info(f"Encrypted Flag: {encrypted_flag_hex}")
# 암호화된 플래그의 보수(complement) 계산
complement_encrypted_flag = xor(bytes.fromhex(encrypted_flag_hex), 0xff)
log.info(f"Complement Encrypted Flag: {complement_encrypted_flag.hex()}")

# 키 조작 & 복호화 수행
p.sendlineafter(b"> ", b"2")
dummy_payload = b"255 255 255 255 255 255 255 255" # 0x00FF FFFF FFFF FFFF
p.sendlineafter(b"dummies instead :>", dummy_payload)
log.success(f"Sent dummy payload: {dummy_payload.decode()}")
# complement_encrypted_flag 복호화
p.sendlineafter(b"send your message(hex) > ", complement_encrypted_flag.hex().encode())
log.success("Sent C_bar to decrypt")
# flag
p.recvuntil(b"encrypted message > ") 
complement_flag_hex = p.recvline().strip().decode()
log.info(f"Received Complement Flag: {complement_flag_hex}")

# 결과의 비트를 다시 뒤집어 원본 플래그 계산
complement_flag_bytes = bytes.fromhex(complement_flag_hex)
flag = xor(complement_flag_bytes, 0xff)
log.success(f"FLAG: {flag}")

# interactive
p.interactive()
```
