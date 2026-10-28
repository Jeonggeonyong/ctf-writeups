# BMP Recovery - Dreamhack
## Challenge Info
- Date: 2026
- CTF Name: Dreamhack
- Category: forensic
- Difficulty (subjective): easy
- Points: 1
- Provided Files: chal.py, flag.bmp.broken
- Tools: HxD
## Brief Description
BMP 파일에서 이런 중요한 값들을 지워버리다니!  
빨리 복구해서 플래그를 읽어주세요!  
플래그 형식은 DH{...}로, flag.bmp를 올바르게 복구하면 찾을 수 있습니다.
## Initial Analysis
### chal.py 코드 분석
``` python
with open('flag.bmp', 'rb') as f:
    data = bytearray(f.read())

data[:0x1C] = b'\x00' * 0x1C
data[0x22:0x36] = b'\x00' * 0x14

with open('flag.bmp.broken', 'wb') as f:
    f.write(data)
```
- `0x00 ~ 0x1B` -> 0으로 덮음
- `0x22 ~ 0x35` -> 0으로 덮음
- `0x1C ~ 0x21` -> biBitCount, biCompression 보존 (복구의 단서)

### BMP 헤더 구조
| 오프셋 | 크기 | 필드 | 설명 | 현재 상태 |
| --- | --- | --- | --- | --- |
| 0x00 | 2 | bfType | 시그니처 `42 4D` ("BM") | 삭제됨 |
| 0x02 | 4 | bfSize | 파일 전체 크기 | 삭제됨 |
| 0x06 | 2 | bfReserved1 | 보통 0 | 삭제됨 (보통 0이므로 복구 불필요) |
| 0x08 | 2 | bfReserved2 | 보통 0 | 삭제됨 (보통 0이므로 복구 불필요) |
| 0x0A | 4 | bfOffBits | 픽셀 데이터 시작 오프셋 | 삭제됨 |
| 0x0E | 4 | biSize | DIB 헤더 크기 (보통 40 = `28 00 00 00`) | 삭제됨 |
| 0x12 | 4 | biWidth | 가로 픽셀 수 | 삭제됨 |
| 0x16 | 4 | biHeight | 세로 픽셀 수 (양수: 아래->위, 음수: 위->아래) | 삭제됨 |
| 0x1A | 2 | biPlanes | 항상 1 (`01 00`) | 삭제됨 |
| 0x1C | 2 | biBitCount | 픽셀당 비트 수 (1, 4, 8, 16, 24, 32) | **보존** |
| 0x1E | 4 | biCompression | 0 = BI_RGB (비압축) 등 | **보존** |
| 0x22 | 4 | biSizeImage | 픽셀 데이터 크기 (BI_RGB에서는 0도 허용) | 삭제됨 |
| 0x26 | 4 | biXPelsPerMeter | 가로 해상도 | 삭제됨 |
| 0x2A | 4 | biYPelsPerMeter | 세로 해상도 | 삭제됨 |
| 0x2E | 4 | biClrUsed | 사용 팔레트 수 (0 = 전부) | 삭제됨 |
| 0x32 | 4 | biClrImportant | 중요 색 수 (0 = 전부) | 삭제됨 |

고정값 혹은 간단히 채울 수 있는 값들은 다음과 같다. 

- `bfType` = 42 4D
- `bfSize` = F6 58 DA 00 (파일 크기는 변화가 없음)
- `bfOffBits` = 36 00 00 00 (헤더 14B + DIB 40B = 54B, 24bpp -> 팔레트 없음)
- `biSize` = 28 00 00 00
- `biPlanes` = 01 00
- `biSizeImage` = C0 58 DA 00 (bfSize - bfOffBits)

### 가로/세로 픽셀 수 계산
``` py
bpp = 0x18
biSizeImage = 0xDA58C0
cands = []

for w in range(1, 10001) :
    row = ((bpp * w + 31) // 32) * 4
    if biSizeImage % row == 0:
        cands.append((w, biSizeImage // row))

for i in cands :
    print(i)
```
BMP는 한 행의 바이트 수가 4의 배수가 되도록 행 끝을 `00`으로 패딩한다. 24bpp는 픽셀 하나가 3바이트이므로 패딩 전 한 행의 크기는 `width × 3`이고, 이 값을 4의 배수로 올림한 것이 실제 `row`이다. 이 `row`로 `biSizeImage`를 나누어 떨어지는 경우에만 유효한 후보이며, 이때 `biSizeImage`를 `row`로 나눈 몫이 행의 개수, 즉 `height`가 된다.

여러 후보들 중 극단적인 값들을 제외하고 brute force로 이미지를 생성해, 정상적인 FLAG가 적힌 이미지를 발견했다.

- width: 2548 (F4 09 00 00)
- height: 1872 (50 07 00 00)

## PoC (Proof of Concept)
1. BMP 고정값 혹은 간단히 채울 수 있는 값들을 채운다.
2. 가로/세로 픽셀 수 후보를 계산한다.
3. BMP 이미지 헤더를 복구하고 FLAG 값을 구한다.

### 복구한 BMP 
!["BMP 헤더"](/Resources/images/BMP%20Recovery-1.png)  
*그림 1. 복구한 BMP 헤더*

!["FLAG"](/Resources/images/BMP%20Recovery-2.png)  
*그림 2. FLAG 값*

## Conclusion
헤더에서 지워진 값을 파일 크기와 보존된 필드로 역산해 복구했다.