# VBR - Dreamhack
## Challenge Info
- Date: 2026
- CTF Name: Dreamhack
- Category: forensic
- Difficulty (subjective): easy
- Points: 1
- Provided Files: vbr.bin
- Tools: HxD
## Brief Description
주어진 VBR을 분석하고, 플래그를 계산하시오.  
### Info
FLAG = DH{(A + B + C)} (단, 더한 값을 십진수로 변환할 것)  
A: 파일시스템이 FAT32면 1, NTFS면 2  
B: 해당 볼륨의 크기  
C: 볼륨 시리얼 번호  
## Initial Analysis
### FAT32 파일 시스템 확인
!["VBR"](/Resources/images/VBR-1.png)  
*그림 1. HxD로 확인한 VBR*

VBR 끝의 시그니처 55 AA로 유효한 부트 섹터임을 확인했고, 오프셋 0x52의 파일 시스템 문자열이 FAT32임을 확인했다.
### FAT32 구조
!["FAT32 구조"](/Resources/images/VBR-FAT32-1.png)  
*그림 2. FAT32 구조*

| 이름 | 오프셋 | 설명 |
| --- | --- | --- |
| Jump Command | 0x00 - 0x02 | 부트 코드로 점프 |
| BPB(BIOS Parameter Block) | 0x03 - 0x59 | 볼륨의 전반적인 설정을 포함 |
| 부트 코드 | 0x5A - 0x1FD | 볼륨 부트 코드 |
| 시그니처 | 0x1FE - 0x1FF | 고정값 `55 AA` |

!["FAT32 BPB"](/Resources/images/VBR-FAT32-2.png)  
*그림 3. FAT32 BPB 구조*

## PoC (Proof of Concept)
!["VBR"](/Resources/images/VBR-2.png)  
*그림 4. HxD로 확인한 파일 시스템*

```
A = 1
```

!["VBR"](/Resources/images/VBR-3.png)  
*그림 5. HxD로 확인한 볼륨 크기*

```
B = 2,097,152,000 (Total Sectors x Bytes Per Sector: 4,096,000 x 512)
```

!["VBR"](/Resources/images/VBR-4.png)  
*그림 6. HxD로 확인한 볼륨 시리얼 번호*

```
C = 245,952,138
```

## Conclusion
BPB는 구조가 고정되어 있어 오프셋만 알면 파일 시스템 종류, 볼륨 크기, 시리얼 번호를 바로 읽을 수 있다. 이를 적용해 A, B, C를 구하고 합산하여 FLAG를 얻었다.
- 배운 점: FAT32와 NTFS의 VBR 구조 차이