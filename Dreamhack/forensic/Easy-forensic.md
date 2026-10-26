# Easy-forensic - Dreamhack
## Challenge Info
- Date: 2026
- CTF Name: Dreamhack
- Category: forensic
- Difficulty (subjective): easy
- Points: 1
- Provided Files: Image.png
- Tools: HxD, HashCalc, Python(Pillow, Numpy)
## Brief Description
이미지 파일 하나를 받았습니다.  
그런데 어째서인지 정상적인 이미지 파일과는 구조가 조금 달라 보입니다...?  
이미지를 분석하여 플래그를 찾아보세요!  
플래그 형식: DH{...}
## Initial Analysis
### 이미지 파일 관찰
제공받은 `Image.png` 이미지 파일이 윈도우 기본 사진 앱을 통해 정상적으로 열리는 것을 확인했다. 문제 설명을 보면 파일 안에 이미지 데이터 외에 다른 데이터 혹은 파일이 숨겨져 있을 것으로 예상했다.

### 시그니처 검사
PNG 파일 시그니처는 다음과 같다.

| 구분 | 시그니처 |
| --- | --- |
| 헤더 | 89 50 4E 47 0D 0A 1A 0A |
| 푸터 | 49 45 4E 44 AE 42 60 82 |

!["PNG 푸터 시그니처"](/Resources/images/Easy-forensic-hex1.png)  
*그림 1. HxD로 확인한 `Image.png`의 푸터 시그니처*

PNG 파일의 푸터 시그니처 탐색 결과 `IEND` 이후, 추가적인 데이터가 존재하는 것을 확인했다. `50 4B 03 04` (.zip 시그니처)가 이어서 존재하는 것을 보아 ZIP 파일이 숨겨진 것으로 판단해 이어서 ZIP 끝부분(EOCD) 시그니처 검색을 진행했다.

!["ZIP EOCD 시그니처"](/Resources/images/Easy-forensic-hex2.png)  
*그림 2. HxD로 확인한 ZIP EOCD 시그니처*

`Image.png` 이미지 파일 마지막에서 ZIP 끝부분의 EOCD 시그니처(`50 4B 05 06`)를 확인할 수 있었으며, 해당 ZIP 데이터 부분을 따로 추출해 .zip 파일 압축 해제를 진행했다.
- 시작: `IEND` 이후 첫 `50 4B 03 04` 위치
- 끝: `50 4B 05 06` 위치에서 22바이트 뒤까지 (파일 마지막)

### 압축 해제한 파일 구성
압축 해제 후 다음의 5가지 파일을 얻을 수 있었다.
- FLAG.png
- GREEN 1.png
- RED 3.png
- Hello.py
- watermelon.txt

### 압축 해제한 파일 관찰
- Hello.py
- watermelon.txt

해당 두 파일에 대해서는 특이점을 발견하지 못했다.

```
플래그는 <GREEN 1>을 <RED 3>한 값입니다.
```

`FLAG.png` 파일에서 해당 내용을 확인할 수 있었다. `GREEN 1`과 `RED 3`는 함께 제공된 PNG 파일을 의미하는 것으로 판단했고, 문장 구조를 보아 `GREEN 1.png`, `RED 3.png` 각 파일에 1개씩 정보가 숨겨진 것으로 예상했다. 파일 이름에 적힌 `1`, `3` 숫자의 의미는 감이 오지 않아 우선 이어서 다른 분석을 진행했다.

`GREEN 1.png`, `RED 3.png` 파일 모두 가짜 FLAG처럼 보이는 값이 적혀 있었으며, 특히 `RED 3.png` 이미지 파일은 유독 전체적으로 푸르스름하게 보였다.

!["GREEN 1 통계"](/Resources/images/Easy-forensic-pyanal1.png)  
*그림 3. Python으로 확인한 GREEN 1.png 픽셀 통계*

`GREEN 1.png`의 G채널은 R, B채널과 비교했을 때 일부 값이 일정하게 이동해 있었다. R, B채널에서 0, 17, 52이던 값이 G채널에서는 2, 19, 54로 +2씩 커졌고, 255는 253으로 −2만큼 작아졌다. 이는 한 비트만 뒤집혔을 때 나타나는 변화량이며, 2는 `0b00000010`이므로 비트 1이 수정된 것으로 판단했다. 따라서 `GREEN 1`은 G채널의 비트 1을 의미한다고 유추할 수 있었다. (비트 번호는 LSB를 0번째로 기준)

!["RED 3 통계"](/Resources/images/Easy-forensic-pyanal2.png)  
*그림 4. Python으로 확인한 RED 3.png 픽셀 통계*

`RED 3.png`에서는 R채널의 일부 값이 G, B채널보다 8만큼 낮아져 있었다. 105는 97, 221은 213, 255는 247처럼 바뀐 값의 차이가 모두 8이었고, R채널 평균도 약 8 낮았다(245.6 vs 253.5). 8은 `0b00001000`이므로 비트 3이 수정된 것으로 판단했고, `RED 3`은 R채널의 비트 3을 의미한다고 유추할 수 있었다.

> **RED 3.png 이미지가 푸르스름하게 보인 이유**  
> R평균(245.6)이 G, B(253.5)보다 낮아서 상대적으로 G, B가 강하게 보여 푸르스름하게 보인 것이다.

!["전체 통계"](/Resources/images/Easy-forensic-pyanal3.png)  
*그림 5. Python으로 확인한 전체 픽셀 통계*

`GREEN 1.png`는 R과 B 채널이 모든 픽셀에서 동일하고 G 채널만 다르다. `RED 3.png`는 G와 B 채널이 모든 픽셀에서 동일하고 R 채널만 다르다. 즉, 파일 이름의 색상과 같은 채널만 수정되어 있었고, 두 이미지 모두 B 채널은 수정되지 않았다. 수정된 채널을 수정되지 않은 B채널과 비교하면, 값이 다른 픽셀이 곧 숨겨진 비트가 뒤집힌 위치이다. `GREEN 1.png`는 G채널과 B채널을, `RED 3.png`는 R채널과 B채널을 비교해 값이 다른 픽셀은 흰색, 같은 픽셀은 검은색으로 채웠다.

## PoC (Proof of Concept)
1. `Image.png` 이미지 파일에서 HxD로 ZIP 파일을 추출 및 압축 해제한다.
2. `GREEN 1.png`와 `RED 3.png`에 숨겨진 정보를 획득한다.
3. 획득한 정보로 `FLAG.png`에 작성된 문장을 완성해 FLAG를 계산한다.

!["GREEN 1 차이 지도(G vs B)"](/Resources/images/Easy-forensic-diff_G_vs_B.png)  
*그림 6. GREEN 1.png 차이 치도*

`FLAG.png`에서 `<GREEN 1>`에 해당하는 글자를 확인할 수 있다.

!["RED 3 차이 지도(R vs B)"](/Resources/images/Easy-forensic-diff_R_vs_B.png)  
*그림 7. RED 3.png 차이 치도*

`FLAG.png`에서 `<RED 3>`에 해당하는 글자를 확인할 수 있다.

### FLAG 획득
`GREEN 1.png`와 `RED 3.png`에서 얻은 단서를 토대로 `FLAG.png` 문장을 완성하면 FLAG 값을 쉽게 구할 수 있다.

## Conclusion
- PNG는 `IEND` 이후의 데이터를 이미지 뷰어가 읽지 않는다. 그래서 정상적으로 열리는 이미지 뒤에도 다른 파일이 붙어 있을 수 있으며, 푸터 시그니처 이후 영역을 확인하는 습관이 필요하다.
- 정보는 `LSB(비트 0)`가 아닌 비트 `1`, `3`에 숨겨져 있었다. 비트 0만 단순 추출했다면 놓쳤을 것이다.