# Hefty Image - Dreamhack
## Challenge Info
- Date: 2026
- CTF Name: Dreamhack
- Category: forensic
- Difficulty (subjective): easy
- Points: 1
- Provided Files: challenge.jpg
- Tools: HxD
## Brief Description
친구가 여행 중에 찍은 사진이라며 파일을 하나 보내왔습니다. 그런데, 평범한 사진 파일치고는 용량이 조금 묵직하네요.  
단순히 사진만 있는 게 아닌 것 같습니다. 이미지 파일 속에 숨겨진 비밀을 파헤쳐 플래그를 획득하세요!
## Initial Analysis
### 이미지 파일 관찰
제공 받은 `challenge.jpg` 이미지 파일이 윈도우 기본 사진 앱을 통해 정상적으로 열리는 것을 확인했다. 문제 설명을 보면 파일 안에 이미지 데이터 외에 다른 데이터 혹은 파일이 숨겨져 있을 것으로 예상했다.

### 시그니처 검사
JPG 파일 시그니처는 다음과 같다. (JFIF 포맷)

| 구분 | 시그니처 |
| --- | --- |
| 헤더 | FF D8 FF E0 |
| 푸터 | FF D9 |

!["HxD jpg 시그니처 확인 1"](/Resources/images/Hefty%20Image-jpg_signature_1.png)  
*그림 1. HxD로 확인한 `challenge.jpg`의 헤더 시그니처*

HxD로 `challenge.jpg`의 헤더 시그니처를 확인한 결과, 정상적인 JPG 헤더였다.

!["HxD jpg 시그니처 확인 2"](/Resources/images/Hefty%20Image-zip_signature_1.png)  
*그림 2. JPG 푸터(`FF D9`) 뒤에 이어지는 ZIP 헤더 시그니처*

이어서 `찾기-16진수` 기능으로 푸터 시그니처를 확인했다. 정상적인 JPEG는 `FF D9`에서 끝나야 하지만, 이 파일은 `FF D9` 뒤에 ZIP 파일 헤더 시그니처(`50 4B 03 04`)가 이어져 있었다. 이미지 뷰어는 `FF D9`까지만 해석하기 때문에, 뒤에 데이터가 덧붙어 있어도 사진은 정상적으로 열린다. 또한 `flag.txt`라는 파일명과 FLAG로 보이는 데이터도 함께 확인되었다.

## PoC (Proof of Concept)
1. HxD에서 `50 4B 03 04`부터 파일 끝까지 선택하여 복사한다.
2. 새 파일에 붙여넣고 `.zip` 확장자로 저장한다.
3. 압축을 해제하면 `flag.txt`에서 FLAG를 확인할 수 있다.

!["zip 파일 추출"](/Resources/images/Hefty%20Image-extracted_zipfile.png)  
*그림 3. 추출한 데이터를 ZIP 파일로 저장*

!["zip 파일 압축 해제"](/Resources/images/Hefty%20Image-unpack.png)  
*그림 4. ZIP 파일 압축 해제*

!["FLAG 획득"](/Resources/images/Hefty%20Image-flag.png)  
*그림 5. FLAG 획득*

## Conclusion
JPG 푸터(`FF D9`) 뒤에 ZIP 파일이 덧붙여진 형태였으며, 이를 추출하여 FLAG를 획득했다.