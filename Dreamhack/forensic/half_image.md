# half image - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: forensic
- Difficulty (subjective): easy
- Points: 1
- Provided Files: flag.png, flag.py
- tools: HxD
## Brief Description
For some reason a flag image was cut in half Can you find the reason and get the flag?
## Initial Analysis
### Code
``` python
from PIL import Image
img = Image.open("testfile.png").convert("RGB") 
width, height = img.size
hw = width // 2
left = img.crop((0, 0, hw, height))
right = img.crop((hw, 0, width, height))
left.save("left.png")
rdata = right.tobytes()
with open("left.png", "rb") as fl: lp = fl.read()
with open("flag.png", "wb") as f_out:
    f_out.write(lp)
    f_out.write(rdata)
```
FLAG 이미지를 세로로 절반으로 나눈 후, 왼쪽 데이터는 png 이미지로 저장하고 오른쪽 데이터는 byte로 변환하여 이어서 저장한다.  
### flag.png
![](/Resources/images/half_image-half_flag.jpg 'half flag')
### flag.png File Signature
- Header Signature: `89 50 4E 47 0D 0A 1A 0A`
- Footer Signature: `49 45, 4E 44 AE, 42, 60, 82`

HxD를 통해 flag.png에 Footer Signature가 존재하는지 먼저 확인한 결과 다음과 같이 존재하는 것을 확인할 수 있었다.  

![](/Resources/images/half_image-Header_Signature.jpg 'header')
![](/Resources/images/half_image-Footer_Signature.jpg 'footer')
## PoC(Poof of Concept)
``` python
from PIL import Image


with open('flag.png', 'rb') as f_in :
    data = f_in.read()

footerSignature = bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82])
splitPoint = data.find(footerSignature)
leftData = data[:splitPoint + len(footerSignature)]
rightData = data[splitPoint + len(footerSignature):]

with open('tmp.png', 'wb') as f_tmp :
    f_tmp.write(leftData)

leftImg = Image.open('tmp.png')
rightImg = Image.frombytes("RGB", (leftImg.width, leftImg.height), rightData)    

w = leftImg.width + rightImg.width
h = leftImg.height
combinedImg = Image.new('RGB', (w, h))
combinedImg.paste(leftImg, (0, 0))
combinedImg.paste(rightImg, (leftImg.width, 0))
combinedImg.save('combined_img.png')
```
flag.png 파일을 읽은 후, 푸터 시그니처까지의 왼쪽 데이터를 tmp.png 이미지로 저장했다. 이후 tmp.png의 크기를 기반으로 오른쪽 데이터를 byte에서 이미지 데이터로 변환한 후, combined_img.png 파일에 왼쪽 오른쪽 이미지 데이터를 함께 저장했다.  
### Result
![](/Resources/images/half_image-FLAG.jpg 'FLAG')