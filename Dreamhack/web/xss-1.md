# xss-1 - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: web
- Difficulty (subjective): easy
- Points: 1
- Provided Files: app.py, base.html, flag.html, index.html, memo.html
- tools: Burp Suite
## Brief Description
여러 기능과 입력받은 URL을 확인하는 봇이 구현된 서비스입니다.  
XSS 취약점을 이용해 플래그를 획득하세요. 플래그는 flag.txt, FLAG 변수에 있습니다.  

플래그 형식은 DH{...} 입니다.
## Initial Analysis
### Environment
- framework: 
    - flask
    - Selenium
- URL End-Point:
    - /memo
    - /vuln
    - /flag
### Code
``` python
#!/usr/bin/python3
from flask import Flask, request, render_template
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
import urllib
import os

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open("./flag.txt", "r").read()
except:
    FLAG = "[**FLAG**]"


def read_url(url, cookie={"name": "name", "value": "value"}):
    cookie.update({"domain": "127.0.0.1"})
    try:
        service = Service(executable_path="/chromedriver")
        options = webdriver.ChromeOptions()
        for _ in [
            "headless",
            "window-size=1920x1080",
            "disable-gpu",
            "no-sandbox",
            "disable-dev-shm-usage",
        ]:
            options.add_argument(_)
        driver = webdriver.Chrome(service=service, options=options)
        driver.implicitly_wait(3)
        driver.set_page_load_timeout(3)
        driver.get("http://127.0.0.1:8000/")
        driver.add_cookie(cookie)
        driver.get(url)
    except Exception as e:
        driver.quit()
        # return str(e)
        return False
    driver.quit()
    return True


def check_xss(param, cookie={"name": "name", "value": "value"}):
    url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
    return read_url(url, cookie)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    return param


@app.route("/flag", methods=["GET", "POST"])
def flag():
    if request.method == "GET":
        return render_template("flag.html")
    elif request.method == "POST":
        param = request.form.get("param")
        if not check_xss(param, {"name": "flag", "value": FLAG.strip()}):
            return '<script>alert("wrong??");history.go(-1);</script>'

        return '<script>alert("good");history.go(-1);</script>'


memo_text = ""


@app.route("/memo")
def memo():
    global memo_text
    text = request.args.get("memo", "")
    memo_text += text + "\n"
    return render_template("memo.html", memo=memo_text)


app.run(host="0.0.0.0", port=8000)
```
## Vulnerability
### XXS(Cross Site Scripting)
``` python
@app.route("/vuln")
def vuln():
    param = request.args.get("param", "")
    return param
```
`/vuln` 엔드포인트는 이용자가 입력한 값을 페이지에 그대로 출력하기 때문에 XSS가 발생한다.
## Exploit
### Strategy
`/flag` 엔드포인트 내부에서 `/vuln` 엔드포인트를 사용하기 때문에, `/flag` 엔드포인트에 `<script>location.href = "/memo?memo=" + document.cookie;</script>`과 같은 익스플로잇 코드를 입력하면 `/memo`에서 FLAG를 확인 가능하다. 
### Exploitation Steps
### PoC(Poof of Concept)