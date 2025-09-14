# Challenge Name - CTF Name
## Challenge Info
- Date: YYYY-MM-DD
- CTF Name:
- Category: rev
- Difficulty (subjective): easy/medium/hard
- Points:
- Provided Files:
- tools:
## Brief Description
I have been playing with a safe lock and a logic analyzer for a while. But I forgot which buttons I pressed, could you take a look?
Note: There are no brackets on the keypad, but you will figure out where they go, won't you?
## Initial Analysis
### Environment
### Code
## Vulnerability
### Vulnerability Summary
| Type | Location | Cause | Impact | Exploitability | Notes |
| --- | --- | --- | --- | --- | --- |
## Exploit
### Strategy
### Payload Components
### Exploitation Steps
### Stack Frame of main
| Variable Name | Offset from EBP |
| --- | --- |
### payload
``` python
from pwn import *
```
## Lessons Learned
## Mitigation Strategies(Remediation)