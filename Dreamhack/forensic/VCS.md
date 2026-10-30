# VCS - Dreamhack
## Challenge Info
- Date: 2026
- CTF Name: Dreamhack
- Category: forensic
- Difficulty (subjective): easy
- Points: 1
- Provided Files: flag.txt, .git/
- Tools: git
## Brief Description
Flag 형식은 DH{...}입니다.
## Initial Analysis
### 폴더 구조 탐색
``` text
C:.
│  flag.txt
│
└─.git
    │  config
    │  HEAD
    │  index
    │
    ├─logs
    │      HEAD
    │
    ├─objects
    │  ├─10
    │  │      7f7e0fe107b8f2446d7b2fbf08dbf1457a161f
    │  │
    │  ├─2a
    │  │      bfa68299544d62f1dcab0c5385cdbd6f938990
    │  │
    │  ├─49
    │  │      e9313c067f3f57cdf21fcdb3959263cc6b7721
    │  │
    │  ├─8c
    │  │      9e2af0b68dac69e8dcb3d79484ab03f65edca5
    │  │
    │  ├─95
    │  │      42483450a4b8796aa07d3ddc96e2b90003a93a
    │  │
    │  ├─ac
    │  │      871165928ec26d3d7c443dbfe95b5c8ca31ce9
    │  │
    │  ├─info
    │  └─pack
    └─refs
        ├─heads
        │      main
        │
        └─tags
```
*그림 1. tree /f 명령어 결과*

!["cat flag.txt"](/Resources/images/VCS-cat1.png)  
*그림 2. flag.txt 내용*

`flag.txt` 파일에 FLAG가 적혀있는 것을 확인했으나, 제출 결과 가짜 FLAG임을 확인했다. (기대도 안 했다.)

### git 브랜치/커밋 기록 확인
!["git branch -a"](/Resources/images/VCS-branch.png)  
*그림 3. git 브랜치 확인 결과*

메인 브랜치 외 다른 브랜치는 존재하지 않는 것을 확인했다.

!["git log"](/Resources/images/VCS-log.png)  
*그림 4. git 커밋 로그*

git 커밋 기록에도 현재 HEAD 위치의 커밋 외 다른 커밋 기록은 존재하지 않은 것을 확인했다. 또한 이미지에는 없지만, `git status` 명령어로 확인 결과 변동된 내용은 없었다.

> **왜 보이지 않았을까?**  
> 브랜치는 커밋 해시가 적힌 `refs/heads/` 아래의 파일(ref)일 뿐이다. `git branch -a`는 이 ref 파일을 읽어서 목록을 보여주고, `git log`는 현재 HEAD에서 parent를 따라 **도달 가능한 커밋만** 보여준다. 삭제된 브랜치의 커밋은 어떤 ref에서도 가리키지 않는 상태가 되므로 두 명령어 모두에 나타나지 않는다. 실제로 `.git/refs/heads/`에는 `main` 파일만 존재했다 (그림 1).

### git reflog 기록 확인
!["git reflog"](/Resources/images/VCS-reflog.png)  
*그림 5. reflog 기록*

reflog에서 `audit/recovery` 브랜치로 이동해 기록 추가 커밋(107f7e0)을 생성한 뒤 `main`으로 돌아온 기록을 확인했다. `refs/heads/`에는 `main`만 있어 `audit/recovery` 브랜치는 삭제된 것으로 보이며, 그래서 `git branch -a`에는 나타나지 않는다. 하지만 커밋 오브젝트는 `objects/`에 남아 있었다.

## PoC (Proof of Concept)
1. reflog에서 확인한 `audit/recovery` 브랜치의 커밋 해시로 이동 (명령어: `git checkout 107f7e0`)
2. flag.txt 확인

!["git checkout"](/Resources/images/VCS-checkout.png)  
*그림 6. git checkout 결과*

> **왜 `audit/recovery`는 실패하고 해시는 성공했을까?**  
> `git checkout audit/recovery`는 브랜치 이름(ref)으로 찾는데, 해당 ref 파일이 삭제되어 실패했다. 반면 커밋 오브젝트(`objects/10/7f7e0...`)는 삭제되지 않고 남아 있어서, 해시로 직접 지정하면 접근이 가능하다. 이때 ref가 아닌 커밋을 직접 가리키므로 `detached HEAD` 상태가 된다.

!["git log"](/Resources/images/VCS-log2.png)  
*그림 7. git 커밋 로그*

!["flag"](/Resources/images/VCS-flag.png)  
*그림 8. FLAG 확인*

## Conclusion
BPB는 구조가 고정되어 있어 오프셋만 알면 파일 시스템 종류, 볼륨 크기, 시리얼 번호를 바로 읽을 수 있다. 이를 적용해 A, B, C를 구하고 합산하여 FLAG를 얻었다.
- 배운 점: 리틀 엔디언 해석, FAT32와 NTFS의 VBR 구조 차이