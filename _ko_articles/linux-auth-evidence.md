---
title: "Linux 인증 로그로 조사하기 · SSH, PAM, sudo"
description: "SSH 인증·PAM 세션·sudo 기록의 차이를 이해하고 가상 로그 14건으로 타임라인을 만듭니다."
category: dfir
tags: [Linux, SSH, Authentication, Blue Team, DFIR, Event Logs]
level: Beginner
updated: "2026-11-20"
translation_url: /wiki/linux-auth-evidence/
---

**학습 목표:** SSH 로그인 실패, 인증 성공, 세션 열림, sudo 허용을 따로 읽고 같은 호스트·계정·시간대의 기록을 연결합니다. 처음이라면 1–3절을 읽은 뒤 6절의 데이터를 직접 따라가 보세요.

## 1. 로그인과 관리자 권한 사이에는 여러 단계가 있습니다

SSH(Secure Shell)는 원격 시스템에 연결하고 보안 채널 안에서 사용자를 인증하는 프로토콜입니다. 인증은 계정에 들어올 자격을 확인하는 단계입니다. 권한 부여는 로그인한 계정이 어떤 일을 할 수 있는지 정합니다. **sudo**는 정책이 허용하는 경우 대상 사용자 권한으로 특정 명령을 실행하도록 요청합니다. 대상이 root인 경우가 흔하지만 다른 계정일 수도 있습니다.

![연결 후 SSH 인증, 세션 열림, sudo 정책 확인, 명령 결과가 차례로 구분되는 흐름]({{ '/assets/diagrams/linux-auth-flow-ko.svg' | relative_url }})

예를 들어 Alex가 승인된 관리 호스트에서 공개키로 로그인하고, 허용된 상태 조회 명령을 sudo로 실행했다고 가정합니다. 연결이 열리면 SSH 전송 계층이 암호화 채널을 만들고, 클라이언트는 사용자 인증을 수행합니다. 키 인증에서는 클라이언트가 키 보유를 증명하고 서버가 계정의 정책에 따라 확인합니다. 그다음 서버가 요청한 세션이나 채널을 열 수 있습니다. 파일 전송이나 비대화형 명령도 가능하므로 인증 성공을 대화형 셸 사용으로 단정하지 않습니다.

**PAM(Pluggable Authentication Modules)**은 Ubuntu 같은 Linux 환경에서 서비스가 인증·계정·세션 처리에 사용하는 모듈 체계입니다. SSH 공개키 인증이 성공해도 배포 설정에 따라 PAM 계정·세션 처리가 이어질 수 있습니다. PAM 세션 메시지는 해당 처리 단계의 기록으로 읽으세요.

## 2. 어떤 로그 줄이 무엇을 뒷받침하나요?

아래는 흔히 볼 수 있는 메시지를 짧게 재구성한 예입니다. 버전과 정책에 따라 프로세스 이름, 형식, 필드가 달라집니다. 가상 CSV는 학습용으로 정규화한 자료라 아래 문자열을 직접 파싱하지 않습니다.

~~~text
sshd[2417]: Failed password for alex from 192.0.2.10 port 51512 ssh2
sshd[2431]: Accepted publickey for alex from 192.0.2.10 port 51516 ssh2
sshd[2431]: pam_unix(sshd:session): session opened for user alex(uid=1001)
sudo[2450]: alex : TTY=pts/1 ; PWD=/home/alex ; USER=root ; COMMAND=/usr/bin/id
~~~

| 관측 | 의미 | 다음에 볼 증거 |
| --- | --- | --- |
| Failed password | 지정된 인증 요청이 실패 | 같은 호스트와 계정의 뒤이은 인증, 원격 주소, 접속 기록 |
| Accepted publickey / password | 서버가 적어도 기록된 방법으로 사용자 인증을 수락 | 세션 열림, 계정·키 지문이 수집됐는지, 정상 작업 일정 |
| session opened / closed | 해당 PAM 서비스의 세션 단계 기록 | 서비스·PID·호스트·부팅·세션 식별자 |
| sudo 허용·거절 | 정책이 특정 호출을 허용 또는 거절한 관측 | 호출자, 실행 대상, TTY·작업 경로·명령, 정책 및 감사 |
| 프로세스·파일 감사 | 실행이나 상태 변화의 별도 증거 | 실제 종료 상태, 후속 프로세스·파일·앱 결과 |

sudo 줄의 맨 앞 alex는 **호출자**, USER=root는 **실행 대상**입니다. TTY는 터미널, PWD는 당시 작업 디렉터리입니다. COMMAND는 기록된 요청 명령입니다. 허용 로그만으로 반환 코드 0이나 파일 변경을 입증하지 못합니다. 실행 감사 또는 서비스·파일 로그를 대조하세요. sudo I/O 기록은 별도 설정과 보존 정책이 필요한 자료입니다. 로그에는 명령 인자 등 민감한 값이 포함될 수 있습니다.

## 3. 먼저 어느 호스트에서 무엇을 수집하는지 확인하세요

systemd 환경이라면 권한이 있는 조사 계정으로 아래처럼 최근 기록과 서비스 이름을 확인할 수 있습니다. 관리 정책을 따르고, 조사 기록에는 필터와 UTC 범위를 남깁니다.

~~~bash
systemctl list-unit-files 'ssh*.service'
journalctl --utc --since "30 minutes ago" -t sshd -t sshd-session --no-pager
journalctl --utc --since "30 minutes ago" -t sudo --no-pager
~~~

- journalctl의 **-t**는 로그 식별자(SYSLOG_IDENTIFIER)를 기준으로 고릅니다. 위 두 SSH 식별자는 후보입니다. 설치 버전에 따라 별도 인증 프로세스 이름과 식별자가 추가로 쓰일 수 있습니다. 읽은 행의 원문과 메타데이터를 확인하세요.
- **-u**로 조회할 때는 실제 유닛 이름을 써야 합니다. 예를 들어 Ubuntu의 일반적인 이름은 ssh.service입니다. 다른 배포판이나 별도 인스턴스에서는 달라질 수 있습니다.
- 파일 로그는 구성에 따라 /var/log/auth.log, /var/log/secure, 중앙 로그 등으로 전달됩니다. journald와 syslog에 같은 이벤트가 있을 수 있으므로 센서·원문·수집 시각으로 중복을 확인합니다.
- 중앙 수집에는 호스트, UTC, 원본 메시지, 서비스, PID, 가능한 경우 부팅 ID와 감사 세션 ID를 남기세요. systemd의 _BOOT_ID와 _AUDIT_SESSION은 조건에 따라 붙는 메타데이터입니다. 후자가 없으면 숫자를 만들어 채우지 않습니다.

결과가 없으면 권한, 시간 범위, 호스트, 유닛·식별자, 저널 보존, 순환 로그, 전달 상태의 순서로 확인하세요. 승인된 정상 로그인 한 건이 로컬 원본과 중앙 수집 모두에 뜨는지 비교하면 어느 구간에서 빠졌는지 좁힐 수 있습니다. 이 장의 명령은 읽기 전용 예입니다. 제품별 메시지와 수집 경로는 자체 환경에서 검증합니다.

## 4. 정상 관리자 작업과 의심 활동을 나눠 해석하기

| 관측 | 가능한 정상 설명 | 보안 가설을 좁힐 자료 |
| --- | --- | --- |
| 실패 여러 건 뒤 로그인 성공 | 암호 오타 또는 정상 자동화 재시도 | 자산별 허용 인증 방법, 접속 주소, 관리자 일정 |
| 한 주소에서 여러 계정 실패 | 승인된 점검 또는 오래된 서비스 설정 | 동일 주소 뒤의 NAT·점프 서버, 대상 폭과 평소 빈도 |
| 익숙하지 않은 키로 인증 성공 | 정기 키 교체 | 승인된 키 목록과 등록 이력, 계정 소유자 확인 |
| 세션 뒤 sudo 거절·허용 | 정상 작업 중 잘못된 명령 후 수정 | sudo 정책, 업무 승인, 실행 대상·명령, 후속 프로세스 |

로그인 정보 악용은 정상 관리와 같은 SSH 경로를 사용할 수 있습니다. 그래서 **실패 → 성공 → 권한 사용**은 조사 우선순위를 조정하는 단서입니다. IP만으로 개인을 식별하지 마세요. 점프 서버나 NAT를 지나면 여러 사람이 같은 주소로 보일 수 있습니다.

평소 인증 방법과 관리 경로를 기록한 뒤 정상 작업과 다른 성공에 우선순위를 두세요. 운영 통제로는 관리 경로 제한, 계정·키 수명 관리, 불필요한 권한 제거, 최소 범위의 sudo 정책이 있습니다. 변경 전 정상 관리 경로와 복구 접근을 확인합니다.

## 5. 타임라인을 만들고 대응하기

1. 질문을 정합니다. 예를 들어 “app01에서 sam 계정의 성공이 승인된 작업인가?”라고 시작합니다.
2. 해당 호스트 원본과 중앙 로그를 확보합니다. UTC, 로컬 시계 오차, 로그 원본, 부팅 ID, 수집 공백을 기록합니다.
3. 같은 **호스트·부팅·계정·원격 IP**에서 실패와 성공을 시간순으로 비교합니다. IP나 시간만 맞으면 후보 관계로 둡니다.
4. 가능한 경우 신뢰할 수 있는 감사 세션과 호스트·부팅·계정으로 sudo를 대조합니다. 식별자가 없으면 PID·TTY·시각·프로세스 계보를 보강하거나 미연결로 남깁니다. SSH와 sudo PID가 서로 다를 수 있고, PID도 재사용됩니다.
5. 정상 작업과 대조한 뒤 침해 근거가 있다면 승인된 대응 절차로 계정·세션·키의 영향을 좁힙니다. 필요한 경우 세션 종료나 키 폐기 등을 조정하고, 조치 시각 및 정상 서비스 검증 결과를 남깁니다.

사고 기록 예시: **“app01의 sam에서 동일 주소의 인증 실패 3건 후 암호 인증이 수락됐다. 같은 호스트·부팅의 감사 세션 42에서 sudo 거절과 허용 각각 1건이 관측됐다. 작업 승인과 실행 결과는 확인 중이다.”**

## 6. 가상 기록 14건으로 연습하기

[linux-auth-events.csv]({{ '/assets/labs/linux-auth-events.csv' | relative_url }}) · [linux-auth-evidence.py]({{ '/assets/labs/linux-auth-evidence.py' | relative_url }})

두 파일을 한 폴더에 저장하고 Python 3에서 실행합니다. 데이터는 외부 접속 없이 읽는 **가상 정규화 CSV**입니다. IP는 문서용 예시이고, boot와 audit_session은 학습을 위해 미리 보강한 값입니다. 개별 제품의 원시 로그에서 항상 보인다는 뜻은 아닙니다.

~~~bash
python3 linux-auth-evidence.py
~~~

| 실습 관측 | 올바른 해석 |
| --- | --- |
| app01 alex: 실패 1회 뒤 공개키 수락 | 같은 IP의 시간상 연결. 정상 시험이라는 설정을 인벤토리와 대조 |
| app01 sam: 5분 안에 실패 3회 뒤 암호 수락 | 암호 추측 가능성을 조사할 후보. 승인된 작업 여부가 남음 |
| app01 sam의 세션 42 | 같은 호스트·부팅·계정에서 sudo 거절과 허용 각 1건 |
| app02 sam의 세션 42 | 숫자가 같아도 app01과 다른 호스트·부팅. 제공 자료에서 미연결 |
| 다른 IP에서 sam 실패 1건 | 앞선 성공과 별도로 기록 |

마지막에 `PASS: 14 rows, one candidate and four scoped sudo observations`가 나와야 합니다. 파일 오류가 나면 두 파일의 이름과 폴더를 확인하세요. 결과 불일치는 CSV의 UTC, 원격 IP, 부팅 ID, 세션 ID를 보고 원인을 찾습니다. **5분·3회는 실습용 기준값**입니다. 운영 탐지는 로그인 기준선과 수집 상태에 맞춰 조정합니다. 게시 과정에서는 CSV 실행 결과를 검증했습니다. 실제 SSH 세션과 PAM·sudo의 수집은 운영 환경에서 따로 확인해야 합니다.

## 7. 확인 문제와 완료 기준

1. **Accepted publickey 한 줄에서 무엇을 말할 수 있나요?** 해당 인증이 수락됐습니다. 셸·파일 전송·명령 결과는 후속 자료에서 확인합니다.
2. **app02의 세션 42를 app01의 sam과 합칠 수 있나요?** 호스트와 부팅이 다릅니다. app02에서 대응하는 세션을 찾거나 미연결로 둡니다.
3. **sudo 허용이면 관리자 작업이 성공했나요?** 정책 허용과 실제 실행 결과는 다릅니다. 실행·종료 상태와 상태 변화를 추가로 확인합니다.
4. **실패가 검색에 안 나오면 실패가 없었나요?** 인가된 정상 시험으로 원본 생성과 전달, 검색 범위를 확인합니다.

완료하려면 가상 사건에서 정상 사례와 조사 후보를 각각 한 줄로 기록하고, 두 사건에 어떤 출처의 증거가 더 필요한지 적으세요.

관련 학습 · [블루팀 기초]({{ '/ko/wiki/blue-team-basics/' | relative_url }}) · [Windows 이벤트와 비교]({{ '/ko/wiki/windows-logs/' | relative_url }}) · [TCP 연결 증거]({{ '/ko/wiki/tcp-evidence/' | relative_url }})

## 다음 학습

[Linux 프로세스 조사와 PID 재사용]({{ '/ko/wiki/linux-process-evidence/' | relative_url }})

## 공식 자료

2026년 11월 20일 검토. SSH 인증 표준은 2006년 문서이며, 제품 명령·로그 동작은 설치 버전과 배포판 설정을 함께 확인하세요.

- [SSH authentication · RFC 4252 (2006)](https://www.rfc-editor.org/rfc/rfc4252.html)
- [OpenSSH sshd](https://man.openbsd.org/sshd.8) · [sshd_config](https://man.openbsd.org/sshd_config) · [Ubuntu OpenSSH Server](https://ubuntu.com/server/docs/openssh-server)
- [systemd journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html) · [Journal fields](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html)
- [Linux-PAM pam_unix manual](https://man7.org/linux/man-pages/man8/pam_unix.8.html) · [sudoers manual source](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in)

## 사용자 인증 전에 SSH 서버 확인하기

[호스트 키 경고를 읽고 서버 신원과 로그인 증거를 구분합니다]({{ '/ko/wiki/ssh-host-key-evidence/' | relative_url }})

## Linux 저널의 로컬·중앙 수집 범위 확인하기

[부팅·네임스페이스·커서로 저널 수집 누락을 조사하는 실습]({{ '/ko/wiki/linux-journal-coverage/' | relative_url }})

## OpenSSH 사용자 인증서 조사

[OpenSSH 사용자 인증서]({{ '/ko/wiki/ssh-user-certificate-evidence/' | relative_url }})에서 발급 CA와 일련번호, 대상의 인증·인가 설정을 대조합니다.

## sudo 허용 이후의 명령 증거 확인하기

[Linux sudo 명령 조사]({{ '/ko/wiki/linux-sudo-command-evidence/' | relative_url }})에서 허용 기록, 프로세스 실행, 종료 상태와 작업 결과를 연결합니다.
