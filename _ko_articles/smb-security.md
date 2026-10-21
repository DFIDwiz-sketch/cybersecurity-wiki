---
title: "SMB 완전 가이드: 원격접속, 원격 실행, 주요 공격과 DFIR 탐지·방어"
description: "SMB 기본 구조부터 RDP와의 차이, PsExec 원격 명령 실행, NTLM Relay, Pass-the-Hash, Windows 로그, Splunk 분석과 보안 강화 방법을 설명합니다."
category: network
tags: [Windows Security, SMB, Network Security, Active Directory, NTLM, Lateral Movement, Remote Execution, PsExec, Blue Team, Red Team, DFIR, Splunk, Detection Engineering]
level: Intermediate
updated: "2026-10-22"
translation_url: /wiki/smb-security/
---

> **문서 목적:** SMB의 원리를 배우고 정상적인 원격 관리와 공격자의 횡적 이동을 DFIR 관점에서 구별하기 위한 실무 가이드입니다. 호스트명과 로그는 가상의 예시이며 관리 명령은 허가된 환경에서만 사용하세요.

## 1. SMB란 무엇인가요?

**SMB(Server Message Block)**는 네트워크를 통해 다른 컴퓨터의 **파일·폴더·프린터·공유 리소스와 일부 프로세스 간 통신**을 이용하는 프로토콜입니다. Windows의 기본 파일 공유 프로토콜이고 Linux의 Samba 및 macOS도 지원합니다.

예를 들어 `\\fileserver\Finance`는 SMB 공유에 접근하는 **UNC 경로**입니다. 회사에서는 파일 서버뿐 아니라 Active Directory의 `SYSVOL`·`NETLOGON`과 Windows 관리용 **Named Pipe 기반 RPC**에도 SMB가 사용됩니다.

### SMB 포트

| 포트 | 역할 |
| --- | --- |
| **TCP 445** | 최신 SMB 통신의 중심 포트 |
| TCP 139 | 구형 NetBIOS 세션을 이용한 SMB |
| UDP 137/138 | 레거시 NetBIOS 이름 조회·데이터그램. 일반적인 파일 전송 포트는 아님 |
| UDP 443 | 지원되는 환경에서 별도로 설정하는 SMB over QUIC |

### SMB 버전

| 버전 | 핵심 특징과 주의사항 |
| --- | --- |
| **SMBv1** | 구형 프로토콜. MS17-010/EternalBlue 등으로 잘 알려져 있으며 사용 중단 권장 |
| **SMB 2.x** | 성능과 통신 구조 개선. Signing과 접근 통제가 중요 |
| **SMB 3.x / 3.1.1** | Encryption 등 보안 기능 지원. 3.1.1은 Pre-authentication Integrity 도입 |

**중요:** SMB 3.1.1로 연결됐다고 해서 모든 공유 파일이 자동으로 암호화되는 것은 아닙니다. 실제 협상된 보안 기능을 확인해야 합니다.

## 2. SMB가 원격접속에도 사용되나요?

**네. 다만 RDP처럼 원격 컴퓨터의 화면을 표시하는 기술은 아닙니다.** SMB는 원격 공유 폴더와 Named Pipe에 접근하게 해 주며, **RPC나 서비스 제어 기능과 결합되면 원격 명령 실행을 지원하는 수단**이 됩니다.

![RDP와 SMB 원격접속 방식 비교]({{ '/assets/diagrams/smb-remote-comparison-ko.svg' | relative_url }})

| 기술 | 대표 포트 | 원격접속의 의미 | SMB 사용 |
| --- | --- | --- | --- |
| **RDP** | TCP/UDP 3389 | 원격 데스크톱 화면·키보드·마우스 | 기본 화면 통신에 SMB 불필요 |
| **SSH** | TCP 22 | 원격 터미널과 명령 실행 | 기본 연결에 SMB 불필요 |
| **WinRM / PowerShell Remoting** | TCP 5985/5986 | 원격 PowerShell 및 관리 | 일반적인 명령 채널에는 SMB 불필요 |
| **SMB 파일 공유** | TCP 445 | 원격 공유 파일의 읽기·쓰기 | 주 프로토콜 |
| **PsExec 방식 실행** | TCP 445 및 구성에 따른 RPC | 관리자 공유와 서비스 제어를 활용한 원격 명령 | 보통 SMB 핵심 사용 |
| **WMI / DCOM 원격 관리** | RPC 관련 포트 | 원격 시스템 관리 | 일부 흐름에서 SMB와 연계되지만 필수는 아님 |

즉 **SMB로 서버에서 명령을 실행했다는 말과 RDP로 로그인했다는 말은 서로 다릅니다.** 또한 TCP 445로 연결했다고 모두 원격 명령을 실행했다는 의미도 아닙니다.

## 3. 정상 SMB 연결의 순서

1. **이름 조회:** DNS 등으로 파일 서버의 IP를 확인합니다.
2. **SMB NEGOTIATE:** SMB 버전과 보안 기능을 협상합니다.
3. **SESSION_SETUP:** Windows에서는 보통 **Kerberos 또는 NTLM**으로 인증합니다.
4. **TREE_CONNECT:** `\\server\Finance` 같은 공유 리소스에 연결합니다.
5. **CREATE/OPEN, READ, WRITE, CLOSE:** 권한이 허용된 파일을 열고 읽거나 쓰고 닫습니다. `CREATE`는 기존 파일을 여는 동작도 포함합니다.
6. **연결 해제:** 파일 핸들, 공유 연결 또는 세션을 종료합니다.

도메인 Kerberos 인증에서는 `cifs/server` 같은 SPN에 대한 서비스 티켓을 사용할 수 있습니다. NTLM은 챌린지-응답 방식이며 **NetNTLMv2 응답과 NT Hash 자체는 서로 다릅니다.**

### 대표적인 공유 리소스

| 공유 이름 | 용도 | 조사 포인트 |
| --- | --- | --- |
| `\\server\Finance` | 일반 업무용 파일 공유 | 비정상적인 파일 읽기·수정 |
| `C$` | C 드라이브 관리 공유 | 일반 PC에서의 예기치 않은 접근 |
| `ADMIN$` | Windows 시스템 디렉터리 관리 공유 | 파일 복사 및 원격 실행 흔적 |
| `IPC$` | Named Pipe 등 프로세스 간 통신 | RPC 관련 활동 |
| `SYSVOL`, `NETLOGON` | AD 그룹 정책 및 로그온 관련 공유 | 정상 트래픽이 많아 기준선 중요 |

**IPC$가 존재한다는 사실만으로 익명 Null Session이 허용되는 것은 아닙니다.**

## 4. PsExec는 SMB로 어떻게 원격 명령을 실행하나요?

![SMB 및 RPC를 이용한 원격 명령 실행 흐름도]({{ '/assets/diagrams/smb-remote-execution-ko.svg' | relative_url }})

정상 관리자 도구인 PsExec 또는 비슷한 서비스 기반 원격 실행 방법을 예로 살펴보겠습니다.

1. **관리 권한 인증:** 관리자나 공격자가 대상 서버에 대한 충분한 관리 권한으로 인증합니다.
2. **관리 공유 접근:** SMB를 통해 대상 서버의 `ADMIN$` 등에 연결합니다. 구현에 따라 원격 실행에 필요한 서비스 파일을 복사합니다.
3. **RPC 서비스 관리:** **Service Control Manager(SCM)**에 RPC로 접근하여 서비스를 생성하거나 시작합니다. 일부 방식에서는 SMB의 Named Pipe를 통해 RPC를 운반합니다.
4. **대상 서버에서 실행:** 해당 서비스가 원격 컴퓨터에서 프로그램이나 명령을 실행합니다.
5. **실행 결과 수신:** 구현에 따라 Named Pipe 등으로 명령 출력과 상태를 전달합니다.

**정확하게 구분해야 합니다.** SMB는 파일 복사와 RPC 통신 경로를 제공할 수 있지만, **서비스를 생성·시작하는 동작 자체는 SCM의 RPC 기능**입니다. 구현마다 서비스 파일 복사 여부, RPC 전송 경로, 결과 수신 방식이 다릅니다.

따라서 원격 관리 도구를 사용했다고 대상 서버의 데스크톱에 로그인한 것은 아닙니다. **적절한 원격 관리자 권한**이 필요하며 정상 관리 작업에도 이러한 패턴이 발생할 수 있습니다.

## 5. SMB를 겨냥한 주요 공격

| 공격 | 원리 | 주요 탐지 수단 | 대표적인 방어 |
| --- | --- | --- | --- |
| **SMB Enumeration** | 열려 있는 445와 공유·계정·설정 조사 | 연결 패턴, 5140·5145 | 445 접근 제한, 최소 권한 |
| **Null Session / 익명 접근** | 잘못 허용된 익명 SMB/RPC 조회 | 공유 감사, 계정·접근 검사 | 불필요한 익명 접근 제한 |
| **LLMNR/NBT-NS Spoofing** | 이름 조회를 속여 가짜 SMB 서버로 유도 | 잘못된 이름 응답, 외부 SMB/NTLM | 불필요한 이름 조회 차단 |
| **NTLM Capture** | 피해자의 NetNTLM 인증 응답 수집 | 비정상 NTLM 교환 | NTLM 축소, 목적지 차단 |
| **NTLM Relay** | 실시간 NTLM 인증을 다른 SMB 서버에 중계 | 인증 이상 + 후속 SMB/RPC 활동 | **SMB Signing 필수** |
| **Pass-the-Hash** | 이미 확보한 **NT Hash**로 NTLM 인증 | 4624 Type 3, 계정·출발지 이상 | LAPS, Credential Guard, NTLM 축소 |
| **Password Spraying** | 여러 계정에 비밀번호 후보를 온라인 시도 | 4625, 4776 등 | 계정 보안과 실패 탐지 |
| **Admin Share Abuse** | `ADMIN$`, `C$` 등 관리자 공유 사용 | 5140·5145, 파일 생성 | 관리자 권한 제한 |
| **PsExec 방식 횡적 이동** | SMB 파일 복사와 RPC 서비스 실행 | 4624 → 5140/5145 → 7045 → 4688 | 네트워크 세분화, EDR |
| **EternalBlue / MS17-010** | 취약한 SMBv1 서버 악용 | IDS/EDR, 패치 상태 | SMBv1 제거, MS17-010 패치 |
| **SMBGhost / CVE-2020-0796** | 과거 특정 SMB 3.1.1 압축 처리 취약점 | 취약 빌드 식별, IDS | 보안 업데이트 |
| **Forced Authentication** | 원격 UNC 경로·RPC 등으로 SMB 인증 유도 | 낯선 UNC/445 연결, NTLM | 불필요한 445·NTLM 차단 |
| **공유 데이터 탈취·랜섬웨어** | 기존 접근 권한으로 대량 파일 읽기·수정 | 5145·4663, EDR, 파일 변경량 | ACL, 백업, 행위 탐지 |

### NTLM Capture, NTLM Relay, Pass-the-Hash 차이

이 세 기법은 동일하지 않습니다.

- **Capture:** NTLM 인증 과정의 **NetNTLM 챌린지-응답**을 확보합니다. 이것은 NT Hash 자체가 아니며 오프라인 암호 추측에 쓰일 수 있습니다.
- **Relay:** 현재 진행 중인 NTLM 인증 교환을 다른 서비스로 중계합니다. 성공에 비밀번호 복구가 반드시 선행되는 것은 아닙니다.
- **Pass-the-Hash:** 별도로 탈취해 확보한 **NT Hash**를 이용하여 NTLM 인증을 수행합니다.

**SMB Signing은 보통 SMB를 대상으로 하는 NTLM Relay를 막는 핵심 수단**이지만 이미 획득한 유효한 NT Hash로 이루어지는 PtH를 그 자체로 막지는 못합니다. LDAP 또는 HTTP 같은 **다른 대상 프로토콜로의 릴레이**는 별도의 보안 통제가 필요합니다.

### 주요 취약점

**EternalBlue (MS17-010, CVE-2017-0144)**는 SMBv1 취약점을 악용한 유명한 공격으로, 2017년 WannaCry 확산과 연결됩니다.

**SMBGhost (CVE-2020-0796)**는 과거 특정 Windows 빌드의 SMB 3.1.1 압축 처리 취약점입니다. **SMBv3를 사용한다는 사실만으로 구현 취약점이 모두 없어진 것은 아닙니다.** 패치 수준과 네트워크 제한이 중요합니다.

## 6. 원격 SMB 공격을 조사할 때 중요한 Windows Event ID

SMB 서버에 대한 파일 공유 접근과 서비스 생성 로그는 주로 **접근받은 대상 서버**에 남습니다. Kerberos·NTLM 인증 관련 이벤트는 **도메인 컨트롤러**에서도 확인할 수 있습니다.

| Event ID | 발생 위치/의미 | 분석상 주의점 |
| --- | --- | --- |
| **4624** | Security, 로그인 성공. Type 3은 일반적으로 네트워크 로그인 | SMB에만 한정되지 않음 |
| **4625** | Security, 로그인 실패 | 공격과 정상 실패를 구분 |
| **4776** | NTLM 자격 증명 검증 | 단독으로 SMB 공격을 입증하지 않음 |
| **4769** | DC, Kerberos TGS 요청 | CIFS 티켓 요청은 정상 SMB 접속에서도 발생 |
| **5140** | Security, 공유 리소스 접근 | 파일 수정의 증거는 아님 |
| **5145** | Security, 상세 공유 리소스 **접근 권한 검사** | 실제 파일 수정 완료와 다름 |
| **4663** | Security, 파일 시스템 객체 접근 | SACL과 File System 감사 설정 필요 |
| **7045** | **System 로그**, 서비스 설치 | 정상 배포 작업에서도 발생 |
| **4697** | Security, 서비스 설치 감사 | 감사 정책이 활성화된 경우 |
| **4688** | Security, 프로세스 생성 | 감사 정책·명령줄 수집 상태 확인 |
| **Sysmon 1/3/11/17/18** | 프로세스·연결·파일·파이프 텔레메트리 | Sysmon 구성에 따라 범위 달라짐 |

**5140의 집계 단위:** Microsoft 설명상 5140은 세션에서 최초 공유 접근 시 기록됩니다. 따라서 5140 이벤트 수는 파일 열기·쓰기 횟수나 전송량이 아니며, 하나의 이벤트 뒤에 여러 파일 작업이 이어질 수 있습니다. 기존 세션의 후속 작업에서는 새 5140이 없을 수도 있습니다. 5145, 적절히 설정된 4663, EDR 파일 기록과 세션·계정·시간을 연결해 해석하세요. [5140 발생 조건](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140).

### 5140과 5145를 구별하세요

- **5140:** 누가, 어느 IP에서, 어떤 공유 폴더에 접근했는지 조사하는 출발점입니다.
- **5145:** 공유 리소스 내부 경로와 요청된 접근 권한을 조사합니다. 공유 수준 접근 검사를 의미하므로 **파일이 실제로 쓰였다는 확정 증거는 아닙니다.**
- **4663:** 적절히 설정된 파일 감사와 함께 실제 파일 시스템의 접근 권한 사용을 확인하는 데 도움이 됩니다.

탐지 규칙에서는 **`4624 Type 3 → ADMIN$ 5140/5145 → 파일 생성 → 7045/4697 → 4688`**와 같이 하나의 호스트와 사용자·시간대에서 이벤트를 연결합니다. 같은 패턴이 정상 소프트웨어 배포에서도 발생한다는 점을 잊지 마세요.

## 7. Splunk 탐지 예시

아래 코드는 **실제 환경에 맞게 필드명과 시간 범위를 수정해야 하는 예시 SPL**입니다. 로그가 없다면 먼저 감사 설정과 Splunk 수집 범위를 확인하세요.

### A. SMB 공유 로그 존재 여부 확인

```spl
index=* (EventCode=5140 OR EventCode=5145 OR EventID=5140 OR EventID=5145)
| stats count by host sourcetype
| sort - count
```

### B. 관리자 공유 접근 조사

```spl
index=* (EventCode=5140 OR EventID=5140)
| eval share=coalesce(ShareName,Share_Name)
| eval requester=coalesce(SubjectUserName,Account_Name,user)
| eval source_ip=coalesce(IpAddress,Source_Address,src_ip)
| where isnotnull(share)
| where like(upper(share),"%\\ADMIN$")
    OR like(upper(share),"%\\C$")
    OR like(upper(share),"%\\IPC$")
| stats count as events values(share) as shares dc(host) as target_host_count values(host) as targets by requester source_ip
| sort - target_host_count - events
```

검색 대상 로그에 따라 ShareName 값의 역슬래시 형태가 다를 수 있으므로 실제 이벤트를 보고 조건을 맞추세요.

### C. 원격 실행과 관련된 서비스 설치 이벤트 조사

```spl
index=* (EventCode=7045 OR EventID=7045 OR EventCode=4697 OR EventID=4697)
| table _time host EventCode EventID ServiceName ServiceFileName ImagePath AccountName
| sort - _time
```

**7045 이벤트 자체만으로 공격 여부를 판단하지 마세요.** 같은 시간대의 ADMIN$ 접근, 파일 생성, 서비스 실행, 변경 승인 기록을 대조해야 합니다.

### D. TCP 445로 여러 서버를 접속한 클라이언트 확인

```spl
index=* (dest_port=445 OR dport=445)
| eval src=coalesce(src_ip,src,source_ip)
| eval dst=coalesce(dest_ip,dest,destination_ip)
| bin _time span=5m
| stats dc(dst) as distinct_servers count as connections values(dst) as servers by _time src
| where distinct_servers>=8
| sort - distinct_servers
```

이는 **네트워크 연결 로그가 존재할 때** 사용할 수 있는 예시입니다. 5분간 8대 이상이라는 값은 보편적인 공격 기준이 아니며 자산 스캔·정상 관리 작업과 비교해야 합니다.

## 8. Zeek, Suricata, Wireshark에서 무엇을 보나요?

- **Zeek `conn.log`:** TCP 445 연결, 통신량, 출발지·목적지 관계를 조사합니다.
- **Zeek SMB 관련 로그:** 파서 및 활성화 상태에 따라 공유 매핑, 파일 접근, SMB 명령의 메타데이터를 조사합니다.
- **Suricata:** 적용된 규칙과 트래픽 관측 위치에 따라 일부 알려진 SMB 취약점 악용 시그니처를 탐지할 수 있습니다.
- **Wireshark:** `tcp.port == 445`, `smb2`, `smb2.cmd == 3` (TREE_CONNECT), `smb2.cmd == 9` (WRITE) 등을 활용합니다.

**SMB Encryption이 적용된 연결에서는 네트워크 장비가 공유 경로나 개별 파일 작업을 파악하지 못할 수 있습니다.** 이 경우 서버 감사 로그, 파일 시스템 기록, EDR 수집이 더욱 중요합니다.

## 9. 원격 SMB 보안 상태 확인과 방어

### 현재 설정 읽기: PowerShell

관리자의 승인된 단말기에서 실행합니다.

```powershell
Get-SmbServerConfiguration |
  Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData

Get-SmbClientConfiguration |
  Select-Object RequireSecuritySignature,EnableInsecureGuestLogons

Get-SmbConnection

Get-SmbShare
Get-SmbShareAccess -Name "Finance"
```

서버의 전역 설정만으로 실제 모든 연결의 Signing·Encryption 여부가 결정되는 것은 아닙니다. 클라이언트 정책과 연결별 협상 결과도 확인합니다.

### 방어 우선순위

1. **SMBv1 제거 및 패치:** Windows, Samba, NAS까지 패치 상태를 관리합니다.
2. **SMB Signing 강제:** SMB 메시지 위·변조와 일반적인 SMB 대상 NTLM Relay를 제한합니다. 오래된 장비와의 호환성은 먼저 테스트합니다.
3. **중요 공유 SMB Encryption:** 전송 중 파일 내용의 노출을 줄입니다.
4. **Kerberos 우선, 불필요한 NTLM 차단:** PtH·Relay·인증 유도 공격 표면을 줄입니다.
5. **TCP 445 네트워크 분리:** 직원 PC 간 직접 SMB 접근은 필요한 경우를 제외하고 제한합니다. DC·승인된 파일 서버·관리 서버는 필요한 경로만 허용합니다.
6. **관리자 계정 최소 권한:** Windows LAPS, Credential Guard, 관리 계정 분리, NTFS 및 공유 권한 점검을 적용합니다.
7. **목적지 로그 수집:** 4624·5140·5145·7045·4688과 관련 EDR 텔레메트리를 중앙 수집합니다.
8. **랜섬웨어 대비:** 불변/오프라인 백업과 복원 테스트를 수행하고 대량 파일 변경을 탐지합니다.

**SMB Signing과 SMB Encryption의 차이:** Signing은 주로 **무결성**을 보호하며 데이터 내용을 숨기는 것은 아닙니다. Encryption은 **기밀성과 무결성**을 제공하지만 해당 연결에서 실제로 사용돼야 효과가 있습니다.

Windows 11 24H2 및 Windows Server 2025에는 Signing 관련 기본 보안 강화가 있지만 **Windows 에디션, 서버/클라이언트 역할, 패치, GPO의 영향을 받습니다.** 모든 장비에 같은 기본값이 적용된다고 가정하지 말고 설정을 확인하세요.

## 10. 실전 DFIR 예시: SMB 횡적 이동 의심

가상의 상황입니다. 평범한 직원 PC `CLIENT01`이 `FILE01:445`로 평소와 다른 연결을 만들고, `ADMIN$`에 접근한 직후 `FILE01`에 새로운 서비스가 생성됐습니다.

1. **범위:** `CLIENT01`이 접근한 서버 전체와 연결 시간을 Zeek·방화벽·EDR에서 확인합니다.
2. **인증:** 대상 서버의 `4624 Type 3`과 필요 시 DC 인증 기록을 비교해 사용자·출발지 IP·인증 방식을 확인합니다.
3. **파일 접근:** 대상의 `5140/5145`에서 ADMIN$ 접근과 파일 경로를 조사합니다.
4. **실행:** `7045/4697`, `4688`, Sysmon 등으로 서비스 파일명, 해시, 서명, 명령줄을 확인합니다.
5. **정상과 공격 구분:** 관리 자동화·승인된 소프트웨어 배포와 비교합니다. **SMB를 사용했다는 사실만으로 PtH 또는 Relay를 확정하지 않습니다.**
6. **대응:** 증거를 보존하고 침해가 확인된 시스템을 적절히 격리하며 계정과 관리자 권한, 불필요한 SMB 통신 경로를 정리합니다.

## 11. 기억할 핵심 내용

- **RDP**는 화면을 보여주는 원격접속입니다. **SMB**는 원격 파일·공유·파이프에 접근하고 **RPC/서비스 제어와 결합해 원격 실행에 사용**될 수 있습니다.
- `ADMIN$` 접근만으로 명령 실행을 확인할 수 없습니다. 서비스 설치와 프로세스 생성을 연결하세요.
- **NTLM Capture / Relay / Pass-the-Hash는 서로 다른 기법**입니다.
- 방어에는 **Signing + 필요한 Encryption + 취약점 패치 + 인증 정책 + 최소 권한 + 네트워크 분리**가 함께 필요합니다.
- 분석 보고서에서는 **공유 접근 사실**, **접근 권한 검사**, **악성 명령 실행 확인**을 명확히 구별해야 합니다.

## 12. 공식 자료 및 관련 위키

- [MITRE ATT&CK T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE DET0530: SMB 관리자 공유 횡적 이동 탐지](https://attack.mitre.org/detectionstrategies/DET0530/)
- [Microsoft Sysinternals: PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)
- [Microsoft: SMB Signing 개요](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview)
- [Microsoft: SMB Signing 설정](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Microsoft: SMB 보안 강화](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening)
- [Microsoft: Audit File Share](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-file-share)
- [Microsoft: Event ID 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
- [관련 문서: WPAD 보안]({{ '/ko/wiki/wpad-security/' | relative_url }})
- [관련 문서: Kerberoasting]({{ '/ko/wiki/kerberoasting/' | relative_url }})
