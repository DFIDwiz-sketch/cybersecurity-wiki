---
title: "Kerberos 인증 완전 가이드: AS-REQ, TGT, TGS, SPN, PAC, 공격·탐지·방어"
description: "Windows AD Kerberos V5의 정상 흐름, 암호화 키, 티켓 캐시, 위임, Windows 4768·4769·4771 이벤트, Splunk 탐지와 문제 해결까지."
category: active-directory
tags: [Windows Security, Active Directory, Kerberos, Authentication, TGT, TGS, SPN, PAC, NTLM, Kerberoasting, Blue Team, Red Team, DFIR, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-21"
translation_url: /wiki/kerberos-authentication/
---

> **선수 지식:** [Active Directory 완전 입문]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }})의 도메인·DC·DNS·계정과 권한을 먼저 읽으면 도움이 됩니다. 이름과 IP는 가상 예시입니다. 실습과 관리 명령은 허가된 환경에서만 실행하세요.

## 1. Kerberos는 무엇인가요?

**Kerberos V5**는 사용자·컴퓨터·서비스가 신뢰할 수 있는 제3자 **KDC(Key Distribution Center)**에서 발급한 티켓으로 서로 인증하는 프로토콜입니다. Windows AD DS의 핵심 도메인 인증 방식이며 **Single Sign-On(SSO)**과 **상호 인증(Mutual Authentication)**을 지원합니다.

예를 들어 사용자 `john`이 Windows PC에 로그인한 뒤 `\\fileserver\Finance`에 접속할 때, 파일 서버에 비밀번호 원문을 반복 전송하는 대신 **해당 서비스용 티켓**을 제시합니다.

**인증(Authentication)**은 신원 검증이고, **권한 부여(Authorization)**는 특정 리소스를 사용해도 되는지 판단하는 것입니다. 티켓이 유효해도 파일 공유나 NTFS 권한이 없으면 접근은 거부될 수 있습니다.

## 2. 알아야 할 용어 12개

| 용어 | 역할 |
| --- | --- |
| **Principal** | 인증받는 사용자, 컴퓨터 또는 서비스 신원 |
| **Realm** | Kerberos 신뢰 영역. Windows에서는 일반적으로 AD 도메인과 연결 |
| **DC / KDC** | 도메인 컨트롤러에서 Kerberos 티켓을 발급하는 기능 |
| **AS** | 최초 신원 확인과 TGT 발급을 담당하는 KDC의 Authentication Service |
| **TGS** | TGT를 확인하고 서비스 티켓을 발급하는 KDC의 Ticket Granting Service |
| **TGT** | KDC에 향후 서비스 티켓을 요청할 때 제시하는 Ticket Granting Ticket |
| **Service Ticket** | 목적 서비스에 제시하는 티켓. 흔히 **TGS 티켓**이라 부름 |
| **SPN** | `cifs/fileserver`처럼 서비스를 식별하는 Service Principal Name |
| **PAC** | 그룹 SID 등 Windows 권한 부여 정보를 담을 수 있는 Privilege Attribute Certificate |
| **Session Key** | 클라이언트–KDC, 클라이언트–서비스 간 통신에 쓰이는 세션별 키 |
| **Authenticator** | 티켓을 제시하는 클라이언트가 관련 세션 키를 가졌음을 증명하는 시간 기반 데이터 |
| **krbtgt** | 도메인의 TGT 보호에 이용되는 핵심 계정 |

**AS와 TGS는 서로 다른 컴퓨터가 아닙니다.** 일반적인 AD에서는 DC의 KDC가 두 기능을 모두 수행합니다.

## 3. 정상 인증 전체 그림: AS → TGS → AP

![Kerberos AS-REQ AS-REP TGS-REQ TGS-REP AP-REQ AP-REP 통신 과정]({{ '/assets/diagrams/kerberos-exchange-ko.svg' | relative_url }})

| 단계 | 메시지 | 기능 |
| --- | --- | --- |
| **AS Exchange** | AS-REQ → AS-REP | 최초 인증과 TGT 발급 |
| **TGS Exchange** | TGS-REQ → TGS-REP | 특정 SPN의 서비스 티켓 발급 |
| **AP Exchange** | AP-REQ → 경우에 따라 AP-REP | 서비스가 티켓을 검증하고 클라이언트/서버 인증 수행 |

KDC에 대한 Kerberos 통신은 보통 **TCP/UDP 88**을 사용하지만, **AP-REQ는 SMB나 HTTP 등 애플리케이션 프로토콜 속에 포함될 수 있어 반드시 88번 포트로 전달되는 것은 아닙니다.**

**중요:** 이 그림은 티켓이 새로 발급되는 대표 상황입니다. TGT·서비스 티켓이 캐시에 이미 있으면 일부 단계가 생략될 수 있습니다.

## 4. AS-REQ와 AS-REP: TGT 발급 상세

1. 사용자가 도메인 PC에 로그인합니다. PC는 DNS와 DC Locator를 이용해 KDC를 찾습니다.
2. 클라이언트가 **AS-REQ**를 보냅니다. 일반적인 비밀번호 기반 사전 인증은 사용자 비밀키로 보호한 타임스탬프 등의 데이터를 포함합니다.
3. KDC는 AD 계정 키, 정책, 시간 조건 등을 검증합니다.
4. KDC는 **AS-REP**에서 **krbtgt 계정 키로 보호된 TGT**와 **클라이언트가 자신의 키로 복호화할 수 있도록 보호된 세션 키 관련 정보**를 제공합니다.
5. 클라이언트는 TGT와 세션 키를 티켓 캐시에 보관합니다.

**중대한 구분:** "TGT 전체가 사용자의 비밀번호로 암호화된다"는 말은 부정확합니다. Windows AD에서 **TGT 자체는 krbtgt 키로 보호**되고, 일반적인 암호 기반 AS-REP에서 **사용자 키는 클라이언트가 읽어야 하는 응답 부분**을 보호합니다.

### Pre-authentication과 AS-REP Roasting

일반적인 사전 인증은 사용자에게 키 보유를 증명하도록 요구합니다. 계정에 **Do not require Kerberos preauthentication**이 설정되어 있으면 공격자가 암호 추측에 악용할 수 있는 AS-REP 데이터를 얻을 가능성이 있습니다(**T1558.004**).

그러나 **Event 4768의 PreAuthType=0 하나만으로 공격이라고 판단하면 안 됩니다.** 계정의 사전 인증 설정과 실제 교환 및 인증 방식까지 확인해야 합니다.

## 5. TGS-REQ와 TGS-REP: 서비스 티켓 발급

`john`이 `\\fileserver\Finance`에 접근한다고 가정합니다.

1. SMB 클라이언트는 `cifs/fileserver.corp.example.com` 같은 **서비스 SPN**을 정합니다.
2. 클라이언트는 **TGT + Authenticator**를 바탕으로 KDC에 **TGS-REQ**를 보냅니다.
3. KDC는 TGT, 계정/서비스, 정책과 SPN 매핑을 확인합니다.
4. KDC가 **TGS-REP**를 보내며 **해당 서비스 계정의 비밀키로 보호된 서비스 티켓**과 관련 세션 키 자료를 제공합니다.
5. 클라이언트는 발급받은 서비스 티켓을 실제 파일 서버에 제시합니다.

**DC의 Event 4769**가 중요한 이유는 이 TGS 요청의 증거이기 때문입니다. 하지만 티켓이 이미 캐시에 있다면 **파일 서버를 다시 이용해도 4769가 새로 기록되지 않을 수 있습니다.**

## 6. AP-REQ와 AP-REP: 실제 서비스에서 검증

클라이언트는 파일 서버의 SMB 인증 과정에서 **AP-REQ**를 전달합니다. 서비스는 자신의 비밀키로 티켓을 열어 클라이언트 신원·세션 키·Authenticator와 시간 조건을 검사합니다.

상호 인증을 요청하고 지원되는 경우 **AP-REP**로 서버 측 응답이 전달됩니다. 이후 서버는 **파일 공유 권한, NTFS ACL, 서비스 권한**을 따로 검사합니다.

따라서 **Kerberos 인증 성공 ≠ 파일 읽기/수정 성공**입니다. KDC에 대한 요청(88번 포트)과 실제 서비스 접근(SMB TCP 445 등)을 구별하세요.

## 7. TGT와 서비스 티켓의 내부 구조

![TGT krbtgt 키와 서비스 티켓 서비스 계정 키, PAC 관계]({{ '/assets/diagrams/kerberos-tickets-ko.svg' | relative_url }})

| 구분 | TGT | Service Ticket |
| --- | --- | --- |
| 발급 단계 | AS | TGS |
| 제시 대상 | KDC/TGS | 목적 서비스 |
| 핵심 보호 키 | **krbtgt 계정 키** | **서비스 계정 또는 컴퓨터 계정 키** |
| 사용 목적 | 서비스 티켓 획득 | 해당 서비스에 인증 |
| 대표 악용 | Golden Ticket, TGT 탈취 | Kerberoasting, Silver Ticket, 티켓 탈취 |

**Session Key와 장기 계정 키는 다릅니다.** AS 교환의 클라이언트–TGS 세션 키, TGS 교환의 클라이언트–서비스 세션 키, 티켓 암호화용 장기키가 각기 다른 역할을 합니다.

또한 Windows 4768/4769에서 **TicketEncryptionType**과 **SessionKeyEncryptionType**을 혼동하지 마세요.

## 8. SPN이란 무엇이며 왜 중복이 위험한가요?

**SPN(Service Principal Name)**은 "어떤 서비스에 접속할지" 식별하는 이름이고 AD의 특정 사용자·컴퓨터·gMSA에 연결됩니다.

| 서비스 | 대표적인 SPN |
| --- | --- |
| 파일 공유 | `cifs/fileserver.corp.example.com` |
| 웹 | `HTTP/intranet.corp.example.com` |
| SQL | `MSSQLSvc/sql01.corp.example.com:1433` |
| 호스트 서비스 | `HOST/server01.corp.example.com` |

SPN이 누락되거나 잘못된 계정에 등록되면 **티켓 요청 실패**, **NTLM로의 대체**, **서비스의 티켓 복호화 실패** 등이 발생할 수 있습니다.

특히 **KRB_AP_ERR_MODIFIED**는 서비스가 받은 티켓을 정상적으로 해독/검증하지 못할 때 발생할 수 있어 SPN 중복, 서비스 계정 비밀번호/키, 잘못된 서비스 계정 연결을 조사해야 합니다.

### 읽기 전용 SPN 진단

```cmd
setspn -L FILESERVER$
setspn -Q cifs/fileserver.corp.example.com
setspn -X
```

`-X`는 SPN 중복 점검에 유용합니다. IP 주소로 `\\192.0.2.10\share`에 접속하면 기본 구성에서 예상된 SPN이 만들어지지 않아 Kerberos가 실패하거나 NTLM로 대체될 수 있습니다. 단, 별도 IP 기반 SPN 구성이 가능한 경우도 있어 **항상 불가능한 것은 아닙니다.**

## 9. PAC는 권한 부여와 어떻게 연결되나요?

Windows Kerberos의 **PAC(Privilege Attribute Certificate)**에는 그룹 SID 등 권한 부여에 필요한 정보가 포함될 수 있습니다.

이 정보는 서비스의 접근 토큰과 ACL 검사에 영향을 줄 수 있지만, **PAC 자체가 파일 접근을 무조건 허가하는 증명서는 아닙니다.** 티켓·PAC의 서명과 검증 정책이 중요합니다.

**공격과의 연결:** krbtgt 비밀키를 탈취하면 **Golden Ticket(T1558.001)** 위조 위험이 있고, 특정 서비스 계정 비밀키가 유출되면 **Silver Ticket(T1558.002)** 위조 위험이 있습니다. 둘은 요구되는 키·영향 범위·로그 가시성이 다릅니다.

## 10. Kerberos 암호화 유형과 2026년 RC4 변경

| 티켓 암호화 유형 | 알고리즘 | 의미 |
| --- | --- | --- |
| **0x17** (23) | RC4-HMAC | 레거시·오프라인 암호 추측 위험 증가 |
| **0x11** (17) | AES128-CTS-HMAC-SHA1-96 | RC4보다 강하지만 약한 암호의 위험은 존재 |
| **0x12** (18) | AES256-CTS-HMAC-SHA1-96 | RC4보다 강하지만 계정/키 보호 필요 |
| 0x1 / 0x3 | DES | 오래된 취약 암호화 방식 |

Microsoft는 **2026년 1월 준비·감사 → 4월 AES 중심 기본 동작 → 7월 최종 Enforcement**로 Kerberos RC4 기본 동작을 변경했습니다(CVE-2026-20833 관련). 7월 업데이트 이후에는 **명시적 설정이 없는 서비스 계정에 RC4를 기본 허용한다는 가정이 더 이상 유효하지 않습니다.** 명시적으로 허용된 RC4 구성, 실제 사용 가능한 키, 정책과 패치 상태는 별도로 점검해야 합니다.

**2026년 탐지 지침:** RC4 `0x17`만 찾지 말고 **모든 암호화 유형의 비정상적인 서비스 티켓 요청 패턴**을 분석하세요. AES 티켓도 약한 서비스 계정 비밀번호를 대상으로 한 오프라인 공격의 재료가 될 수 있습니다.

참고: [Microsoft Windows Release Health](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center/) 및 [RC4 탐지/완화](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos).

## 11. 티켓 캐시, 만료, 시간 동기화

Kerberos는 티켓을 캐시에 저장해 **SSO**를 구현합니다. TGT·서비스 티켓 수명은 도메인 정책과 계정/인증 정책에 따라 달라집니다. 한 번의 서버 접속마다 새 티켓을 받는 것은 아닙니다.

```cmd
klist
klist tgt
w32tm /query /status
w32tm /query /source
```

일반적인 Kerberos 구성에서 허용 시간 오차는 **5분**인 경우가 많지만 정책에서 달라질 수 있습니다. 시각 오차가 커지면 Authenticator 유효성 검증에 실패할 수 있습니다.

**중요:** `klist`는 현재 보이는 로그온 세션의 티켓 캐시를 보여주는 도구입니다. 모든 사용자·시스템 세션을 자동으로 표시한다고 가정하지 마세요.

## 12. NTLM과 Kerberos: 무엇이 다른가요?

| 항목 | Kerberos | NTLM |
| --- | --- | --- |
| 주요 방식 | KDC 티켓 기반 | 챌린지-응답 |
| 서버 신원 확인 | 상호 인증 지원 | Kerberos와 동일한 상호 인증을 기본 제공하지 않음 |
| 핵심 의존성 | DNS, SPN, DC/KDC, 시간 | NTLM 설정 및 인증 검증 |
| 공격 사례 | Kerberoasting, Ticket Theft/Forgery | NTLM Relay, Pass-the-Hash |
| 권장 방향 | 지원되는 서비스에서 우선 | 필요성과 호환성 점검 후 최소화 |

SPN 문제, IP 주소 사용, 레거시 서비스, 정책 등의 이유로 **NTLM Fallback**이 발생할 수 있지만 모든 애플리케이션에서 자동 대체가 보장되는 것은 아닙니다. NTLM 차단 정책이 있으면 접속에 실패할 수 있습니다.

## 13. Kerberos 위임(Delegation)과 Double Hop

사용자 → 웹 서버 → SQL 서버처럼 중간 서비스가 사용자를 대신해 다른 자원에 접속해야 하는 경우입니다.

- **Unconstrained Delegation:** 위임 가능한 신원을 광범위하게 사용하며 위험도가 높습니다.
- **Constrained Delegation(KCD):** 대신 접근할 수 있는 백엔드 서비스를 제한합니다.
- **Resource-Based Constrained Delegation(RBCD):** 백엔드 서비스 계정에서 허용할 프런트엔드 계정을 제어합니다.
- **S4U2Self / S4U2Proxy:** 서비스가 사용자 신원으로 티켓을 요청할 때 활용하는 Kerberos 확장 방식입니다.

위임 설정은 서비스 계정·컴퓨터 계정의 권한과 객체 ACL의 영향을 받습니다. **RBCD가 자동으로 안전한 것은 아니며**, 백엔드 객체에 대한 잘못된 수정 권한은 권한 상승 경로로 악용될 수 있습니다.

## 14. 주요 Kerberos 공격 구분

| 공격 | 핵심 원리 | ATT&CK |
| --- | --- | --- |
| **Kerberoasting** | 서비스 티켓의 서비스 키 기반 암호화 자료로 서비스 계정 암호를 오프라인 추측 | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| **AS-REP Roasting** | 사전 인증이 없는 계정의 AS-REP 자료로 암호 추측 | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| **Golden Ticket** | krbtgt 비밀키를 이용한 TGT 위조 | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) |
| **Silver Ticket** | 특정 서비스 비밀키를 이용한 서비스 티켓 위조 | [T1558.002](https://attack.mitre.org/techniques/T1558/002/) |
| **Pass-the-Ticket** | 확보한 유효 티켓을 다른 보안 세션에 악용 | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |

**각 공격의 전제조건이 다릅니다.** Kerberoasting은 티켓 요청 단계에서 4769가 발생할 수 있지만 오프라인 비밀번호 추측은 DC에 실패 로그를 남기지 않습니다. Silver Ticket의 경우 **KDC에 새 티켓을 요청하지 않고 서비스 티켓을 제시할 수 있어** 새로운 4769가 없을 수 있습니다.

## 15. Windows 이벤트 4768, 4769, 4771 상세

![SOC에서 Kerberos 이벤트 4768 4769 4771을 서비스 로그와 연계]({{ '/assets/diagrams/kerberos-telemetry-ko.svg' | relative_url }})

| 이벤트 | 일반적 기록 위치 | 무엇을 보여주나요? |
| --- | --- | --- |
| **4768** | DC Security | TGT 요청 |
| **4769** | DC Security | 서비스 티켓(TGS) 요청 |
| **4771** | DC Security | Kerberos 사전 인증 실패 |
| **4772 / 4773** | DC Security | Kerberos 티켓 요청 실패 관련 이벤트(환경별 확인) |
| **4624** | 대상 호스트 | 로그인 성공(네트워크 로그온은 Type 3이 흔함) |
| **4625** | 대상 호스트 | 로그인 실패 |
| **4672** | 로그인 호스트 | 특수 권한이 부여된 로그인 |

| 이벤트 필드 | 분석 포인트 |
| --- | --- |
| `TargetUserName` / Account Name | 티켓을 요청한 신원 |
| `IpAddress` / Client Address | 요청 클라이언트 IP |
| `ServiceName` | 4769에서는 서비스에 연결된 **AD 계정 이름**을 나타내는 경우가 많으며 전체 SPN이 아닐 수 있음 |
| `Status` | 성공/실패 코드. `0x0`은 대개 성공 |
| `TicketEncryptionType` | **티켓** 암호화 유형 |
| `SessionKeyEncryptionType` | **세션 키** 암호화 유형(서로 다름) |
| `PreAuthType` | 사전 인증 방법 |
| `ServiceSupportedEncryptionTypes` / `ServiceAvailableKeys` | 대상 서비스 계정의 지원 유형과 실제 키(새 이벤트 형식) |
| `ClientAdvertizedEncryptionTypes` | 클라이언트가 지원한다고 제시한 유형(새 이벤트 형식) |

2025년 Microsoft 업데이트 이후 **4768/4769에 새로운 암호화 관련 필드**가 추가되었습니다. DC 업데이트·로그 파서에 따라 이름이나 존재 여부가 달라집니다.

### 오류 코드 실무 사전

| 코드 | 이름 | 흔한 조사 원인 |
| --- | --- | --- |
| `0x0` | 성공 | 티켓 정상 발급 여부와 추가 행동 확인 |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | 계정 이름/인증 주체 조회 문제 |
| `0x7` | KDC_ERR_S_PRINCIPAL_UNKNOWN | SPN 또는 대상 서비스 조회 문제 |
| `0x18` | KDC_ERR_PREAUTH_FAILED | 잘못된 비밀번호·키/사전 인증 문제 |
| `0xE` | KDC_ERR_ETYPE_NOSUPP | AES/RC4 지원·사용 가능한 키 불일치 |
| `0x25` | KRB_AP_ERR_SKEW | 시계 오차 |
| `0x29` | KRB_AP_ERR_MODIFIED | 서비스 티켓 복호화·검증 문제, SPN·계정 키 등 |

이 오류 값은 **Kerberos 프로토콜 오류 코드**로서, 같은 필드·같은 Windows Event에 전부 기록되는 것은 아닙니다. 서비스 서버의 시스템 로그와 패킷 분석이 필요할 수 있습니다.

## 16. Splunk 탐지: 수집 확인부터 이상 행동 분석

다음은 **예시 SPL**입니다. 실제 DC 로그의 인덱스, sourcetype, XML 필드명, 수집 지연과 검색 시간대에 맞춰 수정하세요.

### A. 이벤트 수집 확인

```spl
index=* (EventCode=4768 OR EventID=4768 OR EventCode=4769 OR EventID=4769 OR EventCode=4771 OR EventID=4771)
| stats count by host sourcetype EventCode EventID
| sort - count
```

### B. 사전 인증 실패의 사용자·IP별 분포

```spl
index=* (EventCode=4771 OR EventID=4771)
| eval requester=coalesce(TargetUserName,Account_Name,user)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval code=coalesce(Status,Failure_Code)
| bin _time span=10m
| stats count as failures dc(requester) as users values(code) as codes
        by _time src
| sort - failures
```

### C. 대량 서비스 티켓 수집 및 RC4 탐색

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=lower(tostring(coalesce(TicketEncryptionType,Ticket_Encryption_Type)))
| eval status=lower(tostring(coalesce(Status,Failure_Code)))
| where isnotnull(requester) AND isnotnull(target)
| where isnull(status) OR status="0x0" OR status="0"
| bin _time span=5m
| stats count as tickets dc(target) as unique_target_accounts
        count(eval(etype="0x17" OR etype="23")) as rc4_tickets
        values(etype) as encryption_types values(target) as targets
        by _time requester src
| where tickets>=10 AND unique_target_accounts>=5
| sort - unique_target_accounts - tickets
```

**중요:** `dc(target)`는 일반적으로 **서로 다른 서비스 계정 수**를 세는 것이며 반드시 개별 SPN 수와 같지는 않습니다. **5분·10건·5개 계정은 단지 출발점**입니다. 정상 관리 서버, 백업, 애플리케이션 동작과 비교해야 합니다.

### D. 특정 고위험 서비스 계정의 희소 요청

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=coalesce(TicketEncryptionType,Ticket_Encryption_Type)
| search target="svc_sql"
| stats count as requests values(etype) as etypes
        min(_time) as first_seen max(_time) as last_seen
        by requester src
| convert ctime(first_seen) ctime(last_seen)
```

티켓을 **한 개만 요청하는 표적형 공격**도 있으므로 대량 티켓 요청 탐지만 사용하면 부족합니다. AES라고 자동 제외하지 마세요.

## 17. 읽기 전용 Windows·AD 점검 명령

```cmd
whoami /all
klist
klist tgt
nltest /dsgetdc:corp.example.com
w32tm /query /status
setspn -X
```

```powershell
Resolve-DnsName -Type SRV "_kerberos._tcp.corp.example.com"

Get-ADUser -Identity "svc_sql" -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,ServicePrincipalName
```

**AS-REP Roasting 노출 가능 계정 인벤토리(읽기 전용):**

```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName,Enabled,DoesNotRequirePreAuth
```

PowerShell의 `Get-ADUser` 등에는 **RSAT ActiveDirectory 모듈**이 필요합니다. 티켓 캐시 삭제나 서비스 계정 암호 변경은 조사 자료를 없애거나 장애를 낼 수 있으니 원인 파악 전 임의로 실행하지 마세요.

## 18. 문제 해결·DFIR 조사 플레이북

**가상 사례:** `CLIENT01`의 `john`이 5분 안에 14개의 서비스 계정으로 TGS를 요청했고 일부 암호화 유형이 RC4입니다.

1. **수집 검증:** DC `4769`가 실제 수집되는지, 출발지 IP·사용자·서비스 계정·상태를 확인합니다.
2. **기준선 확인:** 정상적인 애플리케이션·백업·관리 작업과 비교합니다.
3. **자산 맵핑:** 서비스 계정이 어떤 SPN·서버에 연결되는지와 고권한 여부를 조사합니다.
4. **단말 분석:** LDAP 탐색, 의심 프로세스, 다른 인증 기록을 확인합니다.
5. **후속 사용 확인:** `4624`, `4672`, SMB `ADMIN$` 접근 및 서비스 설치 등 추가 흔적을 조사합니다.
6. **판정 분리:** **티켓 요청 → 비정상 수집 → 비밀번호 복구 의심 → 계정 악용 확인**을 구분해 보고합니다.
7. **대응:** 의심 계정의 사용을 제한하고 비밀번호 변경·서비스 영향 검토·보안 설정 강화는 승인된 대응 절차를 따릅니다.

| 증상 | 우선 확인 |
| --- | --- |
| DC를 찾지 못함 | DNS SRV, 클라이언트 DNS, DC Locator |
| 4771 급증 | 계정 비밀번호/키, 사전 인증, 사용자·IP·시간 |
| NTLM로 대체됨 | SPN, IP 주소 접근, 서비스 설정, 정책 |
| KRB_AP_ERR_MODIFIED | 서비스 계정 비밀키, SPN 중복·잘못된 등록 |
| KDC_ERR_ETYPE_NOSUPP | AES 키 유무, RC4 정책/패치, 지원 유형 |
| 4769 성공인데 파일 접근 거부 | 서버 ACL·공유 권한, 서비스 권한 |
| 서비스 접근은 있는데 4769 없음 | 티켓 캐시, KDC 관측 범위, 서비스 측 로그 |

## 19. 방어 우선순위와 자가 점검

1. **서비스 계정:** 가능한 곳에는 **gMSA**, 그 외에는 긴 무작위 암호와 최소 권한을 적용합니다.
2. **Pre-authentication:** 불필요하게 사전 인증을 비활성화한 계정을 정리합니다.
3. **Encryption:** 2026년 RC4 정책과 AES 키 지원을 점검하고 레거시 암호화를 단계적으로 제거합니다.
4. **SPN:** 등록 주체·DNS 이름·중복 여부를 정기적으로 확인합니다.
5. **Delegation:** Unconstrained Delegation은 피하고 KCD/RBCD 권한과 객체 ACL을 감사합니다.
6. **계정·DC:** 중요 계정 분리, 자격 증명 보호, DC 접근 제한을 적용합니다.
7. **탐지:** 4768·4769·4771을 서비스·호스트·네트워크 데이터와 연관시켜 이상 요청과 후속 행위를 구분합니다.

### 확인 질문

- TGT는 어느 키로 보호되나요? **krbtgt 계정 키.**
- 서비스 티켓은 어느 키로 보호되나요? **해당 서비스 계정/컴퓨터 계정 키.**
- 4769 하나로 Kerberoasting 성공을 알 수 있나요? **아니요.**
- 4769가 없으면 접근도 없었나요? **아니요, 캐시된 티켓일 수 있습니다.**
- 0x17은 암호 유출의 증거인가요? **아니요, RC4 티켓의 암호화 유형입니다.**
- 인증 성공이면 모든 파일 권한이 있나요? **아니요, 권한 부여는 별도로 검사합니다.**

## 20. 공식 참고 자료와 연결 학습

- [Microsoft: Kerberos Authentication Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft: Kerberos Subprotocols](https://learn.microsoft.com/en-us/windows/win32/secauthn/kerberos-subprotocols)
- [Microsoft: Authentication Service Exchange](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-service-exchange)
- [Microsoft: Event 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Microsoft: Event 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [Microsoft: Kerberos troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-troubleshooting-guidance)
- [Microsoft: Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft: Windows 2026 RC4 enforcement](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center/)
- [MITRE ATT&CK: Kerberos ticket attacks](https://attack.mitre.org/techniques/T1558/)
- [위키: Active Directory 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }})
- [위키: Kerberoasting 심화]({{ '/ko/wiki/kerberoasting/' | relative_url }})
- [위키: SMB 보안]({{ '/ko/wiki/smb-security/' | relative_url }})

**다음 주제:** NTLM 인증 완전 가이드 — NTLMv1/v2, NetNTLM, NTLM Relay, Pass-the-Hash, Responder와 Kerberos 차이.
