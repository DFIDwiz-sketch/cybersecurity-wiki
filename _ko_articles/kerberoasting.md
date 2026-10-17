---
title: "Kerberoasting 완전 가이드: 공격 원리, 이벤트 4769, Splunk 탐지와 방어"
description: "SPN과 TGS부터 RC4·AES 암호화, 오프라인 비밀번호 추측, Windows 로그 분석, DFIR 플레이북과 gMSA 방어까지 단계별로 설명합니다."
category: active-directory
tags: [Windows Security, Kerberoasting, Active Directory, Kerberos, Red Team, Blue Team, DFIR, Detection Engineering, Splunk, Credential Access, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-17"
translation_url: /wiki/kerberoasting/
---

> **학습 범위:** 이 문서는 공격 기법의 원리를 이해하고 인가된 실습 환경에서 탐지·방어를 검증하기 위한 자료입니다. 계정 이름, IP, 시간 및 로그는 설명용 가상 사례입니다. 허가 없는 시스템에 인증 정보를 시험하지 마세요.

## 1. Kerberoasting이란 무엇인가요?

**Kerberoasting(커버로스팅)**은 Active Directory의 **Kerberos 서비스 티켓(TGS)**에 포함된 암호화 데이터를 확보하여 **서비스 계정의 비밀번호를 오프라인에서 추측**하는 자격 증명 공격입니다. MITRE ATT&CK 분류는 **[T1558.003](https://attack.mitre.org/techniques/T1558/003/) — Credential Access**입니다.

핵심은 **서비스 티켓의 일부가 대상 서비스 계정의 장기 비밀키로 암호화되어 있다**는 사실입니다. 공격자는 이 부분을 수집하고 비밀번호 후보가 올바른 키를 만드는지 자기 컴퓨터에서 확인합니다.

대부분의 일반적인 AD 환경에서는 **도메인 관리자 권한 없이도** 정상적인 도메인 사용자로 여러 SPN의 서비스 티켓을 요청할 수 있습니다. 다만 티켓을 요청할 수 있다는 사실과 실제 비밀번호를 알아냈거나 해당 서비스에 로그인했다는 사실은 전혀 다릅니다.

**가장 중요한 특징:** 비밀번호 후보를 테스트하는 **오프라인 단계**에서는 DC에 매번 로그인하지 않습니다. 따라서 그 단계 자체는 AD의 로그인 실패 횟수를 증가시키지 않고, 계정 잠금도 유발하지 않습니다. 그러나 **TGS 요청**, 공격 준비 행동, 비밀번호를 알아낸 뒤의 로그인과 계정 악용은 별도 로그에 남을 수 있습니다.

### 다른 공격과 무엇이 다른가요?

| 기법 | 주된 목표 | 핵심 조건 |
| --- | --- | --- |
| **Kerberoasting** | TGS의 암호화 부분으로 **서비스 계정 비밀번호** 추측 | SPN과 인증된 티켓 요청(또는 적절한 캡처 트래픽) |
| **AS-REP Roasting** | AS-REP의 암호화 부분으로 비밀번호 추측 | Kerberos 사전 인증이 비활성화된 계정 |
| **Password Spraying** | 여러 사용자에게 소수의 비밀번호를 **온라인**으로 시도 | 로그인 서비스에 접근 가능 |
| **Pass-the-Hash** | 이미 확보한 NT 해시로 인증 | 별도로 입수한 NT 해시 필요 |
| **NTLM Relay** | 인증을 다른 서버로 중계 | 중계할 인증 교환과 취약한 대상 |

## 2. 선수 지식: Kerberos, TGT, TGS, SPN

- **DC(Domain Controller):** AD 도메인과 인증을 관리하는 서버입니다.
- **KDC(Key Distribution Center):** 보통 DC에서 동작하며 Kerberos 티켓을 발급합니다.
- **TGT(Ticket Granting Ticket):** 사용자가 정상 인증 후 받는 티켓으로, 이를 가지고 서비스 티켓을 요청합니다.
- **TGS(Service Ticket):** SQL, HTTP, 파일 서비스 등 특정 서비스에 접근하기 위한 티켓입니다.
- **SPN(Service Principal Name):** `MSSQLSvc/sql01.example.local:1433`, `HTTP/intranet.example.local` 같은 서비스 식별자입니다.
- **서비스 계정:** 서비스가 실행되거나 서비스가 연결되는 AD 보안 주체입니다. 일반 사용자형 서비스 계정, 컴퓨터 계정, gMSA 등이 있습니다.

### 정상적인 서비스 인증의 예

1. 직원 `john`이 회사 도메인에서 인증하고 TGT를 받습니다.
2. `john`이 SQL 서버에 접근하려고 `MSSQLSvc/sql01.example.local:1433`의 서비스 티켓을 DC에 요청합니다.
3. DC가 연결된 서비스 계정 `svc_sql`의 비밀키로 암호화된 부분을 포함하는 티켓을 발급합니다.
4. 직원의 클라이언트는 티켓을 SQL 서비스에 제시하여 서비스를 이용합니다.

**여기서 어떤 비밀번호를 노리나요?** `john`의 비밀번호가 아니라 **`svc_sql`의 비밀번호**입니다. 티켓을 요청한 계정과 티켓의 대상 서비스 계정을 구분하는 것이 조사에서 매우 중요합니다.

## 3. 공격은 구체적으로 어떻게 진행되나요?

![Kerberoasting 공격 5단계: SPN 탐색, TGS 요청, 오프라인 크래킹, 계정 악용]({{ '/assets/diagrams/kerberoasting-attack-ko.svg' | relative_url }})

### 1단계: 도메인 사용자 권한 확보

공격자는 피싱, 침해된 단말기, 기존 사용자 세션 등의 경로로 **유효한 도메인 인증 상태나 TGT**를 확보할 수 있습니다. 기본적인 Kerberoasting 티켓 요청을 위해 반드시 Domain Admin 권한이 필요한 것은 아닙니다.

### 2단계: SPN과 서비스 계정 확인

AD의 디렉터리 정보를 조회하면 서비스에 연결된 SPN과 계정을 알아낼 수 있습니다. 공격자는 특히 고권한 계정, 사람이 만든 예측 가능한 비밀번호를 쓰는 계정, 오랫동안 암호를 바꾸지 않은 계정을 중요하게 볼 수 있습니다.

예를 들어 다음은 **가상의 SPN 목록**입니다.

| SPN | 연결된 AD 계정 |
| --- | --- |
| `MSSQLSvc/sql01.example.local:1433` | `svc_sql` |
| `HTTP/report.example.local` | `svc_report` |
| `HTTP/intranet.example.local` | `svc_web` |

단순 LDAP 조회는 정상 운영에서도 흔하므로 이것만으로 침해를 확정할 수 없습니다. 환경에 따라 LDAP 쿼리 감사나 프로세스 실행 기록을 함께 확인합니다.

### 3단계: DC에 서비스 티켓 요청

공격자는 유효한 TGT를 이용해 대상 SPN의 **TGS-REQ**를 DC에 보냅니다. DC는 허용되는 경우 **TGS-REP**로 서비스 티켓을 반환합니다.

**이 시점이 주요 탐지 기회입니다.** DC의 Security 이벤트 **4769**에서 누가, 어느 IP에서, 어떤 서비스 계정을 대상으로, 어떤 암호화 유형의 티켓을 요청했는지 확인할 수 있습니다.

다만 정상 사용자도 업무 중 동일한 Kerberos 요청을 수행하므로, 4769 하나만으로 공격 여부를 확정할 수 없습니다.

### 4단계: 암호화된 티켓 데이터를 오프라인에서 분석

공격자는 반환된 서비스 티켓의 **서비스 계정 키로 암호화된 부분**을 크래킹 도구가 다룰 수 있는 형식으로 가공합니다. 비밀번호 후보로 암호학적 결과를 계산하여 수집한 데이터와 일치하는지 확인합니다.

예시 문자열 `$krb5tgs$23$...`은 RC4 기반 Kerberos TGS 데이터를 표현하는 형식 중 하나입니다. **이는 NT 해시를 직접 덤프했다는 뜻이 아닙니다.** 공격자가 검사하는 것은 암호화된 서비스 티켓 정보입니다.

**왜 계정 잠금이 없나요?** 후보 비밀번호를 검증할 때마다 DC에 로그인을 시도하는 것이 아니라 **별도 장비에서 암호학적 연산만 수행**하기 때문입니다. 따라서 이 단계의 수많은 실패는 AD 로그인 실패 이벤트로 기록되지 않습니다.

일반적인 공격·모의훈련에 알려진 도구로 Rubeus, Impacket GetUserSPNs, Hashcat, John the Ripper 등이 있지만, **도구 이름만으로 공격 성공 여부를 판단할 수 없습니다.**

### 5단계: 비밀번호 복구 성공 시 계정 악용

서비스 계정의 비밀번호 추측에 성공하면 공격자는 그 계정에 허용된 범위에서 인증을 시도하거나 권한 상승·횡적 이동을 수행할 수 있습니다. **계정 자체의 권한이 낮다면 피해 범위도 제한될 수 있습니다.** 반대로 Domain Admin 권한을 가진 서비스 계정은 훨씬 위험합니다.

이후의 실제 인증과 원격 작업은 4624, 4648, 4672, 서비스 생성, 예약 작업, 네트워크 접속 등의 흔적을 남길 수 있습니다. 이는 **4단계 오프라인 추측과 구분**해야 합니다.

## 4. 왜 RC4 0x17을 특별히 주의하나요?

| 4769의 Ticket Encryption Type | 방식 | 분석 의미 |
| --- | --- | --- |
| `0x17` = 10진수 23 | **RC4-HMAC** | 오프라인 비밀번호 추측 비용이 상대적으로 낮음 |
| `0x11` = 10진수 17 | **AES128** | RC4보다 강력하나 Roasting 자체는 가능 |
| `0x12` = 10진수 18 | **AES256** | RC4보다 강력하나 약한 비밀번호라면 여전히 위험 |

RC4에서는 비밀번호 후보를 암호키로 변환하는 연산 부담이 비교적 낮지만, Kerberos AES에서는 더 비싼 키 유도 연산을 수행합니다. 그래서 공격자는 가능하면 RC4 유형의 서비스 티켓을 선호합니다.

그러나 **0x17 = 공격 확정이 아닙니다.** 오래된 서비스나 구성이 다른 시스템이 정상적으로 RC4 티켓을 받을 수도 있습니다. **AES라고 안전이 확정되는 것도 아닙니다.** AES 티켓이라도 서비스 계정 비밀번호가 짧거나 예측 가능하면 오프라인 추측 대상이 될 수 있습니다.

**필드 혼동 주의:** `TicketEncryptionType`은 **티켓 암호화 유형**이고, `SessionKeyEncryptionType`은 **세션키 암호화 유형**입니다. RC4 티켓을 찾을 때 이 둘을 혼동하면 안 됩니다.

### 2026년 Microsoft RC4 정책 변화

Microsoft는 2026년 Windows 보안 업데이트를 통해 `msDS-SupportedEncryptionTypes`가 명시되지 않은 계정에 **RC4 사용 가능을 자동으로 가정하던 기본 동작**을 단계적으로 변경했습니다. Microsoft 설명에 따르면 **2026년 4월 업데이트부터 기본 강제 동작이 시작되고, 7월 업데이트부터 최종 강제 단계**가 적용됩니다.

하지만 서비스 계정에 RC4가 **명시적으로 허용**되어 있거나 오래된 시스템·키가 남아 있는 환경에서는 여전히 RC4가 나타날 수 있습니다. 실제 상태는 패치 수준과 AD 구성에 따라 달라집니다.

따라서 **2026년 이후의 탐지는 RC4만 찾으면 불완전합니다.** 모든 암호화 유형에서 비정상적인 TGS 요청 패턴을 확인하고, RC4가 예상 밖에 등장하면 `ServiceSupportedEncryptionTypes`, `ServiceAvailableKeys`, `ClientAdvertizedEncryptionTypes` 등을 추가 조사해야 합니다.

참고: [Microsoft RC4 점검·완화](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos) / [2026년 RC4 변경 설명](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/what-changed-in-rc4-with-the-january-2026-windows-update-and-why-it-is-important/4504732)

## 5. Windows Security Event ID 4769 상세 분석

**4769는 DC가 TGS 요청을 받았을 때 기록하는 Security 로그**입니다(해당 감사 정책이 활성화되어 있어야 함). 티켓 요청 성공과 실패를 포함할 수 있으며, **비밀번호 크래킹 성공 알림은 아닙니다.**

| 로그 필드 | 확인할 내용 |
| --- | --- |
| `EventCode=4769` / `EventID=4769` | TGS 요청 |
| `TargetUserName` / Account Name | 티켓을 **요청한 사용자** |
| `ServiceName` / Service Name | 티켓 대상 **서비스 계정 또는 컴퓨터 계정** |
| `IpAddress` / Client Address | 요청을 보낸 클라이언트 IP |
| `TicketEncryptionType` | 발급한 티켓의 암호화 유형 |
| `Status` / Failure Code | `0x0`은 일반적으로 성공 |
| `ServiceSid` | 대상 서비스 계정의 SID |
| `ServiceSupportedEncryptionTypes` | 서비스 계정에 적용되는 암호화 지원 설정 |
| `ServiceAvailableKeys` | 서비스 계정에서 실제 사용할 수 있는 키 유형 |
| `ClientAdvertizedEncryptionTypes` | 클라이언트가 지원한다고 알린 암호화 유형 |
| `SessionKeyEncryptionType` | 세션키 암호화 유형(티켓 유형과 별개) |

**자주 빠뜨리는 함정:** 4769의 `ServiceName`은 항상 `MSSQLSvc/sql01.example.local:1433`처럼 **전체 SPN**을 기록하는 필드가 아닙니다. 흔히 그 SPN과 연결된 **AD 서비스 계정명**을 나타냅니다. 따라서 `dc(ServiceName)`는 대체로 **서로 다른 서비스 계정 수**를 세는 것이며 정확한 SPN 개수와 같다고 보장할 수 없습니다. 필요한 경우 AD의 SPN 매핑 정보와 교차 검증하세요.

Microsoft는 **2025년 1월 14일 이후 보안 누적 업데이트를 적용한 Windows Server 2016 이상 DC**에서 4769의 새로운 암호화 관련 필드를 제공하기 시작했습니다. 따라서 업데이트하지 않은 DC나 로그 파서에서는 해당 필드가 없을 수 있습니다.

공식 설명: [Microsoft Event 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)

## 6. 같은 사용자가 여러 RC4 티켓을 요청하면 왜 의심스러울까요?

다음은 **설명용 가상 이벤트**입니다.

| 시간 | 요청 사용자 | 원본 IP | 대상 서비스 계정 | 티켓 암호화 |
| --- | --- | --- | --- | --- |
| 10:00:01 | john | 172.16.2.4 | svc_sql | 0x17 |
| 10:00:02 | john | 172.16.2.4 | svc_backup | 0x17 |
| 10:00:03 | john | 172.16.2.4 | svc_web | 0x17 |
| 10:00:04 | john | 172.16.2.4 | svc_report | 0x17 |
| 10:00:05 | john | 172.16.2.4 | svc_exchange | 0x17 |

**하나의 사용자 + 하나의 IP + 매우 짧은 시간 + 서로 다른 서비스 계정 + RC4**가 결합되어 있습니다. 이는 공격자가 비밀번호를 추측할 후보를 늘리려고 여러 서비스 티켓을 한꺼번에 수집할 때 나타날 수 있는 패턴입니다.

하지만 정상적인 관리 서버, 자동화 작업, 애플리케이션 시작 과정에서도 여러 TGS 요청이 발생할 수 있습니다. **5초 동안 5개가 요청됐다고 무조건 공격은 아닙니다.** 실제 탐지 임계값은 평소의 요청량과 대상 서비스 범위에 맞춰야 합니다.

또 다른 함정은 **공격자가 서비스 계정 한 개만 노릴 수 있다는 점**입니다. 고권한 `svc_backup` 계정 하나를 표적으로 삼는 경우 대량 요청 탐지 규칙으로 놓칠 수 있습니다.

따라서 탐지를 두 축으로 설계합니다.

1. **대량 수집 탐지:** 한 사용자/IP가 짧은 시간에 많은 대상 서비스 계정으로 TGS를 요청하는지 확인합니다.
2. **고위험 단일 표적 탐지:** 중요한 서비스 계정에 평소 없던 사용자 또는 IP가 접근하고 있는지 확인합니다. RC4가 발견되면 위험도를 더 높일 수 있습니다.

![4769, 행위 이상 및 인증 로그 연관 분석 흐름도]({{ '/assets/diagrams/kerberoasting-detection-ko.svg' | relative_url }})

## 7. Splunk 탐지 쿼리: 단계별 실습

아래 SPL은 **학습용 템플릿**입니다. 현재 Splunk의 인덱스, sourcetype, Windows XML/JSON 필드명, 수집 시간 범위가 맞지 않으면 결과가 0건일 수 있습니다. 먼저 **DC Security 로그가 실제 수집되고 있는지** 확인하세요.

### A. 4769 로그와 필드명 확인

```spl
index=* (EventCode=4769 OR EventID=4769)
| head 20
| table _time host sourcetype EventCode EventID TargetUserName Account_Name ServiceName Service_Name IpAddress Client_Address TicketEncryptionType Ticket_Encryption_Type Status
```

원본 이벤트에서 어떤 필드가 채워졌는지 확인한 뒤, 가능하면 `index=*` 대신 실제 AD 로그 인덱스로 제한합니다.

### B. RC4 티켓을 요청한 사용자와 IP 조사

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,AccountName,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=lower(trim(coalesce(TicketEncryptionType,Ticket_Encryption_Type,ticket_encryption_type)))
| eval result=coalesce(Status,Failure_Code)
| where in(etype,"0x17","23") AND (isnull(result) OR in(lower(result),"0x0","0"))
| stats count as requests values(target) as targets by requester src etype
| sort - requests
```

`etype="0x17"`은 16진수 표현입니다. 일부 파서에서 `23`이라는 10진수로 추출할 수 있어 두 형태를 모두 처리합니다.

### C. RC4에만 의존하지 않는 대량 TGS 요청 탐지

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,AccountName,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=lower(trim(coalesce(TicketEncryptionType,Ticket_Encryption_Type,ticket_encryption_type)))
| eval result=coalesce(Status,Failure_Code)
| where isnotnull(requester) AND isnotnull(target) AND target!="krbtgt"
| where isnull(result) OR in(lower(result),"0x0","0")
| bin _time span=5m
| stats count as ticket_requests
        dc(target) as distinct_target_accounts
        count(eval(in(etype,"0x17","23"))) as rc4_requests
        values(target) as target_accounts
        values(etype) as encryption_types
        by _time requester src
| where ticket_requests>=10 AND distinct_target_accounts>=5
| sort - distinct_target_accounts - ticket_requests
```

이 쿼리는 **5분 동안 티켓 10건 이상, 대상 서비스 계정 5개 이상**을 예시 기준으로 사용합니다. 실제 운영 전에는 정상 사용자와 자동화 서버의 활동 기준선을 측정하여 조정해야 합니다.

`dc(target)`는 **대상 계정 수**를 세며 전체 SPN 개수와 반드시 같지 않습니다. 또한 이름 끝에 `$`가 붙은 계정을 무조건 제외하지 마세요. 컴퓨터 계정뿐 아니라 gMSA가 포함될 수 있습니다.

### D. 중요한 서비스 계정 하나만 표적으로 삼은 경우

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,AccountName,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=coalesce(TicketEncryptionType,Ticket_Encryption_Type,ticket_encryption_type)
| search target="svc_backup"
| stats count as requests values(etype) as ticket_etypes min(_time) as first_seen max(_time) as last_seen by requester src
| convert ctime(first_seen) ctime(last_seen)
| sort - requests
```

실습에서는 `svc_backup`을 실제 중요한 서비스 계정으로 바꿉니다. **요청 건수가 1건이고 AES 티켓이어도**, 평소 해당 서비스를 이용하지 않던 계정이나 출발지 IP라면 조사할 가치가 있습니다.

## 8. DFIR 조사 플레이북: 탐지 이후 무엇을 하나요?

| 순서 | 확인할 질문 | 주요 증거 |
| --- | --- | --- |
| 1. 데이터 검증 | 해당 이벤트가 DC의 Security 4769인가? | DC 목록, 감사 정책, 로그 수집 상태 |
| 2. 범위 파악 | 누가, 언제, 어디서, 어떤 서비스 계정에 티켓을 요청했나? | 4769의 사용자, IP, 서비스 계정, 성공 여부 |
| 3. 정상 여부 | 평소 그 사용자·서버가 하는 작업인가? | 최근 7~30일 기준선, 업무 및 배포 일정 |
| 4. 엔드포인트 조사 | SPN 탐색이나 비정상 도구 실행이 있었나? | 4688, Sysmon 1, LDAP 관련 흔적(수집된 경우) |
| 5. 후속 침해 확인 | 대상 서비스 계정으로 새 로그인이 발생했나? | 4624, 4648, 4672, 서비스/예약 작업/원격 작업 |
| 6. 판정 | 단순 이상 징후인가, 침해 정황이 추가로 확인됐나? | 독립적인 로그와 엔드포인트·네트워크 증거 |
| 7. 대응 | 어떤 호스트를 격리하고 어떤 비밀번호를 안전하게 바꿀까? | 서비스 의존성, 계정 소유자, 승인된 대응 절차 |

**로그 해석 주의:** 4624는 로그인 성공, 4648은 명시적 자격 증명으로 로그인을 시도한 기록, 4672는 로그인 세션에 특수 권한이 할당된 기록입니다. 이러한 이벤트 중 하나만으로 Kerberoasting 성공을 증명하지는 못합니다. 로그 범위와 감사 설정에 따라 일부 흔적은 수집되지 않을 수 있습니다.

네트워크 분석에서는 보통 TCP/UDP **88번 포트**의 Kerberos 요청·응답을 확인할 수 있습니다. Zeek·패킷 메타데이터가 있다면 요청량과 통신 위치를 분석할 수 있지만, **네트워크에서 티켓 요청을 봤다고 오프라인 암호 추측 성공까지 알아낼 수는 없습니다.**

### 구체적인 조사 예시

`john`이 `172.16.2.4`에서 5분 동안 서로 다른 서비스 계정 18개를 대상으로 TGS 요청을 했다고 합시다.

먼저 `172.16.2.4`가 일반 직원 PC인지 정식 관리 서버인지 확인합니다. 다음으로 서비스 계정 18개의 권한, 티켓 암호화 유형, `john`의 평소 접근 패턴, 같은 시간대의 프로세스 실행 및 LDAP 조회, 그 후 서비스 계정으로 이루어진 비정상 인증을 분석합니다.

**4769 요청량만으로 '비밀번호 크래킹 성공' 또는 '횡적 이동 성공'이라고 판단하지 않습니다.**

## 9. 방어 방법: 가장 효과적인 우선순위

### A. 가능한 서비스는 gMSA 사용

**gMSA(Group Managed Service Account)**를 사용하면 Windows가 긴 무작위 암호를 생성·관리하고 주기적으로 교체합니다. gMSA에도 SPN이 존재하고 TGS 발급은 가능하지만, **사람이 만든 짧은 비밀번호보다 추측이 극도로 어렵다**는 것이 중요한 장점입니다.

### B. 일반 서비스 계정은 25자 이상의 긴 무작위 암호

MITRE는 **25자 이상**의 강력한 서비스 계정 암호를 권장합니다. 임의의 문자로 생성하고 비밀번호 저장소(Password Vault)로 관리합니다. 단순한 회사 이름과 연도·계절을 조합해 길이만 늘리는 방식은 피해야 합니다.

### C. RC4 제거와 AES 전환

Microsoft의 변경 지침을 따라 RC4 의존성을 점검하고 AES 사용으로 전환합니다. 무턱대고 RC4를 끄기 전에 레거시 서비스, `msDS-SupportedEncryptionTypes`, 계정의 AES 키 유무, 키탭 및 운영 중인 서비스 의존성을 확인해야 서비스 장애를 방지할 수 있습니다.

### D. 최소 권한과 로그인 범위 제한

서비스 계정에 불필요한 Domain Admin 권한을 주지 않고, 불필요한 대화형 로그인과 위임 권한도 최소화합니다. 계정 탈취 자체를 완전히 막지 못하더라도 피해 범위를 크게 줄일 수 있습니다.

### E. SPN 자산 관리와 상시 모니터링

사용하지 않는 SPN 정리, 서비스 계정 소유자 지정, 비밀번호 교체 이력 확인, DC 4769 중앙 수집, **대량 요청 + 고위험 단일 계정 요청** 탐지를 함께 수행합니다.

### 방어 담당자가 서비스 계정을 조사하는 PowerShell 예시

RSAT의 ActiveDirectory PowerShell 모듈과 적절한 읽기 권한이 있는 관리 시스템에서 다음과 같이 **사용자형 SPN 계정 목록을 점검**할 수 있습니다.

```powershell
Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties ServicePrincipalName,PasswordLastSet,msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,Enabled,PasswordLastSet,ServicePrincipalName,
    @{Name='SupportedEtypes';Expression={$_.'msDS-SupportedEncryptionTypes'}}
```

이 명령은 **비밀번호 크래킹 명령이 아니라 서비스 계정 보안 점검용 목록 조회**입니다. 컴퓨터 계정이나 gMSA의 SPN까지 포함한 완전한 자산 목록을 만들려면 별도의 계정 유형 조사도 필요합니다.

## 10. 실무에서 자주 하는 오해 정리

- **“4769에서 0x17을 봤으니 공격 확정이다.”** 아닙니다. 정상 RC4 티켓일 수도 있습니다.
- **“로그인 실패 기록이 없으니 공격은 없었다.”** 아닙니다. 오프라인 추측 단계에는 그런 로그가 남지 않습니다.
- **“티켓을 요청한 john의 암호가 공격 대상이다.”** 아닙니다. 공격 대상은 **서비스 계정**의 비밀번호입니다.
- **“4769 ServiceName은 언제나 전체 SPN이다.”** 아닙니다. 흔히 서비스 계정명을 기록합니다.
- **“AES로 설정하면 Kerberoasting은 완전히 불가능하다.”** 아닙니다. 더 어렵지만 약한 비밀번호는 위험합니다.
- **“티켓을 수십 개 요청하는 공격만 잡으면 된다.”** 아닙니다. 한 개의 고가치 계정만 노리는 공격도 있습니다.
- **“RC4를 그냥 끄면 된다.”** 아닙니다. 이전 서비스와 키 호환성 검증이 필요합니다.

## 11. 참고 자료와 연결 문서

- [MITRE ATT&CK: Kerberoasting T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE: DET0157 Kerberoasting 탐지 전략](https://attack.mitre.org/detectionstrategies/DET0157/)
- [Microsoft: Windows Security Event ID 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [Microsoft: Kerberos RC4 탐지 및 완화](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft: 2026년 RC4 변경 사항](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/what-changed-in-rc4-with-the-january-2026-windows-update-and-why-it-is-important/4504732)
- [Microsoft: gMSA 보안 지침](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [관련 문서: WPAD 보안과 DFIR]({{ '/ko/wiki/wpad-security/' | relative_url }})
