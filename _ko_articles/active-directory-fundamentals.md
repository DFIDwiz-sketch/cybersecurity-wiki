---
title: "Active Directory 완전 입문: 도메인, DC, DNS, OU, GPO, 계정과 권한"
description: "AD DS의 논리·물리 구조, 사용자 인증과 권한 부여, 그룹 정책, DNS·복제·FSMO, 보안·탐지와 점검 실습을 단계별로 익힙니다."
category: active-directory
tags: [Active Directory, Windows Security, AD DS, Domain Controller, DNS, LDAP, Kerberos, NTLM, Group Policy, GPO, Windows Server, Blue Team, DFIR, Detection Engineering]
level: Beginner
updated: "2026-10-22"
translation_url: /wiki/active-directory-fundamentals/
---

> **학습 목표:** 조직의 Windows 도메인이 어떻게 작동하는지 설명하고, 정상적인 로그인과 권한 판단을 이해하며, 흔한 설정 실수와 감사·조사 지점을 찾을 수 있도록 구성했습니다. 명령은 별도 표시가 없는 한 **읽기·조회용**이며, `corp.example.com`과 `john` 등은 설명을 위한 가상 이름입니다.

## 1. Active Directory란?

**Active Directory Domain Services(AD DS)**는 조직의 사용자, 컴퓨터, 그룹과 서비스에 대한 정보를 **중앙 관리하는 디렉터리 및 인증 기반 시설**입니다. 직원 500명이 각 PC에 별도 계정을 만드는 대신, 하나의 도메인 계정으로 회사 정책에 따라 여러 컴퓨터와 자원에 접근하게 해 줍니다.

예를 들어 `john@corp.example.com`은 회사 PC에 로그인하고 `\\fileserver\Finance` 공유에 접속하며, 정해진 보안 정책을 적용받을 수 있습니다. 단, **로그인에 성공하는 것과 특정 파일을 읽을 권한이 있다는 것은 별개**입니다.

AD DS는 온프레미스 Windows Server의 디렉터리 서비스입니다. **Microsoft Entra ID**는 클라우드 ID 플랫폼이고, **Microsoft Entra Domain Services**는 관리형 도메인 서비스로서 AD DS와 목적·운영 방식이 다릅니다. 이 문서는 주로 일반 Windows Server 기반 AD DS를 다룹니다.

### AD가 제공하는 다섯 가지 기능

| 기능 | 예시 |
| --- | --- |
| 신원 관리(Identity) | 사용자·컴퓨터·서비스 계정 생성과 수명주기 관리 |
| 인증(Authentication) | Kerberos/NTLM을 이용해 신원을 확인 |
| 권한 부여(Authorization) | 그룹·ACL을 이용하여 공유 파일과 AD 객체 접근 결정 |
| 정책 관리 | GPO를 통해 PC 보안 설정과 사용자 환경 관리 |
| 디렉터리·인프라 | LDAP 검색, DNS를 통한 DC 탐색, DC 간 복제 |

## 2. 포리스트, 트리, 도메인, OU, 사이트는 어떻게 다를까요?

![AD 포리스트, 도메인, OU 논리 구조]({{ '/assets/diagrams/ad-structure-ko.svg' | relative_url }})

| 용어 | 뜻 | 핵심 구분 |
| --- | --- | --- |
| **Forest(포리스트)** | 하나 이상의 도메인이 공유하는 스키마·구성·전역 카탈로그 및 신뢰 구조 | AD DS의 **주요 보안 경계** |
| **Tree(트리)** | 연속된 DNS 이름 공간을 사용하는 도메인 계층 | 논리적인 도메인 관계 |
| **Domain(도메인)** | 계정·인증·디렉터리 파티션을 관리하는 단위 | 동일 도메인의 여러 DC가 복제 |
| **OU(조직 구성 단위)** | 도메인 안의 사용자·컴퓨터 등을 담는 관리 컨테이너 | GPO 연결·관리 권한 위임에 사용 |
| **Site(사이트)** | IP 서브넷과 네트워크 연결성을 반영하는 물리적 배치 | 가까운 DC 선택과 복제 효율 관리 |

**예시:** 포리스트에 `corp.example.com` 도메인과 `research.example.com` 도메인이 있을 수 있습니다. 각각의 도메인에 `OU=Servers`, `OU=Workstations` 같은 OU를 만들고 사용자와 컴퓨터를 배치할 수 있습니다.

- **포리스트와 도메인은 다릅니다.** 도메인이 둘이어도 하나의 포리스트일 수 있습니다.
- **OU는 별도 도메인이 아닙니다.** OU를 새로 만든다고 별도 인증 데이터베이스나 완전한 보안 경계가 생기지 않습니다.
- **Site는 OU와 다릅니다.** `Sydney Site`의 PC와 `Sydney OU`의 PC가 일치할 필요는 없습니다.
- 도메인 간에는 신뢰(Trust)가 중요하지만, **신뢰가 곧 모든 자원 접근 허용을 의미하지 않습니다.**

### 객체의 경로: DN과 OU

예를 들어 `john`의 LDAP Distinguished Name(DN)은 다음처럼 표현될 수 있습니다.

```text
CN=John Lee,OU=Finance,OU=Employees,DC=corp,DC=example,DC=com
```

여기서 `DC=`는 DNS형 도메인 구성 요소, `OU=`는 조직 단위, `CN=`은 객체의 공통 이름입니다. `CN=John Lee`를 `OU=Finance`로 옮기는 것은 **관리상 위치를 바꾸는 일**이며, 자동으로 파일 서버 권한을 부여하지 않습니다.

## 3. Domain Controller(DC)의 역할

DC는 AD DS를 실행하는 서버이며 조직의 신원 기반 시설에서 매우 중요한 역할을 수행합니다.

- **디렉터리 저장:** 사용자·그룹·컴퓨터 및 여러 속성을 보관하는 `NTDS.dit` 데이터베이스를 관리합니다.
- **Kerberos KDC:** TGT 및 서비스 티켓을 발급합니다.
- **LDAP:** 디렉터리 객체를 조회·검색·변경할 수 있는 인터페이스를 제공합니다(권한 필요).
- **DNS(자주 DC와 공동 설치):** 클라이언트가 DC를 찾을 수 있도록 이름과 SRV 레코드를 제공합니다. DNS 서비스가 반드시 모든 DC에 있는 것은 아닙니다.
- **SYSVOL/NETLOGON:** 그룹 정책 파일과 로그온 관련 공유를 제공합니다.
- **복제(Replication):** 다른 DC와 디렉터리 변경사항을 동기화합니다.
- **Global Catalog(GC):** 포리스트 전역에서 일부 속성을 빠르게 검색하고 보편적 그룹 구성 등을 처리하도록 지원합니다. 모든 DC가 GC여야 하는 것은 아닙니다.

**보안 관점:** DC에는 인증 인프라와 중요 계정 정보가 있기 때문에 일반 파일 서버보다 엄격하게 보호해야 합니다. `NTDS.dit`은 비밀번호 평문이 공개된 일반 파일이 아니지만, 디렉터리 비밀정보 및 인증 자료를 보호해야 하는 고가치 자산입니다.

## 4. DNS가 고장 나면 로그인도 문제가 생기는 이유

Windows 클라이언트는 DNS의 **SRV 레코드**를 사용하여 적절한 DC를 찾습니다. 예를 들어 다음과 같은 조회가 사용됩니다.

```text
_ldap._tcp.dc._msdcs.corp.example.com
```

서버 위치 찾기는 `DC Locator` 동작과 AD Site·서브넷 정보를 함께 사용합니다. 이후 LDAP, Kerberos, SMB 등 필요한 서비스를 통해 인증 및 정책 적용이 진행됩니다.

**초보자가 흔히 겪는 문제:** 회사 PC의 DNS를 임의의 공개 DNS 서버로만 설정하면 AD용 SRV 레코드를 찾지 못해 도메인 로그인, 그룹 정책 또는 서비스 접근에 문제가 생길 수 있습니다.

### 관련 프로토콜·기본 포트

| 포트 | 서비스 | 기능 |
| --- | --- | --- |
| TCP/UDP **53** | DNS | DC와 서비스 이름 검색 |
| TCP/UDP **88** | Kerberos | 인증 티켓 요청 |
| TCP/UDP **389** | LDAP / CLDAP | 디렉터리 검색 및 DC Locator 관련 통신 |
| TCP **636** | LDAPS | TLS를 통한 LDAP |
| TCP **3268/3269** | Global Catalog / GC over TLS | 포리스트 검색 |
| TCP **445** | SMB | SYSVOL·NETLOGON 및 파일 공유 |
| TCP/UDP **464** | Kerberos password change | 암호 변경 작업 |
| TCP **135** + 동적 RPC 포트 | RPC | 관리·복제 등 일부 작업 |
| UDP **123** | NTP | Kerberos에 중요한 시간 동기화 |

이 표는 대표 포트이며, 방화벽 정책은 실제 역할과 Microsoft의 포트 요구사항을 기준으로 설계해야 합니다.

## 5. 실제 로그인: 인증과 권한 부여는 다릅니다

![DNS, DC/KDC, 파일 서버를 통한 로그인과 리소스 접근]({{ '/assets/diagrams/ad-authentication-ko.svg' | relative_url }})

정상적인 도메인 사용자가 파일 서버에 접근하는 예입니다.

1. PC가 DNS로 도메인 컨트롤러를 찾습니다.
2. Kerberos 사용 시 클라이언트가 **AS-REQ / AS-REP** 교환을 통해 TGT를 받습니다(조건에 따라 캐시된 자격 증명과 기존 티켓을 사용할 수 있음).
3. `\\fileserver\Finance`에 접근하려고 **TGS-REQ / TGS-REP**로 `cifs/fileserver` 서비스 티켓을 요청합니다.
4. PC가 SMB 연결에서 서비스 티켓을 제시합니다.
5. 서버는 사용자를 확인한 뒤 **공유 권한과 NTFS ACL** 등 실제 자원 권한을 검사합니다.

도메인 인증에 Kerberos가 우선 사용되는 경우가 많지만 호환성·설정에 따라 **NTLM**이 사용될 수도 있습니다. Kerberos는 단지 비밀번호를 DC에 보내는 구조가 아니며, 상세 프로토콜 메시지와 보호 메커니즘은 별도 [Kerberoasting 문서]({{ '/ko/wiki/kerberoasting/' | relative_url }}) 및 향후 Kerberos 심화 문서에서 다룹니다.

**인증(Authentication):** "당신은 누구인가?"  
**권한 부여(Authorization):** "그 신원으로 이 파일을 읽어도 되는가?"

따라서 `4624` 로그인 성공만으로 `salary.xlsx` 파일 접근까지 허용되었다고 단정하면 안 됩니다.

## 6. 사용자, 컴퓨터, 서비스 계정과 주요 속성

AD 객체는 **스키마(Schema)**에 정의된 클래스·속성으로 구성됩니다.

| 객체·속성 | 의미와 활용 |
| --- | --- |
| User | 직원 또는 서비스가 사용하는 신원 |
| Computer | 도메인에 가입된 PC/서버의 계정(보통 이름 끝에 `$`) |
| Group | 여러 보안 주체를 묶어 권한을 관리 |
| `sAMAccountName` | 전통적인 계정 이름인 `john`; `CORP\john`은 도메인의 NetBIOS 이름과 이 속성값을 결합한 로그온 표기 |
| `userPrincipalName`(UPN) | `john@corp.example.com` 형태의 이름 |
| `objectSID`(SID) | 권한 판단에 쓰이는 보안 주체 식별자; 도메인 SID와 RID 등을 포함 |
| `objectGUID` | AD 객체를 식별하는 고유 GUID |
| `servicePrincipalName`(SPN) | `MSSQLSvc/sql01...`, `cifs/fileserver` 같은 서비스 식별 |
| `memberOf` | 객체가 직접 속한 그룹 관계의 일부를 표시; 중첩/기본 그룹 등은 추가 고려 |
| `adminCount` | 관리 대상 보호 메커니즘과 연관될 수 있는 속성; 값만으로 현재 관리자 권한 확정 불가 |

**서비스 계정**은 사람 계정처럼 비밀번호를 직접 관리하는 계정일 수도 있고, Windows가 암호를 관리하는 **gMSA(Group Managed Service Account)**일 수도 있습니다. 서비스 계정에 불필요한 고권한을 부여하면 Kerberoasting 등의 계정 탈취가 더 위험해집니다.

## 7. 그룹 종류, 그룹 범위와 AGDLP

**Security Group**은 접근 권한 부여에 사용합니다. **Distribution Group**은 이메일 배포 등에 사용하며 일반적으로 ACL에 보안 주체로 사용할 수 없습니다.

| 보안 그룹 범위 | 일반적 사용 |
| --- | --- |
| **Global** | 같은 도메인의 직원·역할 그룹을 구성 |
| **Domain Local** | 리소스가 속한 도메인에서 ACL에 권한 부여 |
| **Universal** | 여러 도메인에 걸친 멤버십 관리가 필요한 경우 |
| **Builtin Local** | 미리 정의된 일부 내장 그룹에 사용 |

실무에서 자주 사용하는 설계 방식은 **AGDLP**입니다.

![AGDLP 계정·그룹·권한 관계]({{ '/assets/diagrams/ad-permissions-ko.svg' | relative_url }})

```text
A  Accounts           john, mary
G  Global group       GG_Finance_Staff
DL Domain Local group DL_Finance_Modify
P  Permissions        Finance 폴더의 Modify
```

즉 계정 → 역할 기반 Global 그룹 → 리소스 기반 Domain Local 그룹 → 권한입니다. 여러 도메인까지 확장하면 **AGUDLP** 패턴도 활용할 수 있습니다.

**주의:** 그룹의 중첩, SID, 거부(Deny) ACE, 상속, 공유 및 NTFS ACL에 따라 최종 유효 권한이 달라집니다. AD 그룹에 포함됐다는 사실만으로 특정 파일에 항상 접근할 수 있는 것은 아닙니다.

### 중요한 관리자 그룹

- **Domain Admins:** 해당 도메인의 매우 높은 관리 권한. 일반 직원 계정에 부여하면 안 됩니다.
- **Enterprise Admins:** 포리스트 전체에 영향을 줄 수 있는 고권한 그룹.
- **Schema Admins:** 포리스트 스키마 변경 권한.
- **Account Operators / Backup Operators 등:** 상황에 따라 실질적으로 위험한 권한을 보유할 수 있으므로 멤버십을 점검합니다.
- **DnsAdmins 및 위임된 관리 그룹:** 환경 구성에 따라 중요한 간접 권한 경로가 될 수 있습니다.

그룹 이름만 보지 말고 **실제 ACL, 위임 권한과 계정이 도달할 수 있는 관리자 작업**을 함께 평가해야 합니다.

## 8. OU와 GPO: 관리 위치와 정책 적용

**OU**는 객체를 모아 관리하고 관리 권한을 위임하는 컨테이너입니다. **GPO(Group Policy Object)**는 컴퓨터나 사용자에게 적용할 정책 설정의 묶음입니다.

예를 들어 다음처럼 구성할 수 있습니다.

```text
corp.example.com
├── OU=Workstations
│   └── GPO: Workstation Security Baseline
├── OU=Servers
│   └── GPO: Server Security Baseline
└── OU=Employees
    └── OU=Finance
        └── GPO: Finance User Settings
```

**기본 정책 처리 순서 = LSDOU**입니다.

1. **L**ocal: 로컬 정책
2. **S**ite: 사이트에 연결한 GPO
3. **D**omain: 도메인에 연결한 GPO
4. **OU**: 부모 OU에서 자식 OU 순서로 연결한 GPO

기본적으로 나중에 적용되는 정책이 겹치는 설정에 우선하지만 **Enforced, Block Inheritance, Security Filtering, WMI Filtering, Link Order 및 Loopback** 등의 영향을 고려해야 합니다. GPO가 OU에 연결됐더라도 대상 보안 주체에 적용 권한이 없으면 실제로 적용되지 않을 수 있습니다.

### GPO의 실제 저장 위치

GPO는 **AD의 Group Policy Container(GPC)**와 **SYSVOL에 저장되는 Group Policy Template(GPT)**의 두 부분으로 이해하면 좋습니다. 따라서 GPO 보안 분석에서는 AD 객체 권한과 SYSVOL 파일 권한, 복제 상태를 모두 고려해야 합니다.

**보안 사고 예:** 직원이 GPO를 편집할 권한을 잘못 위임받으면 다수의 PC에 영향을 주는 정책을 변경할 수 있습니다. 하지만 모든 GPO 변경이 곧 악성인 것은 아닙니다.

## 9. 사이트, 서브넷, DC 복제와 Global Catalog

- **Site:** 물리 네트워크와 지리적 연결에 기반합니다. 클라이언트가 적절한 DC를 찾고 복제 트래픽을 효율적으로 보내도록 돕습니다.
- **Subnet:** 어떤 IP 범위가 어느 Site에 해당하는지 연결합니다.
- **Replication:** 일반적인 쓰기 가능한 DC는 **Multi-master** 방식으로 대부분의 디렉터리 변경사항을 복제합니다.
- **SYSVOL Replication:** 현대 도메인은 보통 **DFSR**을 통해 그룹 정책 파일을 복제합니다. AD 데이터베이스 복제와 SYSVOL 파일 복제는 서로 구별해야 합니다.
- **Global Catalog:** 포리스트 내 객체 검색 및 일부 인증 시나리오에 사용됩니다.
- **RODC(Read-Only Domain Controller):** 지사 등에서 읽기 중심의 디렉터리 사본을 제공하고 암호 캐시를 제한하도록 설계할 수 있습니다.

**실무 함정:** 같은 사용자의 그룹 변경이 DC마다 아직 동일하게 반영되지 않았거나 SYSVOL과 AD의 GPO 버전이 맞지 않으면 인증 및 정책 적용 결과가 달라질 수 있습니다. 이러한 복제 지연은 곧바로 공격이라고 단정할 수 없지만 중요한 장애 및 조사 단서입니다.

## 10. FSMO 다섯 가지 역할

AD는 일반적으로 여러 DC가 변경을 처리하지만 특정 작업은 단일 책임자가 필요합니다. 이를 **FSMO(Flexible Single Master Operations)** 역할이라고 합니다.

| 역할 | 범위 | 주된 책임 |
| --- | --- | --- |
| **Schema Master** | 포리스트에 1개 | 스키마 변경 조정 |
| **Domain Naming Master** | 포리스트에 1개 | 도메인 및 디렉터리 파티션 추가·제거 조정 |
| **RID Master** | 각 도메인에 1개 | 새로운 보안 주체의 RID 할당 풀 관리 |
| **PDC Emulator** | 각 도메인에 1개 | 암호 변경 관련 처리·시간 동기화 등 중요 기능 |
| **Infrastructure Master** | 각 도메인에 1개 | 다른 도메인 객체 참조의 업데이트 처리 |

모든 FSMO 역할을 한 서버에만 둬야 한다는 뜻은 아닙니다. 장애 복구 때는 역할 보유자를 확인해야 하며, 임의로 **Seize(강제 탈취)**하는 것은 신중해야 합니다.

### 도메인/포리스트 기능 수준과 Windows Server 2025

**기능 수준(Functional Level)은 DC 운영체제 버전과 별개**입니다. Windows Server 2019/2022에는 별도의 2019/2022 도메인 기능 수준이 없고, 보통 2016 기능 수준을 사용합니다. Windows Server 2025에는 새로운 도메인/포리스트 기능 수준이 있습니다.

기능 수준을 올리려면 해당 범위의 DC 버전·복제 상태·요구사항을 점검해야 합니다. **높은 기능 수준이라고 PC에 자동으로 최신 패치가 깔리거나 사용자 계정이 안전해지는 것은 아닙니다.**

## 11. 신뢰 관계와 보안 경계

같은 포리스트 안의 도메인은 일반적으로 자동의 **양방향 전이 신뢰**로 연결됩니다. 별개 포리스트는 구성된 Forest Trust 등 특정 신뢰 관계를 통해 자원을 공유할 수 있습니다.

하지만 신뢰는 **상대방 신원을 인증할 수 있는 경로**에 가깝고, 실제 파일이나 서버 접근은 **그 자원에 대한 권한 부여**가 있어야 합니다.

중요한 보안 설계 원칙은 **포리스트를 주요 보안 경계로 본다**는 것입니다. 같은 포리스트에서 단지 별도 도메인이나 OU로 나눴다는 이유만으로 고권한 포리스트 관리자에게서 안전하게 분리된다고 보장할 수 없습니다.

## 12. AD에서 자주 악용되는 관리·인증 취약 지점

| 영역 | 공격·오설정의 개념 | 방어 및 탐지 |
| --- | --- | --- |
| Kerberoasting | 약한 서비스 계정 암호에 연결된 서비스 티켓을 오프라인 분석 | gMSA, 긴 무작위 암호, 4769 행동 탐지 |
| NTLM Relay / PtH | 중계되거나 유출된 인증 자료 악용 | SMB/LDAP Signing, 채널 바인딩, NTLM 축소, 자격 증명 보호 |
| LDAP·SPN Enumeration | 계정·서비스·권한 구조 조사 | 비정상 조회·프로세스 모니터링, 최소 공개 |
| 권한 그룹 오용 | 고권한 그룹 멤버십의 비정상 변경 | 4728, 4732, 4756 등 |
| GPO Abuse | 정책 변경 권한 또는 SYSVOL 파일 권한 오용 | GPO 변경 감사, 변경 승인, SYSVOL/AD ACL 확인 |
| ACL/Delegation Abuse | OU·객체에 위임한 수정 권한을 악용 | DACL/ACE 정기 리뷰, 5136/4662(설정 시) |
| DCSync | 높은 디렉터리 복제 권한 악용 | 복제 권한 관리, 4662 등 관련 감사 분석 |
| AD CS 오설정 | 인증서 템플릿·등록 권한·인증 매핑 악용 | PKI/인증서 템플릿 별도 관리 |
| 구형 인증·암호화 | 취약하거나 불필요한 레거시 프로토콜 | Kerberos/LDAP/SMB 보안 강화 및 단계적 전환 |

**중요:** OU나 그룹 구조를 읽거나 서비스 티켓을 요청하는 행위 자체가 항상 공격은 아닙니다. 출발지, 빈도, 업무 역할, 연관 프로세스와 후속 행동을 묶어 판단해야 합니다.

## 13. Windows 이벤트: 어떤 로그가 어디에 남나요?

| 이벤트 | 발생 장소(일반적) | 의미 |
| --- | --- | --- |
| **4768** | DC Security | Kerberos TGT 요청 |
| **4769** | DC Security | Kerberos 서비스 티켓(TGS) 요청 |
| **4771** | DC Security | Kerberos 사전 인증 실패 |
| **4776** | DC/관련 인증 시스템 | NTLM 자격 증명 검증 |
| **4624 / 4625** | 로그온 대상 시스템 | 로그인 성공 / 실패 |
| **4740** | DC 등 | 계정 잠금 |
| **4720 / 4726 / 4738** | 관련 DC Security | 사용자 생성 / 삭제 / 변경 |
| **4728 / 4756** | 관련 DC Security | Global / Universal 보안 그룹 멤버 추가 |
| **4732** | Domain Local 그룹은 DC Security, 서버·워크스테이션의 로컬 그룹은 해당 호스트 Security | 보안 로컬 그룹 멤버 추가; 그룹을 관리하는 시스템에서 수집 |
| **5136** | DC Security | AD 객체 속성 변경(해당 감사·SACL 등 필요) |
| **4662** | DC Security | 감사 대상 AD 객체 작업(대상 SACL 필요) |
| **4672** | 로그온 시스템 | 특수 권한이 할당된 로그온 |
| **1102** | Security 로그가 지워진 시스템 | 감사 로그 삭제 |

**중요:** 이벤트가 안 보인다고 활동이 없었다고 단정하지 마세요. 적절한 감사 정책, 권한(SACL), 로그 수집 설정과 시간 범위를 먼저 확인합니다. `5136`은 AD 변경을 보여주지만 도메인 컨트롤러의 모든 정책·파일 변경을 빠짐없이 입증하는 단일 로그는 아닙니다.

## 14. Splunk 입문용 조사 쿼리

### A. DC 이벤트 수집 확인

```spl
index=* (EventCode=4768 OR EventID=4768
         OR EventCode=4769 OR EventID=4769
         OR EventCode=5136 OR EventID=5136)
| eval event_id=coalesce(EventCode,EventID)
| stats count by host sourcetype event_id
| sort - count
```

`EventCode`와 `EventID`는 수집·파서에 따라 한쪽만 존재할 수 있으므로 `coalesce`로 `event_id`에 통합한 뒤 집계합니다. 두 원본 필드를 동시에 `BY`에 지정하면 한쪽이 없는 이벤트가 집계에서 누락될 수 있습니다.

`index=*`는 데이터 위치를 모를 때 사용하는 탐색용입니다. 운영 환경에서는 실제 인덱스와 시간 범위를 지정하고 수집된 필드명을 확인하세요.

### B. 계정·그룹 변경 탐색

```spl
index=* (EventCode=4720 OR EventID=4720
         OR EventCode=4728 OR EventID=4728
         OR EventCode=4732 OR EventID=4732
         OR EventCode=4756 OR EventID=4756)
| table _time host EventCode EventID SubjectUserName TargetUserName MemberName GroupName
| sort - _time
```

### C. AD 객체 변경 감사 점검

```spl
index=* (EventCode=5136 OR EventID=5136)
| table _time host SubjectUserName ObjectDN AttributeLDAPDisplayName OperationType AttributeValue
| sort - _time
```

**필드명이 비어 있다면** 실제 Windows XML, 이벤트 수집 도구, sourcetype를 먼저 확인하세요. 비어 있는 필드만으로 "이벤트가 없다"라고 판단하지 않습니다.

## 15. 관리자가 실행해 보는 읽기 전용 명령

다음 예시는 **RSAT ActiveDirectory 모듈**을 설치한 관리 PC에서 적절한 조회 권한으로 실행합니다.

### A. 도메인과 포리스트, FSMO 점검

```powershell
Import-Module ActiveDirectory
Get-ADDomain |
  Select-Object DNSRoot,DomainMode,PDCEmulator,RIDMaster,InfrastructureMaster

Get-ADForest |
  Select-Object Name,ForestMode,SchemaMaster,DomainNamingMaster,GlobalCatalogs

Get-ADDomainController -Filter * |
  Select-Object HostName,Site,IsGlobalCatalog,OperatingSystem
```

### B. OU 및 계정 구조 확인

```powershell
Get-ADOrganizationalUnit -Filter * |
  Select-Object Name,DistinguishedName

Get-ADUser -Identity "john" -Properties Enabled,UserPrincipalName,MemberOf |
  Select-Object SamAccountName,Enabled,UserPrincipalName,MemberOf

Get-ADGroupMember -Identity "GG_Finance_Staff" |
  Select-Object Name,ObjectClass
```

### C. DNS로 DC 찾기

```powershell
Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.corp.example.com"
```

```cmd
nltest /dsgetdc:corp.example.com
```

### D. GPO와 복제 상태 읽기

```powershell
Get-GPO -All | Select-Object DisplayName,Id,GpoStatus
```

`Get-GPO`에는 별도의 **GroupPolicy 모듈**과 권한이 필요합니다.

```cmd
repadmin /replsummary
gpresult /r
```

`repadmin`은 도메인 컨트롤러 복제의 오류·지연 요약을 보여주며, `gpresult /r`은 **명령을 실행한 컴퓨터·사용자**에 적용된 정책을 확인합니다. 두 도구의 범위는 다릅니다. **DC/DNS/GPO 구조 변경은 실습용 도메인 또는 승인된 변경 절차에서만 수행**하세요.

## 16. 실습: 회사 도메인의 접근 문제 조사

**가상 상황:** `john`이 도메인 PC에 로그인할 수 있지만 `\\fileserver\Finance`에는 "Access denied"가 나옵니다.

1. **DNS:** PC의 DNS 주소와 `nltest /dsgetdc` 결과를 확인합니다.
2. **사용자 인증:** 4624, DC의 관련 Kerberos/NTLM 이벤트를 확인하고 시간 동기화 문제를 배제합니다.
3. **그룹 멤버십:** `john`이 필요한 Global 그룹에 있는지, 중첩 Domain Local 그룹까지 연결되는지 확인합니다.
4. **권한 부여:** 서버의 **SMB 공유 권한과 NTFS 권한**을 따로 확인합니다. Deny ACE나 토큰 갱신 지연이 있는지 살펴봅니다.
5. **GPO:** 실제 적용 정책(`gpresult`), Security Filtering, 상속 및 SYSVOL 상태를 확인합니다.
6. **복제:** 최근 그룹 변경이 다른 DC나 리소스 서버의 로그인 세션에 아직 반영되지 않았는지 점검합니다.
7. **결론:** "계정이 유효함"과 "자원에 대한 권한 있음"을 구별하여 원인을 보고합니다.

### 확인 문제

1. 새로운 OU를 만들면 새로운 보안 경계가 생기나요? **아니요.**
2. 4769가 나타나면 Kerberoasting인가요? **아니요. 정상 CIFS 서비스 티켓 요청도 발생합니다.**
3. 로그인이 성공했는데 파일을 못 여는 이유는? **공유/NTFS ACL, 그룹, 토큰, 정책 등을 별도로 확인해야 합니다.**
4. DC와 일반 파일 서버 중 누가 사용자·그룹 디렉터리를 복제하나요? **AD DS를 실행하는 DC들이 복제합니다.**
5. OU에 연결한 GPO는 언제나 적용되나요? **아니요. 필터링·상속·링크·처리 조건의 영향을 받습니다.**

## 17. 현업 설계에서 꼭 지킬 보안 원칙

- **포리스트·DC를 고가치 자산으로 보호:** 관리 접근과 인터넷/직원 PC 직접 통신을 엄격히 제한합니다.
- **권한을 사람에게 직접 주기보다 그룹 기반으로 부여:** AGDLP와 정기적인 그룹 멤버십 검토를 활용합니다.
- **관리자 계정 분리:** 일반 업무 계정과 고권한 관리 계정을 구분하고 가능한 피싱 저항성 MFA 등 보호를 적용합니다.
- **서비스 계정 관리:** gMSA 적용 가능성을 검토하고 긴 무작위 비밀번호, 최소 권한, SPN 자산 관리를 수행합니다.
- **Kerberos·LDAP·SMB 강화:** 필요한 곳에 Signing, LDAP Channel Binding, 최신 암호화 및 불필요한 NTLM 축소를 계획합니다.
- **GPO 변경관리:** 편집·연결 권한을 최소화하고 변경 내역을 승인·감사합니다.
- **DNS·복제·백업:** AD 통합 DNS, DC 복제, SYSVOL 복제와 **System State 복원 계획**을 점검합니다.
- **로그 품질 확보:** DC Security, Directory Service, 엔드포인트·파일 서버 기록을 분리 수집하고 정상 기준선을 만듭니다.

## 18. 다음에 읽을 위키 문서

- [Kerberoasting: 공격·4769 탐지·방어]({{ '/ko/wiki/kerberoasting/' | relative_url }})
- [SMB: 원격접속·횡적 이동·방어]({{ '/ko/wiki/smb-security/' | relative_url }})
- [WPAD와 인증 정보 유도]({{ '/ko/wiki/wpad-security/' | relative_url }})
- [Windows 로그 기초]({{ '/ko/wiki/windows-logs/' | relative_url }})
- [Splunk 기초]({{ '/ko/wiki/splunk-basics/' | relative_url }})

- [다음 학습: Kerberos 인증 완전 가이드]({{ '/ko/wiki/kerberos-authentication/' | relative_url }})

**권장 다음 단계:** 이 문서를 이해한 뒤 **Kerberos Authentication 완전 가이드**로 AS-REQ/AS-REP, TGT/TGS, SPN, PAC를 심화하고, 이어 **NTLM 및 주요 공격**으로 넘어가면 자연스럽습니다.

## 19. Microsoft 공식 참고 자료

- [AD DS 논리 모델: Forest / Domain / OU](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-the-active-directory-logical-model)
- [DNS와 AD DS](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/dns-and-ad-ds)
- [DC Locator와 도메인 컨트롤러 검색](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/dc-locator)
- [AD 보안 그룹과 범위](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
- [GPO 처리 순서와 필터링](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)
- [FSMO 역할](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles)
- [2025 도메인·포리스트 기능 수준](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/raise-domain-forest-functional-levels)
- [LDAP 서명과 감사](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
- [Audit Directory Service Access](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-directory-service-access)
