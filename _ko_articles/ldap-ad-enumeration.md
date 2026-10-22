---
title: "LDAP와 Active Directory 열거 완전 가이드: 필터, ACL, BloodHound, 탐지와 방어"
description: "LDAP 정상 동작과 범위를 제한한 디렉터리 조회부터 AD 객체 권한, BloodHound 경로 검증, Windows 로그와 Splunk 탐지, 실무 방어까지 연결해 설명합니다."
category: active-directory
tags: [Windows Security, Active Directory, LDAP, Enumeration, ACL, BloodHound, SharpHound, Blue Team, Red Team, DFIR, Splunk, Detection Engineering]
level: Intermediate
updated: "2026-10-22"
translation_url: /wiki/ldap-ad-enumeration/
---

> **시리즈 4편.** [AD 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}), [Kerberos 인증]({{ '/ko/wiki/kerberos-authentication/' | relative_url }}), [NTLM 인증]({{ '/ko/wiki/ntlm-authentication/' | relative_url }})를 먼저 읽어보세요. 예제는 가상 도메인 `lab.example`을 사용하며 승인된 읽기 전용 점검을 위한 참고 자료입니다. 실제 운영 AD에서 실행한 결과가 아닙니다.

## 1. 전체 흐름: 디렉터리 정보 → 권한 → 경로 → 증거

LDAP 열거(Enumeration)는 사용자·그룹·컴퓨터·설정·관계 정보를 체계적으로 조회하는 과정입니다. 관리자, 자산 관리 시스템, 공격자가 비슷한 검색을 수행할 수 있습니다. 따라서 **누가, 어디에서, 어느 범위와 속성을, 어떤 업무 맥락에서 조회했는지**를 함께 해석해야 합니다.

1. **LDAP:** 어떤 객체가 있고 현재 신원으로 어떤 속성을 읽을 수 있는가?
2. **ACL 분석:** 현재 계정과 소속 그룹은 무엇을 변경할 수 있는가?
3. **BloodHound:** 이 관계들이 중요한 자산에 이르는 경로를 만드는가?
4. **탐지:** 조회·변경·후속 접근을 입증하는 증거는 무엇인가?
5. **방어:** 어떤 불필요한 권한을 제거해야 경로가 끊어지는가?

서비스 계정의 SPN을 읽었다고 비밀번호를 얻은 것은 아닙니다. 가능한 경로를 찾았다고 공격자가 실제로 이동했다는 뜻도 아닙니다. **관측한 정보, 모델이 나타내는 가능성, 확인된 실제 행위**를 구분하세요.

![LDAP 조회에서 ACL 검증과 권한 경로 개선으로 이어지는 흐름]({{ '/assets/diagrams/ldap-workflow-ko.svg' | relative_url }})

## 2. LDAP와 AD는 서로 다릅니다

**AD DS(Active Directory Domain Services)**는 Microsoft의 디렉터리 서비스이고, **LDAP**는 디렉터리에 접근하는 프로토콜입니다. AD에는 DNS·Kerberos·복제 등도 필요합니다. LDAP가 AD 전체이거나 Kerberos 인증과 같은 뜻은 아닙니다.

| 개념 | 의미 | 예시·해석 |
| --- | --- | --- |
| 엔트리 / 객체 | 디렉터리에 표현된 항목 | 사용자, 그룹, 컴퓨터, OU |
| 속성 | 객체의 특성 | `sAMAccountName`, `member`, `servicePrincipalName` |
| DN | 디렉터리 위치를 포함한 고유 이름 | `CN=Alice,OU=Lab,DC=lab,DC=example` |
| RDN | DN의 첫 번째 상대 이름 구성요소 | `CN=Alice` |
| Naming Context | 디렉터리 파티션 | Domain, Configuration, Schema |
| 스키마 | 객체 클래스·속성의 정의 | 자료형, 허용 속성 |
| SID / objectGUID | 객체 상관분석에 유용한 식별자 | 이동·이름 변경 시 DN은 달라질 수 있음 |

`CN=Users`는 일반적으로 OU가 아니라 **컨테이너**입니다. 검색 기준을 만들 때 `CN=`을 무조건 `OU=`로 바꾸지 마세요. AD의 computer 클래스는 user에서 파생되므로 `(objectClass=user)`만 사용하면 컴퓨터 객체도 포함될 수 있습니다.

### 도메인 컨트롤러와 글로벌 카탈로그

DC는 디렉터리 파티션을 보유합니다. **글로벌 카탈로그(GC)**는 다른 도메인의 부분 복제본을 이용해 포리스트 검색을 지원하지만, 모든 속성을 포함하지는 않습니다. GC 응답에 속성이 없다는 이유만으로 원래 도메인의 DC에도 없다고 판단하면 안 됩니다. 서버·포트·Naming Context를 먼저 기록하세요.

## 3. 정상 연결·인증·검색 과정

보호된 세션은 전송 보호 설정, 인증, 검색, 연결 종료 순서로 이해할 수 있습니다.

```text
Client → DC: connect; establish TLS if using LDAPS or StartTLS
Client ↔ DC: Bind / authentication exchange
Client → DC: SearchRequest(base, scope, filter, attributes, controls)
DC → Client: zero or more SearchResultEntry / referrals
DC → Client: SearchResultDone(result code)
Client → DC: next search, next page, or Unbind
```

클라이언트는 TLS를 사용한다면 먼저 이를 설정하고, Bind로 인증 관계를 수립한 뒤 SearchRequest를 보냅니다. DC는 검색 엔트리나 참조(Referral), 최종 결과 코드를 반환합니다. 다음 검색·다음 페이지 요청 또는 Unbind가 이어집니다.

**Bind 성공과 각 작업의 권한 허용은 별개입니다.** Search는 읽을 수 있는 정보를 반환하고, Modify·Add·Delete·ModifyDN은 별도 작업입니다. 성공 코드와 함께 결과가 0개인 경우는 작업 오류·불완전 응답과 다릅니다. 클라이언트가 Referral을 따라가면 처음 선택한 서버 밖으로 검색이 확장될 수 있습니다. [RFC 4511](https://www.rfc-editor.org/rfc/rfc4511.txt).

| 엔드포인트 | 일반적인 용도 | 해석 |
| --- | --- | --- |
| TCP 389 | LDAP, StartTLS·SASL 보호 포함 | 포트만으로 평문이라고 단정할 수 없음 |
| TCP 636 | 연결 시점부터 TLS를 사용하는 LDAP | 인증서 신뢰와 서버 이름 검증 필요 |
| TCP 3268 | GC LDAP | 도메인 LDAP와 검색 범위·속성이 다름 |
| TCP 3269 | TLS 기반 GC | TLS가 GC에 없는 속성을 추가해 주지는 않음 |
| UDP 389 | CLDAP / DC 탐색 | 일반적인 TCP Bind·검색 흐름과 다름 |

**Simple Bind**는 LDAP 계층에서 이름과 비밀번호를 보내므로 TLS로 보호해야 합니다. **SASL**은 협상을 통한 Kerberos 등의 인증 메커니즘을 사용할 수 있습니다. 인증 방식, 암호화, 디렉터리 권한을 구분하세요.

### 서명·암호화·채널 바인딩

서명은 무결성을 제공하고, TLS나 SASL Sealing은 기밀성도 제공합니다. 채널 바인딩(CBT)은 지원되는 인증을 해당 TLS 연결에 묶습니다. CBT는 ACL이 아니며 이미 허용된 읽기 권한을 없애지 않습니다. LDAPS 사용만으로 모든 Relay 방어가 설정되었다고 볼 수 없습니다. OS 이름으로 기본값을 추정하지 말고 유효 정책과 클라이언트 호환성을 확인하세요. [Microsoft LDAP 보안 설명](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing).

## 4. 필터보다 먼저 검색 범위를 정의하세요

각 조회에서 다음 항목을 기록합니다.

```text
server + identity + base DN + scope + filter + requested attributes + limits
```

즉 **서버 + 계정 + Base DN + Scope + 필터 + 요청 속성 + 제한**입니다.

| 범위 | 검색 대상 | 적절한 용도 |
| --- | --- | --- |
| Base | 기준 엔트리 자체 | RootDSE 또는 지정 객체 하나 |
| OneLevel | 기준 바로 아래 자식, 기준 자신 제외 | OU 직속 객체 |
| Subtree | 기준과 모든 하위 객체 | 범위를 정한 실습 OU |

**RootDSE**는 빈 Base DN과 Base 범위로 조회하며 `defaultNamingContext` 등 서버 기능·Naming Context 정보를 제공합니다. 도메인 루트 객체와는 다릅니다. 일부 RootDSE 정보의 익명 조회가 가능해도 일반 디렉터리 검색에는 인증이 필요할 수 있습니다.

필요한 속성만 요청하고 작은 OU부터 시작하세요. 크기·시간 제한과 페이징을 기록합니다. 페이징은 결과 엔트리를 나누어 받을 뿐 추가 권한을 부여하지 않습니다. 그룹의 `member` 같은 대규모 다중값 속성에는 엔트리 페이징과 별도로 **Range Retrieval**이 필요할 수 있습니다. 최종 결과 코드와 완전성을 확인해야 전체 목록이라고 부를 수 있습니다.

## 5. LDAP 필터 문법과 정확한 예제

필터는 SQL이 아니라 앞에 연산자를 놓는 불리언 표현식입니다.

| 목적 | 필터 |
| --- | --- |
| 값 일치 | `(sAMAccountName=alice)` |
| 속성 존재 | `(servicePrincipalName=*)` |
| 접두어 일치 | `(cn=Lab*)` |
| AND | `(&(objectCategory=person)(objectClass=user))` |
| OR | <code>(&#124;(sAMAccountName=alice)(sAMAccountName=bob))</code> |
| NOT | `(!(description=*))` |

필터 값의 리터럴 `*`, `(`, `)`, 역슬래시, NUL은 각각 `\2a`, `\28`, `\29`, `\5c`, `\00`으로 이스케이프합니다. `Ops (Lab)`라는 이름은 `(cn=Ops \28Lab\29)`로 표현합니다. **DN 이스케이프와 필터 이스케이프는 다릅니다.** DN을 필터 값에 넣으면 두 계층을 올바르게 처리해야 합니다. 사용자 입력을 그대로 연결하지 말고 라이브러리의 이스케이프 기능을 사용하세요. [RFC 4515](https://www.rfc-editor.org/rfc/rfc4515).

### AD 전용 Matching Rule

`1.2.840.113556.1.4.803`은 지정 비트가 설정되었는지 검사하는 비트 AND 규칙이며, `1.2.840.113556.1.4.1941`은 해당 DN 링크의 전이적 관계를 탐색합니다. 모든 LDAP 서버에서 지원하는 공통 문법은 아닙니다. [Microsoft 검색 필터 문법](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax).

```text
# Enabled person/user accounts (ACCOUNTDISABLE bit 2 is not set)
(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# User accounts with at least one SPN
(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))

# Accounts with Kerberos pre-authentication disabled
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# Direct members represented by memberOf
(memberOf=CN=Lab-Operators,OU=Lab,DC=lab,DC=example)

# Direct or nested members through the memberOf link chain
(memberOf:1.2.840.113556.1.4.1941:=CN=Lab-Operators,OU=Lab,DC=lab,DC=example)
```

위 예제는 순서대로 활성 사용자, SPN 보유 사용자, Kerberos 사전 인증 비활성 사용자, 직접 그룹 구성원, 중첩 그룹을 포함한 구성원을 조회합니다.

`memberOf`는 Primary Group 관계를 나타내지 않고, 단순 조회는 중첩 그룹을 펼치지 않습니다. 전이적 조회만으로 모든 신뢰·리소스 환경의 Windows 액세스 토큰을 완전히 재구성할 수도 없습니다. `adminCount=1`은 보호·과거 이력의 단서이며 현재 관리자 명단과 같지 않습니다.

`4194304` 플래그는 점검할 설정을 찾는 기준이지 악용 증거가 아닙니다. SPN은 정상 서비스 메타데이터입니다. [UAC 플래그 정의](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties)와 [Kerberoasting 가이드]({{ '/ko/wiki/kerberoasting/' | relative_url }})를 함께 읽어보세요.

## 6. 범위를 제한한 읽기 전용 열거 절차

승인된 실습 OU·담당자·계정·수집 시간대와 신뢰할 수 있는 DC 인증서를 준비합니다. 신원 목록 자체도 민감할 수 있으므로 내보낸 자료는 접근을 통제하세요.

### Windows: Active Directory PowerShell 모듈

RSAT의 ActiveDirectory 모듈과 현재 로그인 신원을 사용합니다. 가상의 `OU=Lab`이 존재해야 합니다. 결과를 100개로 제한했으므로 **전체 목록이 아닌 표본**입니다.

```powershell
Import-Module ActiveDirectory
$dc = 'dc01.lab.example'
$root = Get-ADRootDSE -Server $dc
$base = 'OU=Lab,' + $root.defaultNamingContext

Get-ADUser -Server $dc -SearchBase $base -SearchScope Subtree `
  -LDAPFilter '(&(objectCategory=person)(objectClass=user))' `
  -Properties memberOf,servicePrincipalName,whenChanged `
  -ResultPageSize 100 -ResultSetSize 100 |
  Select-Object SamAccountName,DistinguishedName,memberOf,
    servicePrincipalName,whenChanged
```

`-LDAPFilter`에는 LDAP 문법을, `-Filter`에는 모듈 고유 표현식을 사용합니다. 둘은 바꾸어 쓸 수 없습니다. AD PowerShell Cmdlet은 일반적으로 **AD Web Services(ADWS)**를 이용하므로, 이 예제가 클라이언트에서 LDAP 389/636 통신을 발생시킨다고 보장하지 않습니다. [Get-ADUser 공식 문서](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2025-ps).

### Linux / OpenLDAP: LDAP 직접 조회

`ldapsearch`에서 TLS와 정상 인증서 검증을 사용하고 비밀번호는 프롬프트로 입력합니다. 먼저 실습 CA를 클라이언트 신뢰 저장소에 등록하세요. 연결 실패를 해결하려고 인증서 검증을 우회하지 마세요.

```bash
# Discover the domain naming context (authenticated RootDSE base search)
ldapsearch -LLL -x -H ldaps://dc01.lab.example:636 \
  -D 'reader@lab.example' -W -b '' -s base \
  '(objectClass=*)' defaultNamingContext namingContexts

# Sample at most 100 user entries in the approved OU
ldapsearch -LLL -x -H ldaps://dc01.lab.example:636 \
  -D 'reader@lab.example' -W \
  -b 'OU=Lab,DC=lab,DC=example' -s sub -z 100 -l 15 \
  '(&(objectCategory=person)(objectClass=user))' \
  sAMAccountName distinguishedName memberOf servicePrincipalName
```

첫 명령은 인증된 RootDSE 조회이고, 두 번째는 승인된 OU에서 최대 100개 사용자 엔트리를 조회합니다. `ldap://...:389`에서는 `-ZZ`로 StartTLS 성공을 필수로 요구할 수 있습니다. 이는 연결 시작부터 TLS를 사용하는 LDAPS와 다릅니다. 100개·15초 제한 때문에 부분 결과나 제한 오류가 나올 수 있습니다. LDIF의 `attribute::`는 Base64 값이며 접힌 줄은 앞선 값의 연속입니다. [OpenLDAP ldapsearch 매뉴얼](https://www.openldap.org/software/man.cgi?query=ldapsearch&sektion=1).

| 수집 정보 | 조사 질문 | 해석의 한계 |
| --- | --- | --- |
| 사용자·상태 플래그 | 예상된 계정이며 담당자가 있는가? | 활성 상태가 최근 사용을 입증하지는 않음 |
| 그룹·연결 | 누가 위임된 역할을 이어받는가? | 중첩·Primary Group 한계 확인 |
| 컴퓨터·OS 메타데이터 | 관리 시스템은 어디에 등록되었는가? | OS 문자열이 오래되었을 수 있음 |
| SPN·위임 설정 | 검토할 서비스·신뢰 관계는 무엇인가? | 설정 존재가 악용 증거는 아님 |
| OU·GPO 링크 | 어떤 구조·정책이 자산에 영향을 주는가? | 링크만으로 유효 정책을 증명하지 못함 |
| 보안 설명자 | 누가 읽고 변경하고 권한을 위임하는가? | 유효 권한 해석 필요 |

## 7. 읽을 수 있는 객체에서 AD 유효 권한으로

객체의 **보안 설명자(Security Descriptor)**에는 소유자, 접근을 정의하는 **DACL**, 감사를 정의하는 **SACL** 등이 있습니다. 각 **ACE**는 주체와 허용·거부 작업을 나타내며 속성·속성 집합·자식 클래스에 한정될 수 있습니다. SACL은 감사 조건이지 권한 부여가 아닙니다. [Microsoft 객체 권한 모델](https://learn.microsoft.com/en-us/windows/win32/ad/controlling-access-to-objects-and-their-properties).

ACE는 다음 순서로 확인하세요.

1. Trustee SID와 검토 계정에 적용되는 그룹 구성원 관계.
2. Allow/Deny 유형과 정확한 권한.
3. `ObjectType`: 속성·속성 집합·확장 권한 GUID.
4. `InheritedObjectType`: 하위 클래스 제한 GUID.
5. 상속·전파 플래그, 현재 객체에 대한 적용 여부, 상속 차단 여부.
6. 함께 적용되는 다른 ACE와 평가 순서.

OU에서 상속된 권한이 특정 하위 클래스에만 적용될 수 있습니다. GUID는 스키마나 Extended-Rights 정의로 해석하세요. 모든 `WriteProperty`를 “모든 속성을 바꿀 수 있음”으로 요약하면 안 됩니다. [객체별 ACE 평가](https://learn.microsoft.com/en-us/windows/win32/secauthz/aces-to-control-access-to-an-object-s-properties).

### 변경하지 않고 ACL 읽기

도메인에 연결된 RSAT 세션에서 보안 설명자를 읽을 수 있는 계정으로 실행합니다. AD Provider 드라이브를 지정 DC에 연결합니다.

```powershell
Import-Module ActiveDirectory
New-PSDrive -Name LabAD -PSProvider ActiveDirectory -Root '//RootDSE/' `
  -Server 'dc01.lab.example' | Out-Null
$dn = 'CN=Lab-Operators,OU=Lab,DC=lab,DC=example'
$acl = Get-Acl -LiteralPath ('LabAD:\' + $dn)
$acl | Select-Object Owner,AreAccessRulesProtected
$acl.Access | Select-Object IdentityReference,AccessControlType,
  ActiveDirectoryRights,ObjectType,InheritedObjectType,
  InheritanceType,IsInherited
Remove-PSDrive -Name LabAD
```

이 명령은 설명자의 항목을 나열하며 특정 사용자의 전체 유효 권한을 계산하지 않습니다. DC·수집 시각을 기록하고 GUID를 해석한 뒤 유효 권한을 검토하세요. 마지막의 임시 로컬 드라이브 제거는 디렉터리를 변경하지 않습니다.

## 8. 우선 검토할 권한

| 권한·관계 | 보안상 의미 | 방어 관점의 점검 |
| --- | --- | --- |
| GenericAll | 해당 AD 객체에 대한 광범위한 제어 | 객체 유형·민감도·예외 확인 |
| GenericWrite | 광범위한 속성 쓰기 | 실제 변경 가능한 속성 확인 |
| WriteDacl | 객체의 접근 규칙 변경 | 누가 추가 권한을 위임할 수 있는가? |
| WriteOwner | 적용 규칙에 따른 소유권 변경 | 소유자 권한 제한·유효 권한 평가 |
| ForceChangePassword | 비밀번호 재설정 확장 권한 | 기존 비밀번호를 알고 변경하는 것과 다름 |
| AddMember | 그룹 구성원 제어를 나타내는 관계 | 그룹 `member` 권한과 결과 접근 확인 |
| 복제 관련 확장 권한 | 디렉터리 복제 가능성 | 도메인 루트의 비DC 주체 부여 점검 |
| 관리되는 비밀정보 읽기 | 로컬·서비스 계정 자격 증명 노출 가능성 | 허용된 독자·보호 설정 검토 |

**컴퓨터 객체의 GenericAll은 실행 중인 컴퓨터의 로컬 관리자 권한과 같지 않습니다.** 디렉터리 제어에서 다른 가능성이 생겨도 전제조건을 검증해야 합니다. 소유권 역시 무제한 DACL 제어를 항상 뜻하지 않으며 OWNER RIGHTS와 현재 동작을 고려해야 합니다. [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all), [WriteDacl](https://bloodhound.specterops.io/resources/edges/write-dacl), [소유자 권한 분석](https://specterops.io/blog/2025/03/26/do-you-own-your-permissions-or-do-your-permissions-own-you/).

보호된 관리 객체는 AdminSDHolder/SDProp이 상속 동작을 관리할 수 있습니다. 그룹에서 제외해도 과거 `adminCount`나 상속 상태가 자동 정리되는 것은 아닙니다. 수정한 ACL이 반복 복원된다면 보호 메커니즘부터 확인하세요.

## 9. BloodHound: 관계를 모델링하고 검증하기

**SharpHound는 수집하고, BloodHound는 그래프 관계를 적재·분석합니다.** 사용자·그룹·컴퓨터는 노드이고 구성원·권한·기타 관계는 엣지입니다. 모든 엣지가 곧바로 실행 가능한 제어 단계를 뜻하지는 않습니다.

| 엣지 | 의미 | 피해야 할 단정 |
| --- | --- | --- |
| MemberOf | 그룹 구성원 관계 | 모든 그룹이 특권 그룹임 |
| AdminTo | 컴퓨터에 대한 관리 관계 | 실제 로그인이 발생함 |
| HasSession | 수집 시점에 관측한 세션 관계 | 지금 자격 증명을 반드시 복구할 수 있음 |
| GenericAll / WriteDacl | 객체 제어 가능성 | 권한이 실제로 행사됨 |
| Contains / GPLink | 구조·정책 관계 | 각각 독립적인 악용 단계임 |

그래프는 **특정 시점의 모델**이며 실행 기록이 아닙니다. 세션 정보는 빨리 낡고, 수집 권한에 따라 누락이 생기며, 버전마다 모델 지원도 다릅니다. 수집기·BloodHound 버전, 방법, 시각, 실패를 기록하세요. “경로 없음”이 자료 부족 때문일 수도 있습니다.

### 수집 범위 선택

승인된 최초 점검에서는 질문에 맞는 범위를 선택하세요. `DCOnly`는 멤버 컴퓨터에 접촉하지 않지만 Default/All은 엔드포인트 수집을 포함할 수 있습니다. DC만 수집한 자료는 동일한 실시간 세션·엔드포인트 범위를 제공하지 않습니다. 설치 버전의 옵션을 확인하고 제외 범위를 기록하세요. [SharpHound CE](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound), [수집 옵션](https://bloodhound.specterops.io/collect-data/ce-collection/sharphound-flags).

실제 수집 ZIP이나 그래프에는 내부 신원·제어 관계가 담기므로 공개 위키에 올리지 마세요. 이 문서의 그래프는 가상 자료이며 운영 도메인 수집이 필요하지 않습니다.

## 10. 가상 권한 경로를 끝까지 검토하기

승인된 점검에서 다음 모델을 얻었다고 가정합니다.

```text
LAB\Alice
  --MemberOf--> LAB\Helpdesk-Lab
  --WriteDacl--> LAB\Server-Operators-Lab
  --AdminTo--> APP01
```

두 번째 엣지는 Helpdesk-Lab이 **그룹 객체** Server-Operators-Lab의 DACL을 바꿀 수 있다는 뜻입니다. 세 번째는 수집 자료상 해당 그룹이 APP01에 관리 권한을 가진다는 의미입니다. Alice가 현재 그 그룹에 가입되어 있거나 DACL을 실제 변경했다는 뜻은 아닙니다.

| 단계 | 확인할 증거 | 성급한 결론이 되는 경우 |
| --- | --- | --- |
| 구성원 관계 | 현재 직접·중첩 구성원과 신원 매핑 | 그룹 링크·SID가 오래됨 |
| WriteDacl | 현재 그룹 ACL, Trustee, 적용 ACE | ACE 범위가 다르거나 차단됨 |
| 중간 제어 단계 | 위임으로 그룹 구성원 제어가 가능한지 | 필요한 조건이 그래프에 생략됨 |
| AdminTo | APP01의 현재 로컬 관리·정책 | 로컬 정책·구성원이 변경됨 |
| 업무 영향 | APP01 역할·도달 가능한 민감 서비스 | 대상이 잘못 분류되거나 폐기됨 |

**개선:** 조직 변경 절차에 따라 Helpdesk-Lab이 Server-Operators-Lab에 가진 불필요한 위임을 제거·축소합니다. 전후 ACL과 업무 담당자 승인을 보존하고, 관계를 다시 수집해 우회 경로와 정상 업무를 확인합니다. 가장 짧은 경로가 항상 최고 위험은 아닙니다. 핵심 자산에 대한 도달성과 변경으로 제거되는 경로 수를 고려하세요.

![가상 권한 경로와 검토해야 할 위임]({{ '/assets/diagrams/ldap-path-ko.svg' | relative_url }})

## 11. 로그와 텔레메트리가 입증하는 것

| 자료·이벤트 | 확인 가능한 내용 | 전제조건·한계 |
| --- | --- | --- |
| 네트워크 흐름 | 출발지·DC·포트·시각·통신량 | TLS·Sealing은 검색 내용을 숨김 |
| 엔드포인트 프로세스·네트워크 | 디렉터리에 접속한 프로세스 | 수집 범위·프로세스 연결 품질에 좌우됨 |
| 1644, Directory Service | 선택된 고비용·비효율·느린 검색 | 진단 설정·임계값 필요, 모든 검색 아님 |
| 4662, Security | 감사 대상 디렉터리 객체 작업 | Directory Service Access 감사와 일치 SACL |
| 5136, Security | 감사 대상 속성 변경 | Directory Service Changes 감사와 일치 SACL |
| 4728 / 4732 / 4756 | 보안 글로벌·로컬·유니버설 그룹 구성원 추가 | 관련 계정 관리 감사와 올바른 로그 위치 |
| 4624 / 4769 | 로그인·Kerberos 서비스 티켓 맥락 | 전체 LDAP 검색 이력은 아님 |
| 4688 / PowerShell 4104 | 활성화된 경우 프로세스·스크립트 맥락 | 모든 LDAP 프로그램이 스크립트 로그에 잡히지는 않음 |

1644는 주로 성능 진단 자료입니다. 용량을 계획하고 제한된 시간 동안 사용한 뒤 운영 설정으로 복원하세요. 대량 진단 로그는 부하를 만들 수 있습니다. [Microsoft 1644 설명](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/event1644reader-analyze-ldap-query-performance).

4662에서는 작업·속성 GUID와 객체를 해석합니다. 5136에서는 객체 GUID, 수행 계정·Logon ID, 상관 ID, 속성 이름을 연결하세요. 값 삭제와 추가가 같은 변경에 속할 수 있습니다. **5136은 읽기 전용 검색 기록이 아닙니다.** [4662](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662), [5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136).

### LDAP 전송 보안 이벤트

| 이벤트 | 해석 |
| --- | --- |
| 2886 | 서명을 필수로 요구하지 않는 구성 경고 |
| 2887 | 허용된 비보호 Bind의 주기적 요약 |
| 2888 | 거부된 비보호 Bind 시도의 주기적 요약 |
| 2889 | 진단 로깅 활성화 시 비보호 Bind 클라이언트·신원 상세 |
| 3039 | TLS Bind의 채널 바인딩 토큰 검증 실패 |
| 3040 / 3041 | 문서상 조건에 따른 비보호 TLS Bind 요약 / CBT 구성 경고 |

**2889는 서명된 Bind 성공 이벤트가 아니며, 3041도 채널 바인딩 성공 이벤트가 아닙니다.** 메시지·Provider·OS 버전·유효 설정을 함께 읽으세요. 이 이벤트는 통신·인증 보호 상태를 나타내며 검색의 악성 여부를 직접 증명하지 않습니다. [서명 이벤트 설명](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-signing-in-windows-server), [KB4520412](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412).

## 12. 필터 하나보다 행위 맥락을 탐지하세요

SPN 검색은 정상 관리에서도 발생합니다. 새로운 워크스테이션·계정 조합, 넓은 범위, 여러 민감 속성군, 특이한 프로세스, 후속 제어 변경을 결합해야 더 강한 조사 가설이 됩니다.

| 후보 신호 | 가능한 정상 원인 | 다음 확인 |
| --- | --- | --- |
| 많은 OU·그룹 검색 | 자산·신원 관리 | 승인 출발지·담당자·일정·기준선 |
| 대량 보안 설명자 읽기 | ACL 감사·BloodHound 점검 | 점검 기간·수집 계정·범위 |
| SPN·사전 인증 검색 | 서비스 계정 점검 | 프로세스·후속 Kerberos 동작 |
| 조회 후 그룹·DACL 변경 | 위임 유지보수 | 변경 티켓·객체·수행자 |
| 처음 보는 LDAP 클라이언트 | 신규 애플리케이션 | 소프트웨어 출처·담당자 |

승인된 수집기도 영구적인 무조건 허용 목록으로 삼지 마세요. 승인 계정이 침해될 수 있습니다. 출발지·계정·시간·목적을 함께 기준선으로 관리하세요.

### Splunk 예제: 정규화한 검색 요약

다음은 **설명용 스키마**이며 기본 Windows 로그에 이 필드가 자동 제공된다는 뜻이 아닙니다. 파서를 먼저 만들고 검증하세요. `user`는 추가 보강이 필요할 수 있으며 IP만으로 신원을 단정하면 안 됩니다.

```spl
index=ad_lab sourcetype=ldap_search_normalized
| bin _time span=5m
| stats count AS observed_queries dc(filter) AS distinct_filters
    sum(entries_returned) AS observed_entries
    values(search_base) AS bases values(process_name) AS processes
    BY _time src_ip user
| where observed_queries >= 50 AND distinct_filters >= 5
```

50건·5종 필터는 실습용 조정 가설이며 보편적인 공격 임계값이 아닙니다. 임계값 기반 1644를 입력으로 삼으면 개수는 **기록된 검색 수**이지 전체 검색·고유 객체 수가 아닙니다. 정상 유지보수·승인 점검 구간으로 검증하세요.

### Splunk 예제: 주요 디렉터리 변경

```spl
index=windows sourcetype="XmlWinEventLog:Security" EventCode=5136
  AttributeLDAPDisplayName IN ("nTSecurityDescriptor","member",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-KeyCredentialLink","servicePrincipalName")
| table _time Computer SubjectUserName SubjectLogonId ObjectDN
    AttributeLDAPDisplayName OperationType OpCorrelationID
```

필드명은 Windows Add-on·파서에 따라 다릅니다. 위 검색은 **열거가 아니라 변경**을 찾습니다. 기준 ACL·그룹 관리 이벤트·엔드포인트 증거와 연결하세요. 결과가 없으면 SACL·수집·필드 매핑 누락도 확인해야 합니다.

## 13. 조사 실습: 관측과 결론을 구분하기

다음은 원시 이벤트 출력이 아닌 가상 타임라인입니다.

| 시각(UTC) | 관측 | 적절한 결론 |
| --- | --- | --- |
| 01:00 | 승인 자산 관리 호스트가 Lab OU 조회 | 변경 기록의 범위와 맞으면 정상 조회 |
| 01:20 | 신규 워크스테이션에서 5종 필터군의 검색 70건 기록 | 이상 패턴 조사, 침해 단정 금지 |
| 01:23 | 같은 계정의 그룹 보안 설명자 변경이 5136에 기록 | 변경 발생, 달라진 ACE 해석 필요 |
| 01:24 | 보안 그룹 구성원 추가 기록 | 그룹·대상 구성원·수행자·승인 확인 |
| 01:27 | APP01에서 관련 로그인 발생 | 신원·방식 연결, 인증만으로 실행 증명 불가 |

**질문:** 시작 호스트·프로세스는 무엇인가? 승인된 점검인가? 변경 ACL이 모델의 경로를 실제로 가능하게 하는가? 계정이 구성원 자격을 얻고 사용했는가? 시간대를 정규화하고 시계를 동기화했는가?

**해설:** 신규 출발지와 넓은 조회는 분류·조사 근거이며, 뒤따른 ACL·구성원 변경이 승인되지 않았다면 우선순위를 높입니다. 신원·객체·접근 증거를 연결해야 경로 이용 가설을 뒷받침할 수 있습니다. 이 타임라인만으로 자격 증명 탈취나 도메인 침해를 입증할 수는 없습니다.

원본 XML, 수집 시각, DC, 객체 GUID/SID, 전후 권한, 엔드포인트 기록을 보존하세요. 악용이 확인되면 신원 관리 담당자와 계정·세션 통제 및 권한 복원을 조율하고, 파괴적 정리 전에 증거를 보존합니다.

## 14. 방어: 불필요한 경로 제거와 가시성 개선

| 우선순위 | 조치 | 완료 증거 |
| --- | --- | --- |
| 1 | 특권 그룹·도메인 루트·핵심 서비스 신원의 제어 권한 검토 | 담당자와 유효 권한의 업무 근거 |
| 2 | 오래되거나 넓은 위임 제거, 관리 계층 분리 | 전후 ACL과 핵심 자산 도달성 감소 |
| 3 | 호환성 시험 후 적절한 서명·TLS·CBT 적용 | 유효 정책·앱 시험·Bind 이벤트 검토 |
| 4 | 관리 출발지 제한, 서비스 계정 최소 권한 | 의존성·승인 출발지와 계정 기록 |
| 5 | 필요한 SACL과 DC·엔드포인트 중앙 수집 | 알려진 실습 읽기·변경의 예상 로그 확인 |
| 6 | 개선 후 범위를 정해 재수집 | 경로 제거·우회 검토·정상 업무 확인 |

AD 애플리케이션은 디렉터리 읽기에 의존하므로 광범위한 읽기 권한을 무작정 제거하지 마세요. 민감 속성과 위험한 쓰기·위임 권한을 우선하세요. 전송 보호는 채널을 보호하지만 **허용된 인증 사용자의 열거를 없애지 않습니다.** 강한 인증·최소 권한·엔드포인트 보안·모니터링은 각각 다른 문제를 해결합니다.

서명·CBT 강제 전에 클라이언트를 파악·개선하세요. 인증서 갱신, 이름 검증, 장비 호환성, 복원 기준을 변경 계획에 포함합니다. 인증서 검증 약화나 비보호 Simple Bind를 영구 우회책으로 남기지 마세요.

## 15. 문제 해결과 흔한 오해

| 증상·주장 | 확인·교정 |
| --- | --- |
| 결과가 없음 | Base·Scope·Naming Context·필터·읽기 권한·Referral·GC 속성 |
| 일부 엔트리·구성원만 나옴 | 크기·시간 제한, 페이징, Range Retrieval, 수집 실패 |
| TLS 실패 | 신뢰 체인·호스트 이름·만료·DC 인증서·서비스 설정 |
| Strong authentication required | Bind 방식·유효 서명 정책, 무작정 보호 해제 금지 |
| PowerShell은 되는데 LDAP 통신이 안 보임 | AD 모듈의 ADWS 사용 가능성 |
| GenericAll은 로컬 관리자임 | AD 객체 제어와 호스트 관리 관계는 다름 |
| LDAP 검색은 모두 4662를 남김 | 감사 설정·일치 SACL에 따라 다름 |
| BloodHound 경로가 없으니 안전함 | 범위·최신성·모델 한계를 확인해야 함 |
| 암호화하면 열거를 막음 | 전송 보호와 읽기 권한은 별개 |

## 16. 학습 완료 점검과 다음 문서

- LDAP·AD DS·인증·인가를 구분해 설명할 수 있습니다.
- 범위를 정한 필터를 작성하고 리터럴 이스케이프를 해석할 수 있습니다.
- 서버·신원·Base·Scope·속성·제한·수집 시각을 기록합니다.
- 표본·부분 결과와 전체 목록을 구분합니다.
- ACE 하나의 주체·권한·GUID·상속을 변경 없이 해석합니다.
- 가상 BloodHound 경로의 각 관계를 검증합니다.
- 조회·권한 변경·실제 자원 접근 증거를 구분합니다.
- 감사 전제조건과 탐지 가설을 알려진 정상 동작으로 시험합니다.
- 개선·우회 경로·검증 한계를 기록합니다.

다음으로 [Windows 로그]({{ '/ko/wiki/windows-logs/' | relative_url }}), [Splunk 기초]({{ '/ko/wiki/splunk-basics/' | relative_url }}), [SMB 보안]({{ '/ko/wiki/smb-security/' | relative_url }}), [Kerberoasting]({{ '/ko/wiki/kerberoasting/' | relative_url }})을 읽어보세요.

**다음 학습 — 시리즈 5편:** [Windows 횡적 이동: SMB·RDP·WinRM·WMI·PsExec]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }})에서 디렉터리 권한을 실제 원격 접근·실행·로그 증거와 연결하세요.

**번역 기준:** 2026년 10월 21일 영문판. **한국어판 추가:** 2026년 10월 22일. 위 출처는 프로토콜·제품 동작의 근거이며 실습 도메인·도표·임계값·조사 사례는 설명용 가상 자료입니다. 도구 옵션·이벤트 메시지·정책은 운영 버전과 대조하세요. 게시 과정에서 실제 디렉터리에 명령을 실행하지 않았습니다.
