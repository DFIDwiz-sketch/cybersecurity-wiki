---
title: "AD CS 보안 완전 가이드: 인증서 템플릿, ESC 위험, 강력한 매핑, 탐지와 방어"
description: "인증서 등록·인증의 원리, AD CS 템플릿·CA 권한, 주요 ESC 위험 조건과 최신 매핑 정책을 배우고 감사 로그·Splunk·가상 조사 실습으로 연결합니다."
category: active-directory
tags: [Windows Security, Active Directory, AD CS, PKI, Certificates, Certificate Templates, NTLM Relay, Kerberos, Blue Team, DFIR, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-22"
translation_url: /wiki/ad-cs-security/
---

> **AD 보안 확장편.** [AD 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}), [Kerberos]({{ '/ko/wiki/kerberos-authentication/' | relative_url }}), [NTLM]({{ '/ko/wiki/ntlm-authentication/' | relative_url }}), [LDAP·ACL]({{ '/ko/wiki/ldap-ad-enumeration/' | relative_url }}), [Windows 횡적 이동]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }})을 먼저 읽어보세요. 시스템·인증서는 가상이며 명령은 설정·메타데이터를 조회합니다. 타인 사칭 인증서 요청, 개인키 내보내기, 인증 릴레이, 운영 정책 변경을 수행하는 예제가 아닙니다.

## 1. AD CS가 신원 보안에서 중요한 이유

**Active Directory Certificate Services(AD CS)**는 사용자·장치·서비스의 인증서를 발급·관리하는 Windows Server PKI 역할입니다. 인증·TLS·서명 등 다양한 목적으로 사용됩니다. Enterprise CA는 AD에 저장된 템플릿을 적용할 수 있으며 Standalone CA는 다른 등록 모델입니다. 모든 DC에 AD CS가 자동 설치되는 것은 아닙니다. [Microsoft AD CS 개요](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview).

인증서는 대상이 신뢰 체인·용도·신원 연결·개인키 보유 증명과 정책을 받아들일 때 인증 수단이 됩니다. 잘못된 템플릿이나 등록 엔드포인트는 비밀번호 중심의 모니터링이 놓치는 신원 경로를 만들 수 있지만, 정상 인증서 발급 자체가 침해는 아닙니다.

**위험한 구성, 요청 수신, 인증서 발급, 실제 인증·자원 접근**을 서로 다른 사실로 기록하세요.

## 2. 인증서 용어와 흔한 혼동

| 용어 | 의미 | 조사상 주의 |
| --- | --- | --- |
| 공개 인증서 | 공개키와 인증서 정보를 연결한 서명된 자료 | 파일 보유만으로 개인키 접근을 입증하지 못함 |
| 개인키 | 키 보유 증명·허용된 암호 작업에 사용하는 비밀 | 파일·저장소·백업·서명 작업 권한 보호 |
| Subject / SAN | 인증서가 주장하는 주체·대체 이름 | 요청한 이름과 KDC가 매핑한 계정은 다를 수 있음 |
| EKU | Extended Key Usage, 허용된 용도 | TLS 전용 인증서가 자동으로 AD 로그온 자격 증명이 되지는 않음 |
| 템플릿 | Enterprise 등록 정책과 클라이언트 설정 | 표시 이름·내부 이름·OID는 다른 식별자 |
| Issuer + Serial Number | 발급자 문맥 안에서 인증서 식별 | Serial만으로 서로 다른 CA를 연결하면 안 됨 |
| Thumbprint | 특정 인증서의 지문 | 사용자 SID·개인키·요청 번호와 다름 |
| CSR / 등록 요청 | 공개키·등록 정보를 담은 요청 | 요청 속성과 최종 발급 속성이 다를 수 있음 |
| CRL / OCSP | 해지 상태 확인 수단 | 게시·조회·소비자의 적용은 별개 |

`.cer`는 보통 공개 인증서 자료이며 `.pfx`에는 개인키도 포함될 수 있습니다. 확장자만 믿지 말고 내용·보호 상태를 확인하세요. 내보낼 수 없는 키도 침해된 허용 프로세스를 통해 악용될 수 있습니다.

## 3. 정상 등록과 이후 인증

![인증서 등록·발급·인증·접근은 서로 다른 단계]({{ '/assets/diagrams/adcs-lifecycle-ko.svg' | relative_url }})

1. 정상 클라이언트가 키 쌍을 만들거나 사용하고 등록 정책·템플릿을 선택합니다.
2. 도달 가능한 등록 서비스에 인증한 뒤 요청을 제출합니다.
3. CA가 정책·게시 템플릿·등록 권한·승인/서명 조건을 평가합니다.
4. 발급·거부·보류 상태가 결정됩니다. 최종 인증서와 상태를 확인해야 합니다.
5. **이후 별도 작업에서** 클라이언트가 개인키 보유를 대상 서비스에 증명합니다.
6. 대상은 신뢰·용도·유효기간·해지·매핑 정책을 확인하며 자원 접근에는 여전히 권한 부여가 필요합니다.

Kerberos 인증서 인증은 초기 티켓 교환의 PKINIT과 연결되며 이후에는 일반 Kerberos 티켓을 사용할 수 있습니다. TLS 클라이언트 인증 등 다른 소비자는 별도 처리 방식을 가집니다. 모든 발급이 PKINIT에 쓰이거나 자동으로 새 로그온을 만드는 것은 아닙니다.

오프라인 루트와 온라인 발급 CA는 흔한 설계이지만 모든 조직의 구조가 같지는 않습니다. 실제 신뢰 경로, 해당되는 NTAuth 등 인증 신뢰, 등록 서비스와 의존 애플리케이션을 기록하세요.

## 4. 템플릿: 등록 권한과 정책 제어 권한

Enterprise 템플릿은 Configuration 파티션의 AD 객체입니다. 주체 이름 구성·용도·키 요건·승인·등록 동작을 정의하며 CA가 해당 템플릿을 발급하도록 구성되어 있어야 합니다. [인증서 템플릿 개념](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts).

| 제어 지점 | 확인 질문 | 구분할 것 |
| --- | --- | --- |
| Read / Enroll | CA 정책 아래 누가 사용할 수 있는가? | 템플릿 수정 권한과 다름 |
| Autoenroll | 어떤 적격 클라이언트가 자동 등록하는가? | CA 정책 우회·임의 신원 획득과 다름 |
| Subject/SAN 구성 | AD가 신원을 제공하는가, 요청자가 영향력을 가지는가? | 모든 입력이 인증에 받아들여지는 것은 아님 |
| 인증 가능한 용도 | 어떤 소비자·용도에서 사용하는가? | 사칭 성공을 보장하지 않음 |
| 관리자 승인 / 허가된 서명 | 독립 승인 절차는 무엇인가? | 네트워크 인증과 별개 |
| 템플릿 DACL / 소유자 | 누가 권한·보안 속성을 변경하는가? | 단순 등록 권한과 다름 |
| CA 게시 / CA 권한 | 발급 가능한 템플릿이며 CA 정책이 요청자를 허용하는가? | AD 객체가 존재하는 것만으로 부족 |

중첩 그룹·객체별 ACE·상속을 포함한 유효 ACL을 검토하세요. 템플릿 관리자·CA 관리자·인증서 관리자·Enrollment Agent는 다른 역할입니다. 다른 주체 대신 등록하는 정상 Agent도 범위를 제한하고 감사해야 합니다.

## 5. 주요 ESC 분류를 가설로 읽기

**ESC**는 AD CS 악용 조건을 분류하는 실무 명칭이며 Microsoft CVE 번호나 모든 최신 공격을 포괄하는 목록이 아닙니다. 도구·그래프 버전에 따라 경로가 나뉘거나 이름이 달라질 수 있습니다. 구성·유효 권한·도달 가능한 인증 경로를 확인해야 실제 위험을 판단할 수 있습니다.

| 분류 | 검토할 위험 | 방어 관점의 검증 |
| --- | --- | --- |
| ESC1 | 인증용 템플릿에서 요청자가 신원 정보에 영향력을 가진 등록 | 게시·등록 권한·신원 입력·승인/서명·실제 매핑 |
| ESC4 | 템플릿을 위험하게 바꿀 수 있는 과도한 제어 | 현재 ACL·소유자·정확한 변경 가능 속성·기준 구성·발급 경로 |
| ESC7 | 과도한 CA 관리·인증서 관리자 권한 | 역할 분리·승인·위임 범위 |
| ESC8 | 관련 IIS 등록 엔드포인트의 NTLM Relay 노출 | EPA 필수·HTTPS 전용·인증 Provider·실제 엔드포인트 |
| ESC11 | RPC 등록의 필수 Packet Privacy 보호 미적용 | 유효 Interface Flags·클라이언트·호환 강제 설정 |

템플릿 경로는 [SpecterOps ESC1](https://bloodhound.specterops.io/resources/edges/adcs-esc1), [ESC4](https://bloodhound.specterops.io/resources/edges/adcs-esc4), CA·인터페이스 점검은 [Microsoft 인증서 보안 평가](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates)를 참고하세요.

ESC6/ESC9/ESC16 등으로 설명되는 광범위 SAN 정책·SID 확장 억제 시나리오는 **매핑 동작에 의존**합니다. 플래그 하나만으로 성공 경로를 단정하거나 최신 DC 강화로 모든 템플릿·릴레이·CA 키 위험이 사라졌다고 보지 마세요. 이 문서는 주요 위험군의 방어적 판단을 다루며 모든 ESC 변형을 열거하지 않습니다.

## 6. 강력한 인증서 매핑: 2026년 기준

오래된 자료는 입력한 UPN만으로 계정을 선택할 수 있는 것처럼 설명하기도 합니다. 현재 Windows KDC 보호에서는 **인증서와 계정의 강력한 바인딩**을 확인해야 합니다. 적절한 SID 확장이나 명시적 강력한 매핑 등이 필요하며 Subject·이름만의 매핑은 같은 수준이 아닙니다.

[KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers)에 따라 관련 DC는 2025년 2월 업데이트에서 기본 Enforcement로 전환되었고, **2025년 9월 9일 이후 업데이트**에서는 기존 `StrongCertificateBindingEnforcement` 호환 모드 전환 지원이 제거되었습니다. 2026년 점검에서는 실제 패치·유효 인증 구성을 기록하고 폐기된 레지스트리 우회책을 해결책으로 제시하지 마세요.

이것은 KDC 매핑 통제이며 모든 인증서 악용을 제거하는 기능은 아닙니다. 최종 인증서·허용된 이름/SID 입력·CA/템플릿 처리·강력한 매핑·소비 서비스·공격자 제어 범위를 평가하세요. Schannel/TLS·제3자 CA·등록 플랫폼은 의존성이 다를 수 있습니다. 정상 갱신·인증을 시험하면서 개선하고 실패를 없애려고 검증을 약화하지 마세요.

KB에 설명된 Kdcsvc System 이벤트로 매핑 문제를 조사할 수 있습니다. Provider·메시지·OS·인증서 정보를 확인해야 하며 임의 Provider의 이벤트 번호 39만으로 AD CS 문제라고 판단하면 안 됩니다.

## 7. 등록 릴레이: 대상 프로토콜 보호

공격자가 실시간 인증 교환을 등록 서비스에 전달하면 허용된 등록 정책 아래 중계된 신원용 인증서를 얻을 가능성이 있습니다. 비밀번호 복구가 반드시 선행되는 것은 아니며 컴퓨터 계정도 대상이 될 수 있습니다.

영향받는 웹 등록/CES 구성에 대해 Microsoft는 **EPA와 HTTP 비활성화**를 권고하며 Required EPA가 더 강한 설정입니다. HTTPS만으로 NTLM Relay 방어를 보장하지 않습니다. 설치된 IIS 엔드포인트·관련 CES 구성·NTLM 의존성을 각각 확인하세요. RPC 등록의 Packet Privacy 요건은 별도이며 웹 보호가 RPC를 자동 보호하지 않습니다. [KB5005413](https://support.microsoft.com/en-us/servicing/os/windows-server/2021/07/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs).

IIS 요청·인증 이벤트 하나만으로 릴레이나 발급을 증명하지 못합니다. 출발 호스트·엔드포인트·인증 신원·CA 처리 결과·후속 사용을 연결하세요. 역방향 프록시·로드밸런서·TLS 종료 지점은 바인딩과 출발지 해석에 영향을 줄 수 있으므로 실제 경로를 시험합니다. 불필요한 등록 표면은 의존성을 확인한 뒤 정상 변경 절차로 제거하세요.

## 8. 개인키 탈취와 CA 침해

사용자·장치 인증서 악용에는 보통 개인키나 그 키를 사용하는 작업에 대한 접근이 필요합니다. 계정 비밀번호를 재설정한다고 인증서가 자동 해지되지는 않습니다. 정책·유효기간에 따라 인증 경로가 남을 수 있습니다. [MITRE T1649](https://attack.mitre.org/techniques/T1649/).

발급 CA 개인키 침해는 단일 사용자 비밀번호 문제가 아니라 **신뢰 기반 시설 사고**입니다. 정상 등록 DB 기록 없이 인증서를 만들 수도 있으므로 4887 부재가 CA 키를 이용한 위조를 배제하지 못합니다. CA 호스트·백업·복구 자격 증명·서명 권한을 보호하세요. 하드웨어 기반 키 보호도 올바른 관리가 함께 필요합니다.

키 탈취·템플릿 악용·릴레이는 증거와 대응이 다르므로 구분합니다. 실제 내부 인증서 목록·PFX·개인키·CA 백업은 공개 위키에 올리지 마세요.

## 9. 로그 위치와 감사 전제조건

| 자료 | 수집 위치 | 확인 가능한 내용 |
| --- | --- | --- |
| 4886 / 4887 / 4888 | CA Security | 요청 수신 / 발급 / 거부 |
| 4870 / 4872 | CA Security | 감사된 인증서 해지 / CRL 게시 |
| 4882 / 4885 / 4892 | CA Security | CA 권한 / 감사 필터 / 속성 변경 |
| CA DB와 최종 인증서 | 발급 CA·승인 인증서 목록 | 처리 상태·Issuer/Serial·최종 확장·등록 맥락 |
| 5136 및 구성된 디렉터리 감사 | 관련 DC | 감사 대상 템플릿·매핑 속성 변경, 모든 읽기는 아님 |
| IIS 로그·엔드포인트 설정 | 등록 웹 서버 | 경로·요청·기록된 신원·EPA/인증 맥락 |
| 인증서 관련 필드가 있는 4768 | DC Security | Kerberos 초기 인증, 원본 필드·버전 확인 |
| Kdcsvc System 진단 | 관련 DC | 문서상 조건의 인증서 매핑 실패 |
| 대상 로그온·EDR | 자원·클라이언트 호스트 | 후속 접근·프로세스·키 사용 맥락 |

CA 작업 감사에는 **CA 감사 필터와 Audit Certification Services 정책이 모두 필요**합니다. 전달 설정만으로 활성화되지 않습니다. AD 객체 감사에는 관련 정책·일치 SACL도 필요합니다. 로컬 생성부터 확인한 뒤 전달·보존을 시험하세요. [CA 관리·감사](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority), [Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services).

모든 형식의 원본 CA 이벤트에 최종 SAN·Serial·템플릿·IP가 포함된다고 보장할 수 없습니다. CA DB·인증서·다른 기록으로 보강하되 출처를 보존하세요. 요청자와 최종 인증서 주체는 다를 수 있고 어느 쪽도 개인키를 보유한 호스트를 자동 식별하지는 않습니다.

## 10. 등록·매핑·실제 접근 연결하기

![CA·디렉터리·등록 엔드포인트·대상 호스트 증거 연결]({{ '/assets/diagrams/adcs-evidence-ko.svg' | relative_url }})

1. CA 이름·인스턴스·DB 문맥·호스트를 기록합니다. CA01과 CA02의 같은 요청 번호는 다른 요청입니다.
2. 수신과 발급·거부 결과를 비교합니다. 수신·보류는 발급된 자격 증명이 아닙니다.
3. 최종 인증서의 Issuer·Serial·유효기간·용도·신원/보안 확장을 확보합니다. 요청 속성만으로 추정하지 마세요.
4. 발급 당시 템플릿·CA 정책과 ACL, 앞선 변경·복제·캐시 시점을 확인합니다.
5. 클라이언트·IIS·네트워크 신원과 출발지를 연결하되 요청자·인증서 주체·매핑 계정을 동일시하지 마세요.
6. 호환되는 인증서 식별자와 원본 필드로 후속 인증을 확인합니다. 가까운 4768·4624만으로 인증서 사용을 연결할 수 없습니다.
7. 실제 접근·영향을 따로 추적하고 미확인·정상 대안 가설을 기록합니다.

등록 연결에는 관련 DB 수명 범위의 CA 인스턴스+Request ID, 인증서 식별에는 Issuer+Serial을 사용하세요. Serial 표기·바이트 순서 차이는 각 출처 정의에 따라 정규화합니다. Thumbprint 등 다른 식별자를 서로 같은 키처럼 비교하지 마세요.

## 11. Splunk 조사 템플릿

실제 인덱스·시간·채널·파서가 필요합니다. 운영 검증된 탐지 규칙이나 ESC 악용을 확정하는 쿼리가 아니라 탐색 시작점입니다.

### A. CA 감사 수집 확인

```spl
index=* (EventCode IN (4870,4872,4882,4885,4886,4887,4888,4892)
      OR EventID IN (4870,4872,4882,4885,4886,4887,4888,4892))
| eval event_id=coalesce(EventCode,EventID)
| stats count by host sourcetype event_id
| sort - count
```

### B. CA 호스트별 요청 처리 결과

```spl
index=windows (EventCode IN (4886,4887,4888) OR EventID IN (4886,4887,4888))
| eval event_id=coalesce(EventCode,EventID)
| eval ca_host=coalesce(Computer,host)
| eval request_id=tostring(coalesce(RequestId,RequestID,Request_ID))
| where isnotnull(request_id)
| stats min(_time) AS first_seen max(_time) AS last_seen
    values(event_id) AS events values(Requester) AS requesters
    values(Attributes) AS request_attributes BY ca_host request_id
| convert ctime(first_seen) ctime(last_seen)
```

`RequestId`·`Requester`·`Attributes`를 실제 XML에 매핑하세요. 검색 구간의 정규화된 `ca_host` 하나가 알려진 CA/DB 문맥 하나라는 전제입니다. 호스트·CA·별칭·복원 DB가 겹치면 별도의 CA 인스턴스/DB 식별자로 먼저 정규화해야 합니다. 요청 ID 없는 행은 의도적으로 제외하므로 추출 실패 여부를 따로 점검하세요.

### C. 감사된 템플릿 속성 변경

```spl
index=windows (EventCode=5136 OR EventID=5136)
| where like(lower(ObjectDN),"%cn=certificate templates,cn=public key services,%")
| table _time host SubjectUserName SubjectLogonId ObjectDN
    AttributeLDAPDisplayName OperationType AttributeValue OpCorrelationID
| sort 0 _time
```

Configuration의 일반적인 템플릿 컨테이너 범위입니다. 실제 DN·필드 매핑을 확인하세요. 유효 ACL을 계산하거나 변경이 발급의 원인임을 입증하지는 않습니다. 전후 권한과 승인 기록을 비교합니다.

### D. 요청자·템플릿별 발급 기준선

```spl
index=pki_lab sourcetype=certificate_issuance_normalized outcome=issued
| where isnotnull(ca_instance) AND isnotnull(requester) AND isnotnull(template)
| bin _time span=15m
| stats count AS issued dc(request_id) AS distinct_requests
    values(subject) AS subjects values(serial_number) AS serials
    BY _time ca_instance requester template
| sort - issued
```

마지막 예제는 **설명용 보강 스키마**이며 Windows 기본 필드가 아닙니다. `issued`는 중복을 포함할 수 있는 레코드 수이고, 고유 요청은 CA·시간 버킷별입니다. 갱신·장치 배포·인증서 관리 시스템을 기준으로 중복 제거·조정한 뒤 탐지에 사용하세요. 대량 발급이 아니어도 고위험 인증서 한 건이 중요할 수 있습니다.

## 12. 읽기 전용 설정·인증서 점검

승인된 CA에서 적절한 로컬 권한과 설치된 도구로 실행합니다.

```powershell
Get-Service -Name CertSvc
certutil -getreg CA\AuditFilter
certutil -getreg CA\InterfaceFlags
certutil -getreg policy\EditFlags
certutil -catemplates
```

서비스 상태·감사/인터페이스/정책 플래그와 선택·기본 CA 문맥의 템플릿을 보여줍니다. 감사·정책을 변경하지 않습니다. 비트 필드는 설치 버전 정의와 대조하세요. 플래그 하나만으로 취약점을 확정하지 마세요. `certutil`은 옵션·가용성이 버전별로 다른 관리자 진단 도구이며 보장된 애플리케이션 API가 아닙니다. [certutil 문서](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil).

```powershell
$since = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4886,4887,4888,4870,4872; StartTime=$since} -MaxEvents 100 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
```

제한된 로그 표본이지 전체 내보내기가 아닙니다. 결과가 없으면 감사·권한·보존·시간을 점검하세요. 관리하는 호스트의 로컬 인증서 메타데이터는 다음처럼 조회합니다.

```powershell
Get-ChildItem -Path Cert:\LocalMachine\My |
  Select-Object Subject,Issuer,Thumbprint,NotAfter,HasPrivateKey
```

`HasPrivateKey`는 키 연결이 있다는 뜻이며 조회 계정이 내보내기·사용 권한을 가졌다는 보장은 아닙니다. 이 명령은 개인키·인증서를 내보내거나 전체 체인을 검증하거나 모든 저장소를 조회하거나 인증 성공을 입증하지 않습니다. 실제 점검에서는 해당 사용자/컴퓨터 저장소와 앱 문맥을 확인합니다.

## 13. 가상 조사 실습

[가상 이벤트 12건 CSV 다운로드]({{ '/assets/labs/adcs-investigation-events.csv' | relative_url }}). 교육용 워크시트이며 원본 XML·바로 설치할 Lookup이 아닙니다. 일부 CA 행은 가상 DB로 보강했고 `detail`에 미확인을 표시했습니다. 개인키·실제 내부 신원은 포함하지 않습니다. 공통 CSV의 상세 설명은 영어입니다.

| UTC | 관측 | 올바른 첫 해석 |
| --- | --- | --- |
| 02:00 | CA01이 DEVICE01$의 101번 요청 수신·발급 | 승인된 장치 갱신 확인 |
| 02:10 | DC01의 템플릿 속성 변경 | 정확한 속성·값·수행자·승인 확인 |
| 02:12 | CA01이 reader_lab의 102번을 10BB로 발급 | 낯선 요청자·템플릿 조합, 최종 인증서 확인 |
| 02:13–14 | DC 티켓 이벤트와 APP01 로그온 | 해당 인증서와의 연결은 미확인 |
| 02:15 | CA01의 103번 수신 후 거부 | 발급으로 계산하지 않음 |
| 02:16 | CA02에도 102번 요청 존재 | 다른 CA 문맥, CA01과 병합 금지 |
| 02:20–21 | 10BB 해지·CRL 게시 | 배포·소비자 검증·기존 세션 확인 |

**질문:** 무엇이 실제 발급되었나요? 디렉터리 변경이 같은 템플릿이며 발급 시 유효했나요? 요청자·인증서의 이름·키 보유자·매핑 계정은 누구인가요? 자료만으로 사용을 입증하나요? 해지가 모든 세션을 종료하나요?

**해설:** 첫 갱신은 정상일 수 있습니다. CA01/102는 낯선 조합과 근접 정책 변경 때문에 검토해야 하지만 사칭 증거는 아닙니다. CA01/103은 거부되었고 CA02/102는 별개입니다. 제공된 4768·4624만으로 10BB와 연결하지 못하므로 인증서 인증·후속 악용은 미확인입니다. 해지 수행자는 요청자와 다를 수 있습니다. 게시만으로 모든 소비자의 최신 상태 조회나 기존 티켓·세션 종료를 입증하지 못합니다.

원본 XML, CA DB, 템플릿·ACL 스냅샷, 공개 인증서 메타데이터, 매핑 설정, 웹·엔드포인트 자료를 보존하세요. 개인키 증거는 승인된 보호 절차로만 취급합니다.

## 14. PKI를 유지하면서 개선·대응하기

| 우선순위 | 조치 | 완료 증거 |
| --- | --- | --- |
| 1 | CA·템플릿·등록 엔드포인트·주요 의존성 담당자 지정 | 자산 목록·승인 책임 |
| 2 | 불필요한 템플릿/CA 제어·넓은 등록 제거, 역할 분리 | 유효 ACL·정상 등록 시험 |
| 3 | 불필요한 주체 입력·용도·승인 조건 개선 | 최종 테스트 인증서의 의도한 신원·용도 |
| 4 | 호환 웹 EPA/HTTPS·RPC Packet Privacy, NTLM 축소 | 실제 엔드포인트 경로·의존성 시험 |
| 5 | 매핑 강제·패치 유지 | 약한 우회 없이 정상 인증 성공 |
| 6 | CA·장치 키·백업·관리 접근 보호 | 키 보관·서명 권한·복구 시험 |
| 7 | 감사 생성·전달·보존 검증 | 알려진 수신·발급·거부·변경 기록 도착 |

인증서·키 침해 시 Issuer/Serial과 관련 발급을 식별하고 CA 절차로 해지·해지정보 게시·검증을 수행합니다. 키 보유 경로와 계정·티켓·세션도 조사하세요. 비밀번호 교체는 인증서 해지와 다르며 해지 하나가 모든 세션의 즉시 종료를 보장하지 않습니다.

CA 키 침해는 PKI·신원 사고 담당자가 신뢰 제거·복구/재구축·재발급 범위를 결정해야 합니다. CA 삭제·루트 신뢰 제거·운영 계층 해지를 임의 수행하면 VPN·Wi-Fi·스마트카드·TLS·장치 관리에 영향을 줄 수 있습니다. 증거를 보존하고 시험된 복구 계획을 사용하세요.

## 15. MITRE 매핑과 흔한 오해

| 행위 | 관련 매핑 | 필요한 증거 |
| --- | --- | --- |
| 인증 인증서 탈취·위조 | [T1649](https://attack.mitre.org/techniques/T1649/) | 발급만이 아닌 인증서·키 오용 또는 위조 증거 |
| 관련 환경의 실시간 NTLM Relay | [T1557](https://attack.mitre.org/techniques/T1557/) | 인증 증거로 뒷받침되는 중간자 경로 |
| 후속 원격 서비스 사용 | [T1021](https://attack.mitre.org/techniques/T1021/) | 실제 원격 접근, 확인된 하위 기법 적용 |

- **AD CS 설치 = 취약:** 특정 조건·유효 권한을 확인해야 합니다.
- **Enroll = 템플릿 수정:** 정책 사용과 변경 권한은 다릅니다.
- **SAN 이름 = 매핑 계정:** 최종 인증서·매핑·소비자 정책이 필요합니다.
- **HTTPS만 적용하면 릴레이 제거:** 엔드포인트 바인딩·인증 보호도 필요합니다.
- **4887 = 인증서로 로그인:** 발급 증거입니다.
- **4887이 없으면 위조도 없음:** CA 키 위조는 정상 요청 경로를 거치지 않을 수 있습니다.
- **비밀번호 재설정 = 인증서 무효:** 자동으로 같은 효과가 나지 않습니다.
- **요청 번호는 전역 고유:** CA·DB 문맥을 함께 보존해야 합니다.

## 16. 학습 완료 점검과 다음 학습

공개키·개인키, 등록·인증, 템플릿 사용·제어, 발급·접근을 구분해 설명하세요. 유효 등록 경로 하나와 감사 전제조건을 검토하고, CA를 혼합하지 않고 요청을 연결하며 실습이 입증하지 못하는 사실을 명시할 수 있어야 합니다.

[LDAP·ACL 분석]({{ '/ko/wiki/ldap-ad-enumeration/' | relative_url }}), [NTLM 릴레이 보호]({{ '/ko/wiki/ntlm-authentication/' | relative_url }}), [Kerberos 인증]({{ '/ko/wiki/kerberos-authentication/' | relative_url }}), [Windows 횡적 이동]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }})과 연결해 학습하세요. [Windows 지속성]({{ '/ko/wiki/windows-persistence/' | relative_url }})으로 이어서 학습하세요. 다음 확장 계획은 Sysmon입니다.

**출처 검토: 2026년 10월 22일.** Microsoft·SpecterOps는 제품 동작·주요 위험 모델, MITRE는 행위 분류의 근거입니다. 도표·쿼리·실습은 직접 구성한 가상 교육 자료입니다. 필드·도구·악용 전제조건은 버전별로 달라집니다. 게시 과정에서 실제 인증서 등록·키 내보내기·릴레이·운영 정책 변경·운영 Splunk 테스트를 수행하지 않았습니다.
