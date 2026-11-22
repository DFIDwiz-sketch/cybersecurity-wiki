---
title: "Active Directory gMSA 조사 · 조회 자격에서 서비스 동작까지"
description: "관리 암호 조회 자격, 서비스 로그온, Kerberos 티켓 활동과 실제 워크로드 증거를 구분합니다."
category: active-directory
tags: [Active Directory, gMSA, Service Accounts, Windows Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /wiki/ad-gmsa-evidence/
---

**학습 목표.** Active Directory 정책에서 Windows 서비스의 로그온과 애플리케이션 상태까지 따라갑니다. 어느 호스트에 그룹 관리 서비스 계정을 사용할 자격이 생겼는지, 실제로 사용했는지는 각각 어떤 증거로 확인하는지 설명합니다.

## 1. 왜 관리 서비스 계정을 사용하나요?

**서비스 계정**은 워크로드가 사용하는 신원입니다. **gMSA(Group Managed Service Account)**는 Active Directory가 암호를 관리하는 도메인 계정으로, 승인된 여러 호스트에서 사용할 수 있습니다. 웹 서버나 보고서 서버 여러 대가 같은 서비스 신원을 쓰면서 운영자가 직접 암호를 배포하는 일을 줄일 수 있습니다. **KDS(Key Distribution Service)**는 도메인 컨트롤러의 암호 생성에 관여합니다. **암호 조회 정책**은 어떤 주체가 관리 암호를 가져올 수 있는지 정합니다. 애플리케이션이 들어오는 Kerberos 인증을 사용한다면 **SPN(Service Principal Name)**은 서비스 이름을 계정에 연결합니다.

| 계정 유형 | 일반적인 사용 범위 | 암호 관리 |
| --- | --- | --- |
| 일반 도메인 계정 | 운영자가 구성한 범위 | 운영자 또는 외부 관리 시스템 |
| 독립 실행형 MSA | 도메인에 가입한 서버 한 대 | AD가 관리 |
| 그룹 MSA | 승인된 도메인 가입 호스트 여러 대 | AD가 관리하고 권한 있는 호스트가 가져옴 |

gMSA 자체가 데이터베이스나 공유 폴더 접근 권한을 부여하는 것은 아닙니다. 리소스 권한과 워크로드 구성을 별도로 확인합니다. 애플리케이션 지원 여부와 배포 조건은 사용하는 Windows Server 버전의 문서를 확인하세요. 이 장의 명령 참조는 Windows Server 2025 기준입니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ad-gmsa-evidence-ko.svg' | relative_url }}" alt="Active Directory에서 암호 조회 자격을 확인하고, 대상 호스트에서 서비스 로그온과 프로세스를 찾습니다. 실제 업무 수행 여부는 애플리케이션 또는 리소스 기록에서 확인합니다.">
  <figcaption>암호 조회 자격, 서비스 로그온, 작업 완료는 각각 별도의 증거로 판단합니다.</figcaption>
</figure>

## 2. 정상 서비스 시작을 따라가기

가상의 `REPORT01`과 `REPORT02`가 `LAB\ReportSvc$`로 보고서 서비스를 실행한다고 가정합니다. 두 서버의 컴퓨터 계정은 승인된 전용 암호 조회 그룹에 속합니다. 구성 목록에는 두 호스트와 서비스에 지정한 계정의 SID가 기록돼 있습니다.

1. 승인된 배포에서 서비스에 gMSA를 지정하고 전용 그룹에 암호 조회 권한을 부여합니다. 직접 지정된 주체와 관련된 중첩 그룹을 확인합니다. 어느 도메인 컨트롤러(DC)에서 언제 조회했는지 기록해 실제 구성을 대조합니다.
2. `REPORT01`에서 서비스 로그온이 요청됩니다. 성공 감사가 설정돼 있으면 대상 호스트의 보안 로그 4624, 로그온 유형 5에서 gMSA의 SID를 확인할 수 있습니다. 서비스에 설정된 계정, 프로세스 증거, 수집 시각을 대조합니다. 서비스 여러 개가 같은 계정을 쓸 수 있습니다.
3. 독립된 애플리케이션 기록에서 보고서 서비스가 정상 점검 작업을 끝냈는지 확인합니다. 클라이언트가 Kerberos 서비스 티켓도 요청했다면 DC의 이벤트 4769에서 티켓 요청과 결과를 확인합니다. 요청자와 대상 서비스는 별도 필드입니다. 티켓이 발급됐다고 해서 애플리케이션이 실행됐거나 요청을 받아들였다고 볼 수는 없습니다.

## 3. 변경과 실제 사용을 구분하기

| 관측 | 다음에 확인할 증거 |
| --- | --- |
| gMSA의 허용 주체가 바뀜 | 객체 GUID, 변경 속성, 전후 상태, 행위자, DC, 시각과 승인 내역을 확인합니다. 새 호스트에 자격이 생겼는지 확인합니다. |
| 컴퓨터가 암호 조회 그룹에 추가됨 | 실제 그룹 경로와 승인 내역, 영향을 받는 gMSA를 확인합니다. gMSA의 조회 정책 속성은 그대로일 수 있습니다. |
| `Test-ADServiceAccount`가 성공함 | 해당 시점의 로컬 준비 상태가 확인됐습니다. 서비스 시작, 프로세스 소유자와 앱 상태를 별도로 확인합니다. |
| 예상 밖 호스트의 4624 유형 5 | 대상 SID, 호스트, 서비스 구성과 프로세스를 대조합니다. 유지보수나 승인된 서비스 이동도 확인합니다. |
| 계정에 연결된 서비스의 4769 | DC에서 상태와 대상을 확인한 뒤 서비스 쪽 증거를 찾습니다. 이 이벤트는 암호를 가져왔다는 기록이 아닙니다. |

조회 권한 그룹이 너무 넓으면 서비스 신원을 사용할 수 있는 시스템이 늘어납니다. 그룹 구성원이 침해됐거나 승인되지 않은 변경이 있으면 오용 가능성이 커집니다. 그룹 변경은 자격의 변화에 관한 증거입니다. 실제로 누군가 암호를 가져왔는지는 알 수 없습니다. 정상 배포나 오래된 자산 목록 때문에 새 호스트가 낯설게 보일 수도 있습니다. 복제 지연, 호스트 준비 상태나 구성 오류로 인한 시작 실패와 예상 밖 호스트에서의 사용을 구분합니다.

1. **권한 범위를 정합니다.** UTC 시각, 객체 GUID와 SID, 관련 계정과 그룹 ID, 호스트 목록과 예상 SPN을 기록합니다. 계정과 조회 그룹을 누가 바꿀 수 있는지 ACL을 확인합니다. 관리 암호 데이터는 수집하지 않습니다.
2. **감사 수집 범위를 확인합니다.** 쓰기 가능한 DC에서 디렉터리 서비스 변경 감사가 켜져 있고 객체에 맞는 SACL이 있다면, 이벤트 5136으로 `msDS-GroupMSAMembership` 또는 `servicePrincipalName` 변경을 조사할 수 있습니다. 속성에 따라 다른 감사 범위가 필요할 수 있습니다. 도메인 보안 그룹의 구성원 변경은 DC의 보안 그룹 관리 성공 감사를 봅니다. 전역 그룹 추가는 4728, 유니버설 그룹 추가는 4756입니다. 실제 그룹 범위를 확인하고, 이벤트가 없으면 감사 범위와 보존 상태를 먼저 확인합니다.
3. **실행 증거를 연결합니다.** 대상 호스트에서 로그온 성공 감사가 켜져 있는 경우 4624의 대상 SID, 호스트, 유형, 시각을 프로세스 자료와 대조합니다. DC의 4769는 Kerberos 서비스 티켓 작업 감사와 필요한 결과 유형이 설정된 경우 수집합니다. 지원되는 서버에서는 2025년 보안 업데이트 이후 4769 구조가 바뀌었으므로 수집한 XML 필드를 확인한 뒤 정규화합니다. 실제 결과는 서비스 상태, 리소스 접근 또는 앱 기록으로 검증합니다.
4. **대응하고 검증합니다.** 승인되지 않은 경로를 확인하면 허용된 자료를 보존하고, 서비스 담당자와 사고 변경 절차에 따라 접근을 차단하거나 제한합니다. 의존 서비스를 확인하고 필요한 자격 증명 복구를 조율합니다. 이후 실제 조회 자격과 워크로드 상태를 검증합니다. 디렉터리 변경 즉시 기존 세션까지 종료된다고 가정하지 마세요.

## 4. 읽기 전용 조회와 오프라인 실습

승인된 도메인 가입 Windows 시스템에서 ActiveDirectory PowerShell 모듈, 적절한 DC 연결, 위임된 읽기 권한을 준비합니다. `ReportSvc`를 실습 계정으로 바꾸세요. 첫 명령은 디렉터리의 메타데이터만 조회합니다. 두 번째 명령은 관리 계정이 구성된 서비스 대상 호스트에서 실행합니다. 로컬 준비 상태를 확인하는 명령으로 서비스 실행 여부까지 판단하지 않습니다.

```powershell
Get-ADServiceAccount -Identity ReportSvc -Properties PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames |
    Select-Object Name,SID,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames
Test-ADServiceAccount -Identity ReportSvc
```

조회에 실패하면 모듈, 계정 이름, 연결된 도메인과 읽기 권한을 확인합니다. 로컬 시험에 실패하면 도메인 관리자와 계정 구성, DC 연결, 실제 조회 권한을 확인합니다. 이후 시작 실패는 서비스와 앱 자료로 조사합니다. Windows 절차는 공식 문서로 검토했으며 이번 게시 작업에서 도메인에 연결해 실행하지 않았습니다.

<a href="{{ '/assets/labs/ad-gmsa-evidence.py' | relative_url }}" download="ad-gmsa-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/ad-gmsa-evidence-cases.json' | relative_url }}" download="ad-gmsa-evidence-cases.json">가상 사례</a>를 승인된 작업 공간에 저장합니다. 사례는 계정 하나와 관측 한 건의 범위로 정리했습니다. 증거의 판정 과정을 보여 주며 Windows 권한 엔진을 구현하지 않습니다. 스크립트는 로컬 파일만 읽습니다.

```bash
python3 ad-gmsa-evidence.py ad-gmsa-evidence-cases.json
```

```text
healthy_service: service_outcome_confirmed
policy_change: eligibility_changed_usage_unproven
group_change: eligibility_changed_usage_unproven
readiness_only: readiness_only
ticket_only: ticket_activity_only
unexpected_logon: unexpected_host_logon
incomplete_join: service_logon_only
```

일곱 사례를 실행했습니다. 파일이 열리지 않으면 폴더와 파일명을 확인하세요. 판정이 다르면 먼저 호스트와 SID가 같은지 보세요. 마지막 사례에는 서비스 로그온이 있지만 상태 기록은 다른 프로세스에 속하므로 서비스 결과까지 확인할 수 없습니다.

## 5. 확인 문제와 완료 기준

- **컴퓨터가 중첩된 조회 그룹에 추가됐습니다. 계정을 사용했나요?** 실제 조회 자격을 확인한 뒤 호스트나 리소스 쪽에서 사용 증거를 찾습니다.
- **준비 상태 시험이 성공했습니다. 보고서가 완성됐나요?** 서비스 프로세스를 찾고 같은 호스트·SID·프로세스의 독립된 결과를 확인합니다.
- **DC가 서비스 티켓을 발급했습니다. 보고서 서버가 암호를 가져왔나요?** 티켓 활동에 관한 기록입니다. 권한과 호스트의 관측을 별도로 조사합니다.

일곱 결과가 예상과 일치하고, 조회 자격·서비스 로그온·워크로드 성공에 필요한 증거를 각각 설명하면 실습을 완료한 것입니다.

## 공식 참고자료

2026년 11월 23일에 검토했습니다. Microsoft의 gMSA 관리 문서는 Windows Server 2016~2025를 대상으로 합니다. 이전 이벤트 예시는 조사 대상의 이벤트 버전과 정책을 기준으로 해석합니다.

- [Microsoft gMSA 관리](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/manage-group-managed-service-accounts) · [gMSA 암호 조회 권한 속성](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [Get-ADServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adserviceaccount?view=windowsserver2025-ps) · [Test-ADServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/test-adserviceaccount?view=windowsserver2025-ps)
- [고급 감사 정책](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration) · [이벤트 5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136) · [이벤트 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [이벤트 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)

[이전 · Active Directory 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}) · [다음 · Windows 서비스 실행 증거]({{ '/ko/wiki/windows-service-runtime-evidence/' | relative_url }}) · [관련 · Kerberos 인증]({{ '/ko/wiki/kerberos-authentication/' | relative_url }})
