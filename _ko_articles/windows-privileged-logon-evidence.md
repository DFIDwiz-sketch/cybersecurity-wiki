---
title: "Windows 특권 로그온 조사 · 부여부터 사용까지"
description: "4624·4672·4688과 특권 사용 이벤트를 연결해 세션의 특권, 토큰 상승, 실제 작업 기록을 구분합니다."
category: dfir
tags: [Windows Security, Windows, Event Logs, Privileges, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /wiki/windows-privileged-logon-evidence/
---

새 로그온에 민감한 특권이 부여됐다는 경보가 나왔습니다. 프로세스가 그 특권을 사용했을까요? 작업은 성공했을까요? Windows가 로그온 세션에 부여한 것과 이후에 관측한 동작을 먼저 구분합니다.

## 1. 증거가 보여 주는 범위

**로그온 세션**은 계정이 로그온할 때 만들어지는 보안 맥락입니다. 세션을 만든 Windows 호스트가 **Logon ID**를 부여합니다. **보안 식별자(SID)**는 사용자나 서비스 등 보안 주체를 식별합니다. **액세스 토큰**에는 프로세스나 스레드의 신원, 그룹, 특권 정보가 들어 있습니다. **특권**은 특정 시스템 동작을 할 수 있는 능력이며, 토큰 안에서 활성화되거나 비활성화될 수 있습니다. 특정 객체를 대상으로 하는 ACL의 권한과는 별개입니다. **사용자 계정 컨트롤(UAC)**은 프로세스가 어떤 토큰으로 시작하는지에 영향을 줄 수 있습니다.

| 보안 이벤트 | 보여 주는 증거 | 감사 수집 조건 |
| --- | --- | --- |
| 4624 | 세션을 만든 컴퓨터에서 로그온 성공. New Logon의 SID와 ID 확인 | Audit Logon의 성공 감사 |
| 4672 | 새 로그온에 부여된 민감한 특권. Subject의 SID와 ID, `PrivilegeList` 확인 | Audit Special Logon의 성공 감사 |
| 4688 | 새 프로세스와 기록된 경우 토큰 상승 유형, 생성자·대상 맥락 | Audit Process Creation의 성공 감사. 명령줄은 별도 정책 필요 |
| 4673 / 4674 | 특권 서비스 호출 시도 / 특권 객체 작업 시도 | 해당 Privilege Use 하위 범주, 결과에 맞는 성공·실패 감사 |
| 작업·객체 기록 | 애플리케이션 결과 또는 관측한 상태 변경 | 해당 작업을 기록하도록 앱이나 객체 감사 구성 |

4672에는 토큰의 모든 속성이 들어 있지 않습니다. 어떤 특권을 활성화했거나 사용했는지도 보여 주지 않습니다. 4688의 Type 2(원시 값 `%%1937`)는 상승된 프로세스 토큰입니다. Type 1(`%%1936`)은 서비스나 Local System 등에서 볼 수 있는 전체 토큰이고, Type 3(`%%1938`)은 제한된 토큰입니다. 운영체제와 계정의 맥락에서 원시 값을 해석합니다. 4688로 프로세스가 어떤 특권을 실제로 사용했는지는 알 수 없습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-privileged-logon-evidence-ko.svg' | relative_url }}" alt="원본 Windows 호스트의 로그온과 특권 부여를 연결합니다. 프로세스 토큰과 특권 사용 이벤트를 구분해 읽고 별도로 작업 결과를 확인합니다.">
  <figcaption>특권 부여, 프로세스 생성, 작업 시도, 독립적으로 관측한 결과를 세션 맥락에서 대조합니다.</figcaption>
</figure>

## 2. 정상적인 서비스 세션 따라가기

가상 사례에서 `lab-ws-a`의 유지보수 서비스가 시작됩니다. 이번 부팅에서 유형 5(서비스) 4624의 New Logon은 SID `S-1-5-21-110-220-330-1042`와 Logon ID `0x4d2`를 기록합니다. 같은 SID와 ID를 가진 4672의 Subject에는 감사와 보안 로그를 관리하는 특권인 `SeSecurityPrivilege`가 포함돼 있습니다. 승인된 유지보수 계획의 계정, 서비스, 예상 특권과 대조하세요.

4688 버전 2는 서비스 프로세스를 기록합니다. 이 사례에서 서비스 관리자가 생성자이고 서비스 계정이 Target Subject이므로, 새 프로세스를 서비스 계정과 연결할 때 유효한 Target Logon ID를 사용합니다. 대상 필드가 없거나 자리표시자라면 현재 스키마에 어떤 맥락만 남았는지 기록하세요. 이전 이벤트 버전에는 Target Subject 없이 생성자만 남을 수 있습니다. `TargetLogonId`가 `0x0`이면 새 프로세스를 다른 세션에 연결할 키로 쓸 수 없습니다.

이후 서비스 계정의 4674에 특권 객체 작업 시도와 동일한 특권이 기록됩니다. 이벤트의 감사 성공·실패 키워드, 관련 객체와 프로세스 필드, Microsoft가 정의한 이벤트의 적용 범위를 함께 확인하세요. 성공 키워드는 감사된 작업의 결과를 나타냅니다. 예약된 유지보수 작업 전체가 끝났는지는 작업 결과와 예상한 출력 또는 상태 변화로 확인해야 합니다. 실패 키워드 역시 해당 기록의 시도가 실패했음을 보여 주며, 전체 작업의 실패 원인까지 알려 주지는 않습니다.

## 3. 수집·탐지·대응

1. **원본 호스트와 시간 범위를 보존합니다.** Security 원본 XML 또는 EVTX, 공급자, 원본 `Computer`, 이벤트 버전·채널·레코드 ID, UTC 시각과 관련 부팅 경계를 남깁니다. 원본 장치의 같은 부팅 구간 안에서 4624의 `TargetLogonId`를 4672·4673·4674의 `SubjectLogonId`와 대조하고 SID도 확인합니다. 수집기 호스트 이름으로 대조하지 마세요. Logon ID와 PID는 로컬 식별자입니다. 프로세스까지 연결하려면 생성 시각과 수명, 확보 가능한 프로세스 GUID를 확인합니다. 세션이 일치한다는 사실만으로 단일 프로세스를 특정할 수 없습니다.
2. **정책과 수집을 따로 확인합니다.** 실제 적용된 감사 하위 범주, 성공·실패 수집 여부, 보존 기간, 전달 필터와 지연을 확인하세요. 백업·복원 특권 사용에는 Microsoft가 별도로 설명하는 감사 조건도 있습니다. 결과가 비어 있으면 설정이나 자료 누락도 살핍니다. 명령줄에는 민감한 값이 들어갈 수 있으므로 승인된 정책 아래에서 수집하고, 접근을 제한하며 필요한 경우 보고서에서 가립니다.
3. **정상 활동의 맥락과 대조합니다.** SYSTEM은 이러한 특권을 흔히 받습니다. 계정과 SID, 호스트의 역할, 승인된 서비스 신원, 로그온 유형, 유지보수 시간대와 예상 프로세스를 비교하세요. 거의 쓰지 않는 관리 계정의 예상 밖 서비스 또는 대화형 로그온은 출처와 후속 기록을 살펴볼 단서입니다. 4672 경보만으로 권한 상승 공격, 침해, 계정을 조작한 개인을 확정할 수 없습니다.
4. **확인된 범위에 맞춰 대응합니다.** 승인된 계정 또는 호스트 변경 전에 관련 이벤트 구간과 수집 상태를 보존하세요. 접근 범위를 좁히기 전에 담당자와 서비스의 특권 부여 요건을 확인합니다. 특권 사용이 의심되면 영향받은 객체나 워크로드의 증거를 모으고, 확인하지 못한 부분을 남깁니다. 정책을 조정한 후 정상 관리 작업이 계속 동작하는지도 확인하세요.

Security 로그를 읽을 권한이 있는 승인된 Windows 호스트에서 다음 PowerShell 조회로 범위를 좁힐 수 있습니다. 감사 정책을 바꾸거나 특권 작업을 호출하지 않습니다. 사건에 맞게 시간 범위를 조정하고 증거 원본은 별도로 보존하세요.

```powershell
$filter = @{
    LogName = 'Security'
    ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id = 4624, 4672, 4673, 4674, 4688
    StartTime = (Get-Date).AddHours(-2)
}
Get-WinEvent -FilterHashtable $filter -MaxEvents 100 |
    ForEach-Object { $_.ToXml() }
```

100건 제한은 표본 확인용이므로 이벤트가 많은 호스트에서는 관련 기록이 빠질 수 있습니다. 접근 거부는 수집 오류입니다. 이벤트가 없으면 먼저 호스트와 시간대, 감사 설정, 보존 기간을 확인합니다. 명령은 Microsoft 공식 문서로 검토했습니다.

## 4. 오프라인에서 이벤트 연결하기

승인된 학습 환경에서 <a href="{{ '/assets/labs/windows-privileged-logon-evidence.py' | relative_url }}" download="windows-privileged-logon-evidence.py">세션 연결 스크립트</a>와 <a href="{{ '/assets/labs/windows-privileged-logon-evidence.json' | relative_url }}" download="windows-privileged-logon-evidence.json">가상 증거</a>를 같은 디렉터리에 저장하세요. Python 3.8 이상에서 실행합니다.

```bash
python3 windows-privileged-logon-evidence.py windows-privileged-logon-evidence.json
```

각 사례는 이미 정리한 별도의 레코드 집합입니다. 프로세스의 `target`은 명시적으로 관측한 Target Subject를 뜻합니다. 스크립트는 원본 호스트, 부팅 식별자, SID, 숫자로 변환한 Logon ID로 이벤트를 연결합니다. 4688은 명시적인 대상 맥락만 보고하고 생성자 값을 대신 사용하지 않습니다. 같은 세션에서 감사된 작업의 특권이 부여 기록에도 있었는지 출력합니다. 이 결과는 세션 단위 상관관계입니다. Windows 원본 로그 해석, 프로세스 인과관계, 애플리케이션 결과까지 검증하지는 않습니다.

| 사례 | 기대 결과 |
| --- | --- |
| `assignment_only` | 로그온과 특권 부여 확인. 연결되는 프로세스와 특권 사용 기록 없음 |
| `elevated_without_use` | 특권 부여와 Type 2 프로세스 확인. 연결되는 특권 사용 기록 없음 |
| `same_session_audit_success` | 부여 기록과 같은 특권으로 감사된 작업의 성공 확인 |
| `same_session_audit_failure` | 부여 기록과 같은 특권으로 감사된 작업의 실패 확인 |
| `different_host` | 다른 호스트의 같은 SID와 Logon ID는 연결하지 않음 |
| `different_boot` | 같은 호스트라도 다른 부팅의 ID는 연결하지 않음 |
| `creator_only` | 생성자는 기록됐으나 연결할 수 있는 명시적 프로세스 대상 맥락이 없음 |
| `different_privilege` | 같은 세션에 작업은 있으나 해당 특권이 이 부여 레코드에는 없음 |

프로세스가 연결되지 않으면 이벤트 버전과 대상 필드가 유효한지 확인하세요. 특권 사용이 연결되지 않으면 원본 호스트, 부팅, SID, 비교 가능한 Logon ID, 감사 수집 범위를 차례로 살펴봅니다. 복사본에서 `different_host`의 특권 사용 호스트를 부여 기록의 호스트와 같게 바꾸면 성공 감사 기록이 연결되어야 합니다. 게시한 Python 실습은 가상 자료로 실행했습니다. Windows 호스트에서 특권 작업을 실행하지 않았습니다.

## 5. 확인 문제와 완료 기준

1. **4672 하나로 특권 작업 성공을 증명할 수 있나요?** 해당 로그온에 열거된 특권이 부여됐다는 증거입니다. 작업 이벤트와 결과를 별도로 따라갑니다.
2. **4688의 Creator Subject를 새 프로세스의 신원으로 쓰면 왜 안 되나요?** 생성자는 다른 신원으로 프로세스를 시작할 수 있습니다. 생성자와 대상을 모두 남기고 기록으로 확인한 범위만 귀속합니다.
3. **4674의 성공 감사는 어디까지 보여 주나요?** 그 이벤트에 기록된 특권 객체 작업의 결과입니다. 서비스나 객체의 별도 증거로 전체 작업의 결과를 확인합니다.
4. **4673·4674가 없으면 특권을 쓰지 않은 걸까요?** 해당 작업의 감사 정책과 실제 수집 구간이 중요합니다. 확인한 구간과 자료의 공백을 함께 기록하세요.

정상 서비스 사례를 설명하고 호스트와 부팅이 다른 두 잘못된 연결을 걸러 내고, 작업 완료를 주장하기 전에 확보할 증거를 말할 수 있으면 완료입니다.

## 공식 참고자료와 다음 학습

검토일 2026년 11월 23일. 이벤트 스키마는 버전별 필드를 설명하는 Microsoft의 Windows 10 시기 문서를 참조했습니다. 현재 Windows Server 감사 지침과 PowerShell 문서는 별도로 확인했습니다. 실제 수집 대상의 Windows 빌드에서 적용 정책과 이벤트 버전을 확인하세요.

- [Microsoft 보안 이벤트 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672), [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Microsoft 보안 이벤트 4673](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4673), [4674](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4674)
- [Windows Server 고급 감사 정책](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration), [민감한 특권 사용 감사](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-sensitive-privilege-use), [PowerShell Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

[이전 · Windows 보안 이벤트 조사]({{ '/ko/wiki/windows-logs/' | relative_url }}) · [다음 · RDP 세션 증거]({{ '/ko/wiki/rdp-session-evidence/' | relative_url }})

[관련 글 · 4688과 4689로 프로세스 생성 조사]({{ '/ko/wiki/windows-process-creation-evidence/' | relative_url }})
