---
title: "Windows 레지스트리 변경 조사 · Security와 Sysmon 연결하기"
description: "키와 값에 대한 작업을 구분하고, 변경한 프로세스를 가상 XML에서 추적합니다."
category: dfir
tags: [Windows, Registry, Sysmon, Event Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/windows-registry-change-evidence/
---

앱 업데이트 뒤 워크스테이션에 잘못된 설정이 적용됐다고 가정해 봅시다. 레지스트리 값이 바뀐 사실을 확인했지만, 어떤 계정이 요청했고 어느 프로세스가 값을 썼는지 알아야 합니다. 실제로 신고한 사용자의 설정이었는지도 확인해야 합니다. 변경 대상과 동작, 프로세스 수명, 수집 조건을 차례로 확보하세요. 로그 채널이 익숙하지 않다면 [Windows 이벤트 조사 입문]({{ '/ko/wiki/windows-logs/' | relative_url }})부터 읽어 보세요.

## 1. 키, 값, 변경 주체를 구분하세요

**키**는 이름을 가진 그릇으로 하위 키와 값을 담을 수 있습니다. **값**에는 이름, 유형, 데이터가 있습니다. 이름이 비어 있는 값도 있습니다. **하이브**는 키와 값의 묶음이며 이를 뒷받침하는 파일이 있습니다. `HKEY_LOCAL_MACHINE`(HKLM)은 컴퓨터 설정과 관련됩니다. 로드된 사용자 프로필 하이브는 `HKEY_USERS`(HKU) 아래에 나타납니다. `HKEY_CURRENT_USER`(HKCU)는 호출 프로세스와 Windows 매핑 규칙에 따라 가리키는 위치가 정해집니다. 따라서 조사자의 HKCU가 다른 사용자의 설정을 볼 수도 있습니다. 변경 대상 SID와 변경을 요청한 SID를 각각 보존하세요. 관리자나 서비스가 다른 사용자의 하이브를 수정할 수 있습니다.

WOW64는 레지스트리 일부를 32비트와 64비트 논리 뷰로 나누며 공유되는 키도 있습니다. 경로를 같은 것으로 처리하기 전에 OS와 프로세스 아키텍처, 실제 키, 선택한 뷰를 확인하세요. 실습은 단순한 HKU 경로를 사용합니다. `Wow6432Node`나 `CurrentControlSet`은 매핑 근거와 적용 맥락을 확인할 때까지 기록에 나타난 형태로 보존하세요.

| 출처와 동작 | 뒷받침하는 내용 | 수집 조건 |
| --- | --- | --- |
| Security 4657, 값 변경 | 키와 값 이름, 동작, 요청 계정, 호출 PID, 남아 있는 이전·이후 값. 데이터를 비교하기 전에 동작과 값 유형 확인 | Audit Registry 성공 감사가 실제 적용되고 대상 키의 SACL에 일치하는 Set Value 감사 항목이 있어야 함. SACL은 무엇을 감사할지 지정 |
| Sysmon 12, 객체 생성·삭제 | `EventType`과 대상 경로를 확인해 키 또는 값의 동작을 판단 | Sysmon이 동작 중이고 `RegistryEvent` 필터가 해당 작업과 대상을 포함 |
| Sysmon 13, 값 설정 | 값을 쓴 동작, 대상, 프로세스 정보. Microsoft 문서는 DWORD·QWORD에 대한 쓰기 데이터를 설명. 그 밖의 값은 실제 이벤트와 유형별 수집 범위 확인 | 같은 Sysmon 동작·필터 조건 |
| Sysmon 14, 이름 변경 | 키 또는 값의 이름 변경과 새 이름. `EventType`, 이전 대상, 기록된 새 이름을 보존 | 같은 Sysmon 동작·필터 조건 |
| 하이브 또는 현재 상태 스냅샷 | 수집한 시점의 키, 값 이름, 유형 및 남아 있는 데이터 | 올바른 컴퓨터나 사용자 하이브와 뷰를 수집. 나중에 찍은 스냅샷만으로 이전 값 전체나 변경 주체를 복원하기 어려움 |

Security 기록은 `Security` 채널의 `Microsoft-Windows-Security-Auditing` 공급자가, Sysmon 기록은 `Microsoft-Windows-Sysmon/Operational` 채널의 `Microsoft-Windows-Sysmon` 공급자가 남깁니다. 이벤트 ID와 함께 공급자와 채널을 확인하세요. 4657에서 쓴 프로세스의 PID는 `EventData.ProcessId`입니다. 이벤트를 발행한 컨텍스트의 `System.Execution.ProcessID`는 다른 값일 수 있습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-registry-change-evidence-ko.svg' | relative_url }}" alt="Security 감사와 Sysmon은 같은 레지스트리 동작을 각각 기록할 수 있습니다. 호스트, 시각, 객체, 프로세스 맥락을 비교해 두 기록을 연결하고 앱에 적용된 증거를 별도로 찾습니다." style="max-width: 100%; height: auto;">
  <figcaption>그림 1. 변경 대상과 변경 시점의 프로세스 수명이 일치하면 두 공급자의 기록을 연결할 근거가 강해집니다.</figcaption>
</figure>

## 2. 가상의 정상 변경 한 건을 읽어 보세요

10:02:00 UTC에 `WKSTN-01`에서 승인된 예시 편집기가 사용자 표시 설정인 `ShowGrid`의 DWORD 데이터를 `0`에서 `1`로 바꿉니다. 이 변경에는 승인 기록이 있습니다. Security 4657의 `ObjectName=\REGISTRY\USER\[SID]\Software\WikiLab\Preferences`와 `ObjectValueName=ShowGrid`는 대상 키와 값 이름입니다. `EventData.ProcessId`는 16진수 `0x1388`, 십진수 `5000`입니다. 가까운 시각의 Sysmon 13은 `HKU\[SID]\Software\WikiLab\Preferences\ShowGrid`, PID `5000`, `ProcessGuid`를 보여 줍니다. 두 경로는 같은 사용자 하이브의 값을 가리킬 수 있습니다. `[SID]`는 일치하는 대상 SID를 뜻합니다.

Sysmon 이벤트 1에서 그 GUID를 찾아 시작을 확인하고 이벤트 5가 있으면 종료도 확인하세요. 10:05에 예시 편집기가 종료되고, 10:06에 같은 편집기의 별도 인스턴스가 다른 GUID와 PID 5000으로 시작합니다. 해당 GUID에 연결된 10:07 이벤트는 새 프로세스 수명에 속합니다. 값 이름과 PID가 같더라도 호스트, 시각, 이미지와 수명이 중요합니다. 4657의 주체 SID로 계정을 파악할 수 있지만 사람이 직접 입력했는지는 알 수 없습니다. 나중에 앱이 설정을 읽었다는 로그를 찾으면 적용 여부를 판단할 근거가 하나 더 생깁니다.

## 3. 변경, 오용, 실제 효과를 구분하세요

보안에 영향을 주는 값을 승인 없이 바꾸면 이후 권한 판단이나 동작에 영향을 줄 수 있습니다. 설정 관리, 정책 새로 고침, 업데이트와 복구도 비슷한 기록을 남길 수 있습니다. 값을 썼다는 사실만으로 앱이 값을 읽었거나 등록된 작업이 실행됐다고 보기는 어렵습니다. 쓰기, 변경 후 상태, 이후 앱 또는 프로세스 동작의 증거를 타임라인에 각각 남기세요.

키 이름만 바꿔도 같은 내용의 경로가 달라집니다. 값을 삭제한 뒤 다시 만들면 현재 스냅샷은 정상처럼 보일 수 있습니다. 수집 범위가 있다면 Sysmon 12나 14를 보고, 별도로 수집한 상태도 보존하세요. 비어 있는 값, 없는 필드, 화면에 보이는 자리 표시자는 의미가 다릅니다. 정규화하기 전에 원본 XML과 유형을 확보하세요.

## 4. 블루팀 수집·탐지·대응

1. **범위를 좁혀 수집합니다.** 호스트, 시각, 원본 이벤트, 채널, 공급자, 레코드 ID, 객체 식별자와 데이터 유형을 보존하세요. 전달 문제로 판단하기 전에 원본 채널을 확인합니다. 다음은 읽기 권한이 있는 Windows 단말에서 PowerShell로 최근 30분을 조회하는 읽기 전용 예제입니다. 해당 기록을 생성하도록 구성돼 있어야 하며 조회 자체가 감사 정책이나 Sysmon 필터를 활성화하지 않습니다.

```powershell
$since = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id = 4657
    StartTime = $since
}
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ProviderName = 'Microsoft-Windows-Sysmon'
    Id = 1, 5, 12, 13, 14
    StartTime = $since
}
```

2. **객체와 프로세스를 함께 대조합니다.** 호스트, 시각, 동작, 구체적인 키와 값으로 같은 쓰기 후보를 찾으세요. 4657의 데이터 PID·이미지를 해당 수명의 Sysmon 기록과 비교하고, Sysmon 안에서는 `ProcessGuid`로 연결합니다. `SubjectLogonId`와 Security 4624를 연결할 때는 같은 호스트와 부팅 범위를 확인합니다. 센서별 시각 정밀도와 수집 공백을 감안하세요. 변경한 프로세스나 계정이 배포를 지시한 서비스나 운영자를 그대로 보여 주지는 않습니다.
3. **예상 밖 변경을 조사하고 복구를 확인합니다.** 중요 설정 목록에서 승인된 작성자 또는 배포 시간대를 벗어난 변경을 찾고, 필요한 경우 대상 SID와 레지스트리 뷰를 포함하세요. 알려진 승인 쓰기가 원본과 수집기 양쪽에 있는지 확인하고 정상 업데이트도 대조군에 포함합니다. 4657이 없다면 정책, SACL, 보존 상태를, Sysmon이 없다면 필터와 전달 상태를 확인합니다. 복구 전 현재 상태와 프로세스 증거를 확보하고 승인 절차에 따라 설정을 되돌린 뒤 앱 동작을 확인하세요. 레지스트리에 민감한 경로나 설정이 있을 수 있으므로 조사에 필요한 범위로 수집과 공유를 제한합니다.

## 5. 승인된 오프라인 실습

<a href="{{ '/assets/labs/windows-registry-change-evidence.py' | relative_url }}" download>Python 판정 도구</a>와 <a href="{{ '/assets/labs/windows-registry-change-events.xml' | relative_url }}" download>가상 XML</a>을 같은 폴더에 내려받으세요. 소유하거나 사용을 승인받은 환경에서 Python 3으로 실행합니다. 도구는 실습 파일만 읽고 레지스트리 설정에 손대지 않습니다.

```bash
python3 windows-registry-change-evidence.py
```

XML에는 Security 4657 한 건, 연결되는 쓰기와 혼동할 수 있는 Sysmon 쓰기, 두 프로세스 수명, 생성 및 이름 변경 예시가 담겨 있습니다. 도구로 공급자와 채널, PID 표기, 하이브의 별칭, 대상 SID 차이, PID 재사용을 확인합니다. 실습에서 비교하는 범위는 사용자 SID가 적힌 HKU 경로와 그에 대응하는 내부 경로입니다. 고정된 시각 허용 범위와 시작·종료 기록은 가상 자료의 전제입니다. 운영에서는 시계와 수집 상태를 확인하고 시작·종료 기록이 없거나 여러 후보가 남는 경우를 처리해야 합니다.

기대 결과는 `8/8 controls passed.`입니다. 대조 시험으로 Security 기록의 `ObjectValueName`을 `ShowGrid`에서 `ShowOther`로 바꾸세요. 일치하는 쌍이 사라지고 종료 코드가 실패를 나타내야 합니다. 편집하지 않은 자료에서 연결이 안 되면 두 파일의 버전, XML 네임스페이스와 인코딩을 확인하세요. 가상 XML에서 동작과 값 유형은 사람이 읽을 수 있는 영문 레이블로 넣었습니다. 실습은 Python 3.12에서 검증했습니다. Windows의 감사 발생, 수집과 앱 동작은 Microsoft 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

1. **Security에서 서비스 계정이 사용자 하이브에 썼습니다. 누구의 설정이 바뀌었나요?** 대상 하이브의 SID를 확인하세요. 요청 계정은 이벤트의 주체입니다.
2. **두 기록에 PID 5000이 있습니다. 무엇을 더 확인할까요?** 같은 호스트의 같은 프로세스 수명인지 확인하고 이미지, 객체, 동작을 비교합니다. Sysmon에서는 가능하면 GUID를 확보하세요.
3. **나중에 실행할 동작이 레지스트리에 등록됐습니다. 실제로 실행됐나요?** 트리거가 발생한 기록과 결과 프로세스 또는 앱 동작의 증거가 필요합니다.

**완료 기준.** 여덟 가지 대조와 실패 대조를 재현하고, 쓰기 기록에서 확인한 사실과 실제 효과를 판단할 때 필요한 증거를 설명하세요. 이어서 [프로세스 생성 조사]({{ '/ko/wiki/windows-process-creation-evidence/' | relative_url }})와 [지속성 조사]({{ '/ko/wiki/windows-persistence/' | relative_url }})를 살펴보세요.

## 공식 참고자료

2026-11-26에 검토했습니다. Security 자료는 이벤트 버전 0과 과거 예시를 포함합니다. 현재 환경에 적용할 때는 Windows 빌드와 설치된 Sysmon 스키마를 확인하세요.

- Microsoft Windows 감사의 [이벤트 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)과 [Audit Registry](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-registry)
- Microsoft Sysinternals의 [Sysmon 이벤트와 필터](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Microsoft Win32의 [미리 정의된 키](https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys), [레지스트리 하이브](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives), [WOW64 레지스트리 리디렉터](https://learn.microsoft.com/en-us/windows/win32/winprog64/registry-redirector)
