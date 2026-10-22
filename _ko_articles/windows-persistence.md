---
title: "Windows 지속성 가이드: Run 키, 예약 작업, 서비스, WMI, 탐지와 대응"
description: "Windows 지속성을 등록·트리거·실행으로 구분하고 Run 키·예약 작업·서비스·WMI를 감사 로그, Splunk 검색과 가상 조사 실습으로 분석합니다."
category: blue-team
tags: [Windows Security, Persistence, Blue Team, DFIR, Registry, Scheduled Tasks, Windows Services, WMI, Sysmon, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-22"
translation_url: /wiki/windows-persistence/
---

> **Windows 방어 확장편.** [Windows 횡적 이동]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }})과 [AD CS 보안]({{ '/ko/wiki/ad-cs-security/' | relative_url }})에서 이어지는 문서입니다. 이름·실습 기록은 모두 가상이며 명령은 로컬 설정·로그를 조회합니다. 예제로 지속성을 설치하거나 실행하지 않습니다.

## 1. 지속성이란 무엇인가

지속성(Persistence)은 프로세스 종료·로그오프·재부팅 같은 중단 이후에도 공격자가 실행·접근을 다시 확보하도록 하는 능력입니다. 어떤 중단을 견디는지는 방식별로 다릅니다. 로그온 항목은 재부팅 후 남아도 해당 사용자의 로그온이 필요할 수 있고, 일회성 작업은 반복 동작이 없을 수 있습니다.

**지속성·실행·권한 상승·횡적 이동**을 구분하세요. 같은 서비스·작업이 여러 행위를 지원할 수 있지만 설치 이벤트 하나로 모두 입증되지는 않습니다. 사용자별 등록이 자동으로 관리자·SYSTEM 권한을 얻는 것도 아닙니다.

주요 호스트 방식을 다루며 모든 Windows 지속성을 열거하지 않습니다. 계정 변경·도메인 정책·인증서 접근·부팅 구성·애플리케이션 확장은 별도 조사가 필요합니다. 엔드포인트를 정리해도 탈취 자격 증명·인증서가 자동 무효화되지는 않습니다.

## 2. 등록·트리거·실행은 서로 다른 주장

![지속성 설정에서 실제 실행까지의 조사 흐름]({{ '/assets/diagrams/persistence-chain-ko.svg' | relative_url }})

| 단계 | 확보할 증거 | 아직 모르는 것 |
| --- | --- | --- |
| 구성 변경 | 레지스트리 값·작업 XML·서비스 설정·WMI 객체 | 활성화·승인·실행 가능 여부 |
| 트리거 조건 충족 | 로그온·일정·시작·서비스 요청·WMI 이벤트 | 실제 실행·성공 여부 |
| 프로세스·동작 실행 | 프로세스·부모·명령·계정·스케줄러/서비스 맥락 | 목표 달성 여부 |
| 후속 접근·영향 | 자원 접근·통신·파일·앱 로그 | 신뢰할 연결 없이 같은 원인인지 여부 |

**현재 상태**는 지금 존재하는 구성을, **과거 로그**는 언제 누가 변경했는지를 설명합니다. 어느 쪽도 다른 쪽을 완전히 대체하지 못합니다. 삭제된 작업은 이력에 남을 수 있고 오래된 작업의 생성 로그는 보존 범위 밖일 수 있습니다.

## 3. 주요 네 가지 방식 비교

| 방식 | 일반적 트리거·범위 | 권한 고려사항 | 핵심 자료 |
| --- | --- | --- | --- |
| Run / Startup | 관련 사용자 로그온 | 사용자별 변경은 비관리자도 가능할 수 있으며 시스템 위치에는 적절한 권한 필요 | Hive/SID·실제 Startup 경로·값/바로가기 대상 |
| 예약 작업 | 정의된 조건·수동 요청 | 생성자와 실행 계정은 다르며 높은 권한에는 승인 필요 | 호스트+전체 TaskPath/TaskName+전체 정의 |
| Windows 서비스 | 시작·요청·지원되는 기타 조건 | SCM·서비스의 유효 권한 필요 | 이름·명령/인수·계정·시작 설정·ACL |
| 영구 WMI 구독 | 필터에 맞는 이벤트 | Namespace·객체·Consumer 보안 규칙 적용 | 필터+Consumer+Binding·Namespace |

등록이 그대로여도 실행 대상·스크립트를 바꿀 수 있으면 중요합니다. 파일·상위 폴더 권한과 참조 스크립트·라이브러리까지 점검하세요. 익숙한 이름·경로·유효 서명만으로 정상이라고 판단하지 않습니다.

## 4. Run 키와 Startup 폴더

일반적 위치는 HKCU·HKLM의 `Software\Microsoft\Windows\CurrentVersion` 아래 Run·RunOnce 키와 사용자별·공용 Startup 폴더입니다. 실제 피해 프로필의 경로를 해석해야 합니다. 대응자 셸의 HKCU는 대응자 자신의 Hive입니다.

Run은 일반적으로 로그온 시 적용되고 RunOnce는 일회성과 삭제 규칙에 예외가 있습니다. 시스템 범위 Run 항목이 SYSTEM 실행을 의미하지는 않습니다. 레지스트리 아키텍처 View와 로드·미로드 사용자 Hive에 따라 목록이 달라집니다. [Microsoft Run/RunOnce](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys), [MITRE T1547.001](https://attack.mitre.org/techniques/T1547/001/).

값 형식·데이터·Hive/SID, 파일·바로가기 내용, 실제 대상·인수·작업 디렉터리·변경 증거를 보존하세요. 미확인 대상을 식별하려고 실행하지 마세요. Startup 바로가기의 해시는 그 링크의 해시이며 참조 실행 파일의 해시와 다릅니다.

## 5. 예약 작업

트리거·동작·활성 상태·Principal·Run Level·Logon Type·조건·설정을 포함한 전체 정의를 확인하세요. 등록 수행자와 실행 계정을 구분합니다. 비활성화·조건 미충족·실행 실패가 가능하므로 등록은 실행이 아닙니다.

감사가 구성되면 Security **4698**은 생성, **4702**는 갱신, **4699**는 삭제를 기록합니다. 이름만 검색하지 말고 전체 경로·XML을 보존하세요. Task Scheduler Operational 이력과 프로세스 자료로 실제 실행을 조사할 수 있습니다. 보존·이벤트 버전·로깅 설정에 따라 가시성이 다릅니다. [Microsoft 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698), [작업 감사 정책](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events).

기존 업체 작업의 변경도 포함해 전후 정의를 비교합니다. Microsoft처럼 보이는 경로가 진위를 보장하지 않으며 루트 작업이 반드시 악성도 아닙니다. 최종 실행 상태는 단서이지 전체 과거 실행 이력이 아닙니다.

## 6. Windows 서비스

내부 이름·실행 명령·계정·시작 모드·상태·의존성·유효 권한을 확인합니다. 공유 호스트가 DLL을 로드하는 서비스는 실행 파일 경로만으로 모든 구성 요소가 보이지 않습니다. 따옴표 없는 경로도 파싱·공백·후보 위치 쓰기 권한·실행 문맥을 확인해야 악용 가능성을 판단할 수 있습니다.

Security **4697**은 Audit Security System Extension, System **7045**는 Service Control Manager의 설치 이벤트입니다. 스키마·감사 의존성이 다릅니다. 설치만으로 시작·악성 지속성을 확정하지 않습니다. 기존 서비스 변경·실행 파일 교체는 새 설치 이벤트 없이도 중요합니다. [Microsoft 4697](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697), [Splunk System 7045 예시](https://research.splunk.com/endpoint/8e204dfd-cae0-4ea8-a61d-e972a1ff2ff8/), [MITRE T1543.003](https://attack.mitre.org/techniques/T1543/003/).

서비스 기반 원격 관리는 [횡적 이동]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }})과 겹칠 수 있습니다. 원격 출발지·인증·존속 기간을 따로 확인하세요. 짧은 원격 실행이 반복 가능한 지속성을 곧바로 증명하지는 않습니다.

## 7. 영구 WMI 이벤트 구독

영구 구독은 이벤트 필터와 Consumer를 Binding으로 연결합니다. 세 객체, 필터의 이벤트 Namespace·Query, Consumer의 실제 동작·대상, 보안 문맥을 확인하세요. WMI 쿼리·`WmiPrvSE.exe`·일반 원격 WMI 실행만으로 영구 구독을 입증하지 못합니다. [Microsoft 영구 Consumer](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times), [MITRE T1546.003](https://attack.mitre.org/techniques/T1546/003/).

아래 조회는 일반적인 `root/subscription`을 대상으로 합니다. 전체 Namespace 목록이 아니며 Consumer의 모든 하위 형식 속성 대신 이름 등을 보여줍니다. 참조된 Consumer의 형식별 내용은 승인된 증거 조사 절차로 확인하세요. 정상 모니터링·관리 도구도 구독을 사용합니다.

## 8. 증거와 감사 전제조건

| 자료 | 채널·수집 조건 | 의미 |
| --- | --- | --- |
| 4698 / 4702 / 4699 | Security; Audit Other Object Access Events | 작업 생성·갱신·삭제 |
| 4697 | Security; Audit Security System Extension | 서비스 설치 |
| 7045 | System; Service Control Manager | 별도 스키마의 서비스 설치 |
| 4657 | Security; Audit Registry와 일치 Set Value SACL | 감사된 레지스트리 값 변경 |
| 4688 | Security; Audit Process Creation | 프로세스 생성, 명령줄에는 추가 정책 필요 |
| Sysmon 1 / 11 | Sysmon Operational 및 유효 설정 | 프로세스 생성·파일 생성/덮어쓰기 |
| Sysmon 12 / 13 / 14 | Sysmon Operational 및 유효 설정 | 레지스트리 생성/삭제·값 설정·이름 변경 |
| Sysmon 19 / 20 / 21 | Sysmon Operational 및 유효 설정 | WMI 필터·Consumer·Binding 활동 |
| 현재 구성·EDR | 대상 호스트 | 현재 상태·파일·권한·실행 맥락 |

Provider+채널+이벤트 번호로 종류를 식별하세요. 전달 전에 감사 생성을 시험해야 합니다. 레지스트리 Security 감사에는 정책과 적절한 SACL이 필요합니다. Sysmon은 버전·유효 Include/Exclude 규칙에 영향을 받으며 네트워크 이벤트 3은 기본 활성화가 아닙니다. [Microsoft 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657), [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688), [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

PID는 재사용될 수 있습니다. 가능하면 호환 ProcessGuid와 호스트·시간을 사용하고 PID만 있으면 생성 시각·수명도 보존하세요. Logon ID는 호스트·세션 문맥이지 전역 신원 키가 아닙니다. 다른 호스트를 작업명·서비스명·PID만으로 합치지 마세요.

## 9. 읽기 전용 로컬 점검

관리 권한이 있는 호스트에서 필요한 권한·모듈로 실행합니다. 라이브 조회이며 포렌식 획득을 대체하지 않습니다. 오류·누락도 기록하세요.

### A. 작업과 서비스

```powershell
Get-ScheduledTask |
  Select-Object TaskPath,TaskName,State,Actions,Triggers,Principal

Get-CimInstance -ClassName Win32_Service |
  Select-Object Name,DisplayName,State,StartMode,StartName,PathName
```

Actions·Triggers·Principal은 중첩 객체여서 화면 출력에 세부 정보가 생략될 수 있습니다. 전체 작업 정의·서비스별 설정을 확인하세요. `PathName`에는 인수가 포함될 수 있으므로 해시 도구에 그대로 파일명처럼 전달하지 마세요.

### B. 현재 프로필·시스템 로그온 위치

```powershell
$runPaths = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($runPath in $runPaths) {
  if (Test-Path -LiteralPath $runPath) {
    Get-ItemProperty -LiteralPath $runPath
  }
}
$startupPaths = @(
  [Environment]::GetFolderPath('Startup'),
  [Environment]::GetFolderPath('CommonStartup')
)
foreach ($startupPath in $startupPaths) {
  if ($startupPath -and (Test-Path -LiteralPath $startupPath)) {
    Get-ChildItem -LiteralPath $startupPath -Force |
      Select-Object FullName,Length,LastWriteTimeUtc
  }
}
```

현재 PowerShell의 레지스트리 View에서 네 키와 해석된 두 폴더만 확인합니다. 모든 프로필·다른 아키텍처 View·오프라인 Hive를 열거하지 않습니다. 키가 없는 것은 정상일 수 있습니다. Startup 파일을 나열하며 대상을 따라가거나 실행하지 않습니다. 타임스탬프는 변경·조작될 수 있습니다.

### C. WMI 구독 구성 요소

```powershell
Get-CimInstance -Namespace root/subscription -ClassName __EventFilter |
  Select-Object Name,EventNamespace,Query,CreatorSID
Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer |
  Select-Object @{Name='ClassName'; Expression={$_.CimClass.CimClassName}},Name,CreatorSID
Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding |
  Select-Object Filter,Consumer
```

반환된 Filter·Consumer 참조를 Namespace 안에서 연결하세요. 이름만으로는 부족합니다. 접근 거부는 가시성 공백이며 부재 증거가 아닙니다. 구독을 만들거나 제거하지 않습니다.

### D. 제한된 Security 로그 표본

```powershell
$since = (Get-Date).AddHours(-4)
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  Id=4698,4702,4699,4697,4657
  StartTime=$since
} -MaxEvents 200 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
```

최대 200건·4시간이라는 제한이 있습니다. System 7045·Sysmon·Task Scheduler Operational은 포함하지 않으므로 필요하면 별도로 수집하세요. 실제 조사에서는 원본 EVTX/XML·수집 시각을 보존합니다.

[Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)는 추가 자동 시작 위치의 목록을 보완할 수 있습니다. 표시 필터를 적용하기 전에 전체 기준선을 보존하세요. 서명은 완전한 신뢰 판정이 아니며 평판·업로드 기능은 외부 서비스와 통신할 수 있으므로 조직 증거 정책을 따릅니다.

## 10. Splunk 조사 검색

실제 인덱스·시간·파서 매핑을 먼저 정합니다. `Channel`/`LogName`·Provider·이벤트 데이터는 수집기별로 다릅니다. 예제는 매핑된 채널을 요구하므로 제외·누락 필드를 따로 조사하세요. 운영 검증된 탐지 규칙이 아니라 조사 템플릿입니다.

### A. 작업 변경

```spl
index=windows (EventCode IN (4698,4702,4699) OR EventID IN (4698,4702,4699))
| eval channel=coalesce(Channel,LogName)
| where channel="Security"
| eval event_id=coalesce(EventCode,EventID), endpoint=coalesce(Computer,host)
| table _time endpoint event_id SubjectUserName SubjectLogonId TaskName TaskContent TaskContentNew
| sort 0 _time
```

호스트+전체 경로+시간으로 전후 정의를 비교합니다. 갱신된 내용은 필드명·스키마가 다를 수 있으므로 원본 XML에서 정규화하세요. 생성자 로그온은 같은 엔드포인트에서 연결하고 실행에는 스케줄러·프로세스 증거를 찾습니다.

### B. 두 출처의 서비스 설치

```spl
index=windows (EventCode IN (4697,7045) OR EventID IN (4697,7045))
| eval channel=coalesce(Channel,LogName), provider=coalesce(Provider_Name,ProviderName,SourceName)
| eval event_id=coalesce(EventCode,EventID), endpoint=coalesce(Computer,host)
| where (channel="Security" AND event_id=4697)
    OR (channel="System" AND event_id=7045 AND provider="Service Control Manager")
| table _time endpoint channel event_id ServiceName ServiceFileName ImagePath
    ServiceAccount AccountName ServiceStartType StartType SubjectUserName
| sort 0 _time
```

Security·System 필드를 별도로 매핑하세요. 같은 설치가 두 기록을 남겨도 서비스 두 개로 세면 안 됩니다. System 이벤트가 항상 생성자를 식별하지는 않으므로 실행 계정을 생성자로 대신 쓰지 마세요.

### C. 일반 로그온 키 주변 레지스트리 변경

```spl
index=sysmon (EventCode=13 OR EventID=13)
| eval channel=coalesce(Channel,LogName)
| where channel="Microsoft-Windows-Sysmon/Operational"
| where like(lower(TargetObject),"%currentversion%")
| table _time host Image ProcessGuid User TargetObject Details
| sort 0 _time
```

넓은 `currentversion` 문자열은 **후보 필터**이지 정확한 Run 키 탐지가 아닙니다. 무관 경로가 포함되고 다른 위치의 방식은 누락됩니다. 결과에서 정확한 키 경계·값 이름·Hive/SID·관련 View를 확인하세요. 값 설정 이벤트만으로 대상 실행을 입증하지 못합니다.

### D. WMI 등록 활동

```spl
index=sysmon (EventCode IN (19,20,21) OR EventID IN (19,20,21))
| eval channel=coalesce(Channel,LogName), event_id=coalesce(EventCode,EventID)
| where channel="Microsoft-Windows-Sysmon/Operational"
| table _time host event_id Operation User EventNamespace Name Query
    Type Destination Consumer Filter
| sort 0 _time
```

필터·Consumer·Binding 이벤트의 필드는 다릅니다. 특정 필드가 비어도 유형상 정상일 수 있습니다. 객체 참조와 과거 상태를 복원하세요. 19/20/21은 Consumer 실행 증거가 아닙니다. 정상 모니터링 제품을 기준으로 조정하고 예상 밖 수행자·변경된 대상을 조사합니다.

## 11. 가상 조사 실습

[가상 이벤트 12건 다운로드]({{ '/assets/labs/windows-persistence-events.csv' | relative_url }}). 공통 CSV의 설명은 영어이며 분석용 워크시트입니다. 원본 XML·바로 사용할 탐지 데이터셋이 아닙니다. `process_ref`는 교육용 표식이며 원본 ProcessGuid가 아닙니다. XML 요약·7045 수행자는 가상 보강 정보입니다.

| UTC | 관측 | 조사 질문 |
| --- | --- | --- |
| 03:00 | InventoryLab 등록·inventory 프로세스 관측 | CHG-LAB-01과 스케줄러 증거가 둘을 설명하는가? |
| 03:10 | 사용자별 LabReminder Run 값 설정 | 어떤 SID·명령·파일인가? 후속 실행 미제공 |
| 03:12–15 | UpdateCheckLab 생성·변경, check.exe 관측 | 무엇이 바뀌었으며 해당 작업 실행과 연결되는가? |
| 03:16 | WS02에 같은 작업 경로 | 다른 호스트 객체이며 WS01과 병합 금지 |
| 03:20 | LabBackupSvc 설치 | 승인 설치·시작 설정·실제 실행은? |
| 03:22 | WMI 필터·Consumer·Binding 등록 | 전체 참조·동작·권한·실행은? |
| 03:30 | WS01 UpdateCheckLab 삭제 | 프로세스 종료·다른 방식 처리도 확인했는가? |

**해설:** Inventory 활동은 정상일 수 있지만 승인 증거가 필요합니다. WS01 UpdateCheckLab은 동작 변경·사용자 프로필 경로 때문에 검토할 가치가 있으며 악성 확정은 아닙니다. 가까운 프로세스도 작업 실행 증거 없이는 후보 연결입니다. Run 값·WMI Binding은 등록 활동을 보여주며 후속 성공 실행을 증명하지 않습니다. WS02는 별개이고 서비스 설치는 시작 증거가 아닙니다. 작업 하나를 삭제해도 기존 프로세스·다른 지속성이 제거되지는 않습니다.

**관측·추론·미확인**으로 기록하세요. 원본 XML의 각 버전·스케줄러 이력·레지스트리 데이터·서비스 설정·WMI 참조·파일·프로세스 증거를 확보합니다. 자료에 없는 트리거 성공·페이로드 동작을 만들어 넣지 마세요.

## 12. 상관분석과 대응 흐름

![증거 보존, 범위 확인, 차단과 검증]({{ '/assets/diagrams/persistence-response-ko.svg' | relative_url }})

1. 호스트 신원·시간대/시계·사용자/SID·수집 제한을 확정합니다.
2. 가능하면 변경 전 등록·실행 대상 증거를 보존하되 실제 피해가 진행 중이면 차단을 우선합니다.
3. 생성자·구성 변경·트리거 조건·실제 실행·후속 활동을 독립 증거로 재구성합니다.
4. 승인 소프트웨어·변경 기록·유효 쓰기 권한을 검증하고 추가 지속성·탈취 신원을 조사합니다.
5. 서비스 담당자·사고 대응 책임자와 격리 및 좁은 범위의 비활성화·제거를 조정합니다.
6. 실행 중 프로세스·변조 대상·계정/토큰·최초 침입 경로를 따로 처리합니다.
7. 원하는 상태·모니터링을 검증하고 안전할 때만 통제된 트리거 시험을 수행한 뒤 재생성·재발을 감시합니다.

이름만 보고 서비스·작업·WMI 객체를 무조건 삭제하지 마세요. 의존성·복구 정보를 보존합니다. 재부팅은 페이로드를 실행하거나 휘발성 증거를 지울 수 있어 조사 지름길이 아닙니다. 호스트 무결성을 확립할 수 없으면 재구축·복구가 필요할 수 있습니다.

## 13. 강화와 흔한 실수

| 통제 | 확인 방법 |
| --- | --- |
| 최소 권한·관리 분리 | SCM/서비스·작업·레지스트리·WMI 유효 권한 |
| 실행 대상·상위 폴더 보호 | 바이너리·스크립트·라이브러리·설정 ACL |
| 애플리케이션 제어·엔드포인트 보호 | 시험된 정책·정상 업무 범위 |
| 감사/EDR 수집·보존 | 알려진 정상 변경이 전체 수집 경로에 도착 |
| 관리 기준선·변경 책임 | 소유자·만료·복구를 포함한 차이 검토 |
| 신원 대응·재발 감시 | 관련 자격 증명/인증서 처리·미승인 재생성 없음 |

PowerShell·WMI·서명된 파일·사용자 경로를 일괄 악성 또는 정상으로 취급하지 마세요. 유효 서명은 승인 증거가 아니며 해시 일치는 내용 식별이지 의도 판정이 아닙니다. 현재 목록이 깨끗해도 과거 지속성이 없었다고 증명하지 못합니다.

도구명이 아닌 입증된 행위에 매핑합니다. Run/Startup → [T1547.001](https://attack.mitre.org/techniques/T1547/001/), 예약 작업 → [T1053.005](https://attack.mitre.org/techniques/T1053/005/), 서비스 → [T1543.003](https://attack.mitre.org/techniques/T1543/003/), WMI 구독 → [T1546.003](https://attack.mitre.org/techniques/T1546/003/). 실행·지속성 의도와 증거는 따로 기록하세요.

## 14. 학습 완료 점검과 다음 학습

등록·실행을 구분하고 한 방식의 트리거·실행 계정을 설명하세요. 작업은 호스트·전체 경로로 한정하고 Security·System·Sysmon 출처를 구분해야 합니다. 가상 사례가 입증하지 못하는 사실과 정리 후 검증 방법도 설명하세요.

[Windows 로그]({{ '/ko/wiki/windows-logs/' | relative_url }}), [Splunk 기초]({{ '/ko/wiki/splunk-basics/' | relative_url }}), [Windows 횡적 이동]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }}), [AD CS 신원 위험]({{ '/ko/wiki/ad-cs-security/' | relative_url }})을 함께 참고하세요. 다음 계획은 Sysmon이며 아직 별도 문서 링크는 없습니다.

**출처 검토: 2026년 10월 22일.** Microsoft는 제품 동작·이벤트 해석, MITRE는 행위 분류의 근거입니다. 도표·쿼리·실습은 직접 구성한 교육 자료입니다. 게시 과정에서 지속성 설치·미확인 페이로드 실행·호스트 정책 변경·운영 Splunk 탐지 검증을 수행하지 않았습니다.
