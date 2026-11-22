---
title: "Windows 예약 작업 실행 조사 · 등록에서 실제 결과까지"
description: "Windows 예약 작업의 정의, 실행 인스턴스, 동작 완료와 실제 결과를 구분합니다."
category: blue-team
tags: [Windows Security, Scheduled Tasks, Task Scheduler, Windows Logs, Sysmon, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/windows-scheduled-task-runtime-evidence/
---

예약 작업은 등록된 뒤 인스턴스를 시작하고 동작을 실행해 결과를 남길 수 있습니다. 이 단계들이 기록돼도 기대한 결과물이 없을 수 있습니다. 이 장에서는 실행 파일을 호출하는 Windows 예약 작업을 조사하면서 각 단계에서 무엇을 확인할 수 있는지 살펴봅니다.

## 1. 실행을 보기 전에 정의부터 읽으세요

**예약 작업**은 Windows 작업 스케줄러가 실행할 수 있도록 저장한 정의입니다. **트리거**는 매일 정해진 시각처럼 작업을 시작할 수 있는 조건입니다. **동작(action)**은 수행할 내용을 정합니다. 실행 파일을 호출하는 동작에서는 명령, 인수, 작업 디렉터리를 따로 읽으세요. **실행 주체(principal)**는 로그온 유형과 실행 수준을 포함한 실행 계정과 문맥을 정합니다. 등록 로그의 **주체(subject)**는 등록이나 변경을 요청한 계정으로, 실행 계정과 다를 수 있습니다.

정의에는 이미 실행 중인 인스턴스가 있을 때의 처리 같은 **설정**도 들어 있습니다. 설정에 따라 새 실행을 무시하거나 대기열에 넣거나, 병렬로 실행하거나, 실행 중인 인스턴스를 중지할 수 있습니다. 예약 시각이 지났다면 설정, 실행 조건과 이력을 확인하세요. **작업 인스턴스**는 한 번의 실행을 가리킵니다. 같은 작업 경로에 여러 실행 인스턴스가 있을 수 있습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-scheduled-task-runtime-evidence-ko.svg' | relative_url }}" alt="작업 등록과 트리거 평가를 거쳐 인스턴스와 동작이 시작될 수 있습니다. 스케줄러는 동작의 반환 결과를 기록하고, 앱이나 파일 증거는 기대한 결과를 뒷받침합니다. 트리거 관측만으로는 시작을 확인할 수 없습니다.">
  <figcaption>등록, 스케줄러 이력, 작업 결과의 기록은 각기 다른 질문에 답합니다.</figcaption>
</figure>

## 2. 정상 실행 한 건을 따라가세요

가상의 워크스테이션 `WK-01`에 `\Training\InventoryReport` 작업이 있습니다. 승인된 동작은 로컬에 자산 요약 파일을 생성하는 것입니다. 관리자가 08:00 UTC에 작업을 바꾸면 Security 4702에 새 정의가 기록됩니다. 08:30 UTC에 스케줄러가 인스턴스 `run-a`와 동작 시작을 기록합니다. 예상한 실행 이미지와 짧은 시간 구간에 해당하는 프로세스 생성 기록이 실행을 뒷받침합니다. 운영팀은 실행 이력의 필드를 대조해 프로세스의 연관성을 확인합니다. 동작의 반환 값은 0입니다. 이후 파일 시스템과 앱 로그에서 이번 실행으로 생성된 새 보고서를 각각 확인합니다. 각 관측은 앞 단계에서 알 수 없던 사실을 더해 줍니다.

| 조사 질문 | 증거와 해석 범위 |
| --- | --- |
| 작업 정의가 생성되거나 바뀌었나요? | Security 4698은 생성, 4702는 갱신입니다. 4699는 삭제, 4700은 활성화, 4701은 비활성화를 기록합니다. |
| 인스턴스가 시작되거나 끝났나요? | TaskScheduler Operational 100은 시작, 102는 인스턴스 완료를 기록합니다. 호스트, 전체 작업 경로, 인스턴스 ID를 대조하세요. |
| 동작이 시작되거나 끝났나요? | Operational 200은 시작, 201은 완료를 기록합니다. 동작 이름, 작업 인스턴스 참조, 있는 경우 반환 코드를 확인합니다. 한 작업에는 여러 동작이 있을 수 있습니다. |
| 어떤 프로세스가 실행됐나요? | 수집된 Security 4688 또는 Sysmon 1로 프로세스 식별과 부모 정보를 확인합니다. |
| 기대한 결과가 발생했나요? | 앱 로그, 파일 메타데이터와 내용, 목적지 관측을 확인합니다. 그 결과를 이번 실행과 연결하는 데 필요한 근거를 보존하세요. |

TaskScheduler 공급자의 인스턴스 시작에는 보통 `InstanceId`, 동작 이벤트에는 `TaskInstanceId`가 쓰입니다. 설치된 빌드에서 공급자, 채널, 이벤트 버전과 XML을 확인하세요. 같은 작업 경로는 삭제 후 다시 만들거나 다른 호스트에서 사용할 수 있습니다. 실행 기록은 원본 호스트, 전체 작업 경로와 인스턴스 ID로 묶고 동작의 식별 정보와 순서를 따로 확인합니다. 같은 실행 파일을 한 인스턴스에서 반복 호출하면 동작 순번이나 추가 이벤트 문맥을 확인하세요. 이를 확보하지 못하면 시작과 완료의 연결이 모호할 수 있습니다.

## 3. 의심스러운 변경과 결과 누락을 조사하세요

익숙한 작업 이름 뒤에서 인수, 실행 계정, 트리거 또는 쓰기 가능한 동작 경로가 예상과 달라졌을 수 있습니다. 마지막으로 승인된 작업 정의와 최근에 기록된 정의를 비교하세요. 패치나 정비도 정상적인 작업 생성·변경을 설명할 수 있습니다. 배포 기록, 승인된 실행 파일, 관찰된 프로세스에서 독립 근거를 찾으세요. 대응 전에 작업 XML과 실행 파일 관련 정보를 보존합니다.

반환 값 0은 보통 실행 파일이 성공을 보고했다는 뜻입니다. 감싸는 프로그램이 내부 작업 실패 후에도 0을 반환할 수 있습니다. 0이 아닌 값은 프로그램이 정의한 코드 또는 스케줄러 실패 문맥으로 해석하세요. 원본 값과 해석을 각각 기록합니다. 완료가 찍혔는데 산출물이 없으면 앱 로그, 작업 디렉터리, 실행 계정, 권한, 저장 대상 상태를 확인하세요. 200이나 201이 없을 때는 이력 비활성화, 보존·전달 공백, 트리거 미실행, 실행 시작 실패를 모두 고려합니다. 활성화 상태와 실행 조건, 오류 이벤트에서 원인을 좁혀 보세요.

## 4. 승인된 호스트에서 수집하고 대조하세요

1. 호스트, 조사 구간과 시간 기준을 기록하세요. 가능하면 원본 호스트의 Security와 TaskScheduler Operational에서 채널, 공급자, 버전, 레코드 ID를 포함한 원본 XML을 보존합니다. 변경 이벤트는 **Audit Other Object Access Events** 성공 감사가 필요합니다. Operational 이력은 채널이 켜져 있고 기록이 보존돼야 합니다. 전달 범위도 따로 확인하세요.
2. 프로세스 생성은 **Audit Process Creation** 성공 감사를 사용해 Security 4688을 수집합니다. 명령줄 수집은 별도의 정책이 필요합니다. 또는 Sysmon이 설치돼 있고 설정이 포함한 경우 Sysmon 1을 사용하세요. 필요한 경우 16진수 PID를 변환하고 동일 호스트·프로세스 수명을 대조하세요. 후속 Sysmon 기록은 ProcessGuid로 연결할 수 있습니다. 공급자 XML의 `System/Execution`에 있는 PID는 이벤트를 쓴 프로세스의 것일 수 있으므로 실행한 프로세스와 연결하기 전에 필드의 의미를 확인합니다.
3. 전체 경로, 인수, 실행 계정, 트리거, 설정, 승인된 변경 시각을 비교하세요. 스케줄러 기록에서 해당 실행을 찾고 프로세스, 앱이나 리소스의 흔적으로 이어 가세요. 시각과 실행 이미지가 비슷하면 연결 후보로 기록합니다.
4. 예상 밖 변경이나 동작 시작이 이어지면 알려진 배포가 설명하는지 확인합니다. 작업 정의, 관련 파일과 실행 증거를 보존하고 호스트 운영자와 대응하세요. 조치 후 승인된 범위에서 무해한 대조 작업으로 작업 동작과 로그 수집 경로를 확인합니다.

이벤트 읽기 권한과 ScheduledTasks 모듈이 있는 Windows 호스트에서 다음 명령으로 이력과 최신 실행 정보를 조회할 수 있습니다. 가상의 작업 경로와 시간은 승인된 조사 범위에 맞춰 바꾸세요. 마지막 실행 시각과 결과는 조회 당시의 값이라 이후 실행으로 덮일 수 있습니다.

```powershell
$channel = 'Microsoft-Windows-TaskScheduler/Operational'
(Get-WinEvent -ListLog $channel).IsEnabled
(Get-WinEvent -ListProvider 'Microsoft-Windows-TaskScheduler').Events |
  Where-Object { $_.Id -in 100,102,200,201 } |
  Select-Object Id, Version, Description
Get-WinEvent -FilterHashtable @{
  LogName = $channel
  Id = 100,102,200,201
  StartTime = (Get-Date).AddHours(-2)
} -MaxEvents 40 | ForEach-Object { $_.ToXml() }
Get-ScheduledTaskInfo -TaskPath '\Training\' -TaskName 'InventoryReport' |
  Select-Object LastRunTime, LastTaskResult
```

이력 조회는 모든 작업에서 조건에 맞는 최근 이벤트를 최대 40개 보여 줍니다. XML에서 전체 작업 경로를 대조하고, 대상 실행이 빠졌다면 시간 구간이나 개수 제한을 조정하세요. 결과가 비면 읽기 권한, 채널 상태와 보존을 확인하세요. PowerShell 명령과 이벤트 설명은 문서로 검토했으며 실제 Windows에서 실행하지 않았습니다.

## 5. 가상 실행 열 건으로 오프라인 실습하기

<a href="{{ '/assets/labs/windows-scheduled-task-runtime-evidence.py' | relative_url }}" download="windows-scheduled-task-runtime-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/windows-scheduled-task-runtime-evidence-cases.json' | relative_url }}" download="windows-scheduled-task-runtime-evidence-cases.json">가상 JSON 자료</a>를 같은 폴더에 내려받아 소유하거나 승인받은 작업 공간에서 Python 3으로 실행하세요. 자료에는 Windows 원본 XML 대신 학습용 필드가 있습니다. 각 사례는 특정 작업과 실행 인스턴스 하나, 지정된 동작 하나를 조사합니다. 구별 가능한 정규화 동작 참조가 이미 주어집니다. 실제 기록에서는 이 정보를 바로 얻기 어려울 수 있습니다.

```bash
python3 windows-scheduled-task-runtime-evidence.py windows-scheduled-task-runtime-evidence-cases.json
```

```text
normal: effect_observed
registration_only: run_unobserved
start_only: action_unobserved
launch_only: completion_unobserved
nonzero: nonzero_result
zero_only: zero_effect_unobserved
other_host: completion_unobserved
other_instance: completion_unobserved
early_effect: zero_effect_unobserved
duplicate_completion: ambiguous_completion
```

실행 전에 각각의 결과를 예상해 보세요. 이 실습은 먼저 확인되지 않은 단계를 표시하고, 반환 값이 0인 경우 결과를 대조합니다. 실제 조사에서는 0이 아닌 값이 기록돼도 일부 결과가 남을 수 있습니다. 실습은 동작을 시작한 시점과 같거나 그 이후에 관찰된 결과만 연결합니다. 프로그램은 종료하기 전에 파일을 쓸 수 있습니다. 파일 오류가 나면 현재 폴더와 두 파일 이름을 확인하세요. 예상하지 못한 연결이 나왔다면 호스트, 작업 경로, 인스턴스, 동작 참조와 이벤트 순서를 살펴보세요. Python 분석기는 이 가상 자료로 실행 검증했습니다.

## 6. 확인 문제와 완료 기준

- **4698에서 예상 실행 파일을 봤습니다. 실행된 건가요?** 작업 등록을 확인한 상태입니다. 인스턴스와 동작, 프로세스 생성 증거를 찾아보세요.
- **201 두 건이 같은 작업과 실행 파일을 가리킵니다. 더 가까운 시각으로 연결하면 될까요?** 호스트, 인스턴스와 동작 발생을 먼저 구분하세요. 원본 메타데이터로 전달 중복을 제거하고 실제 모호함이 남으면 그대로 기록합니다.
- **반환 값이 0인데 예상 파일이 없습니다. 이제 무엇을 보나요?** 앱 출력과 작업 디렉터리, 계정 권한, 파일 증거를 확인하고 프로그램의 반환 값 정의를 검토하세요.

결과 열 줄이 모두 일치하고 `registration_only`, `zero_only`, `duplicate_completion`에서 다음으로 볼 자료를 설명할 수 있으면 실습 완료입니다.

## 공식 참고자료와 이벤트 분석 자료

2026-11-22 검토. Microsoft의 Security 이벤트 문서에는 이전 Windows 10 예제가 포함돼 있습니다. 실제 설치 빌드에서 이벤트 구조와 수집을 확인하세요. 명령 참조는 Windows Server 2025, Sysmon 참조는 2026년 9월 게시 버전을 기준으로 검토했습니다.

- 작업 정의와 설정, 동작 진단. [Microsoft Task Scheduler 스키마](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema) · [예약 작업 문제 해결](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/troubleshoot-scheduled-tasks-not-running)
- 등록·갱신 및 감사 요건. [Microsoft Audit Other Object Access Events](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-object-access-events) · [이벤트 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698) · [이벤트 4702](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4702)
- 공급자 메타데이터와 최신 실행 정보. [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) · [Get-ScheduledTaskInfo](https://learn.microsoft.com/powershell/module/scheduledtasks/get-scheduledtaskinfo)
- 프로세스 증거. [Microsoft 이벤트 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688) · [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Operational 이벤트 매핑. 다음 분석 자료와 대조했고 대상 빌드에서 확인할 수 있습니다. [Splunk Security Content · 동작 시작](https://research.splunk.com/endpoint/b3632472-310b-11ec-9aab-acde48001122/) · [EVTX Parser · 작업 시작](https://www.evtxparser.com/en/events/task-scheduler/100) · [동작 완료](https://www.evtxparser.com/en/events/task-scheduler/201) · [작업 완료](https://www.evtxparser.com/en/events/task-scheduler/102)

[이전 학습 · Windows 지속성 개요]({{ '/ko/wiki/windows-persistence/' | relative_url }}) · [다음 학습 · Windows 서비스 실행 증거]({{ '/ko/wiki/windows-service-runtime-evidence/' | relative_url }})
