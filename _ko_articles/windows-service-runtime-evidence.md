---
title: "Windows 서비스 실행 증거 · 시작, 프로세스, 기능 확인"
description: "가상 사례 일곱 건으로 Windows 서비스 설정, SCM 상태, 프로세스·모듈 기록과 실제 작업 결과를 대조합니다."
category: blue-team
tags: [Windows Security, Windows Services, Windows Logs, Sysmon, DFIR, Blue Team]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/windows-service-runtime-evidence/
---

서비스 이름이나 설치 이벤트를 확보한 뒤, 실제로 서비스가 시작되어 어떤 일을 했는지 확인할 때 읽는 글입니다. 작업 스케줄러·Run 키·WMI와 서비스 등록의 관계는 [Windows 지속성 가이드]({{ '/ko/wiki/windows-persistence/' | relative_url }})에서 다룹니다. 여기서는 Windows 사용자 모드 서비스의 등록, 시작, 모듈 로드, 실제 작업 완료를 차례로 확인합니다.

## 1. 설정과 현재 상태가 답하는 질문

**서비스 제어 관리자(SCM)**는 설치된 서비스의 설정을 관리하고, 서비스가 보고한 상태를 보관합니다. 서비스에는 조회에 쓰는 **내부 이름**과 사용자에게 표시하는 **표시 이름**이 있습니다. 시작 설정은 서비스가 어떤 조건에서 실행될 수 있는지 알려 줍니다. 수동 시작 서비스도 실행 중일 수 있고, 자동 시작 서비스도 중지 상태일 수 있습니다. 현재 설정은 수집 시점의 스냅샷으로 기록하고, 과거 변경은 해당 시점의 감사 로그나 인벤토리 이력으로 확인하세요.

일반적인 시작 과정에서는 `STOPPED`에서 `START_PENDING`을 거칩니다. 서비스가 제어 요청을 받을 준비가 되면 `RUNNING`을 보고합니다. 대기 중에는 진행을 나타내는 **체크포인트**와 이번 작업에 필요한 예상 시간을 나타내는 **대기 힌트**가 있을 수 있습니다. 대기 중인 화면을 한 번 본 것만으로 시간 초과를 단정할 수 없습니다. 조회 시각과 반복 관측, 원본 오류를 대조해 정상 초기화와 실패를 구분합니다. SCM 조회는 가장 최근에 전달된 상태를 반환하므로 실제 전이와 시차가 생길 수 있습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-service-runtime-ko.svg' | relative_url }}" alt="설정을 확인한 다음 SCM 상태를 읽습니다. 시작 대기 또는 실패라면 오류와 수집 범위를 확인합니다. 실행 중 보고가 있으면 프로세스나 모듈을 대조하고 독립적인 업무 기록으로 기능을 확인합니다.">
  <figcaption>수집된 상태에 맞춰 다음 증거를 찾습니다. 실행 중이라면 프로세스 증거를 확보한 뒤 서비스 기능을 별도로 확인합니다.</figcaption>
</figure>

| 확인한 증거 | 뒷받침하는 판단 | 다음 확인 |
| --- | --- | --- |
| 서비스 설정 또는 설치 기록 | 관측 범위에서 서비스가 구성되거나 설치됨 | 시작 시도가 있었는지 |
| SCM의 대기·실패·실행 중 보고 | 해당 상태 또는 실패가 보고됨 | 원본 오류, 프로세스 연결, 관측 시각 |
| 프로세스 생성 또는 모듈 로드 | 특정 프로세스가 생성되었거나 모듈을 로드함 | 어느 서비스가 사용했고 작업이 완료됐는지 |
| 애플리케이션 상태 확인 또는 트랜잭션 | 시험한 범위에서 정해진 동작이 성공함 | 검사 대상, 실행 주체, 관측 결과 |

## 2. 정상 변경과 시작 실패를 따라가기

가상의 변경 요청에 따라 H1의 보고서 에이전트 `DemoReport`를 업데이트한다고 가정합니다. 09:00 UTC의 인벤토리에는 승인된 서비스 이름, 시작 유형, 실행 파일 경로가 남습니다. 09:02의 프로세스 생성 이벤트에는 `report.exe`가 기록됩니다. 09:02:03에는 SCM 스냅샷이 같은 PID와 `RUNNING`을 보여 줍니다. 이후 에이전트에는 실행 ID가 일치하는 시험 보고서 한 건이 완료된 기록이 남습니다. 변경 요청서는 승인을, SCM과 프로세스 기록은 시작을, 시험 결과는 그 실행에서의 기능을 뒷받침합니다.

다른 호스트에서는 프로세스가 생성된 뒤 서비스가 대기 상태에 머물렀고 SCM에 시작 시간 초과가 기록됐습니다. 원인을 정하기 전에 상세 오류, 의존 서비스와 계정 기록, 엔드포인트 정책, 애플리케이션 로그, 최초 관측 시각을 확인합니다. Windows Server 문서는 이벤트 7000과 7011이 나타나는 특정 시간 초과 사례를 다룹니다. 이 번호의 의미는 해당 이벤트의 문맥과 메시지로 확인하세요. 정상 배포의 문제와 비인가 변경 모두에서 시작 실패가 나타날 수 있습니다.

공유 프로세스형 서비스는 여러 서비스가 `svchost.exe` 같은 호스트를 함께 쓸 수 있습니다. 호스트 프로세스가 조사 대상 서비스보다 먼저 시작되기도 합니다. 모듈 로드 기록이 있으면 어떤 모듈이 어느 프로세스에서 로드됐는지 좁힐 수 있습니다. 작업을 특정 서비스에 귀속하려면 신뢰할 수 있는 서비스 설정과 해당 애플리케이션의 이벤트, 트랜잭션 ID 또는 측정된 출력을 대조하세요. 같은 모듈을 여러 구성 요소가 사용할 수 있습니다.

## 3. 수집하고 대조한 뒤 대응 범위 정하기

1. **서비스를 식별합니다.** 호스트, 부팅 구간, UTC 시각, 내부 이름과 표시 이름, 설정된 계정, 실행 명령, 의존성, 서비스 유형과 담당자를 기록하세요. System·Security 이벤트의 원본과 함께 공급자, 채널, 버전, 레코드 ID를 보존합니다. 파일 메타데이터와 해시는 승인된 수집 방식으로 확보합니다. 실행 명령에는 인수가 포함될 수 있으므로 확인된 파일 경로와 별도 필드로 취급하세요.
2. **이벤트가 수집됐는지 확인합니다.** Security 4697은 설치 시점의 이벤트입니다. 이를 조사하려면 **Audit Security System Extension** 성공 감사와 로그 접근·보존이 필요합니다. System 채널에서는 이름과 시간에 맞는 Service Control Manager 원본 이벤트를 확인하고 오류 문구와 값을 남깁니다. 중앙 로그에 결과가 없으면 로컬 생성과 전달 범위도 확인합니다. 수집 전반은 [Windows 이벤트 조사]({{ '/ko/wiki/windows-logs/' | relative_url }})에 이어집니다.
3. **일치하는 프로세스를 찾습니다.** 가능하면 Sysmon의 `ProcessGuid`처럼 프로세스 한 인스턴스를 식별하는 값을 사용합니다. 호스트와 시각을 함께 대조하고 PID만 쓸 때는 부팅 구간과 생성·종료 시간을 확인하세요. `QueryServiceStatusEx`에서 시작·중지 대기 상태의 PID는 유효하지 않을 수 있고, 중지 상태의 PID는 유효하지 않습니다. 스냅샷보다 뒤에 생성된 프로세스와 연결하거나 부팅 경계를 넘어 PID를 재사용하지 마세요. Sysmon 이벤트 1은 해당 이벤트가 수집되고 활성 필터에 포함돼야 확인할 수 있습니다. 이벤트 7은 모듈 로드 기록이며 ImageLoad 수집을 설정해야 합니다. 기본값에서는 꺼져 있습니다. 공유 호스트에서는 실습의 파일명보다 실제 전체 모듈 경로와 확보한 해시를 우선합니다.
4. **확보한 증거에 따라 대응합니다.** 파일, 모듈, 계정을 승인된 기준선 및 변경 기록과 대조합니다. 새 설치 이벤트 없이도 기존 설정이나 파일이 교체될 수 있습니다. 설명되지 않는 변경이라면 담당자와 사고 대응 책임자에게 공유하고 증거를 보존하세요. 공유 호스트를 중지하거나 격리하기 전에는 영향을 받을 다른 서비스와 업무를 확인합니다. 실제 영향은 애플리케이션 증거로 확인하고 어느 호스트·시간대·채널이 확인됐는지 기록합니다.

설치나 설정 변경 경보를 확인할 때는 이전 값과 이후 값이 같은 호스트의 같은 서비스에서 나온 것인지 먼저 보세요. 나중에 탐지를 검증할 때는 승인된 정상 변경과, 다른 호스트에 같은 이름이 있는 가상 사례를 함께 사용하세요. 예기치 않은 서비스 등록, 설명되지 않은 실행 파일, 수집 범위 미확인에 각기 다른 사유를 남기면 조사 우선순위를 정하기 쉽습니다.

## 4. 승인된 Windows 호스트에서 읽기 전용 조회

PowerShell을 쓸 수 있는 지원 Windows 환경에서 로컬 SCM·CIM 조회 권한과 Windows 이벤트 로그 서비스가 있는 경우입니다. 내부 이름 `EventLog`로 조회하고 PowerShell에서는 `sc.exe`를 명시합니다. 아래 명령은 수집 시간을 출력하고 현재 정보를 읽습니다.

```powershell
Get-Date -Format o
sc.exe qc EventLog
sc.exe queryex EventLog
Get-CimInstance Win32_Service -Filter "Name = 'EventLog'" |
  Select-Object Name, DisplayName, StartMode, State, ProcessId, StartName, PathName
```

설정과 상태가 서로 다른 시각에 조회될 수 있습니다. 반환되는 상태, 종료 코드, 체크포인트를 남기고 유효한 PID를 확보한 경우에만 프로세스 증거를 대조합니다. 조회 사이에 상태가 바뀌면 시간과 함께 다시 관측하세요. 접근 거부나 서비스 이름 오류도 수집 결과에 기록합니다. 명령은 제품 문서에서 확인했으며 Windows 환경에서 실행하지 않았습니다.

## 5. 오프라인 증거 판독 실습

두 파일을 같은 폴더에 내려받고 Python 3.10 이상으로 그 폴더에서 실행합니다. **가상 정규화 JSONL**을 읽는 실습입니다. 초 단위 시간과 호스트, 부팅, 프로세스 식별자는 학습용입니다. 실제 제품의 원본 XML과 필드에는 별도 정규화가 필요합니다. 스크립트는 로컬 가상 파일만 읽습니다. 이 가상 실습은 Python 3.12에서 실행 검증했습니다.

<a href="{{ '/assets/labs/windows-service-runtime-review.py' | relative_url }}" download>windows-service-runtime-review.py</a> · <a href="{{ '/assets/labs/windows-service-runtime-cases.jsonl' | relative_url }}" download>windows-service-runtime-cases.jsonl</a>

```bash
python3 windows-service-runtime-review.py windows-service-runtime-cases.jsonl
```

```text
approved: dedicated_process_and_health
pending: pending
timeout: start_failure
shared_host: shared_host_only
module_observed: shared_module_observed
pid_reused: shared_host_only
registration_only: registration_only
```

스크립트는 호스트, 부팅 구간, 관측 시각을 기준으로 범위를 잡습니다. 가상 예제는 모듈 파일명과 미리 정한 짧은 상태 확인 구간을 사용합니다. 운영에서는 더 확실한 프로세스 식별자, 전체 경로, 서비스 트랜잭션이나 동등한 증거가 필요합니다. `shared_module_observed`는 식별한 공유 프로세스에서 일치하는 모듈 로드 기록이 있었다는 뜻입니다. 행이 없으면 실제 로드 여부를 추정하기 전에 ImageLoad 정책과 수집 범위를 확인하세요. 파일을 열지 못하면 작업 폴더와 확장자를 확인합니다. 분류가 예상과 다르면 같은 PID의 이벤트를 사용하기 전에 관측 시각과 호스트·부팅 구간부터 대조하세요.

## 6. 확인 문제와 해설

- **프로세스 생성과 시작 대기 상태만 있으면 시작 성공인가요?** 프로세스 관측과 대기 보고는 확인됐습니다. 이후의 실행 중 보고, 명시적 실패 또는 다른 수명 주기 증거로 타임라인을 완성해야 합니다.
- **`pid_reused`에서 앞선 모듈 로드 기록을 가져올 수 있나요?** 앞선 프로세스는 종료됐고, 현재 상태와 연결된 프로세스와 식별자가 다릅니다. 이전 부팅 구간의 기록도 현재 상태와 연결할 수 없습니다.
- **승인된 파일이면 서비스가 제 역할을 했다는 뜻인가요?** 파일 승인은 설정이나 출처 확인에 도움이 됩니다. 시험한 시간대의 실제 출력이나 일치하는 상태 확인 결과, 트랜잭션을 찾아야 합니다.

일곱 줄의 결과를 재현하고, `approved`에서 각 판단을 뒷받침하는 증거를 짚어 보세요. `pending`, `shared_host`, `registration_only`에 각각 필요한 다음 증거 출처를 한 가지씩 적으면 실습을 마친 것입니다.

## 공식 참고자료

검토일은 2026-11-22입니다. Win32 API 문서는 Windows 서비스의 동작을 설명합니다. 실제 이벤트의 스키마와 수집 여부는 운영 중인 OS와 Sysmon 버전에서 확인하세요. 4697 문서는 과거 XML 예시를 포함하며, 시간 초과 문서는 특정 Windows Server 사례를 다룹니다.

- Win32 SCM과 설치 서비스 데이터베이스. [Microsoft Learn · 서비스 제어 관리자](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager)
- Win32 서비스 수명 주기. [Microsoft Learn · 서비스 상태 전이](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions)
- Win32 스냅샷과 PID 유효 조건. [Microsoft Learn · QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- Win32 프로세스 유형, 체크포인트와 대기 힌트. [Microsoft Learn · SERVICE_STATUS_PROCESS](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process)
- CIM 필드 정의. [Microsoft Learn · Win32_Service와 SC](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- Windows SDK 명령줄 도구. [Microsoft Learn · SC 조회 명령](https://learn.microsoft.com/en-us/windows/win32/services/configuring-a-service-using-sc)
- Windows 10 문서와 당시 XML 예시. [Microsoft Learn · Security 이벤트 4697](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697)
- 지원되는 Windows Server 버전의 시간 초과 사례. [Microsoft Learn · Windows Server 이벤트 7000·7011](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/service-not-start-events-7000-7011-time-out-error)
- Windows Sysmon 이벤트 정의와 수집 전제조건. [Microsoft Learn · Sysmon 이벤트](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

[이전 · Windows 지속성]({{ '/ko/wiki/windows-persistence/' | relative_url }}) · [다음 · Sysmon 조사]({{ '/ko/wiki/sysmon-investigation/' | relative_url }})

## 예약 작업 실행 확인하기

[Windows 예약 작업 실행 조사]({{ '/ko/wiki/windows-scheduled-task-runtime-evidence/' | relative_url }})에서 작업 정의부터 스케줄러 인스턴스, 실행 프로세스와 실제 결과까지 이어서 확인하세요.
