---
title: "PowerShell 스크립트 블록 조사 · 4104 이벤트 복원"
description: "PowerShell 이벤트 조각을 복원하고 수집 범위와 독립 증거를 대조해 실제 결과를 확인합니다."
category: blue-team
tags: [PowerShell, Windows, Event Logs, Blue Team, DFIR, Detection Engineering]
level: Beginner
updated: "2026-11-23"
translation_url: /wiki/powershell-script-block-evidence/
---

**학습 목표.** Windows의 PowerShell 스크립트 블록 기록을 원래 순서로 복원합니다. 복원한 텍스트에서 확인할 수 있는 범위와, 파일 변경 같은 실제 결과를 입증하기 위해 필요한 추가 증거를 설명합니다.

## 1. 스크립트 블록이란 무엇인가요?

**스크립트 블록**은 스크립트 본문, 함수 본문, 중괄호로 묶은 코드처럼 PowerShell이 다루는 코드 단위입니다. **이벤트 공급자(provider)**는 이벤트를 내보내는 구성 요소입니다. **채널**은 그 기록이 쓰이는 이벤트 로그입니다. **런스페이스(runspace)**는 PowerShell 호스트 프로세스 안의 실행 환경입니다. 한 프로세스에 여러 런스페이스가 있을 수 있습니다.

스크립트 블록 로깅은 PowerShell 엔진이 처리한 코드를 기록합니다. 프로세스 명령줄에 파일 이름만 있어도 스크립트 내용을 확인할 수 있습니다. 각 줄과 분기의 실행, 개별 호출, 그 뒤의 작업 결과는 별도 증거가 필요합니다. 이미 기록된 블록을 다시 사용하면 새 블록 생성 이벤트 없이 코드가 실행될 수 있습니다.

| 증거 | 확인할 내용 |
| --- | --- |
| Windows PowerShell 5.1의 4104 | `Microsoft-Windows-PowerShell/Operational` 채널입니다. 5.1 정책을 적용한 뒤 새 세션에서 확인합니다. |
| Windows용 PowerShell 7.6의 4104 | `PowerShellCore/Operational` 채널입니다. 공급자가 등록돼 있는지, 7.x 설정이 실제 적용됐는지 확인합니다. |
| 보안 로그 4688 | 프로세스 생성 감사가 켜져 있을 때 시작을 기록합니다. 명령줄은 별도 정책이 필요하고, 제공 필드는 이벤트 버전에 따라 다릅니다. |
| Sysmon 1 | Sysmon이 설치됐고 수집 규칙에 해당 프로세스가 포함될 때 시작과 ProcessGuid를 확인합니다. |
| 파일·서비스·애플리케이션 증거 | 확인하려는 결과에 맞는 자료를 골라 해당 동작과 시각을 확인합니다. |

Windows 한 대에 두 PowerShell 채널이 함께 있을 수 있습니다. 5.1 채널만 검색하면 PowerShell 7의 활동을 놓칠 수 있습니다. Linux와 macOS에서의 PowerShell은 각 운영체제의 로깅을 사용합니다. 이 장은 Windows를 기준으로 설명합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/powershell-script-block-evidence-ko.svg' | relative_url }}" alt="하나의 PowerShell 스크립트 블록이 순번을 가진 여러 4104 이벤트로 나뉠 수 있습니다. 원본 출처와 블록별로 묶고 번호가 모두 있는지 확인한 뒤, 복원 텍스트를 프로세스와 결과 증거에 연결합니다.">
  <figcaption>조각을 검증한 뒤 코드를 해석하고, 별도 관측을 통해 실행 결과를 확인합니다.</figcaption>
</figure>

## 2. 정상 기록 하나를 복원해 봅시다

예약된 인벤토리 작업에서 PowerShell 스크립트가 로컬 소프트웨어의 버전을 보고한다고 가정합니다. 해당 4104 이벤트가 수집기로 2번, 1번, 다시 2번 순서로 들어옵니다. 도착 순서만 보면 코드가 뒤집혔거나 중복된 것처럼 보일 수 있습니다.

1. 원본 이벤트 XML을 보존합니다. `System/Computer`, `Provider`, `Channel`, `TimeCreated`, 값이 있으면 `Execution/ProcessID`, 그리고 `EventRecordID`를 남깁니다. 전달 과정에서도 원본 채널을 보존하세요. 발생 시각과 수집기의 수신 시각은 다를 수 있습니다.
2. 원본 호스트·공급자·채널과 확인된 프로세스 수명 범위 안에서 `EventData`의 `ScriptBlockId`로 묶습니다. 실습 자료는 시간이 제한돼 있고 PID가 가리키는 프로세스가 명확하다고 가정합니다. 운영 조사에서는 호스트 이름을 안정적인 자산 식별자에 연결하고 PID 재사용 여부를 확인합니다. `Path`가 비어 있는 것만으로 코드의 출처를 판단하기는 어렵습니다.
3. `MessageTotal`이 일치하고 `MessageNumber`가 1부터 그 전체 개수까지 모두 있는지 확인합니다. 같은 번호가 반복되면 내용을 비교합니다. 같은 묶음 안에서 내용도 같다면 복원할 때 중복을 제외하고 원본은 보존합니다. 번호가 같은데 텍스트가 다르면 충돌입니다. `ScriptBlockText`는 번호순으로 이어 붙이고 공백이나 줄바꿈을 임의로 추가하지 않습니다.
4. 같은 원본 호스트와 프로세스 수명에서 이벤트를 내보낸 프로세스를 찾습니다. 보안 로그 4688에서는 4104의 실행 PID를 새 프로세스의 `NewProcessId`와 비교합니다. 이 값은 16진수로 표시될 수 있습니다. 4688의 `System/Execution`에 있는 공급자 PID를 새 프로세스 PID로 쓰면 안 됩니다. Sysmon 1을 쓴다면 프로세스 ID를 대조한 뒤 후속 Sysmon 이벤트를 연결할 때 `ProcessGuid`를 유지합니다. 보고서 생성 성공 여부는 같은 인벤토리 작업의 애플리케이션 로그에서 확인할 수 있습니다.

로컬 로그 덮어쓰기, 너무 좁은 검색 시간, 이벤트 필터, 전달 누락으로 일부 조각만 남을 수 있습니다. 수집기 기록이 불완전하면 먼저 원본 호스트를 확인하세요. 비슷한 블록을 가져와 빈 부분을 메우거나 도착 순서대로 붙이면 다른 코드를 만들 수 있습니다.

## 3. 맥락과 함께 탐지하고 조사하기

침해 과정에서 정상 스크립트 인터프리터가 원치 않는 동작을 자동화하는 데 오용될 수 있습니다. 인벤토리 도구, 관리 에이전트, 관리자도 같은 인터프리터를 사용합니다. 키워드 하나, 평소와 다른 부모 프로세스, 비어 있는 경로, 이벤트 수준만으로 악성을 판단하기는 어렵습니다. 함수 정의가 기록돼도 함수가 호출됐는지는 별도로 확인해야 합니다. 파일 변경처럼 주장하는 효과를 독립된 관측으로 검증하세요.

1. **수집 범위를 확인합니다.** OS와 엔진 버전, 로컬 채널과 공급자, 실제 적용된 스크립트 블록 로깅 설정, 보존 기간, 수집기 구독을 기록합니다. 새 세션에서 구분하기 쉬운 승인된 정상 명령으로 로컬 기록과 수집기 사본을 모두 확인합니다. UTC 시각을 비교해 지연과 누락을 남깁니다. 기록이 없어 보인다면 조회 권한도 점검합니다.
2. **범위를 정해 타임라인을 만듭니다.** 원본 호스트, 사용자나 서비스 신원, 예약 시각과 프로세스 생성 기록부터 확인합니다. 매칭한 시간 범위와 다른 후보 프로세스를 기록합니다. 파일 메타데이터나 별도로 수집한 애플리케이션 결과 등 주장하는 효과에 맞는 자료를 연결합니다. PowerShell을 호스팅하는 프로세스 이름이 언제나 `powershell.exe`나 `pwsh.exe`인 것은 아닙니다.
3. **예외를 조사합니다.** 텍스트와 프로세스 맥락을 승인된 작업 정의 및 유지보수 내역과 대조합니다. 처음 본 스크립트와 예상 밖의 시작 경로가 함께 나타나고, 호스트 변화까지 맞아떨어지는지 확인합니다. 조각이 빠지거나 충돌하는 비율은 행위 탐지와 별도로 측정합니다. 원본을 보존하고, 증거가 뒷받침되면 사고 대응 절차에 따라 격리 등 필요한 조치를 판단합니다.
4. **기록을 보호합니다.** 스크립트 본문과 명령줄에 비밀 값이 들어갈 수 있습니다. 접근을 제한하고 교육·티켓용 사본에서 민감 정보를 가립니다. Microsoft의 Protected Event Logging은 CMS 형식으로 기록을 보호합니다. 발행 장비에는 암호화용 공개 인증서를 두고 개인키는 승인된 복호화 환경에서 관리합니다. 보호된 조각은 암호문을 보존하고 승인된 절차로 복호화한 뒤 평문을 해석하거나 복원합니다. 복호화 개인키를 엔드포인트에 배포하지 않습니다.

## 4. 승인된 Windows와 오프라인에서 실습하기

소유하거나 승인받은 Windows 실습 장비에서 로깅이 이미 설정된 엔진의 새 세션을 엽니다. `Write-Output 'Wiki4104-Control'`처럼 식별하기 쉬운 정상 명령을 실행한 뒤 대응하는 이벤트를 찾습니다. 아래 조회는 읽기 전용입니다. 로컬 채널이 정상 동작하고 로그 읽기 권한이 있어야 합니다. 실습 시각에 맞춰 조회 범위를 잡고 사용한 엔진의 채널을 선택하세요. XML에 민감한 코드가 포함될 수 있으므로 승인된 환경 안에서만 열람합니다.

```powershell
$channel = 'Microsoft-Windows-PowerShell/Operational'
# Windows에서 PowerShell 7은 'PowerShellCore/Operational'을 사용합니다.
Get-WinEvent -FilterHashtable @{
    LogName   = $channel
    Id        = 4104
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 50 | ForEach-Object { $_.ToXml() }
```

채널을 읽지 못하면 공급자 미등록과 접근 거부를 구분하세요. 맞는 기록이 없으면 엔진, 적용된 정책, 새 세션, 조회 시각을 확인합니다. 50건 제한은 이벤트가 적은 실습용이며, 바쁜 호스트에서는 관련 조각이 잘릴 수 있습니다. 실제 조사 자료를 내보낼 때는 관련 기록을 모두 포함하도록 범위를 지정하세요. Windows 명령은 공식 문서로 검토했으며 이번 게시 과정에서 Windows에서 실행하지 않았습니다.

<a href="{{ '/assets/labs/powershell-script-block-evidence.py' | relative_url }}" download="powershell-script-block-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/powershell-script-block-evidence-cases.json' | relative_url }}" download="powershell-script-block-evidence-cases.json">정규화한 가상 기록</a>을 한 폴더에 저장하세요. 스크립트는 이 JSON 자료만 읽습니다. 조각을 묶고 순번을 검증하며, 보호된 내용 여부는 실습 자료에 표시돼 있습니다. EVTX를 읽거나 CMS를 복호화하지 않으며, 프로세스 수명을 추정하거나 스크립트 내용을 실행하지도 않습니다. 결과에는 복원 텍스트를 출력하지 않습니다.

```bash
python3 powershell-script-block-evidence.py powershell-script-block-evidence-cases.json
```

```text
out_of_order: complete
missing_middle: incomplete
conflicting_copy: conflict
separate_sources: complete, incomplete
mixed_totals: conflict
protected_fragment: protected
invalid_index: invalid
```

입력을 못 찾으면 현재 폴더와 파일 이름을 확인하세요. `separate_sources`는 두 호스트에서 같은 블록 ID를 의도적으로 사용합니다. 호스트가 다른 조각을 섞으면 안 됩니다. 텍스트가 완성돼도 원본 프로세스 수명을 확인하지 못했다면 한 번의 실행으로 묶어 해석하기 어렵습니다. Python은 가상 기록으로 실행했고, 복원 순서도 확인했습니다.

## 5. 확인 문제와 완료 기준

- **전체 3개 중 1번과 3번이 있습니다. 전체 블록으로 보고해도 되나요?** 빠진 조각을 명시하고 원본에서 2번을 확인합니다.
- **같은 순번의 텍스트가 다릅니다. 무엇을 사용해야 하나요?** 둘 다 보존하고 원본과 묶음 기준을 확인합니다. 수집기에 먼저 도착했다는 이유로 고르지 않습니다.
- **4104 텍스트를 전부 복원했습니다. 모든 명령이 성공했나요?** 완전한 텍스트는 엔진이 처리한 내용을 보여 줍니다. 실제 효과는 프로세스와 결과 기록을 대조해 확인합니다.

일곱 줄의 출력이 예상과 일치하고, 엔진과 묶음 기준, 빠진 번호, 주장하는 결과에 필요한 독립 증거 하나를 설명하면 실습을 마친 것입니다.

## 공식 참고자료

2026년 11월 23일에 검토했습니다. Windows PowerShell 5.1과 Windows용 PowerShell 7.6을 대상으로 하며, 소스 코드는 7.6.0 태그 기준입니다.

- 채널과 정책, 보호된 이벤트에 관한 Microsoft Learn 문서. [Windows PowerShell 5.1 로깅](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) · [Windows용 PowerShell 7.6 로깅](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.6)
- PowerShell 7.6.0의 이벤트 필드와 조각 기록 구현. [이벤트 매니페스트](https://github.com/PowerShell/PowerShell/blob/v7.6.0/src/PowerShell.Core.Instrumentation/PowerShell.Core.Instrumentation.man#L3875) · [엔진 소스](https://github.com/PowerShell/PowerShell/blob/v7.6.0/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs#L1421)
- 이벤트 조회와 프로세스 증거에 관한 Microsoft Learn 문서. [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.6) · [Windows 보안 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688) · [Sysmon 이벤트](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)

[이전 · Windows 이벤트 로그]({{ '/ko/wiki/windows-logs/' | relative_url }}) · [다음 · Sysmon 조사]({{ '/ko/wiki/sysmon-investigation/' | relative_url }}) · [관련 · Windows 이벤트 전달]({{ '/ko/wiki/wef-delivery-evidence/' | relative_url }})
