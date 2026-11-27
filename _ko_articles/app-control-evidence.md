---
title: "Windows App Control · 감사·차단·서명 이벤트 읽기"
description: "Windows 코드 무결성 정책 판정, 서명 기록, 정책 활성화를 연결하고 파일 차단과 악성코드 실행의 증거를 구분합니다."
category: blue-team
tags: [Windows Security, App Control for Business, Code Integrity, Windows Logs, Blue Team, Detection Engineering]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/app-control-evidence/
---

**학습 목표.** 시험 배포 중인 노트북에서 앱이 코드 정책을 통과하지 못했다는 기록이 나왔습니다. Windows가 실제로 파일을 차단했는지, 서명 기록에서 무엇을 알 수 있는지, 계획한 정책이 그 장치에 로드됐는지 확인합니다.

## 1. 애플리케이션 제어는 무엇을 평가하나요?

**App Control for Business**는 Windows 장치 전체에 코드 실행 정책을 적용합니다. 이전 명칭은 Windows Defender Application Control(WDAC)입니다. 설정한 정책 옵션에 따라 드라이버나 사용자 모드 코드를 제어할 수 있습니다. 규칙은 코드 서명 인증서, 서명된 파일 속성 또는 해시 등을 근거로 삼습니다. **해시**는 바이트나 파일 형식에 맞춰 정의한 데이터의 지문입니다. **서명자**는 전자서명에 연결된 주체입니다. 이 정보는 파일의 특성을 보여주고, 해당 파일이 조직의 허용 규칙을 충족하는지는 정책이 판정합니다.

**감사 모드**는 감사 정책을 위반한 항목을 나중에 검토할 수 있도록 기록합니다. **강제 적용**은 적용 중인 정책을 통과하지 못한 파일을 차단합니다. 단계적으로 시험하면 업무 앱에 필요한 구성 요소가 빠졌는지 먼저 살펴볼 수 있습니다. 여러 정책이나 제어 기능이 함께 동작할 때 감사 기록만으로 실제 작업의 완료 여부를 판단하기는 어렵습니다. Microsoft는 AppLocker를 별도 기술로 설명합니다. 이 장은 실행 파일과 DLL의 코드 무결성 이벤트에 집중합니다.

| 이벤트 ID | 채널 | 증거가 보여주는 내용 |
| --- | --- | --- |
| 3076 | CodeIntegrity/Operational | 해당 감사 정책을 강제 적용했다면 이 파일을 차단했을 것입니다 |
| 3077 | CodeIntegrity/Operational | 강제 적용 정책이 이번 파일 사용 시도를 차단했습니다 |
| 3089 | CodeIntegrity/Operational | 관련 판정의 서명 세부 정보입니다. `TotalSignatureCount=0`인 기록은 서명이 없음을 보고합니다 |
| 3099 | CodeIntegrity/Operational | 정책이 로드됐습니다. 세부 정보와 옵션을 확인해 어느 정책인지 식별합니다 |

조회 범위에 3076·3077이 없다면 해당 표본에서 부정 판정을 찾지 못한 것입니다. 실행 성공 여부는 별도의 프로세스나 애플리케이션 증거로 확인하세요. 이 이벤트 ID만으로 실행된 파일 전체를 파악할 수는 없습니다.

## 2. 정상적인 시험 배포 따라가기

가상의 Windows 11 시험 그룹에서 승인된 자산 관리 앱을 사용합니다. 이미 승인된 빌드는 화면이 정상적으로 열립니다. 이후 공급자가 보조 DLL을 업데이트합니다. 감사 단계에서 그 DLL을 불러오려는 시도가 정책 조건을 충족하지 못해 3076이 생성됩니다. 대응하는 3089에는 서명 정보가 있습니다. 별도로 승인된 강제 적용 시험에서는 3077이 DLL 차단을 기록했지만 앱 창은 그대로 열려 있을 수 있습니다. 담당자는 승인된 배포 출처, 재현 절차, 프로세스 기록을 대조해 어떤 기능이 영향을 받았는지 판단합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/app-control-evidence-ko.svg' | relative_url }}" alt="파일이 정책 조건을 통과하지 못하면 감사 모드에서는 3076, 강제 적용에서는 3077이 기록됩니다. 서명은 같은 활동의 3089를 확인하고 정책 로드는 3099에서 별도로 확인합니다.">
  <figcaption>판정은 3076 또는 3077, 서명 정보는 관련 3089, 정책 로드는 3099에서 확인합니다.</figcaption>
</figure>

이벤트 뷰어의 XML에서 `System > Correlation` 아래 `ActivityID`를 찾습니다. 원래 컴퓨터, 공급자와 채널을 보존하세요. 관련 시간 범위에서 같은 호스트의 기록을 비교하고, 비어 있지 않은 활동 ID가 일치할 때 3076·3077을 3089에 연결합니다. 경로와 시각은 연결을 뒷받침하지만 활동 ID를 대신할 수는 없습니다. 서명이 여러 개면 3089도 여러 건 나올 수 있습니다. 설치 환경에서 제공되는 전체 서명 수와 서명 인덱스를 비교하세요. 전달된 중복은 원본 로그 범위를 확인한 뒤 제거합니다. 일치하는 3089의 서명 수가 0인 경우와 일치하는 3089를 찾지 못한 경우는 구분합니다.

## 3. 정책 판정을 맥락과 함께 해석하기

| 관측 결과 | 다음에 확인할 자료 |
| --- | --- |
| 공급자 업데이트 후 3076 발생 | 승인 앱 목록, 배포 출처, 서명자와 정책 버전. 실제 기능은 별도로 확인합니다 |
| 3077이 DLL을 가리킴 | DLL을 불러오려던 프로세스와 재현 가능한 작업. 앱 전체 상태는 프로세스나 애플리케이션 기록에서 확인합니다 |
| 낯선 파일이 차단됨 | 경로와 관련 파일 정보를 보존하고 승인 목록, 프로세스 기록과 엔드포인트 증거를 대조합니다 |
| 중앙 수집기에 3089가 없음 | 원본과 전달된 XML, 시간 범위, 보존 기간과 구독 필터. 확인 전에는 서명 상태를 미확인으로 기록합니다 |
| 3099가 있는데 시험 결과가 예상과 다름 | 정책 ID, 모드 옵션, 배포 기록. 로드 이벤트의 시각과 장치를 함께 확인합니다 |

승인되지 않은 프로그램도 차단될 수 있고, 정상 업데이트도 정책 조건을 충족하지 못하면 같은 이벤트를 남길 수 있습니다. 정책을 통과한 프로그램의 이후 동작도 관찰해야 합니다. 서명이 있다는 사실만으로 배포자의 의도나 실행 후 행동을 판정할 수는 없습니다. 예기치 않은 차단이 반복되거나 출처가 의심되면 증거를 보존해 사고 대응 절차에 따라 검토하고, 정책 변경은 담당자와 조율하세요. 설치 프로그램과 스크립트는 해당 채널과 실행 호스트를 따로 봅니다. App Control은 이러한 경로에 **AppLocker / MSI and Script** 채널을 사용합니다. Microsoft 문서에 따르면 스크립트 호스트에 따라 8029와 함께 제한된 실행이 일어날 수도 있습니다.

## 4. 블루팀 수집·탐지·대응

1. **수집 범위를 정합니다.** 장치, OS 빌드, UTC 시각, 적용 대상 정책 ID, 배포 그룹과 기대 동작을 기록합니다. 채널이 있고 읽기 권한이 있는지 확인하세요. 지원 빌드의 `CiTool.exe -lp -json`은 비활성 정책도 포함해 목록을 보여줍니다. 과거 상태는 3099와 배포 기록을 함께 봅니다. Microsoft CiTool 문서의 기본 제공 범위는 Windows 11 22H2부터와 Windows Server 2025입니다.
2. **원본 이벤트를 보존합니다.** 승인된 Windows 호스트에서 로컬 이벤트 로그를 읽을 권한이 있다면 아래 PowerShell 예시로 최근 두 시간을 조회할 수 있습니다. 사고 시간에 맞게 범위를 조정하세요. 증거를 수집할 때는 원본 EVTX를 보관하고, 중앙 수집기로 변환하기 전에 XML 필드를 보존합니다.
3. **원본과 수집기를 비교합니다.** 내보낸 XML의 `Computer`, `Channel`, `Provider`, `TimeCreated`, `EventRecordID`, `EventID`, `Correlation`을 남깁니다. 정책·파일·서명 필드도 가능한 한 원본 그대로 확보하세요. 결과가 비어 있다면 보호 상태를 판단하기 전에 열람 권한, 수집 상태, 전달 필터와 시간 범위를 확인합니다.
4. **시험 배포를 검증합니다.** 승인된 일회용 Windows VM에서는 사전에 승인된 감사·강제 적용 시험 정책과 무해한 파일을 사용합니다. 허용돼야 할 작업과 정책에 걸려야 할 무해한 작업을 각각 실행하고 기대 결과와 시각을 적습니다. 원본에서 판정과 관련 기록을 확인한 뒤 수집기까지 도착했는지 봅니다. 전체 적용 전에는 별도 강제 적용 시험 그룹과 승인된 복구 계획을 사용합니다. 감사 결과와 실제 차단은 별도 탐지 조건으로 운영하세요.


```powershell
$filter = @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3076, 3077, 3089, 3099
    StartTime = (Get-Date).AddHours(-2)
}
$events = Get-WinEvent -FilterHashtable $filter
$events | ForEach-Object { $_.ToXml() }
```

## 5. 오프라인 실습 · 일곱 가지 판정 연결하기

<a href="{{ '/assets/labs/app-control-events-lab.py' | relative_url }}" download>app-control-events-lab.py</a>를 내려받아 Python 3.10 이상에서 `python3 app-control-events-lab.py`를 실행하세요. 일부 필드만 담은 가상 XML 문자열을 읽습니다. Windows 로그를 열거나 장치 설정을 변경하지 않습니다. 레코드 ID를 이용한 중복 제거는 이 가상 수집 구간에만 적용됩니다. 실제 조사에서는 로그 인스턴스나 내보내기 범위를 보존하고 서명 인덱스와 파일 정보도 확인하세요.

| 판정 레코드 | 기대 결과 |
| --- | --- |
| 1과 3 | 서명 없음이 보고된 감사 판정, 그리고 일치하는 서명 기록 두 건이 있는 실제 차단 |
| 6 | 일부 서명 기록만 있는 실제 차단. 중복 전송은 새 서명으로 세지 않습니다 |
| 8과 14 | 일치하는 3089가 없는 감사 판정. 다른 호스트 이벤트와 같은 활동 ID의 3099는 서명 정보가 될 수 없습니다 |
| 9와 11 | 연결 ID가 없는 실제 차단과 서명 수가 서로 다른 별도의 실제 차단 |

마지막 줄은 `7 synthetic decisions checked.`입니다. 파일을 찾지 못하면 내려받은 폴더와 파일명을 확인하세요. 기대 결과와 다르면 `Computer`, XML 네임스페이스, 활동 ID와 서명 수를 먼저 비교합니다. 실습은 Python 3.12로 실행했습니다. Windows 이벤트 생성, PowerShell 수집, CiTool, 실제 정책 동작은 Microsoft 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **3076이 있습니다. 실행이 차단됐다고 보고해도 될까요?** 감사 정책을 강제 적용했다면 차단할 항목이었다고 기록합니다. 실제 실행 여부와 다른 제어 기능의 판정은 별도로 확인하세요.
- **DLL의 3077이 보이면 앱 전체가 중지됐다고 볼 수 있나요?** 어떤 DLL을 불러오지 못했는지 먼저 식별하고, 앱 전체 결과는 실행이나 업무 기능 기록에서 확인합니다.
- **수집기에 3089가 없으면 서명이 없는 파일인가요?** 동일 활동의 원본 3089에서 서명 수가 0으로 보고됐는지 확인하세요. 수집 범위도 함께 점검합니다.
- **3099로 어떤 파일이 차단됐는지 알 수 있나요?** 3099는 정책 로드를 기록합니다. 차단 여부는 정책 정보, 시각, 장치와 판정 이벤트를 연결해 설명합니다.

**완료 기준.** 원본 시스템, 정책 모드, 파일 판정, 확보한 활동 ID, 앱 또는 사고 결과를 확정하는 데 필요한 추가 증거 하나를 기록하세요.

[이전 · Windows 이벤트 로그]({{ '/ko/wiki/windows-logs/' | relative_url }}) · [다음 · 탐지 규칙 검증]({{ '/ko/wiki/detection-validation/' | relative_url }})

## 공식 참고자료

2026년 11월 21일 검토했습니다. Microsoft 이벤트 문서는 Windows 10·11과 Windows Server 2016·2019·2022·2025를 다룹니다. 기능, 필드와 도구의 지원 범위는 빌드와 정책에 따라 달라질 수 있습니다. 시험 환경의 버전에서 확인하세요.

- [App Control 개요와 현재 명칭](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol) · [App Control과 AppLocker의 지원 범위](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/feature-availability)
- [코드 무결성과 스크립트 이벤트 ID](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations) · [Windows 이벤트 XML Correlation 필드](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-correlation-systempropertiestype-element)
- [감사 정책 분석과 배포](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/audit-appcontrol-policies) · [CiTool 기술 문서](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/citool-commands)
- [PowerShell Get-WinEvent 필터](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)

[Authenticode 서명, 전체 파일 해시, App Control 증거 대조하기]({{ '/ko/wiki/windows-authenticode-evidence/' | relative_url }})
