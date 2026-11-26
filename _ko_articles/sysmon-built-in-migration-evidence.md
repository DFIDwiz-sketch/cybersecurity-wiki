---
title: "Windows 내장형 Sysmon 전환 · 전환 뒤에도 이벤트가 수집되는지 확인하기"
description: "내장형과 독립 설치형 Sysmon의 차이를 이해하고, XML 필드와 가상 사례로 전환 후 수집 공백을 찾습니다."
category: blue-team
tags: [Windows, Sysmon, Windows Event Logs, Detection Engineering, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/sysmon-built-in-migration-evidence/
---

**학습 순서** · [Sysmon 이벤트 조사]({{ '/ko/wiki/sysmon-investigation/' | relative_url }}) → 전환 검증 → [Windows 이벤트 전달]({{ '/ko/wiki/wef-delivery-evidence/' | relative_url }}).

## 1. Sysmon이 Windows 기능이 되면 무엇이 달라지나요?

**Sysmon**은 선택한 시스템 활동을 Windows 이벤트 로그에 남기는 서비스와 드라이버입니다. **독립 설치형**은 Sysinternals에서 별도로 배포합니다. **내장형 Sysmon**은 Windows 선택적 기능입니다. Microsoft는 지원되는 Windows 11 빌드와 Windows Server 2025를 문서에 안내합니다. 실제 운영 빌드와 누적 업데이트에서 기능을 확인하세요. Sysinternals에 따르면 Windows 11의 내장형 선택적 기능은 2026년 2월부터 제공됐습니다. 이전 독립 설치형 안내는 설치·업데이트 경로가 다릅니다.

| 항목 | 독립 설치형 Sysmon | 내장형 Sysmon |
|---|---|---|
| 업데이트 | 별도로 배포한 Sysinternals 릴리스를 추적합니다. | Windows 빌드와 업데이트 채널을 기록합니다. 내장형 바이너리는 Windows 업데이트로 제공됩니다. |
| 공존 | Microsoft는 내장형 활성화 전에 독립 설치형을 제거하도록 안내합니다. | 호스트별 전환을 계획합니다. 서로 다른 시험 호스트 그룹이나 같은 호스트의 전후를 비교하세요. |
| 화면 표시 메시지 | 내장형과 화면에 표시되는 문구가 다를 수 있습니다. | Windows 표시 언어에 맞게 번역될 수 있습니다. Microsoft 문서에 따르면 기본 이벤트 XML 데이터는 표시 언어와 무관합니다. |
| 수집 검증 | 설치된 빌드, 실제 적용 정책, 관측 이벤트를 대조합니다. | 전환 후에도 같은 증거를 비교합니다. 기능과 서비스 상태만으로 이벤트 수집 범위를 알 수는 없습니다. |

**이벤트 공급자**는 기록을 발행한 구성 요소입니다. **채널**은 원본 이벤트가 기록되는 로그입니다. 이벤트 XML의 **System**에는 공급자, 이벤트 ID, 컴퓨터, 생성 시각 등이 들어갑니다. **EventData**에는 이벤트 고유 필드가 이름과 값으로 들어갑니다. 프로세스 생성(Event ID 1)의 `Image`, `ProcessGuid`가 예입니다. **표시 메시지**는 사람이 읽도록 도구가 표시하는 문자열입니다. 이 장의 **카나리**는 고유 표식을 넣은 무해한 동작이며, 기대한 이벤트 한 건이 끝까지 도착하는지 확인할 때 사용합니다.

## 2. 정상 시험 전환 따라가기

1. **기준 수집.** 승인된 정책 파일과 해시, 바이너리 또는 Windows 빌드, 로컬에서 관측한 이벤트 필드, 수집된 후속 기록을 남깁니다. 호스트 역할과 입력이 비슷한 조건을 비교하고 시각은 UTC로 기록하세요.
2. **전환 시점 기록.** 승인된 변경의 담당자, 티켓, 기존 수집 범위, 시작·종료 시각을 기록하세요. 두 설치 형태가 같은 호스트에서 동시에 실행된다고 가정하지 말고 실제 빌드의 지원 조건을 따릅니다.
3. **로컬 수집 확인.** 전환 후 기능·서비스 상태와 로컬 이벤트를 확인한 다음 Event ID 1 카나리 하나를 만듭니다. 공급자, 원본 컴퓨터, UTC, `Image`, `ProcessGuid`, `CommandLine` 안의 표식을 대조하세요.
4. **전달과 검색 확인.** 같은 이벤트를 첫 수신 지점과 SIEM에서 따라갑니다. XML의 이름 있는 값과 정규화된 필드를 대조하고, 원본에서 이벤트를 만든 시각과 각 지점에 도착한 시각을 따로 기록합니다. 수집기의 레코드 번호가 원본 채널 번호와 같다고 가정하지 마세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/sysmon-built-in-migration-evidence-ko.svg' | relative_url }}" alt="승인된 시험 호스트에서 Windows 빌드와 정책, 고유한 로컬 프로세스 이벤트, 전달본, SIEM 정규화 이벤트를 차례로 확인합니다. 표시 언어가 달라도 고유 표식으로 대조할 수 있습니다." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>일치하는 이벤트나 필수 필드가 처음 사라진 지점을 찾으세요.</figcaption>
</figure>

**가상 정상 사례.** 시험 엔드포인트 `LAB-WS01`에서 콘솔 명령이 고유 표식을 출력합니다. 로컬 Sysmon XML에는 Event ID 1, 예상한 실행 파일, 표식과 프로세스 GUID가 기록됩니다. 같은 이벤트의 전달본은 한국어 메시지를 표시하지만 해당 XML 값이 일치합니다. SIEM에서도 같은 표식과 GUID를 검색할 수 있습니다. 관측한 시간 범위에서 시험한 프로세스 생성 경로를 검증한 것입니다. 다른 이벤트 유형과 워크로드도 별도로 시험하세요.

## 3. 원인을 판단하기 전에 공백을 좁히세요

| 관측 | 확인할 수 있는 것 | 다음 확인 |
|---|---|---|
| Event ID 4 | Sysmon이 서비스 상태 변경을 기록했습니다. | 승인된 변경 시간, 서비스 인벤토리, 전후 정상 이벤트를 대조합니다. |
| Event ID 16 | Sysmon이 설정 갱신을 기록했습니다. | 실제 정책과 승인 정책, 변경 이력을 비교합니다. 누가 바꿨는지와 수집 영향은 추가 근거가 필요합니다. |
| Event ID 255 | Sysmon이 오류를 보고했습니다. | 전체 이벤트를 보존하고 시각, 생산자 상태, 영향받은 유형을 점검하세요. ID만으로 유실량을 계산할 수 없습니다. |
| 로컬에는 카나리가 있으나 기록한 시간 범위의 수집기에는 없음 | 로컬 생성은 확인했고 전달은 미확인입니다. | 구독이나 에이전트 설정, 식별자, 대기열, 도착 지연을 확인합니다. |
| 수집기 XML에는 값이 있으나 SIEM 필드가 비어 있음 | 일치하는 이벤트가 수집기에 도착했습니다. | 원본 수집, 인덱스 경로, 변환·파서·필드 매핑을 비교합니다. |
| 숫자 ID 1만으로 검색했더니 다른 공급자 이벤트가 나옴 | 같은 번호를 다른 공급자도 사용합니다. | 공급자, 원본, 카나리 식별자를 함께 확인합니다. |

잘못된 정책 범위나 승인되지 않은 변경은 관측 범위를 줄일 수 있습니다. 정상 전환, 표시 언어 변경, 수신 지연도 비슷하게 보일 수 있습니다. 승인 티켓과 시스템 관리 기록 등 별도 변경 증거를 수집 검증 결과와 대조하세요. 예상 밖의 변경은 근거를 확인해 조사 범위를 넓힙니다. 카나리 한 건이 보이지 않는 것만으로 조작을 단정할 수 없습니다.

## 4. 블루팀 수집·탐지·대응

아래는 승인된 Windows 호스트에서 실행하는 읽기 전용 예시입니다. PowerShell과 로컬 Sysmon Operational 로그 읽기 권한이 필요합니다. DISM은 지원되는 Windows 이미지에서 조회하며 관리자 세션이 필요할 수 있습니다. 기능이 없거나 채널 읽기가 거부되면 각각 구분해 기록하세요. 증거를 확보할 때는 화면 출력 외에 원본 EVTX 또는 XML을 보존합니다. 실제 조사에서는 예시의 최근 두 시간 대신 사건의 시간 구간을 사용하세요.

~~~powershell
Get-WindowsOptionalFeature -Online -FeatureName Sysmon
Get-CimInstance Win32_Service -Filter "Name LIKE 'Sysmon%'" |
  Select-Object Name, State, PathName
$channel = 'Microsoft-Windows-Sysmon/Operational'
$since = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{
  LogName = $channel
  ProviderName = 'Microsoft-Windows-Sysmon'
  Id = 1,4,16,255
  StartTime = $since
} -MaxEvents 100 | ForEach-Object { $_.ToXml() }
~~~

서비스 예시는 일반적인 이름을 조회합니다. 인벤토리와 배포 이력에서 비교 대상 바이너리를 확인하세요. 이미 신뢰가 확인된 바이너리에서 `-s`는 설정 스키마를, 파일명 없는 `-c`는 현재 설정을 표시합니다. 정책 파일의 SHA-256과 이벤트의 해시 필드는 서로 다른 입력을 나타낼 수 있습니다. 같은 바이트와 알고리즘을 비교하고, 적용된 필터와 배포하려던 정책을 모두 기록하세요.

프로세스 생성 이벤트를 수집하도록 설정한 승인된 시험 호스트에서 아래처럼 무해한 표식을 생성합니다. 문자열만 출력하며 네트워크에 연결하지 않습니다. 표식과 UTC를 남기고 로컬 Event ID 1 XML과 전달본을 확인하세요. 승인된 정책이 이 실행 파일을 제외한다면 승인된 대체 활동을 쓰고 기대 수집 범위를 기록합니다.

~~~powershell
$marker = 'SYSMON-LAB-' + [guid]::NewGuid().ToString('N')
$startedUtc = (Get-Date).ToUniversalTime().ToString('o')
& "$env:SystemRoot\System32\cmd.exe" /d /c "echo $marker"
[pscustomobject]@{ Marker = $marker; StartedUtc = $startedUtc }
~~~

전후 정책과 로컬·수집기·SIEM 증거를 보존하고 원본 시계와 전달 시간을 확인합니다. 호스트 그룹과 이벤트 유형별로 설명되지 않는 감소를 살펴보세요. 로컬 카나리가 없으면 정책, 서비스, 공급자, 채널부터 확인합니다. 수집기에 도착했다면 엔드포인트 정책을 조정하기 전에 수집·정규화 경로의 변경을 찾으세요. 승인된 방식으로 수집을 복구한 뒤 같은 카나리와 필요한 필드 검사를 반복합니다.

## 5. 오프라인 실습 · 전환 사례 여섯 가지

Python 3이 있는 승인된 작업 공간의 같은 디렉터리에 두 파일을 저장하세요. 가상 자료는 네임스페이스가 있는 Windows 이벤트 XML과 정규화된 SIEM 행을 담습니다. 표시 메시지는 설명용 문구이며 실제 Windows에서 수집한 문구가 아닙니다. 스크립트는 공급자·컴퓨터·이벤트 ID·UTC 범위·XML 필드를 확인하고 프로세스 GUID와 표식을 단계별로 대조합니다. Windows 설정을 바꾸거나 네트워크에 연결하지 않습니다.

- <a href="{{ '/assets/downloads/sysmon-built-in-migration-evidence/inspect_migration.py' | relative_url }}" download>Python 점검 스크립트 다운로드</a>
- <a href="{{ '/assets/downloads/sysmon-built-in-migration-evidence/migration_cases.json' | relative_url }}" download>가상 사례 여섯 가지 다운로드</a>

~~~sh
python3 inspect_migration.py migration_cases.json
~~~

| 사례 | 기대 결과 |
|---|---|
| 언어가 다른 표시 메시지 | XML 필드와 SIEM 행이 일치해 통과합니다. |
| 구성 갱신만 확인 | 일치하는 로컬 프로세스 카나리가 없습니다. |
| 전달 공백 | 로컬 XML은 일치하지만 수집기에 해당 이벤트가 없습니다. |
| 인덱싱에서 필드 누락 | SIEM 프로세스 식별자는 일치하지만 명령줄 표식이 없습니다. |
| 공급자별 ID 중복 | 다른 공급자가 발행한 Event ID 1을 제외합니다. |
| 시간 범위를 벗어난 기록 | 식별자가 같아도 기간 밖의 SIEM 이벤트를 제외합니다. |

여섯 사례가 모두 예상과 일치해야 합니다. 실패 경로를 보려면 JSON을 복사하고 첫 사례의 SIEM `command_line`을 빈 문자열로 바꾸세요. 첫 비교가 실패하고 종료 코드는 1이어야 합니다. 비교를 시작하지 못하면 파일 이름, JSON 문법, XML 네임스페이스를 확인하세요. 오프라인 스크립트는 실행했고 PowerShell과 실제 전환 절차는 Microsoft 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **센서가 정상인데 메시지 문자열을 찾는 룰이 왜 깨질 수 있나요?** 표시 언어만 바뀌고 이름 있는 XML 필드 값은 유지될 수 있습니다. 원본 XML과 파서를 비교하세요.
- **ID 4와 16으로 Event ID 1 수집을 입증할 수 있나요?** 두 기록은 서비스 상태와 설정 갱신을 보여줍니다. 실제 정책에서 어떤 측정값이 나오는지는 로컬 카나리로 확인하세요.
- **카나리 한 건이 통과하면 모든 호스트의 전환이 끝났나요?** 한 이벤트의 한 경로를 검증한 것입니다. 필요한 이벤트 유형, 빌드, 호스트 역할, 언어, 전달 경로별로 검증합니다.

각 사례에서 처음 확인되지 않은 단계를 찾고, 일부러 비교 실패를 재현하고, 특정 이벤트와 전달 경로를 승인할 때 필요한 증거를 설명하면 실습을 완료한 것입니다.

## 공식 참고자료

**2026-11-27** 검토. Microsoft의 2026년 Windows Sysmon 안내, Sysinternals 릴리스 문서, Microsoft PowerShell 참조 기준입니다. 실행 전 Windows 빌드, 업데이트 상태와 설치 형식을 확인하세요.

- [Microsoft Learn · 내장형 Sysmon, 업데이트, 표시 언어](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview)
- [Microsoft Learn · 내장형 Sysmon 구성](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)
- [Microsoft Learn · 내장형 Sysmon 이벤트](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Sysinternals · 독립 설치형 Sysmon과 이벤트 ID](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- PowerShell · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent), [Get-WindowsOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/dism/get-windowsoptionalfeature).
