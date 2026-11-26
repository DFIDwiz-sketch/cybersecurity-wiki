---
title: "Microsoft Defender Antivirus · 탐지와 조치 결과 확인하기"
description: "Windows Defender Operational 로그에서 탐지와 조치를 연결하고 리소스 조치 결과와 사고 종결을 구분합니다."
category: blue-team
tags: [Microsoft Defender, Windows, Event Logs, Incident Response, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/windows-defender-remediation-evidence/
---

Windows 워크스테이션에서 파일 하나를 탐지했다는 Microsoft Defender Antivirus 이벤트가 수집기에 도착했습니다. 먼저 제품이 무엇을 탐지했는지 확인합니다. 그다음 해당 파일에 어떤 조치가 이뤄졌는지, 기기 전체에 추가 조사가 필요한지 판단합니다. 질문을 나눠 놓으면 상태값 하나만 보고 사고를 일찍 종결하는 일을 줄일 수 있습니다.

## 1. 탐지에서 조치까지 따라가기

**탐지**는 파일이나 스크립트 같은 리소스에 대한 제품의 판정입니다. **조치**는 제품이 해당 리소스에 적용했다고 보고한 작업으로, 격리나 차단 등이 있습니다. 이 장에서 **위협 처리**는 해당 리소스를 치료·격리·제거했다고 보고한 조치를 가리킵니다. 성공 여부와 후속 작업은 따로 확인합니다. 격리는 리소스에 대한 접근을 제한하고, 제거는 리소스를 삭제합니다. 기기의 네트워크 통신 등을 제한해 추가 피해를 막는 **봉쇄**는 별도의 대응 결정입니다.

이 장의 Windows Antivirus 이벤트는 **Microsoft-Windows-Windows Defender/Operational** 채널에서 확인합니다. **Threat ID**는 위협 분류를 가리키며 여러 탐지에서 반복될 수 있습니다. 원본 이벤트에 개별 탐지 식별자인 **Detection ID**가 있으면 안정적인 기기 식별자와 함께 보존합니다. 리소스와 시각은 이를 뒷받침하는 자료로 남깁니다. 이벤트 레코드 ID는 원본 채널의 해당 로그 세대에서 한 행을 가리킵니다. 원본 추적에는 유용하지만 탐지와 조치를 연결하는 식별자로 쓰기에는 적합하지 않습니다.

| Defender Operational 이벤트 | 확인할 질문 | 함께 읽을 정보 |
| --- | --- | --- |
| 1116 | 제품이 무엇을 탐지했나요? | 리소스, 탐지 출처, 제품 및 보안 인텔리전스 버전, 확인 가능한 식별자 |
| 1117 | 제품이 어떤 조치를 기록했나요? | 조치, 상태 또는 오류 필드, 필요한 후속 작업 |
| 1118 | 조치 중 비치명적 오류가 발생했나요? | 시도한 조치와 오류. 동일 탐지의 후속 결과가 있는지 확인합니다 |
| 1119 | 조치 중 치명적 오류가 발생했나요? | 시도한 조치와 오류. 담당자에게 알리고 기기의 다른 증거를 검토합니다 |

조치 필드를 함께 읽어야 합니다. **Allow(허용)** 또는 **No action(조치 없음)**이면 리소스가 처리됐다는 근거가 없습니다. **Block(차단)**은 시도한 실행이나 작업이 제한됐음을 뜻하며 파일 삭제 여부는 별도로 확인해야 합니다. **Quarantine(격리)**이 성공해도 그 시점의 해당 리소스에 대한 관측입니다. 이전 실행 여부, 다른 복사본, 기기 나머지 부분의 상태는 따로 확인합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-defender-remediation-evidence-ko.svg' | relative_url }}" alt="1116 탐지 이벤트에서 시작해 기기와 개별 탐지를 연결합니다. 1117은 조치와 결과를 읽고, 1118 또는 1119는 조치 시도의 실패를 확인합니다. 조치 기록이 없으면 수집과 조치 상태를 점검합니다. 사고 종결 전에는 기기의 다른 증거도 확인합니다." style="max-width: 100%; height: auto;">
  <figcaption>그림 1. 리소스와 조치 기록을 연결한 뒤 기기 전체의 대응 여부를 판단합니다.</figcaption>
</figure>

## 2. 정상적인 조치 타임라인 읽기

다음은 가상 관측입니다. UTC 10:00:00에 워크스테이션 `LAB-01`이 다운로드 폴더의 파일에 대한 1116 이벤트를 남깁니다. 탐지 식별자는 `D-01`이고 출처는 실시간 보호입니다. 10:00:05에 같은 기기의 동일한 탐지에 대해 1117이 기록되고 `Quarantine`과 성공 결과가 표시됩니다. 전달된 기록은 10:02:13에 수집기에 도착합니다. 사고 순서는 원본 시각과 기기 간 시계 오차를 고려해 판단하고, 수집 시각은 전달 지연을 조사하는 데 씁니다.

보고서에는 “Defender가 탐지된 리소스의 격리 성공을 보고함”이라고 적습니다. 10시 이전에 기기에서 의심스러운 프로세스 활동도 보였다면 해당 환경의 프로세스 생성 기록을 확인합니다. 예를 들어 Security 4688을 보려면 프로세스 생성 감사가 활성화돼 있어야 합니다. Sysmon 이벤트 1은 Sysmon이 설치되어 있고 해당 프로세스를 수집하는 설정이 필요합니다. 기기와 시각을 기준으로 확인 가능한 경로, 해시, 부모·자식 프로세스를 대조합니다. Antivirus 이벤트의 사용자나 프로세스 이름은 검사 당시의 맥락일 수 있으므로 추가 확인의 단서로 사용합니다.

## 3. 오용 가능성과 증거 공백 해석하기

반복되는 경보는 여러 기기의 복사본, 같은 위협으로 분류된 여러 리소스, 재시도된 조치에서 발생할 수 있습니다. 위협 이름이나 Threat ID만으로 합치면 아직 처리되지 않은 탐지에 다른 건의 성공을 잘못 연결할 수 있습니다. 공격자나 승인되지 않은 보호 정책 변경이 관측 범위를 줄일 수도 있지만 로그 로테이션, 전달 지연, 서로 다른 제품 동작 모드도 로그 공백을 만들 수 있습니다. 승인된 변경과 사고 당시의 상태를 확인할 수 있는 자료를 찾습니다. 현재 상태 스냅샷은 수집 시점의 상태를 보여 줍니다.

다운로드 검사나 스크립트 내용 점검 중에 탐지가 일어날 수 있습니다. 연관 프로세스가 보인다고 탐지된 코드가 실행됐다고 판단할 수는 없습니다. 허용 조치도 실제 실행 여부를 설명하지 못합니다. 제품의 판정과 별도로 확인한 동작을 구분해 적습니다. 원본에 Detection ID가 없으면 기기, 리소스, Threat ID, 출처 및 좁힌 원본 시간대를 함께 대조합니다. 후보가 여러 개 남으면 하나를 임의로 연결하지 않고 검토 대상으로 남깁니다.

## 4. 블루팀 수집·탐지·대응

1. **원본 기록을 수집합니다.** 사용 승인을 받았고 채널 읽기 권한이 있는 Windows 기기에서 이벤트 뷰어 또는 아래 읽기 전용 PowerShell을 사용합니다. 최근 4시간은 예시입니다. 사고 구간과 시간대를 기록하세요. 조직의 수집 절차에 따라 원본 EVTX, 이벤트 XML, 수집기 기록을 보존합니다. 외부에 실제 경로나 계정 정보를 게시하지 마세요. Defender 명령에는 Defender 모듈과 로컬 제품 데이터 접근 권한이 필요합니다. 예제는 현재의 동작 모드와 조회 가능한 탐지 이력을 읽습니다.

~~~powershell
$channel = 'Microsoft-Windows-Windows Defender/Operational'
$end = Get-Date
Get-WinEvent -FilterHashtable @{
  LogName = $channel
  Id = 1116, 1117, 1118, 1119
  StartTime = $end.AddHours(-4)
  EndTime = $end
} | ForEach-Object { $_.ToXml() }

Get-MpComputerStatus | Select-Object AMRunningMode
Get-MpThreatDetection
~~~

2. **판단 전에 수집 범위를 확인합니다.** 동작 모드, 채널 보존 범위와 전달 구독, 기기 식별자, 원본 시계, XML 필드 보존 여부를 확인합니다. 제품 빌드별 구조화 필드를 살펴보고 정규화한 행과 원본을 연결해 둡니다. 예상 전달 지연을 고려해 로컬과 중앙 조회 결과를 대조합니다. 1117이 없으면 조치 결과가 미확정입니다. 1117이나 오류 이벤트에 대응하는 탐지가 없으면 수집이나 조회 범위에 탐지 기록이 빠졌을 가능성을 확인합니다.
3. **리소스별 조치 결과를 분류합니다.** 1118·1119, 허용 조치, 정해진 전달 시간 이후에도 조치가 연결되지 않은 탐지를 추적합니다. 동일한 탐지에서 실패와 이후의 성공을 모두 확인했다면 두 기록을 보존합니다. 미해결 실패는 시도한 조치와 오류, 제품이 요구한 후속 작업, 연관 리소스를 확인합니다. 재부팅이 필요한 경우 승인된 절차를 따르고, 연관 행위와 업무 영향을 바탕으로 봉쇄 여부를 판단합니다.
4. **기기 상태는 별도로 검증합니다.** 관련 리소스마다 조치 결과를 보고하고 후속 상태, 실제 실행, 재탐지, 다른 기기의 노출을 조사합니다. 새 탐지나 사후 복원, 조회 구간 바깥의 리소스에 따라 판단이 바뀔 수 있습니다. 수집원 선택은 [Windows 보안 이벤트 조사 입문]({{ '/ko/wiki/windows-logs/' | relative_url }}), 실제 봉쇄 검증은 [엔드포인트 격리 증거]({{ '/ko/wiki/endpoint-isolation-evidence/' | relative_url }})에서 이어서 읽을 수 있습니다.

## 5. 승인된 오프라인 실습

<a href="{{ '/assets/labs/windows-defender-remediation-evidence.py' | relative_url }}" download>Python 분석기</a>와 <a href="{{ '/assets/labs/windows-defender-remediation-evidence.csv' | relative_url }}" download>가상 이벤트 CSV</a>를 같은 폴더에 저장하세요. 본인이 소유하거나 사용 승인을 받은 환경에서 Python 3으로 아래 명령을 실행합니다. 분석기는 실습 파일만 읽습니다. CSV는 학습용 정규화 예시이며 Microsoft 이벤트 스키마와 다릅니다. 타임스탬프는 UTC이고 `reported_success`는 가상 필드입니다. 실제 수집기에서는 해당 제품 버전에서 확인한 조치와 결과 필드로 성공 여부를 판단해야 합니다.

~~~bash
python3 windows-defender-remediation-evidence.py
~~~

| 실습 행 | 기대 결과 |
| --- | --- |
| LAB-01 D-01과 LAB-02 D-01 | LAB-01에만 격리 보고가 연결됩니다. 같은 탐지 ID를 가진 LAB-02는 탐지만 보입니다 |
| LAB-01 D-02와 D-03 | 각각 허용과 차단입니다. 리소스가 처리됐는지는 알 수 없습니다 |
| LAB-01 D-04와 D-05 | D-04는 실패 후 제거 성공입니다. D-05는 치명적 조치 오류입니다 |
| LAB-01 D-06과 D-07 | D-06은 조치 결과 미확정이고, D-07은 연결할 탐지가 없습니다 |
| LAB-01 레코드 120과 LAB-01 D-08 | 앞 사례는 탐지 식별자가 없어 연결할 수 없습니다. D-08은 같은 시각의 모순된 결과를 검토해야 합니다 |

정상적으로 실행하면 결과 열 줄이 나옵니다. 대조 실험에서는 CSV를 복사하고 LAB-01의 격리 행에서만 `D-01`을 `D-X`로 바꾼 뒤 분석기에 복사본의 파일명을 인자로 전달합니다. LAB-01 D-01은 `detection-only`, D-X는 `missing-detection`이 나와야 합니다. 기본 결과가 다르면 파일이 같은 판본인지, 열 이름과 UTC 시간 형식이 유지됐는지 확인하세요. Python 실습은 가상 데이터로 실행했습니다. PowerShell과 제품 동작은 Microsoft 문서로 검토했으며 Windows 기기에서 실행하지 않았습니다.

## 6. 확인 문제와 완료 기준

1. **1117만 보고 위협 처리가 완료됐다고 할 수 없는 이유는 무엇인가요?** 결과는 기록된 조치와 상태에 따라 다릅니다. 허용·차단과 성공이 확인된 격리·제거는 의미가 다릅니다.
2. **한 기기에서 치명적 조치 오류가 났고, 다른 기기에서 같은 Threat ID에 대한 격리를 보고했습니다. 첫 기기의 조치는 끝났나요?** 기기와 개별 탐지마다 결과를 확인해야 합니다. 두 번째 기기의 성공은 첫 번째 기기에 대한 결과를 제공하지 않습니다.
3. **검사 맥락만으로 실행을 확인할 수 있나요?** 프로세스 생성과 실행 계보를 대조하고, 실행 여부를 판단하기 전에 해당 구간의 수집 범위를 명시합니다.

**완료 기준.** 기본 결과와 대조 실험을 재현하고 이벤트를 연결하는 근거를 하나 설명합니다. 리소스의 조치 결과, 실행 여부의 불확실성, 다음에 수집할 자료를 구분해 짧은 사고 기록을 작성합니다.

## 공식 참고자료

검토일 2026-11-26. 지원되는 Windows 기기의 Microsoft Defender Antivirus와 아래 PowerShell 인터페이스의 공식 문서를 확인했습니다. 이 장은 1116–1119 이벤트 계열을 다루며 Microsoft 카탈로그에는 과거 및 추가 계열도 있습니다. 적용 환경의 채널, 동작 모드, 이벤트 필드를 확인하세요.

- [Microsoft Defender Antivirus 이벤트 ID와 오류 코드](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus#event-id-1116)
- [Defender Antivirus 검사 결과 확인](https://learn.microsoft.com/en-us/defender-endpoint/review-scan-results-microsoft-defender-antivirus), [Get-MpThreatDetection 명령](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection)
- [Windows용 Defender Antivirus와 동작 모드](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows), [Get-WinEvent 명령](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [Security 4688과 프로세스 생성 감사](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688), [Sysmon 프로세스 생성](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation)
