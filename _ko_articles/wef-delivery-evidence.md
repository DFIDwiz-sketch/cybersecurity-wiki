---
title: "Windows 이벤트 전달(WEF) · 엔드포인트부터 SIEM까지 확인하기"
description: "가상 사례 10건으로 이벤트 생성, 구독 선택, 수집기 도착, SIEM 가시성의 차이를 확인합니다."
category: blue-team
tags: [Windows Security, Windows Logs, WEF, SIEM, Blue Team, Detection Engineering, DFIR]
level: Beginner
updated: "2026-11-20"
translation_url: /wiki/wef-delivery-evidence/
---

**학습 목표.** Windows 이벤트 한 건이 어느 단계까지 확인됐는지 설명합니다. 각 단계의 기록으로 무엇을 판단할 수 있는지와 추가 확인이 필요한 지점을 구분합니다.

## 1. 무엇을 어디로 보내나요?

Windows 이벤트 **공급자(provider)**는 활동을 기록하는 구성 요소입니다. **채널**은 이벤트가 쌓이는 이름 있는 로그입니다. Application, Security, 제품의 Operational 채널 등이 있습니다. **Windows 이벤트 전달(WEF)**은 이미 기록된 이벤트를 골라 **Windows 이벤트 수집기(WEC)**가 실행되는 시스템으로 보냅니다. **구독**에는 어떤 장치가 참여하는지, 어떤 이벤트를 선택하는지, 어떻게 어떤 채널로 전달하는지가 정해져 있습니다. **SIEM**은 별도의 입력으로 WEC의 로그를 가져갈 수 있습니다. 이 입력에도 권한, 마지막 읽기 위치, 파싱 방식이 있습니다.

**원본 시작 구독**에서는 허용된 장치가 보통 그룹 정책을 통해 수집기에 접속하도록 설정됩니다. **수집기 시작 구독**에서는 수집기가 원본 장치 목록을 정의합니다. 두 방식 모두 원본 이벤트가 기록되어 있어야 하고, 읽기 권한과 구독의 선택·전달 경로가 정상이어야 합니다. 이벤트 생성과 감사 설정은 엔드포인트 또는 해당 제품이 담당합니다.

## 2. 정상 시험 이벤트 한 건을 따라가세요

![원본 채널에 이벤트가 기록되고 WEF 구독이 선택합니다. WEC가 지정 채널에 기록하면 SIEM이 이벤트를 파싱하고 저장합니다. 단계마다 확인할 증거가 다릅니다.]({{ '/assets/diagrams/wef-delivery-flow-ko.svg' | relative_url }})

가상 시험에서 10:00 UTC에 `lab-ws01.example.test`가 Application 채널에 이벤트 ID 970과 고유한 표식 `wiki-wef-w01`을 남깁니다. 시험 구독에는 해당 공급자와 채널이 포함됩니다. 수집기에는 10:01에 전달본이 도착하고 10:01:15에 SIEM에서 검색됩니다. 이 세 시각은 용도가 다릅니다. SIEM에 나중에 들어와도 원본 발생 시각은 10:00입니다.

| 단계 | 확인할 기록 | 해석할 때 주의할 점 |
| --- | --- | --- |
| 엔드포인트 | 원본 이벤트, 장치, 공급자, 채널, 이벤트 ID, 발생 시각과 표식 | 원본이 생성되지 않았거나 보존 기간이 지나면 전달할 수 없음 |
| WEF 구독 | 참여 대상, 활성 여부, 선택 쿼리, 기존 이벤트 읽기, 실행 상태와 일정 | 하트비트는 통신 상태를 보여 줌. 특정 이벤트의 선택·도착은 따로 확인 |
| WEC | 설정된 대상 채널의 전달본. 일반적인 예는 `ForwardedEvents` | 원본 XML을 보고 발생 장치와 수집기 이름을 구분 |
| SIEM | 예상 입력·인덱스·시간 범위에서 찾은 원본 필드 | 정규화 과정에서 값이 바뀔 수 있음. 수집기 사본과 대조 |

연결이 돌아오면 WEF는 **북마크**라는 마지막 처리 위치부터 전달을 이어갑니다. 장치가 오프라인인 동안 원본이 덮어써졌다면 북마크로 되살릴 수 없습니다. 설정에 표시된 로그 크기와 실제로 남은 시간 범위를 모두 확인하세요. 기본 구독은 원본 장치가 구독을 받은 뒤에 생성된 이벤트를 전달합니다. **기존 이벤트 읽기(Read existing events)**를 설정하면 아직 남아 있고 구독 쿼리와 일치하는 이전 이벤트도 수집할 수 있습니다. 과거 공백을 판단할 때 해당 설정을 확인하세요. 묶음 전달과 하트비트 주기는 구독마다 다르므로 방금 만든 표식이 정상적으로 대기 중일 수 있습니다.

## 3. 읽기 전용 점검으로 공백을 좁히세요

1. **원본부터 확인합니다.** 공급자가 예상 채널에 기록했는지 봅니다. 감사 정책이나 제품 설정, 시간 범위, 읽기 권한과 실제 보존 구간을 확인합니다. 이벤트 ID만으로는 종류를 확정할 수 없으므로 발생 장치·채널·공급자를 묶어 검색합니다.
2. **구독을 확인합니다.** WEC가 동작 중이고 읽기 권한이 있는 승인된 수집기에서 다음을 실행할 수 있습니다. 실제 구독 ID와 원본 장치 이름으로 바꾸세요. `gs`는 설정, `gr`은 실행 상태를 조회합니다.
   
   ```powershell
   wecutil gs "Wiki-WEF-Lab"
   wecutil gr "Wiki-WEF-Lab" "lab-ws01.example.test"
   ```
   
   선택 쿼리, 대상 장치, 전달 채널, 기존 이벤트 읽기와 전달 설정을 비교합니다. 엔드포인트의 `Microsoft-Windows-Eventlog-ForwardingPlugin/Operational` 채널에서 연결·구독 진단을 볼 수 있습니다. Microsoft의 원본 시작 구독 예시에서 104는 구독 관리자 연결 성공, 100은 구독 생성 성공을 나타냅니다. 채널·공급자·메시지를 함께 확인하세요. 개별 원본 이벤트의 전달 여부는 대상 채널에서 따로 봅니다. 인증, 연결과 채널 읽기 권한은 승인 절차에 따라 확인합니다.
3. **WEC와 SIEM 입력을 따로 봅니다.** 수집기의 실제 대상 채널을 조회합니다. WEC에 표식이 있고 SIEM에 없으면 후속 입력기, 경로, 읽기 위치, 시간 매핑, 인덱스 권한과 보존을 확인합니다. SIEM의 `host`가 수집기 이름이라면 원본 XML의 `System/Computer`를 보존한 필드를 찾아 구분합니다.
4. **중복을 대조하고 증거로 대응합니다.** 이 실습에서는 고유 표식과 장치·채널·이벤트 ID를 함께 비교합니다. 실제 내보내기에서는 공급자, 원본 이벤트 시각과 관측된 레코드 번호도 보존하세요. 중복을 제거하기 전에 원본을 대조합니다. `EventRecordID`는 기록할 때 부여된 번호입니다. 값 하나만으로 다른 장치·채널·로그 생애에 걸쳐 동일 이벤트를 알아낼 수 없습니다.

**오용 가능성과 대응.** 감사나 구독 설정이 바뀌거나 전달이 중단되거나 보존 기록이 사라지면 가시성이 낮아질 수 있습니다. 정상 재연결, 승인된 구독 편집, 파서 변경도 공백의 원인이 될 수 있습니다. 기준 설정과 변경 이력을 대조하고 원본 보존과 구독 상태를 확인합니다. 원본과 수집기 기록을 접근이 제한된 곳에 보존하세요. 수집 공백이 확인되면 승인된 다른 증거를 확보하고 영향받은 장치와 시각을 기록합니다. 복구는 같은 경로에 새 정상 표식을 기록한 뒤 단계별로 확인합니다. 하트비트만으로 복구를 확정하지 않습니다.

## 4. 오프라인 실습 · 전달 사례 10건

[가상 전달 기록]({{ '/assets/labs/wef-delivery-cases.json' | relative_url }})과 [Python 검토기]({{ '/assets/labs/wef-delivery-review.py' | relative_url }})를 한 폴더에 저장하고 Python 3로 실행합니다.

```sh
python3 wef-delivery-review.py
```

자료에는 2030년의 가상 시각과 세 단계의 정규화된 값이 있습니다. 실제 EVTX나 Windows 이벤트 XML은 포함하지 않습니다. 수집 범위, 필터, 상태와 전달 기한은 조사자가 별도로 검증해야 할 사실을 실습용으로 요약했습니다. 검토기는 우선순위에 따라 사례별로 한 가지 판단을 출력하고 시스템에는 접속하지 않습니다.

| 사례 | 기대 결과 | 근거 |
| --- | --- | --- |
| W01 | 전체 경로 확인 | 같은 범위의 표식이 세 단계에 있음 |
| W02 | 원본에서 일치 항목 없음 | 원본을 볼 수 있는 범위에서 검색했으나 일치 없음 |
| W03 | 구독 선택에서 제외 | 원본은 있으나 확인된 필터와 불일치 |
| W04 | 전달 시간 범위가 열려 있음 | 원본은 있고 합의한 대기 시간이 지나지 않음 |
| W05 | 원본 수집 범위 공백 | 해당 시간의 기록이 원본에서 덮어써짐 |
| W06 | 실행 상태 오류 | 원본은 있고 구독이 전달 경로 오류를 보고 |
| W07 | SIEM 도착 미확인 | WEC에는 있으나 SIEM에서 발견하지 못함 |
| W08 | 인덱스 메타데이터 불일치 | SIEM 행에서 수집기가 발생 호스트로 바뀜 |
| W09 | 인덱스 중복 행 | 같은 범위의 표식에 두 행이 일치 |
| W10 | 수집기 도착 미확인 | 활성 상태지만 전달 기한이 지나도 해당 이벤트를 못 찾음 |

예상 마지막 줄은 `Reviewed: 10`입니다. 파일 오류가 나면 이름, 폴더와 JSON 문법을 확인합니다. W08이 일치로 판정됐다면 발생 호스트 값을 대조하세요. W09를 실제 조사에서 만나면 시간과 입력 경로도 봅니다. 관측 행이 둘이라고 해서 원본 이벤트가 둘이었다는 뜻은 아닙니다.

### 승인된 Windows 환경에서 선택 점검

격리된 시험 장치와 승인된 실습 구독을 사용하세요. 구독에 Application의 `Wiki-WEF-Lab` 공급자, 이벤트 ID 970, 정보 수준 이벤트가 포함돼 있어야 합니다. 승인된 관리자가 아래처럼 새로운 고유 설명으로 로컬 표식 한 건을 기록할 수 있습니다.

```powershell
eventcreate /l APPLICATION /so Wiki-WEF-Lab /t INFORMATION /id 970 /d "wiki-wef-test-unique-01"
```

이벤트 뷰어나 엔드포인트의 읽기 권한이 있는 PowerShell에서 원본을 찾습니다. 표식을 본인 실습 값으로 바꾸고 시험이 시작된 때를 포함하는 조회 범위를 사용하세요.

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Application'
  ProviderName = 'Wiki-WEF-Lab'
  Id = 970
  StartTime = (Get-Date).AddMinutes(-30)
} | Where-Object { $_.ToXml() -like '*wiki-wef-test-unique-01*' } |
  Select-Object TimeCreated, MachineName, ProviderName, Id, RecordId
```

WEC에서는 구독에 지정된 대상 채널에서 원본 XML 필드를 비교한 뒤 승인된 SIEM 입력에서도 같은 표식을 찾으세요. 관측할 수 있다면 도착 지연도 기록합니다. 결과가 없으면 원본부터 위 단계대로 진행하세요. 이 표식은 선택한 Application 경로를 시험합니다. Security나 Sysmon 이벤트의 생성과 전달은 해당 채널에서 따로 검증해야 합니다. 다운로드 실습은 클라우드에서 실행했습니다. 실제 Windows 명령과 WEF 동작은 Microsoft 문서로 검토했으며 Windows 배포 환경에서 실행하지 않았습니다.

## 5. 확인 문제와 완료 기준

1. **원본 장치가 활성인데 WEC에 표식이 없습니다. 정상 경로인가요?** 활성은 실행 상태입니다. 필터와 대기 시간을 확인하고, 그 표식이 WEC에 도착했는지 확인합니다.
2. **기존 이벤트 읽기로 덮어쓴 원본을 복구할 수 있나요?** 원본에 아직 남은 범위의 기록만 읽을 수 있습니다.
3. **W07과 W08의 차이는 무엇인가요?** W07은 SIEM에서 기록을 찾지 못했습니다. W08은 기록이 있지만 정규화된 발생 호스트가 다릅니다.
4. **이벤트 ID 970만으로 시험이 실행됐음을 알 수 있나요?** 공급자·채널·발생 장치·시각·고유 표식을 함께 확인합니다.

W04·W05·W08·W10을 분류하고 마지막으로 확인된 단계와 남은 의문을 해소할 증거를 적으면 완료입니다.

[이전 · Windows 이벤트 로그]({{ '/ko/wiki/windows-logs/' | relative_url }}) · [다음 학습 · 탐지 검증]({{ '/ko/wiki/detection-validation/' | relative_url }}) · [관련 · Sysmon 조사]({{ '/ko/wiki/sysmon-investigation/' | relative_url }})

## 공식 참고자료

2026년 11월 20일 검토했습니다. 시험 절차를 적용할 때는 설치된 Windows 버전과 구독·감사 정책을 확인하세요.

- 2025년 8월에 갱신된 Microsoft WEF 설명. 구독, 북마크, 하트비트와 로그 덮어쓰기. [침입 탐지에 WEF 사용](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- Windows 이벤트 수집기 구독 방식과 Win32 이벤트 스키마. [원본 시작 구독](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription) · [발생 장치 스키마](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-computer-systempropertiestype-element) · [EventRecordID 스키마](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventrecordid-systempropertiestype-element)
- Windows 11·Server 2025 등을 대상으로 한 명령 참조와 PowerShell 7.6 문서. [wecutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wecutil) · [eventcreate](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/eventcreate) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.6)
