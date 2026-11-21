---
title: "Windows 보안 로그 공백 · 지우기, 보존, 전달 구분하기"
description: "원본 이벤트와 오프라인 사례 아홉 건으로 로그 지우기, 용량 초과, 감사 정책 변경, 전달 공백을 구분합니다."
category: dfir
tags: [Windows, Event Logs, Windows Event Forwarding, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/windows-log-continuity/
---

**학습 목표.** Windows 보안 로그가 한동안 비어 있을 때 어느 단계부터 증거가 보이지 않는지 확인합니다. 로그 지우기, 오래된 기록의 덮어쓰기, 감사 범위 변경, 전달 문제 가운데 무엇이 증거로 뒷받침되는지 설명할 수 있습니다. 채널이 낯설다면 [Windows 보안 이벤트 분석 입문]({{ '/ko/wiki/windows-logs/' | relative_url }})부터 살펴보세요.

## 1. 이벤트가 검색되기까지 거치는 네 단계

**공급자(provider)**는 이벤트를 발행하는 구성 요소입니다. Windows는 레코드를 Security나 System 같은 **채널**에 기록합니다. **감사 정책**은 여러 보안 이벤트 유형이 어떤 조건에서 생성되는지 결정합니다. **EVTX**는 이벤트 로그 파일입니다. 현재 파일에는 호스트의 최근 기록만 남아 있을 수 있습니다. **Windows 이벤트 전달(WEF)**은 선택한 원본 이벤트를 **Windows 이벤트 수집기(WEC)**로 보냅니다. 이후 **SIEM**이 이를 수집하고 검색할 수 있도록 색인할 수 있습니다.

`EventID`는 해당 공급자의 이벤트 유형을 식별합니다. `EventRecordID`는 기록할 때 붙는 레코드 번호입니다. 같은 원본 채널과 로그 수명 안에서 쓸 수 있으며, 호스트·채널·아카이브·수집기의 가공 데이터가 하나의 번호 체계를 공유하지는 않습니다. 필터링한 스트림에서는 번호가 건너뛸 수 있습니다. `TimeCreated/@SystemTime`은 원본 이벤트의 시각입니다. 도착이나 색인 시각은 따로 보존하세요.

<figure style="margin-inline:0">
  <img src="{{ '/assets/diagrams/windows-log-continuity-ko.svg' | relative_url }}" width="400" height="396" alt="이벤트는 생성된 뒤 원본 채널이나 아카이브에 보존됩니다. 전달 대상이면 수집기에 도착하고, SIEM에 색인되어 검색됩니다.">
  <figcaption>그림 1. 기대한 증거가 가장 먼저 사라진 단계를 찾아보세요. 앞 단계에 남은 사본은 보존합니다.</figcaption>
</figure>

## 2. 이벤트의 의미와 보존 모드 비교

| 증거 | 문서에 정의된 의미 | 다음에 확인할 것 |
| --- | --- | --- |
| Security 1102 · `Microsoft-Windows-Eventlog` | 보안 감사 로그가 지워짐 | 기록된 주체, 세션, 변경 이력, 별도로 보존된 증거 |
| System 104 · `Microsoft-Windows-Eventlog` | 이벤트 로그 하나가 지워짐. 페이로드에서 대상 로그를 확인 | 대상이 Application이면 Security를 지웠는지 알 수 없음 |
| Security 1104 · `Microsoft-Windows-Eventlog` | 보안 로그 용량이 가득 참 | 실제 적용 중인 보존 모드, 디스크 공간, 기록 범위, 뒤이어 기록된 이벤트 |
| Security 1105 · `Microsoft-Windows-Eventlog` | 보안 로그가 가득 차 자동 백업 과정에서 새 로그 파일이 만들어짐 | 아카이브 위치와 기록 범위, 보존 성공 여부 |
| Security 1100 · `Microsoft-Windows-Eventlog` | 이벤트 로그 서비스가 종료됨. 정상 시스템 종료도 포함 | 재부팅·유지보수 기록과 이후 수집 상태 |
| Security 4719 · `Microsoft-Windows-Security-Auditing` | 시스템 감사 정책이 변경됨 | 하위 범주의 GUID와 변경 값, 실제 적용 정책, 적용 시각, 승인 내역 |

Microsoft는 1100, 1102, 1104, 1105를 자동 생성 이벤트로 분류합니다. 4719는 감사 정책 변경 하위 범주 설정과 관계없이 생성된다고 문서에 명시되어 있습니다. 그래도 사건을 조사할 때 보려면 채널이 동작하고 충분히 보존되어야 하며, 중앙에서 찾으려면 전달도 정상이어야 합니다. 공백 전후에 기대하는 일반 이벤트는 조건이 다를 수 있습니다. 4624는 성공한 로그온 감사가, 4688은 프로세스 생성 감사가 적용되어야 합니다.

| 로그 모드 | 용량 한도에 도달했을 때 | 조사에서 보이는 현상 |
| --- | --- | --- |
| Circular | 새 이벤트를 저장하며 오래된 레코드를 덮어씀 | 평상시에도 가장 오래된 레코드가 최근 쪽으로 이동 |
| AutoBackup | 가득 찬 로그를 아카이브하고 새 활성 파일을 만듦 | 활성 파일에 없는 항목이 별도 아카이브에 있을 수 있음 |
| Retain | 기존 레코드를 자동으로 덮어쓰지 않음 | 가득 차면 새 기록이 더 이상 들어오지 않을 수 있으므로 용량과 공백을 조사 |

최대 용량은 바이트로 설정합니다. 실제로 보존되는 기간은 가장 오래된 이벤트와 최근 이벤트의 시각, 세그먼트 이력과 기록 발생량을 바탕으로 추정하세요. 지금의 설정과 가장 오래된 레코드 번호는 현재 상태를 보여 줍니다. 과거 설정이나 공백 원인은 다른 증거로 확인합니다.

## 3. 승인된 유지보수 사례를 따라 읽기

가상 사례 W01에서 수집기는 07:00 UTC에 `LAB-WIN-01`에서 생성한 1102를 보존했습니다. 원본 XML에서는 채널 Security와 공급자 `Microsoft-Windows-Eventlog`를 확인할 수 있습니다. 주체 정보는 `UserData/LogFileCleared`에 들어 있으며 `SubjectUserSid`, `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`가 포함됩니다. 파서가 `EventData`만 읽으면 이 값을 놓칠 수 있습니다. 실습 파일에는 이 페이로드에서 가져온 것으로 가정한 주체와 로그온 ID만 담았습니다.

1. 원본 `System/Computer`, 채널, 공급자, `TimeCreated`, 레코드 정보와 주체를 확보합니다. 수집기 도착 시각이 있다면 따로 기록하세요.
2. `SubjectLogonId=0x124a`를 **같은 호스트와 부팅 맥락**의 4624에서 새 세션의 `TargetLogonId`와 대조합니다. 시각과 SID도 일치하는지 봅니다. 4624가 없으면 보존 기한이 지났거나 수집 범위에서 빠졌을 수 있습니다. 세션을 확인한 뒤에도 실제 사용 주체와 의도는 다른 증거로 검증해야 합니다.
3. 실습에는 확인한 변경 승인 시간대와 별도로 확보한 이전 아카이브가 주어집니다. 실제로는 티켓, 작업 주체, 아카이브 내용으로 확인합니다. 이 경우 로그 지우기가 관측됐고 유지보수라는 설명을 뒷받침하는 증거가 있습니다. 이전 아카이브도 기록 범위와 무결성을 확인하세요.

W02도 1102가 남아 있지만 승인 내역이 확인되지 않았습니다. **지우기 관측, 원인 미확인**으로 기록하고 조사합니다. W03에는 지우기 이벤트가 관측되지 않았습니다. 현재 Circular 로그에서 가장 오래된 번호는 45211이고 이전에 본 45021은 같은 활성 로그 수명에 속합니다. 이는 활성 로그 보존 범위에서 제외됐다는 판단을 뒷받침합니다. 이전 레코드의 사본이 모두 사라졌는지는 알 수 없습니다.

## 4. 원본을 바꾸지 않고 수집하고 판단하기

호스트, 시간 범위, 기대하는 채널을 정한 뒤 승인된 원본 EVTX 내보낸 파일과 아카이브, 따로 보존된 수집기·SIEM 사본을 확보합니다. 파일 시각과 해시를 기록하고 조사에는 복사본을 씁니다. 원본의 시계 오차와 수집 UTC 시각, 이벤트 번호, 공급자, 채널, 원본 컴퓨터, 레코드 번호, 수집 경로를 보존합니다. 실제 구독의 필터와 전달 시간을 예상한 이벤트에 대조하세요. 전달된 이벤트는 원본 필드를 보존할 수 있지만 SIEM의 `host`에는 수집기 이름이 들어갈 수 있습니다.

아래 명령은 **승인된 Windows 호스트**에서 Security 채널과 감사 정책 조회 권한이 있는 PowerShell 세션을 전제로 합니다. 현재 로그와 정책을 조회하며 내보내거나 수정하지 않습니다. 사건에 맞게 시간 범위를 조정하세요. 결과가 비어 있으면 보존 구간, 권한, 오류, 검색 범위를 확인하고 다른 소스와 비교합니다. 페이로드 보존에는 원시 XML 또는 승인된 별도 증거 내보내기를 사용하세요.

```powershell
$since = (Get-Date).AddHours(-24)
Get-WinEvent -ListLog Security |
  Select-Object LogName, LogMode, MaximumSizeInBytes, IsLogFull, OldestRecordNumber, RecordCount
Get-WinEvent -LogName Security -Oldest -MaxEvents 1 |
  Select-Object TimeCreated, RecordId, MachineName, LogName
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  Id = 1100, 1102, 1104, 1105, 4719
  StartTime = $since
} | Select-Object TimeCreated, MachineName, LogName, ProviderName, Id, RecordId
auditpol /get /category:*
```

| 관측 | 비교할 증거 | 대응 |
| --- | --- | --- |
| 예상 밖 1102 | 주체, 같은 호스트의 세션, 작업 승인, 엔드포인트 기록, 별도 사본 | 영향받은 구간을 보존하고 호스트·계정 범위를 좁힘. 추가 근거를 확인해 격리 여부 조율 |
| 로그 가득 참 또는 덮어쓰기 | 실제 보존 모드, 가장 오래된 이벤트, 이벤트 발생량, 아카이브, 저장 상태 | 로그 소유자와 수집 범위를 복구하고 새 정상 이벤트로 저장과 전달을 검증 |
| 선택된 이벤트가 원본에는 있으나 예상 지연을 넘겨도 WEC에 없음 | 구독 실행 상태, 연결, 실제 수신 채널, 원본 보존 상태 | 해당 전달 구간부터 조사. WEC에 있으면 SIEM 수집 단계를 별도로 확인 |
| 수집 범위가 달라질 때 4719 관측 | 변경된 하위 범주와 값, 그룹 정책 적용 기록과 기준 설정 | 필요한 이벤트가 생성됐을 조건인지 판단. 실제 적용 설정을 확인하고 정상 수집으로 복구됐는지 검증 |

관리 권한을 가진 주체는 보존된 증거를 없애거나 앞으로 생성되는 이벤트를 줄여 가시성을 떨어뜨릴 수 있습니다. 정상 재부팅, 승인된 감사 변경, 용량 초과, 수집기 장애도 한 소스에서는 비슷하게 보입니다. 결론을 내기 전에 출처를 대조하세요. WEF는 원본 로그를 버퍼로 사용합니다. 연결이 끊긴 동안 원본이 덮어써도 수집기에 별도의 통지가 없을 수 있습니다. 하트비트, 레코드 번호의 점프, 또는 1102 부재만으로 원인을 확정할 수 없습니다. 전달 쪽은 [WEF 전달 증거]({{ '/ko/wiki/wef-delivery-evidence/' | relative_url }})에서 이어서 다룹니다.

## 5. 오프라인 실습 · 증거 조합 아홉 가지

<a href="{{ '/assets/labs/windows-log-continuity-cases.json' | relative_url }}" download="windows-log-continuity-cases.json">가상 사례 자료</a>와 <a href="{{ '/assets/labs/windows-log-continuity-review.py' | relative_url }}" download="windows-log-continuity-review.py">Python 분석 스크립트</a>를 같은 디렉터리에 저장하세요. 소유한 컴퓨터나 샌드박스에서 Python 3.10 이상으로 실행합니다. 스크립트는 필요한 필드만 추린 로컬 JSON을 읽습니다. Windows나 수집기가 필요 없고 호스트에 접속하거나 로그 지우기 이벤트를 생성하지 않습니다. 이벤트 밖의 값은 별도 증거로 확인했다고 가정한 사실입니다.

```sh
python3 windows-log-continuity-review.py windows-log-continuity-cases.json --check
```

| 사례 | 예상 결론 |
| --- | --- |
| W01 | Security 로그 지우기 관측. 유지보수라는 설명을 뒷받침하는 증거가 있음 |
| W02 | Security 로그 지우기 관측. 원인은 미확인 |
| W03 | 같은 활성 로그 수명에서 Circular 보존 범위를 벗어났다는 근거가 있음 |
| W04 | 선택 대상 이벤트가 원본에 남아 있음. 예상 지연 시간이 지난 후 전달 구간 점검 |
| W05 | Retain 모드의 보안 로그가 가득 참. 빠진 기록의 범위를 확인 |
| W06 | 감사 정책 변경 관측. 제공된 자료에는 지우기 이벤트가 없음 |
| W07 | System 104의 대상은 Application. 가까운 시각의 1102는 다른 호스트의 기록 |
| W08 | AutoBackup 증거가 있음. 아카이브의 위치와 기록 범위를 검증 |
| W09 | 이벤트 로그 서비스 종료가 확인된 재부팅과 일치 |

2026-11-21에 Python 3.12.14로 실행해 `9/9 synthetic cases matched.`를 확인했습니다. Windows 명령, 이벤트 스키마와 WEF 동작은 공식 문서로 확인했습니다. 실제 Windows 호스트에서 재현하지 않았습니다. 실습이 실패하면 파일명과 디렉터리, Python 버전을 확인하고, 수정한 자료는 원본으로 되돌리거나 다시 내려받으세요. 실제 수집을 검증할 때는 본인 소유의 테스트 호스트에서 적용 감사 정책을 확인하고 승인된 정상 이벤트 하나가 각 단계에서 보이는지 확인합니다.

## 6. 확인 문제와 완료 기준

1. **SIEM에 4624의 레코드 번호 20과 27이 있습니다. Security가 지워졌나요?** 구독이 일부 유형만 선택하면 번호가 건너뛸 수 있습니다. 원본의 기록 범위와 구독 필터, 1102 여부를 함께 확인하세요.
2. **1102로 행동한 사람과 의도까지 알 수 있나요?** 해당 동작에 연결된 보안 주체를 남깁니다. 같은 호스트의 세션, 원본 증거와 승인 기록을 대조해 누가 어떤 이유로 작업했는지 확인합니다.
3. **선택된 대조 이벤트가 원본에 있지만 예상 지연을 넘겨도 WEC에서 보이지 않습니다. 어디를 먼저 보나요?** 원본과 수집기 사이의 구독 상태, 수신 채널, 지연을 조사합니다. 먼저 원본 사본을 확보하세요.
4. **4688이 사라졌을 때 4719를 찾으면 무엇을 더 알 수 있나요?** 이벤트 생성 범위가 바뀌었을 가능성을 설명할 수 있습니다. 적용된 변경이 프로세스 생성 성공 감사를 바꿨는지, 보존과 전달도 정상인지 확인하세요.

아홉 사례를 재현하고 각 사례에서 공백이 처음 확인되는 단계를 설명하며, 악성 여부 판단에 필요한 독립 증거를 하나씩 고를 수 있으면 이 장을 마친 것입니다. [WEF 전달 증거]({{ '/ko/wiki/wef-delivery-evidence/' | relative_url }})와 [증거 보존]({{ '/ko/wiki/evidence-preservation/' | relative_url }})으로 이어서 학습하세요.

## 공식 참고자료

검토일은 2026-11-21입니다. 이벤트 스키마는 Windows 10 시기의 감사 문서를 바탕으로 하며, 운영에 적용할 때는 관리 중인 Windows 버전에서 공급자, 채널, 동작을 확인하세요.

- Microsoft Learn [1100](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1100), [1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102), [1104](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1104), [1105](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1105). 2021년 감사 이벤트 문서.
- Microsoft Learn [4719](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719), [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624). 감사 변경 및 로그온 스키마.
- [Windows 이벤트 전달](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection). Windows 호스트와 수집기 동작, System 104, 원본 덮어쓰기.
- [EventRecordID](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-eventrecordid-systempropertiestype-element)와 [.NET Framework EventLogMode](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogmode?view=netframework-4.8.1). 레코드 스키마와 보존 모드.
- Windows PowerShell 5.1 [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-5.1)와 지원 Windows 클라이언트·서버의 [auditpol get](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get).
