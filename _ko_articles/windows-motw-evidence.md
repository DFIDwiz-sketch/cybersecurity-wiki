---
title: "Windows Mark of the Web 조사 · Zone.Identifier 읽기"
description: "NTFS 다운로드 표시, 파일 본문, Sysmon 스트림 생성과 프로세스 증거가 각각 알려 주는 것을 대조합니다."
category: dfir
tags: [Windows Security, NTFS, Mark of the Web, Sysmon, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/windows-motw-evidence/
---

**학습 목표.** 내려받은 파일의 복사본 두 개는 SHA-256이 같지만 한쪽에만 인터넷 영역 표시가 있습니다. 이런 차이가 생기는 이유, Sysmon의 스트림 생성 기록이 더해 주는 증거, 실행 여부를 확인하는 데 필요한 자료를 알아봅니다.

## 1. Windows가 파일에 함께 저장하는 정보

NTFS 파일에는 **데이터 스트림**을 여러 개 저장할 수 있습니다. **이름 없는 스트림**은 앱이 일반적인 방식으로 파일을 읽을 때 얻는 본문입니다. **이름 있는 스트림**은 같은 파일에 별도의 바이트를 붙입니다. 흔히 대체 데이터 스트림(ADS)이라고 부릅니다. Windows와 해당 기능을 쓰는 앱은 **Zone.Identifier**라는 스트림에 보안 영역 정보를 저장할 수 있습니다. 이 형태의 **Mark of the Web(MOTW)**는 Windows와 앱이 파일을 어떻게 처리할지 판단하는 데 쓰일 수 있습니다.

일반적인 스트림은 `[ZoneTransfer]`로 시작합니다. `ZoneId`는 보안 영역을 나타냅니다. Microsoft 문서에서 0은 로컬 컴퓨터, 1은 로컬 인트라넷, 2는 신뢰할 수 있는 사이트, 3은 인터넷, 4는 제한된 사이트입니다. 작성 앱이 `HostUrl`이나 `ReferrerUrl`을 저장했다면 출처 조사에 단서가 될 수 있습니다. 필드가 있는지와 의미는 작성 도구에 따라 달라집니다. 예를 들어 압축을 푼 도구가 참조 위치에 압축 파일 경로를 남길 수 있습니다. 모든 값은 검증이 필요한 메타데이터로 취급하세요. 영역 번호만으로 게시자, 실제 출처, 파일의 안전성을 확인할 수 없습니다.

| 관측 | 답할 수 있는 질문 | 더 필요한 근거 |
| --- | --- | --- |
| 이름 없는 스트림의 SHA-256 | 두 파일 본문의 해시가 같은가? | 영역 메타데이터를 비교하려면 ADS를 따로 읽거나 해시해야 합니다. |
| 읽을 수 있는 Zone.Identifier | 수집한 시점에 어떤 표시가 있었는가? | 작성 프로세스와 독립적인 다운로드·전송 기록이 필요합니다. |
| Sysmon 이벤트 ID 15 | 설정된 센서가 이름 있는 스트림 생성을 관측했는가? | 나중에 수집한 파일과 연결하려면 같은 파일이 유지됐는지 확인합니다. |
| 프로세스 또는 앱 기록 | 관련 이미지가 시작됐거나 특정 작업이 관측됐는가? | 정확한 이미지·문서와의 일치, 이후 동작을 보여 주는 기록을 확인합니다. |
| Office 또는 앱 정책 이벤트 | 특정 제어가 무엇을 평가하고 어떻게 판정했는가? | 실제 앱 버전, 적용 설정과 평가 대상을 확인합니다. |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-motw-evidence-ko.svg' | relative_url }}" alt="NTFS 파일의 본문과 Zone.Identifier는 서로 다른 스트림입니다. Sysmon은 이름 있는 스트림의 생성을 기록할 수 있습니다. 나중에 무엇이 실행되거나 열렸는지는 별도의 프로세스 또는 앱 기록으로 확인합니다." width="480" height="378">
  <figcaption>파일 본문, 영역 표시, 생성 이벤트, 이후 동작은 각각 다른 지점에서 얻는 증거입니다.</figcaption>
</figure>

## 2. 정상 다운로드 한 건 따라가기

가상의 상황에서 브라우저가 NTFS에 `report.txt`를 저장합니다. 브라우저는 `Zone.Identifier`에 `ZoneId=3`과 출처 단서를 기록합니다. Sysmon 수집 범위에 들어 있으면 비슷한 시각에 스트림 생성 이벤트가 남습니다. 조사자가 나중에 복사본 두 개를 수집합니다. A에는 표시가 남았고, 다른 전송 방식을 사용한 B에서는 스트림이 관측되지 않습니다. 이름 없는 스트림의 SHA-256은 두 파일 모두 같습니다. 이는 조사한 본문이 일치한다는 근거입니다. 전송 경로와 수집 방식은 각 복사본에 어떤 표시가 남았는지 설명합니다. 이 상황에는 프로세스 시작을 보여 주는 관측이 없습니다.

파일을 만든 앱, 정책과 저장소가 모두 영향을 줍니다. Microsoft Attachment Manager 정책은 영역 정보가 보존되는 방식에 관여할 수 있습니다. NTFS 방식의 표시는 해당 흐름에서 이름 있는 스트림을 보존할 수 있어야 합니다. Microsoft 문서에 따르면 FAT32는 이 표시를 보존하지 않습니다. 압축 풀기, 동기화, 복사 과정에 따라 목적지에 전달되는 메타데이터가 달라집니다. 실제 도구, 버전, 옵션과 목적지를 확인하세요. 브라우저, 설치 프로그램 또는 압축 해제 도구는 최종 경로에 직접 다운로드하는 경우 외에도 스트림을 기록할 수 있습니다.

Microsoft는 적용 대상 Windows용 Office에서 인터넷 매크로가 기본적으로 차단되는 경우를 설명합니다. 실제 판정은 Office 빌드, 유효 정책, 파일 위치, 신뢰 설정과 대조하세요. Office 문서는 대개 앱을 통해 열립니다. 어떤 문서를 열었는지는 앱 또는 문서 접근 자료로, 이후 실제 동작은 독립된 증거로 확인합니다. Office 프로세스가 시작됐다는 기록만으로 특정 문서가 열렸거나 매크로가 실행됐다고 볼 수 없습니다.

## 3. 표시가 없거나 다른 증거와 모순될 때

| 관측 | 가능한 설명 | 구분할 자료 |
| --- | --- | --- |
| 승인된 파일에 인터넷 표시가 있음 | 정상 다운로드, 예상된 압축 처리 또는 앱이 메타데이터 기록 | 승인된 출처, 검증한 게시자나 산출물 출처 증명, 맞는 다운로드 기록 |
| 수집 시점에 표시가 없음 | 작성 앱이 저장하지 않음, 전송 중 누락, 정책 변경, 다른 파일을 수집함 | 원본과 대상의 파일 식별값, 스트림을 포함하는 수집, 호스트 정책과 과거 기록 |
| 표시를 읽을 수 없음 | 도구나 권한의 한계, 지원하지 않는 저장소, 파일이 사라짐 | 수집 결과, 파일시스템, 조회 방법. 조회 실패와 정상 조회에서 스트림이 없었던 경우를 구분합니다. |
| 수집 파일과 같은 경로에 이벤트 15가 있음 | 같은 파일이 계속 있었거나 다른 파일이 이름을 재사용함 | 확보 가능한 장치·볼륨·파일 ID, 생성·이름 변경·교체 타임라인, 본문 해시 |
| URL이 의심스럽거나 다른 증거와 충돌함 | 일부 리디렉션만 기록됨, 압축 해제 메타데이터, 작성 도구의 부정확한 정보 또는 고의로 잘못된 값 기록 | 브라우저·프록시 이력, 출발지와 목적지 기록, 앱 사용 맥락. 초동 조사 중 신뢰하지 않는 URL을 열지 않습니다. |

소프트웨어는 영역 메타데이터를 쓸 수 있습니다. 공격자가 출처를 다르게 보이게 하거나 메타데이터가 보존되지 않는 흐름을 이용하면 위험 판단이 달라질 수 있습니다. 상황에 맞게 정책 강제, 파일 내용 검사, 검증된 출처 증명을 활용하세요. 표시 부재, 인터넷 영역 값, URL 하나로 악성 여부나 실행 여부를 판단할 수 없습니다.

## 4. 블루팀의 수집, 탐지, 대응

1. **파일의 수명과 두 종류의 스트림을 보존합니다.** UTC, 수집 호스트, 볼륨, 경로, 확보 가능한 파일 ID, 수집 도구·담당자와 오류를 기록합니다. 본문과 관련 이름 있는 스트림을 함께 보존하는 절차를 쓰고 복사본에 실제로 남았는지 확인합니다. 해시가 어느 스트림을 대상으로 하는지 표시하세요. URL의 쿼리 문자열에 식별값이나 비밀값이 있을 수 있으므로 URL 자료는 승인된 증거 저장소에 둡니다.
2. **수집 범위를 확인한 뒤 이벤트를 연결합니다.** 활성 Sysmon 구성에서 `FileCreateStreamHash`(ID 15)를 수집하고 `Microsoft-Windows-Sysmon/Operational`이나 후속 저장소에 보존해야 합니다. Microsoft 문서에 따르면 이벤트에는 이름 없는 스트림의 해시와 이름 있는 스트림의 내용이 기록됩니다. 원본 XML, 구성된 해시 알고리즘, 호스트, 레코드 ID, 시각, 전체 대상 경로와 작성 프로세스를 확인합니다. ID 15는 여러 이름 있는 스트림에 적용되므로 MOTW를 조사할 때는 `Zone.Identifier`로 끝나는 스트림을 골라 보세요. ID 1을 수집했다면 프로세스 이미지와 시각을 별도로 대조합니다. ID 15의 `ProcessGuid`는 스트림을 쓴 프로세스를 설명합니다. 나중에 파일을 열거나 실행한 프로세스는 별도 근거가 필요합니다.
3. **범위를 제한한 탐지를 검증합니다.** 예를 들어 감시 중인 다운로드 경로에서 스트림이 생성되고 이후 실행 또는 문서 제어 이벤트가 독립적으로 확인된 경우를 조사 대상으로 삼을 수 있습니다. 동일 호스트에서 파일의 수명과 해시가 맞는지 확인하세요. 정상 다운로드, 관련 없는 스트림, 같은 경로의 재사용, 수집 공백을 대조 사례로 둡니다. 여러 복사본이 같은 해시를 가질 수 있습니다. 해시나 이름 외에도 파일 식별값, 시각, 이동 기록을 활용합니다.
4. **독립 증거로 대응 범위를 결정합니다.** 승인 출처나 릴리스 서명으로 파일을 확인하고 네트워크·전달 자료와 제어 판정을 대조합니다. 실행이 의심되면 프로세스 식별 정보, 자식 프로세스와 영향을 확인하고 엔드포인트 대응 절차를 적용합니다. 출처, 실행 또는 표시 이력을 확인할 수 없을 때는 미확정으로 남기세요.

승인된 Windows 조사 복사본이 NTFS에 있고 PowerShell의 Windows FileSystem 공급자와 읽기 권한이 있을 때 다음 명령으로 스트림과 본문 해시를 확인할 수 있습니다. 경로를 본인이 관리하는 복사본으로 바꾸세요. 이름 있는 스트림이 확인된 상태에서 `Get-Content`를 사용합니다. 출력에 비공개 URL이 포함될 수 있습니다.

```powershell
$item = 'C:\Evidence\report.txt'
Get-Item -LiteralPath $item -Stream *
Get-Content -LiteralPath $item -Stream Zone.Identifier
Get-FileHash -LiteralPath $item -Algorithm SHA256
```

승인된 Windows 호스트에 Sysmon이 있고 로그 읽기 권한이 있으면 최근 스트림 기록의 메타데이터를 조회합니다. 원본 XML은 승인된 환경에서 확인하세요. 권한 오류, 로그 누락, 비활성 이벤트 규칙은 수집 범위를 제한합니다.

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 15
  StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, MachineName, Id, RecordId
```

## 5. 오프라인 증거 실습

<a href="{{ '/assets/labs/windows-motw-evidence.py' | relative_url }}" download>Python 3 확인 도구</a>와 <a href="{{ '/assets/labs/windows-motw-evidence-cases.json' | relative_url }}" download>가상 증거</a>를 관리하는 폴더 한 곳에 내려받고 실행합니다.

```sh
python3 windows-motw-evidence.py
```

도구는 로컬 JSON을 읽고 본문을 대신하는 문자열의 실제 SHA-256을 계산합니다. 현재 표시, 일치한 스트림 생성, 독립적인 프로세스 시작 근거를 각각 비교합니다. `lifetime`과 이미지 일치 여부는 가상의 수집기가 붙인 값입니다. 실제 Sysmon에 이 필드가 있다고 가정하지 마세요. 실행 파일을 나타내는 사례도 본문에는 무해한 텍스트를 사용합니다.

| 사례 | 설명할 결과 |
| --- | --- |
| A, B, H | 본문 해시는 같습니다. 인터넷 표시, 표시 부재, 신뢰할 수 있는 사이트 값이 각각 관측됩니다. |
| C, D | 과거 스트림 생성은 현재 표시 부재와 함께 나타날 수 있습니다. 서로 다른 파일의 수명은 연결할 수 없습니다. |
| E, G, J | 읽기 불가, 영역 키 중복, URL만 있고 영역 값이 없는 경우의 한계를 구분합니다. |
| F, L | F에는 일치하는 생성과 독립적으로 연결된 프로세스 시작이 있습니다. L의 다른 스트림 이름과 불일치 이미지로는 같은 판단을 할 수 없습니다. |
| I, K | 해시가 다르거나 해당 파일이 생기기 전 이벤트는 연결 근거가 되지 않습니다. |

`12/12 MOTW evidence cases matched.`와 본문 해시 일치 두 건을 확인하세요. 음성 대조로 JSON을 복사한 뒤 A의 **이벤트** 호스트를 `fixture-b`로 바꿔 복사본 이름을 명령 인수로 전달합니다. A는 인터넷 영역으로 남되 `stream-create-unconfirmed`로 바뀝니다. 일치 건수는 11건, 종료 코드는 1입니다. 입력 오류가 나면 Python 3, 파일명과 JSON 문법을 확인하세요. 불일치가 나오지 않으면 바꾼 호스트 필드와 넘긴 파일을 확인합니다. 원본과 수정본은 클라우드 Python에서 실행했습니다. NTFS, PowerShell, Office와 Sysmon은 공식 문서로 검토했습니다.

## 6. 확인 문제와 해설

1. **SHA-256이 같은 두 파일의 MOTW가 왜 다를 수 있나요?** 이 해시는 이름 없는 스트림을 대상으로 합니다. 영역 표시의 바이트는 별도 스트림에 있습니다.
2. **Zone.Identifier가 없으면 로컬에서 만든 파일인가요?** 해당 스트림을 정상적으로 관측할 수 있는 환경에서 수집 당시 없었다는 뜻입니다. 실제 출처는 전송 이력과 독립된 로그로 확인합니다.
3. **일치한 이벤트 15는 무엇을 보여 주나요?** 해당 센서와 시각에 기록된 이름 있는 스트림 생성입니다. 파일의 수명과 대조하고 이후 실행은 다른 증거로 뒷받침합니다.
4. **ZoneId 3으로 Office 판정을 알 수 있나요?** 실제로 관측한 표시 값입니다. 앱과 버전, 유효 정책, 실제 판정을 대조하세요.

**완료 기준.** A/B와 A/H의 해시 결과, C와 E의 차이를 설명하고 음성 대조를 재현합니다. 다운로드 출처와 실행 여부를 확인할 독립 자료를 각각 하나씩 제시하세요.

## 공식 참고자료

2026-11-26 기준으로 검토했습니다. Windows와 Office 동작은 공급자의 현재 문서를 기준으로 설명합니다. Microsoft의 2018년 분석은 당시의 수집 사례와 작성 주체에 따라 값이 달라지는 이유를 설명합니다. 실제 조사에는 설치 빌드와 수집 구성을 확인하세요.

- 스트림 구조와 첨부 파일 정책. [Microsoft NTFS 파일 스트림](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) · [Attachment Manager 정책](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-attachmentmanager)
- Windows용 Office 기본 동작과 영역 값. [Microsoft Office 인터넷 매크로 지침](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked#mark-of-the-web-and-zones)
- 스트림 생성과 출처 메타데이터. [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-15-filecreatestreamhash) · [Microsoft 다운로드 분석, 2018](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/hunting-tip-of-the-month-browser-downloads/220454)
- 읽기 전용 명령. [Get-Item](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) · [Get-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content) · [Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

[이전 · NTFS USN 조사]({{ '/ko/wiki/ntfs-usn-evidence/' | relative_url }}) · [다음 · Sysmon 조사]({{ '/ko/wiki/sysmon-investigation/' | relative_url }})
