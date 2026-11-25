---
title: "Windows WFP 연결 허용·차단 조사"
description: "Security 5156·5157을 프로세스 수명, 필터 출처, 실제 통신 결과와 대조합니다."
category: blue-team
tags: [Windows, Windows Firewall, WFP, Windows Event Logs, Sysmon, Blue Team, DFIR]
level: Beginner
updated: "2026-11-25"
translation_url: /wiki/windows-wfp-connection-evidence/
---

워크스테이션에서 TCP 443 연결에 대한 이벤트 5156이 남고, 몇 초 뒤 같은 상대 주소에 대한 5157이 기록됐습니다. 호스트, 방향, 양쪽 주소와 포트, 프로토콜과 프로세스 수명 구간을 대조하기 전에는 두 개의 판단으로 봅니다. 이 장에서는 호스트의 필터가 내린 판단과 그 뒤 실제로 일어난 일을 확인하는 방법을 배웁니다.

## 1. Windows Filtering Platform이 기록하는 내용

**Windows Filtering Platform(WFP)**은 Windows 네트워크 스택에서 필터링을 제공하는 기반입니다. Windows 방화벽뿐 아니라 다른 공급자도 WFP에 필터를 등록할 수 있습니다. **필터**는 네트워크 처리 지점인 **계층(layer)**에서 주소, 애플리케이션, 프로토콜 등의 조건을 평가합니다. ALE(Application Layer Enforcement) 계층은 아웃바운드 연결 요청이나 인바운드 수신·수락 같은 작업을 승인합니다. 판단과 함께 계층·방향을 읽으세요. 연결 승인과 패킷 삭제는 관측하는 작업이 다릅니다.

보안(Security) 채널의 연결 이벤트는 **필터링 플랫폼 연결 감사(Audit Filtering Platform Connection)** 하위 범주에서 성공과 실패 감사를 제어합니다. 해당 감사가 켜져 있으면 **5156**은 WFP가 연결을 허용했을 때, **5157**은 연결을 차단했을 때 기록됩니다. 여기서 성공은 Windows 감사 분류를 의미합니다. 앱의 요청 성공 여부는 별도 증거로 확인합니다. `EventData`의 `ProcessID`는 이벤트에 나타난 애플리케이션의 PID입니다. `System/Execution/@ProcessID`는 이벤트를 기록한 공급자의 실행 문맥에 속합니다. 두 필드를 구분하세요.

| 출처 | 직접 확인할 수 있는 증거 | 후속 질문 |
| --- | --- | --- |
| Security 5156 | 로컬 WFP의 연결 허용 판단 | 패킷이 경로를 지나 서비스에 도착했나요? |
| Security 5157 | 표시된 계층에서 내린 연결 차단 판단 | 어느 필터와 정책이 이 작업에 적용됐나요? |
| Security 5152 | WFP의 패킷 차단. 연결 감사와는 별도 하위 범주 | 어떤 패킷과 필터였나요? |
| Sysmon 1·3 | ProcessGuid로 연결되는 프로세스 생성과 설정된 TCP·UDP 관측 | 어느 프로세스 인스턴스였나요? |
| 방화벽 텍스트 로그·캡처·서비스 로그 | 프로필별 방화벽 기록, 관측 지점의 패킷, 앱의 처리 기록 | 각 자료로 후속 단계 어디까지 확인할 수 있나요? |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-wfp-connection-evidence-ko.svg' | relative_url }}" alt="기록 호스트와 통신 정보를 확인하고 WFP 판단을 프로세스, 네트워크와 서비스 증거에 대조합니다.">
  <figcaption>로컬 필터 판단은 한 단계입니다. 실제 전송과 앱 처리에는 별도 확인이 필요합니다.</figcaption>
</figure>

## 2. 정상 연결 한 건 따라가기

가상 예시에서 `ws-12.example.test`의 승인된 에이전트가 문서용 주소에 상태 페이지를 요청합니다. 시각은 모두 UTC입니다.

1. 09:02:05에 프로세스 시작 기록에서 `status-agent.exe`의 PID 914와 인스턴스 식별자를 확인합니다. 시작 시각, 실행 파일 경로, 수집했다면 종료 시각도 기록합니다.
2. 09:02:08에 같은 호스트의 Security 5156에서 아웃바운드 TCP(`Protocol=6`), `192.0.2.12:50811` → `198.51.100.20:443`을 확인합니다. 앱 PID를 그 호스트에서 실행 중이던 PID 914의 수명 구간과 대조하고 실행 파일도 비교합니다. `\device\harddiskvolume2\...` 같은 장치 경로를 드라이브 문자 경로와 비교하려면 해당 호스트의 볼륨 매핑이 필요합니다.
3. 승인된 지점의 패킷 캡처에는 TCP 핸드셰이크가 있고, 대응하는 서버 액세스 로그에는 상태 요청이 있습니다. 시각, 양쪽 주소와 포트, NAT·프록시 매핑과 가능한 요청 ID를 대조하세요. 핸드셰이크로 전송 연결을, 서비스 기록으로 요청 처리를 확인합니다.
4. 뒤이어 기록된 5157의 출발지 포트는 50812입니다. 별도 건으로 기록합니다. 하나의 상대 주소에 여러 서비스가 있을 수 있고, 재시도나 병렬 요청의 관측도 서로 다를 수 있습니다. 50812에 대한 차단으로 앞서 관측한 50811의 결과를 설명할 수 없습니다.

Windows는 PID를 재사용할 수 있습니다. 원본 컴퓨터, PID, UTC 시각과 실행 파일을 대조하고 프로세스가 이벤트 시각에 이미 시작됐는지, 종료 기록이 있다면 그 이후에 끝났는지 확인하세요. 재부팅이나 시각 오차가 있으면 후보를 특정하기 어려울 수 있습니다. Sysmon을 설치하고 기본으로 꺼진 네트워크 로깅을 설정했다면 이벤트 3에서 ProcessGuid를 얻을 수 있습니다. Security 5156·5157 자체에는 Sysmon의 이 식별자가 없습니다.

## 3. 수집·탐지·대응

**감사와 전달 범위를 확인합니다.** 호스트 역할, OS 빌드, 성공·실패 감사 설정, Security 로그 보존 기간과 수집기 필터를 기록합니다. 5156은 많은 로그를 만들 수 있습니다. 정해진 호스트에서 먼저 수집해 원본과 전달본의 보존 범위를 측정하세요. 원래의 `Computer`, `Channel`, 공급자, `EventRecordID`, 버전, `SystemTime`과 수집 시각을 보존합니다. 방향(`Direction`), 실행 파일(`Application`), 프로토콜, 주소와 포트는 정규화한 값과 원본을 모두 남깁니다. 표시 문구는 언어에 따라 달라집니다. 기록 호스트 기준으로 방향을 해석하고 주소 계열과 로컬·원격 역할을 보존하세요. 승인된 정상 동작으로 호스트에서 수집기까지 전달되는지도 확인합니다.

**차단의 출처를 확인합니다.** `FilterRTID`, `LayerRTID`와 계층을 확인하세요. 런타임 식별자는 같은 호스트에서 이벤트 시점과 가까운 WFP 스냅샷과 대조합니다. 정책이 그대로여도 필터 ID가 바뀔 수 있습니다. Microsoft는 Windows 11과 Windows Server 2022부터 개선된 5157·5152에 Filter Origin과 Interface Index가 추가됐다고 설명합니다. 사용 전에 수집본의 스키마와 원본 XML을 확인하세요. Filter Origin은 방화벽 규칙 ID 또는 기본 차단 필터를 가리킬 수 있습니다. 기본 필터에는 대응하는 사용자 규칙이 없습니다. 명시적 규칙 ID가 있다면 로컬·그룹 정책·MDM 중 어디서 적용했는지, 당시 정책과 현재 유효 정책은 같은지 확인합니다. 사건 당시 프로필과 인터페이스도 기록하세요. 현행 구성이 달라졌을 수 있습니다.

**가능한 원인을 비교합니다.** 새로 차단된 목적지는 정책 배포, 네트워크 프로필 전환, 업데이트 서버 문제 또는 승인되지 않은 아웃바운드 통신에서 나타날 수 있습니다. 예상 밖 실행 파일이 허용됐다면 승인 소프트웨어와 서명자, 상위 프로세스, 대상 서비스와 과거 목적지를 확인하세요. 차단 이벤트로 확인할 수 있는 것은 해당 작업에서의 판단입니다. 다른 시도나 경로는 추가 조사가 필요합니다. 허용 이벤트만으로 자격 증명 전달, 요청 완료, 데이터 반출이나 침해 여부를 판단할 수 없습니다.

**정해진 범위에서 탐지와 대응을 검증합니다.** 시범 탐지에서는 차단된 아웃바운드 이벤트를 원본 컴퓨터, 정규화한 이미지, 프로토콜과 원격 엔드포인트로 묶어 15분 간격으로 집계하세요. 해당 자산의 승인 목적지와 소프트웨어 기준선과 비교합니다. 가능하면 서로 다른 프로세스 수명 구간 수와 이벤트 건수를 따로 셉니다. 재시도가 많으면 관측 건수도 늘어납니다. 승인된 작업에 장애가 나면 설정을 조정하기 전에 정책의 출처와 프로필을 대조하세요. 프로세스와 서비스 양쪽 증거가 오용을 뒷받침하면 기록을 보존하고 영향받은 호스트를 좁혀 승인된 대응을 진행합니다. 복구 후 알려진 정상 작업을 다시 수행해 앱 결과까지 확인하세요.

### 승인된 Windows 호스트에서 읽기 전용 조회

Security 채널과 감사 정책에 읽기 권한이 있는 계정으로 Windows PowerShell 또는 Windows에서 실행하는 PowerShell을 사용하세요. 아래 AuditPol 하위 범주 이름은 영문입니다. 현지화된 시스템에서는 하위 범주 목록을 조회해 해당 언어의 이름이나 대응 GUID를 사용하세요. 예제는 보존된 최근 30분 이벤트를 찾습니다. 결과가 비어 있으면 감사 정책, 보존 또는 조회 범위를 확인합니다.

~~~powershell
auditpol /get '/subcategory:Filtering Platform Connection'
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id = 5156, 5157
    StartTime = (Get-Date).AddMinutes(-30)
} -MaxEvents 30 | ForEach-Object { $_.ToXml() }
~~~

원본 `EventData`는 필드 이름으로 읽고 출력은 승인된 조사 저장소에 보관하세요. 필요한 수집 기간과 로그 규모를 검토한 뒤에만 `-MaxEvents` 제한을 조정합니다. 실행 시각을 남기세요. 현재 감사 설정만으로 과거 수집 범위를 복원할 수 없습니다.

## 4. 오프라인 실습 · 가상 XML에서 다섯 가지 판단

<a href="{{ '/assets/labs/windows-wfp-review.py' | relative_url }}" download="windows-wfp-review.py">Python 확인 스크립트 다운로드</a> · <a href="{{ '/assets/labs/windows-wfp-cases.xml' | relative_url }}" download="windows-wfp-cases.xml">가상 XML 다운로드</a>

두 파일을 같은 폴더에 저장하세요. 승인된 환경에서 Python 3으로 실행합니다.

~~~bash
python3 windows-wfp-review.py windows-wfp-cases.xml
~~~

각 사례에는 네임스페이스를 넣은 간략한 Security 이벤트 XML과 별도의 가상 프로세스·서비스 관측이 있습니다. 실제 EVTX 내보내기 파일은 아닙니다. 확인 스크립트는 제공한 구조를 사용하며 네트워크나 Windows API를 호출하거나 정책을 변경하지 않습니다. 프로세스 기록의 경로는 매핑이 끝난 것으로 가정하고 수명 구간을 명시합니다. 서비스 기록에는 대조한 클라이언트 엔드포인트와 호스트가 있습니다. 실습에서는 양쪽 주소·포트와 프로토콜이 정확히 일치하며 시계도 동기화됐다고 가정합니다. 운영에서는 NAT, 프록시, 기록 누락과 시각 오차를 따로 확인해야 합니다.

| 사례 | 판단에 쓰는 증거 | 예상 결과 |
| --- | --- | --- |
| 01 | 5156, 실행 중인 프로세스와 같은 통신의 서비스 기록 | 허용, 프로세스와 서비스 확인 |
| 02 | 5157, 실행 중인 프로세스와 다른 출발지 포트의 서비스 기록 | 차단, 서비스 결과 미확인 |
| 03 | 5156, PID는 같지만 프로세스가 이벤트 이전에 종료됨 | 허용, 프로세스 미확인 |
| 04 | 5156, 통신 정보는 같지만 가상 기록의 원본 호스트가 다름 | 허용, 서비스 결과 미확인 |
| 05 | 5157, PID와 수명은 일치하지만 이미지가 다름 | 차단, 프로세스 미확인 |

`PASS`가 다섯 줄 나와야 합니다. 파일을 찾지 못하면 두 파일이 같은 폴더에 있는지, 그 폴더에서 실행했는지 확인하세요. 판단이 다르면 XML 필드의 이름, 시각, 양쪽 주소·포트와 프로토콜을 대조합니다. 복사본에서 02의 서비스 출발지 포트를 바꿔 보세요. 같은 포트의 후속 서비스 기록이 있어도 그 기록을 어느 시도에 연결할 수 있을지 생각해 보세요. 이 스크립트는 차단된 작업의 서비스 결과를 미확인으로 남깁니다.

## 5. 확인 문제와 완료 기준

1. **TCP 443에 대한 5156은 HTTPS 전송을 입증하나요?** 로컬에서 허용했다는 기록입니다. 후속 TCP, TLS와 앱 증거를 확인하세요. 포트만으로 TCP 위의 프로토콜을 알 수 없습니다.
2. **같은 호스트에서 다음 주에 FilterRTID를 찾아도 되나요?** 새 스냅샷도 참고할 수 있지만 런타임 ID는 바뀔 수 있습니다. 사건과 가까운 스냅샷을 우선하고, 제공되는 Filter Origin과 당시 구성을 대조하세요.
3. **나중에 시작한 프로세스의 PID가 같으면 해당 앱을 식별할 수 있나요?** 이벤트 시각과 프로세스 수명을 비교하고 호스트와 이미지를 확인합니다. 후보가 겹치거나 증거가 빠졌다면 미확인으로 남깁니다.
4. **SIEM 검색 결과가 비어 있으면 무엇을 확인했나요?** 그 시간과 조회 범위의 검색 결과만 확인했습니다. 활동에 관해 판단하기 전에 원본 감사 설정, 보존과 전달 상태를 확인합니다.

다섯 사례를 재현한 뒤 5157 한 건에 대해 호스트, 방향, 계층, 주소·포트·프로토콜, 프로세스 증거와 남아 있는 불확실성 한 가지를 적으면 완료입니다.

## 공식 참고자료와 다음 학습

검토일은 **2026-11-25**입니다. Microsoft의 Windows 10 감사 예시는 2021년 문서에서 기본 필드를 설명합니다. 현행 Filter Origin 문서는 Windows 11과 Windows Server 2022에 도입된 필드를 설명합니다. Python 실습은 가상 자료로 실행했고 Windows 조회 명령과 감사 동작은 공식 문서로 검토했습니다.

- 플랫폼과 승인 계층. [WFP 개요](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) · [ALE 계층](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
- 보안 이벤트 스키마와 발생량. [5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156) · [5157](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157) · [5152](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5152) · [필터링 플랫폼 연결 감사](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-connection)
- 추가 필드와 프로필별 파일 로그. [Filter Origin](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation) · [Windows 방화벽 로깅](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging)
- 읽기 전용 조회와 프로세스 관측. [AuditPol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) · [Sysmon v15.22, 2026-09-10](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

이전 학습 · [Windows 보안 로그]({{ '/ko/wiki/windows-logs/' | relative_url }})  
다음 학습 · [Sysmon 프로세스·네트워크 증거]({{ '/ko/wiki/sysmon-investigation/' | relative_url }}) · [방화벽과 NAT 증거]({{ '/ko/wiki/firewall-nat-evidence/' | relative_url }})
