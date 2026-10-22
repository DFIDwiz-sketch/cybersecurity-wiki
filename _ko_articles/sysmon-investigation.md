---
title: "Sysmon 가이드: 이벤트 수집, 필터, ProcessGuid 상관분석, Splunk와 조사 실습"
description: "Sysmon 수집 경로와 주요 이벤트를 이해하고 프로세스 수명·필터·수집 상태를 검증하며 가상 타임라인을 분석합니다. 관측과 입증의 차이를 함께 익힙니다."
category: tools
tags: [Windows Security, Sysmon, Blue Team, DFIR, Windows Logs, ProcessGuid, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-22"
translation_url: /wiki/sysmon-investigation/
---

> **Windows 텔레메트리 확장편.** [Windows 로그]({{ '/ko/wiki/windows-logs/' | relative_url }})와 [Windows 지속성]({{ '/ko/wiki/windows-persistence/' | relative_url }})에서 이어집니다. 실습의 이름·GUID·이벤트는 가상입니다. 예제는 조회·설정 설명용이며 에이전트 설치·정책 적용·미확인 페이로드 실행을 수행하지 않습니다.

## 1. 조사에서 Sysmon의 역할

Sysmon은 엔드포인트 이벤트를 제공하는 Windows 서비스·드라이버입니다. Security 로그·EDR을 보완하며 악성 판정 엔진은 아닙니다. 현재 Windows 이벤트 채널은 `Microsoft-Windows-Sysmon/Operational`입니다. [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

분석가는 관측을 구체적 질문과 연결해야 합니다. 프로세스 실행·통신·레지스트리 변경의 순서를 확인해도 의도·전송 문서·성공한 지속성을 모두 입증하지는 못합니다.

엔드포인트 범위·설정·수집·보존 조건 안에서 결론을 내리세요. 검색 결과가 없다는 것은 검색 결과에 대한 설명이지 호스트가 정상이라는 증거가 아닙니다. 이 문서는 Windows용이며 Linux 구현·모든 이벤트를 열거하지 않습니다.

## 2. 전체 증거 수집 경로

![엔드포인트 생성, 전달, 파싱과 조사는 별도 단계]({{ '/assets/diagrams/sysmon-pipeline-ko.svg' | relative_url }})

| 단계 | 검증 질문 | 오해를 만드는 실패 |
| --- | --- | --- |
| 엔드포인트 생성 | 설치 빌드·활성 규칙이 로컬에서 기록했는가? | 제외된 이벤트를 활동 부재로 해석 |
| 로컬 채널 | 접근·장애 대비 크기가 적절한가? | 수집 전 덮어쓰기 |
| 전달기·수집기 | 원래 호스트·XML이 보존되는가? | 수집기 이름을 출발 호스트로 사용 |
| 파싱·인덱싱 | 이벤트 종류·시간·식별자가 정확한가? | PID/GUID·채널 누락 |
| 조사 | 호환 증거로 순서를 연결했는가? | 가까운 이벤트를 인과관계로 단정 |

WEF는 기존 이벤트를 전달하며 Sysmon 설치·필터 활성화·채널 용량 변경을 대신하지 않습니다. 생성과 전달을 따로 시험하세요. [Microsoft WEF 지침](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection).

호스트 역할별로 예상 에이전트/빌드·정책 버전·채널·최근 시험·전달 경로·보존·담당자를 기록합니다. 일부 호스트가 대시보드에 보인다고 전체 자산 수집을 입증하지는 못합니다.

## 3. 주요 이벤트: 먼저 관측을 설명하기

아래는 간단한 이벤트 지도이며 기본 수집을 보장하는 표가 아닙니다. 설치 스키마와 [공식 이벤트 정의](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)를 확인하세요.

| ID | 관측 | 조사 한계 |
| --- | --- | --- |
| 1 / 5 | 프로세스 생성 / 종료 | 프로세스 수명은 전체 사용자 세션이 아님 |
| 3 | 네트워크 연결 | 앱 페이로드·정보 유출 확정 아님 |
| 7 | 이미지 로드 | DLL 로드만으로 악성 입증 불가 |
| 10 | 프로세스 접근 | 접근만으로 자격 증명 탈취 입증 불가 |
| 11 | 파일 생성/덮어쓰기 | 전체 내용·모든 쓰기 이력은 아님 |
| 12 / 13 / 14 | 레지스트리 생성/삭제 / 값 설정 / 이름 변경 | 등록은 후속 실행이 아님 |
| 19 / 20 / 21 | WMI 필터 / Consumer / Binding | 등록은 Consumer 실행이 아님 |
| 22 | DNS 쿼리 | 후속 연결 성공 증거 아님 |
| 4 / 16 / 255 | 서비스 상태 / 구성 변경 / 오류 | 문맥·승인 변경 검토 필요 |

이벤트별 실제 필드를 보존하고 존재하지 않는 공통 스키마를 가정하지 마세요. 특정 필드 부재는 이벤트 유형상 정상일 수 있습니다. 원본·파서 보강·분석가 추론을 보고서에서 구분하세요.

## 4. ProcessGuid·PID·부모 관계

PID는 재사용됩니다. ProcessGuid는 프로세스 인스턴스를 구분하는 데 도움이 됩니다. 출발 엔드포인트+호환 GUID+시간을 사용하고 원본 식별자도 보존하세요. 이미지 경로는 인스턴스 키가 아닙니다.

![같은 PID도 서로 다른 프로세스 수명에 속할 수 있음]({{ '/assets/diagrams/sysmon-process-lifetimes-ko.svg' | relative_url }})

| 연결 후보 | 올바른 범위 |
| --- | --- |
| ProcessGuid ↔ ProcessGuid | 같은 출발 호스트·호환 표기 |
| ParentProcessGuid ↔ ProcessGuid | 자식의 부모 참조를 부모 자신의 생성 기록에 연결 |
| PID ↔ PID | 같은 호스트·표기·입증된 수명 |
| 이미지 경로 ↔ 이미지 경로 | 위치·내용 단서이며 고유 프로세스 아님 |
| Logon ID ↔ Logon ID | 호스트·세션 문맥이며 전역 사용자 키 아님 |

이벤트마다 출발 프로세스·대상 프로세스·등록 객체의 의미가 다릅니다. 프로세스 접근에서는 출발·대상 식별자를 모두 확인하고 대상 GUID를 수행자로 취급하지 마세요. WMI 등록 이벤트 모두에 프로세스 생성과 같은 필드가 있는 것은 아닙니다.

부모 참조는 유용하지만 트리 하나로 실제 실행 주체의 전체 맥락이 설명되지는 않습니다. 명령·토큰/사용자·실행 환경·다른 출처를 확인하세요. 부모 생성 기록이 없으면 검색 구간·보존·수집 공백을 조사합니다.

## 5. 설정은 검토된 수집 범위 결정

정책의 출처·검토일·해시·대상 역할과 버전을 관리하세요. 바이너리·설정 스키마·정책 버전은 서로 다릅니다. 네트워크 3·이미지 로드 7은 기본 수집으로 가정하면 안 됩니다. Exclude는 Include보다 우선하며 명시적 그룹 관계로 의도를 분명히 할 수 있습니다. [Sysmon 설정 정의](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).

전부 수집하거나 시끄러운 프로세스를 전부 제외하기 전에 조사 요건을 정하세요. 규칙마다 기록될 정상 활동·기록되지 않을 근접 사례·필수 필드·출발 호스트·수집 지연 기대치를 적습니다.

[SwiftOnSecurity 설정 저장소](https://github.com/SwiftOnSecurity/sysmon-config)는 커뮤니티 정책 관리 사례입니다. 적용 전 실제 버전·라이선스·전제를 검토하세요. 널리 쓰인다는 이유만으로 자신의 환경 수집을 보장하지 않습니다. 아래 XML은 직접 구성한 교육 예제입니다.

### 의도적으로 좁은 필터 조각

```xml
<EventFiltering>
  <RuleGroup name="Lab network scope" groupRelation="and">
    <NetworkConnect onmatch="include">
      <DestinationIp condition="is">192.0.2.10</DestinationIp>
      <DestinationPort condition="is">443</DestinationPort>
    </NetworkConnect>
  </RuleGroup>
</EventFiltering>
```

완성된 배포 설정이 아닌 `EventFiltering` 조각입니다. 의도는 목적지 **192.0.2.10 AND 포트 443**입니다. 문서용 주소이며 실제 실습 서버를 기대하고 통신하지 마세요.

수용 시험은 해당 조합의 일치, 같은 주소의 다른 포트·다른 주소의 443 불일치입니다. 다른 규칙·제외 설정은 유효 결과를 바꿀 수 있습니다. 대상 바이너리 스키마와 통제된 양성/음성 시험으로 확인한 뒤 배포하세요.

전체 자산 네트워크 수집용으로 적합하지 않습니다. XML 형식 검사는 스키마 호환·런타임 동작을 입증하지 못합니다. 게시 과정에서 설정을 로드하지 않았습니다.

## 6. 안전한 배포와 복구

| 단계 | 작업 | 검토 가능한 증거 |
| --- | --- | --- |
| 계획 | 지원 호스트·승인 바이너리·정책·담당자 확인 | 버전 관리 패키지·변경 기록 |
| 시범 | 대표적인 소수 호스트 시험 | 로컬 표본·자원/이벤트량 측정 |
| 검증 | 스키마·포함/제외·전달 확인 | 양성/음성 결과·파싱 필드 |
| 확장 | 통제된 그룹별 적용 | 수집 범위·서비스 상태 |
| 복구 | 이전 승인 패키지/정책·절차 보존 | 시험한 복구·의존성 기록 |

에이전트 설치·변경은 호스트에 영향을 줍니다. 공식 절차와 조직 변경 관리를 따르세요. 실행 예제는 읽기 전용으로 구성했습니다. 오래된 설치 명령을 지원·패키지 출처 확인 없이 운영에 복사하지 마세요.

디스크·처리 부하·이벤트량·전달 적체·라이선스/보관 비용을 측정합니다. 넓은 제외 규칙은 비용을 줄여도 필요한 조사 경로를 없앨 수 있습니다. 영향을 받는 탐지 담당자와 이를 기록하세요.

## 7. 읽기 전용 조회와 원본 필드

승인된 호스트·권한으로 실행합니다. 제한된 라이브 조회이며 포렌식 획득·전체 자산 감사를 대체하지 않습니다.

### A. 서비스·채널 확인

```powershell
Get-Service |
  Where-Object { $_.Name -like 'Sysmon*' } |
  Select-Object Name,Status,StartType

Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' |
  Select-Object LogName,IsEnabled,RecordCount,MaximumSizeInBytes,LogMode
```

일반적인 Sysmon 이름을 조회하며 사용자 지정 이름은 놓칠 수 있습니다. 서비스 실행만으로 필터·전달을 검증하지 못합니다. 접근 실패·수집 시각도 기록하고 접근 불가를 빈 로그로 해석하지 마세요.

### B. 설치 스키마·활성 설정

```powershell
& 'C:\Tools\Sysmon64.exe' -s
& 'C:\Tools\Sysmon64.exe' -c
```

이미 설치되어 신뢰하는 바이너리 경로로 바꾸세요. `-s`는 스키마, 파일명 없는 `-c`는 설정을 표시합니다. 읽기 전용 점검 중 설정 파일명을 덧붙이지 마세요. 다운로드·설치를 수행하는 예제가 아닙니다. 승인된 목록 관리 절차로 결과를 보존하세요.

### C. 제한된 표본의 이름 기반 EventData

```powershell
$sysmonSince = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'
  Id=1,3,5,11,13,22
  StartTime=$sysmonSince
} -MaxEvents 100 | ForEach-Object {
  $sysmonEvent = $_
  [xml]$sysmonXml = $sysmonEvent.ToXml()
  $sysmonRow = [ordered]@{
    TimeUtc = $sysmonEvent.TimeCreated.ToUniversalTime().ToString('o')
    EventId = $sysmonEvent.Id
    RecordId = $sysmonEvent.RecordId
    Computer = $sysmonEvent.MachineName
  }
  foreach ($sysmonData in $sysmonXml.Event.EventData.Data) {
    $sysmonRow[$sysmonData.Name] = $sysmonData.'#text'
  }
  [pscustomobject]$sysmonRow
}
```

2시간 내 최대 100건입니다. 이벤트별 출력 속성이 다르므로 개별 객체·원본 XML을 확인해 화면 형식에 필드가 숨지 않도록 하세요. 유형·버전을 넘어 `Properties[0]` 같은 고정 위치를 가정하지 마세요. 증거 획득에는 원본 EVTX/XML을 별도 보존합니다. [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent).

## 8. 출처 의미를 보존하며 정규화하기

원본 Computer·Provider·채널·버전·Record ID·EventData·시각을 보존합니다. 호스트 발생·수신·인덱싱 시각을 구분하세요. Sysmon 이벤트 시각은 UTC이며 SIEM 화면은 다른 시간대로 표시할 수 있습니다.

| 정규화 필드 | 검증 |
| --- | --- |
| endpoint | WEC/전달기가 아닌 원래 호스트 |
| event_id | 숫자와 Provider·채널 |
| process_guid / parent_guid | 올바른 원본 필드·원본 값 보존 |
| process_id | 원본 표기·프로세스 수명 |
| event_time | 명시적 파싱·시계 정렬 |
| image / command_line | 수집된 전체 값·조용한 잘림 방지 |

별칭·GUID 대소문자는 일관되게 정규화할 수 있지만 없는 GUID를 만들면 안 됩니다. Security 4688은 자체 감사 조건·필드 의미를 가진 보완 자료입니다. PID가 비슷하다고 Sysmon ProcessGuid가 생기지 않습니다. 4688에서는 새 프로세스의 `NewProcessId`를 비교하세요. 원본 `ProcessId`는 생성자 프로세스 ID이므로 필드명이 같다고 연결하면 안 됩니다. 16진수·10진수 표기도 명시적으로 변환해야 합니다. 명령줄 수집에는 추가 정책도 필요합니다. [Microsoft 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688).

중복은 출발 신원·채널·레코드 문맥으로 평가합니다. 로그 수명 변화로 Record ID가 재설정될 수 있으므로 번호만으로 전역 중복 제거하지 마세요. 해시는 특정 파일 표현·알고리즘을 식별하며 실행 승인 여부는 아닙니다.

## 9. Splunk 조사 템플릿

실제 인덱스·시간·파서를 사용하세요. 원본 XML에서 `Channel`/`LogName`·Computer·GUID 별칭을 먼저 매핑합니다. 매핑된 Sysmon 채널이 없는 행은 의도적으로 제외하므로 파싱 공백을 따로 조사하세요.

### A. 이벤트 유형별 범위와 최신성

```spl
index=sysmon
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| eval event_id=coalesce(EventCode,EventID)
| stats count AS records max(_time) AS latest_event BY endpoint event_id
| eval age_seconds=now()-latest_event
| convert ctime(latest_event)
| sort 0 endpoint event_id
```

호스트 역할·활동량·예상 빈도로 최신성을 해석합니다. 검색 구간에 이미 존재하는 호스트·이벤트만 반환합니다. 완전히 빠진 시스템은 외부 예상 자산 목록과 비교해야 합니다. 시계 오차·미래 시각이 age를 왜곡할 수 있어 원본 시간을 확인하세요.

### B. 한 프로세스 인스턴스의 여러 이벤트

```spl
index=sysmon (EventCode IN (1,3,5,11,13,22) OR EventID IN (1,3,5,11,13,22))
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| eval process_guid=lower(coalesce(ProcessGuid,ProcessGUID)), event_id=coalesce(EventCode,EventID)
| where endpoint="WS01" AND process_guid="{00000000-0000-0000-0000-000000000001}"
| table _time endpoint event_id process_guid ProcessId Image CommandLine
    ParentProcessGuid QueryName DestinationIp DestinationPort TargetFilename TargetObject
| sort 0 _time
```

호스트·가상 GUID를 실제 사례 값으로 바꾸세요. `host` 대체는 원래 엔드포인트를 의미할 때만 유효합니다. 타임라인이며 인과관계·전체 이력을 보장하지 않습니다. 생성·종료 누락을 조사하고 수명 경계를 임의로 만들지 마세요.

### C. 프로세스 생성의 부모 참조

```spl
index=sysmon (EventCode=1 OR EventID=1)
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| eval process_guid=lower(coalesce(ProcessGuid,ProcessGUID))
| eval parent_guid=lower(coalesce(ParentProcessGuid,ParentProcessGUID))
| where isnotnull(parent_guid) AND parent_guid!=""
| table _time endpoint process_guid ProcessId Image CommandLine
    parent_guid ParentProcessId ParentImage ParentCommandLine User
| sort 0 _time
```

각 행은 자식과 기록된 부모 참조입니다. 트리 복원에는 같은 호스트·적절한 시간 범위의 부모 Event 1을 찾아야 합니다. 이 검색은 그 연결을 수행하거나 비정상 부모를 자동 분류하지 않습니다.

### D. 서비스·설정·오류 검토

```spl
index=sysmon (EventCode IN (4,16,255) OR EventID IN (4,16,255))
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| eval event_id=coalesce(EventCode,EventID)
| table _time endpoint event_id State Version SchemaVersion Configuration
    ConfigurationFileHash ErrorId Description
| sort 0 _time
```

유형·버전별 필드가 다르므로 XML로 매핑합니다. 주기적 Heartbeat가 아닌 상태·변경·오류 관측입니다. 오래된 Event 4는 현재 정상 상태를 보장하지 않고 Event 255 부재도 무오류 수집 증거가 아닙니다. 승인 변경·호스트 상태·독립 전달 상태를 함께 봅니다.

운영 Splunk에서 실행 검증하지 않았습니다. 경보로 만들기 전 추출·누락 필드·중복·대표 정상 활동을 시험하세요.

## 10. 조사 질문과 대안 설명

| 관측 | 작업 가설 | 확정 전 필요한 증거 |
| --- | --- | --- |
| 낯선 프로세스와 통신 | 예상 밖 앱·악용 | 부모·명령·소유자·호스트 맥락·목적지 소유 |
| 자동 시작 레지스트리 변경 | 지속성 가능성 | 정확한 값·대상·승인·후속 트리거/실행 |
| 프로세스 접근 | 민감 프로세스 상호작용 | 출발/대상·접근 맥락·승인 도구·독립 행위 |
| DNS와 가까운 통신 | 관련 통신 가능성 | 같은 인스턴스·DNS 결과·실제 목적지, 일대일 단정 금지 |
| 정책 변경 후 기록 없음 | 수집 회귀 가능성 | 유효 정책·로컬 생성·활동·전달 상태 |

보강 정보는 출처를 유지합니다. 평판·서명·허용 목록은 분류를 돕지만 의도 확정은 아닙니다. 악성 프로세스도 흔한 이름을 사용하고 정상 앱도 드문 동작을 할 수 있습니다.

이벤트 번호가 아닌 입증된 ATT&CK 행위에 매핑하세요. 레지스트리 기록이 자동으로 [T1547.001](https://attack.mitre.org/techniques/T1547/001/)이 되거나 프로세스 접근이 자동으로 자격 증명 덤프가 되지는 않습니다. 방식별 입증은 [Windows 지속성]({{ '/ko/wiki/windows-persistence/' | relative_url }})을 참고하세요.

## 11. 가상 프로세스 수명 실습

[가상 타임라인 14건 다운로드]({{ '/assets/labs/sysmon-investigation-events.csv' | relative_url }}). 영어 공통 CSV이며 분석용 워크시트입니다. 원본 Sysmon XML·운영 파서 시험 데이터가 아닙니다. GUID는 가상, `object`는 서로 다른 필드의 요약입니다. Security PID는 교육용으로 10진수 정규화했습니다. 악성코드·실제 조직 정보는 없습니다.

| UTC | 관측 | 범위 |
| --- | --- | --- |
| 04:01–04:02 | WS01 프로세스 A, PID 4100, GUID 끝 0001 | DNS·통신·파일·레지스트리에 A의 GUID |
| 04:05–04:10 | WS01 프로세스 B, PID 4100, GUID 끝 0002 | 재사용 PID, 다른 수명 |
| 04:05 | 정규화 PID 4100·inventory.exe인 Security 4688 | B와 명시된 생성 시각이 같아 보완 후보, GUID 연결은 아님 |
| 04:06 | WS02 PID 4100, GUID 끝 0003 | 다른 호스트·프로세스 |
| 04:07–04:08 | WS01 설정 변경·오류 | 원인·수집 영향 미확인 |

**질문:** A에 속하는 이벤트는 무엇인가요? B가 A의 이전 통신을 수행했나요? DNS가 후속 연결에서 그 응답을 사용했다고 입증하나요? Run 값이 로그온 실행 성공인가요? 설정 변경이 오류의 원인인가요?

**해설:** WS01의 A GUID로 제공된 기록을 연결합니다. 같은 PID여도 B·WS02는 분리해야 합니다. DNS 응답·통신 내용·전송량·후속 로그온 실행·부모 맥락·승인 설정 차이는 제공되지 않아 미확인입니다. 설정·오류가 가깝다는 것은 단서이며 입증된 인과가 아닙니다. 이 실습의 4688은 B와 명시된 생성 시각·호스트·PID·이미지가 같으므로 B의 보완 후보입니다. 원본 이벤트와 계정·명령 맥락을 검증한 뒤 연결해야 하며 정규화 PID 하나로는 부족합니다. 생성 시각이 다른 신규 프로세스 이벤트를 이미 실행 중인 인스턴스에 조용히 합치지 말고 불일치로 조사하세요.

## 12. 정상 활동으로 수집 시험하기

1. 시범 호스트의 소규모 승인 활동과 예상 이벤트·필드를 정합니다.
2. 빌드·활성 정책 해시·시간 구간·출발 호스트를 기록합니다.
3. 로컬 생성 후 전달·인덱싱 사본을 확인합니다.
4. 좁은 규칙 밖의 근접 사례를 시험하고 예상 제외와 전달 실패를 구분합니다.
5. 건수·신원·시각을 비교하고 잘림·중복·지연을 조사합니다.
6. 한계·담당자 수용 결과를 기록하고 관련 정책·빌드·수집 경로 변경 시 재시험합니다.

XML·PowerShell 구문 검사는 해당 단계만 검증하며 에이전트 실제 시험을 대체하지 않습니다. 이 문서 제작을 위해 통신을 생성하거나 호스트 에이전트를 변경하지 않았습니다.

## 13. 보존·개인정보·대응

명령줄·경로·사용자·DNS에는 내부 정보나 실수로 입력한 비밀이 담길 수 있습니다. 원본·보강 자료에 접근 통제·보존·사고 처리 규칙을 적용하세요. 공개 예제는 비식별화하되 보호된 원본 증거를 훼손하지 않습니다.

사고 시 호스트·수집기 증거·설정 이력·수집 공백을 보존합니다. 차단과 로깅 변경은 별도로 조정하세요. 가시성을 잃을 수 있는 센서 재시작·제거를 첫 조치로 삼지 마세요. 전체 정책을 바꾸기 전에 문제 범위를 파악합니다.

종료 기록에는 관측·지지된 가설·미확인·격리/복구·예상 텔레메트리 복구 여부를 담습니다. 더 많은 이벤트도 보관·해석할 수 있어야 유용합니다.

## 14. 학습 완료 점검과 관련 문서

PID 재사용과 부모 GUID 연결을 설명하고 필터로 제외될 활동 하나를 식별하세요. 텔레메트리 누락과 활동 부재를 구분하고 로컬에서 SIEM까지의 검증 계획·실습이 입증하지 못하는 사실을 제시해야 합니다.

[Windows 지속성]({{ '/ko/wiki/windows-persistence/' | relative_url }}), [Windows 횡적 이동]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }}), [Windows 로그]({{ '/ko/wiki/windows-logs/' | relative_url }}), [Splunk 기초]({{ '/ko/wiki/splunk-basics/' | relative_url }})로 연결해 학습하세요. 계획했던 AD·인증·원격 관리·AD CS·지속성·Sysmon 확장 순서를 마쳤습니다. 학습 단계의 완료이며 Windows 보안 전체를 다뤘다는 뜻은 아닙니다.

[다음 학습: Windows 자격 증명 보호와 덤핑 탐지]({{ '/ko/wiki/windows-credential-protection/' | relative_url }})에서 LSASS·SAM·LSA Secrets와 보호 상태·접근 증거를 연결해 분석하세요.

**출처 검토: 2026년 10월 22일.** Microsoft는 제품·수집 정의, 커뮤니티 저장소는 정책 관리 사례, MITRE는 행위 분류의 근거입니다. 도표·검색·필터 조각·실습은 직접 구성한 교육 자료입니다. 게시 검사는 문서 일치·구문·자료 제공을 대상으로 하며 운영 Sysmon·Splunk 검증은 각 환경에서 필요합니다.
