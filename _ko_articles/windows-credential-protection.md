---
title: "Windows 자격 증명 보호: LSASS, SAM, LSA Secrets, Credential Guard와 덤핑 탐지"
description: "Windows 자격 증명 저장소와 보호 경계를 구분하고 Credential Guard·LSA 보호 상태를 검증하며 Sysmon·Splunk와 가상 실습으로 LSASS 접근을 조사합니다."
category: blue-team
tags: [Windows Security, Credential Access, Credential Guard, LSA Protection, LSASS, Blue Team, DFIR, Sysmon, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-22"
translation_url: /wiki/windows-credential-protection/
---

> **Windows 신원 방어 확장편.** [Sysmon 조사]({{ '/ko/wiki/sysmon-investigation/' | relative_url }}), [Windows 지속성]({{ '/ko/wiki/windows-persistence/' | relative_url }}), [NTLM 인증]({{ '/ko/wiki/ntlm-authentication/' | relative_url }})에서 이어집니다. 예제는 상태·정책·로그 조회용입니다. 메모리·레지스트리 Hive·해시·인증 티켓을 추출하지 않으며 실습 신원·GUID는 가상입니다.

## 1. 자격 증명 접근은 별도의 조사 주장

Credential Dumping은 OS 메모리·저장소에서 재사용 가능한 인증 자료를 얻으려는 행위입니다. 계정 악용·횡적 이동에 선행할 수 있지만 프로세스 실행·LSASS 접근·수상한 파일명·원격 로그온은 서로 다른 관측입니다. [MITRE T1003](https://attack.mitre.org/techniques/T1003/).

**어떤 프로세스가, 어떤 자료에 접근할 수 있었고, 어떤 보호가 적용되었으며, 어떤 작업이 실제 성공했고, 이후 신원이 악용되었는지** 순서대로 조사하세요. 경보 하나로 호스트의 모든 계정이 탈취되었다고 단정하지 마세요.

주요 Windows 저장소와 방어 조사를 다룹니다. 덤핑 명령·보호 우회·오프라인 크래킹·운영 공격을 가르치는 문서가 아닙니다. DC 침해·디렉터리 복제 악용은 별도 신원 기반 시설 대응이 필요합니다.

## 2. LSASS·SAM·LSA Secrets의 차이

| 표면 | 역할·자료 | 조사 범위 |
| --- | --- | --- |
| LSASS | 인증 프로세스와 세션·보안 상태 | 로그온·프로토콜·OS·보호에 따라 내용이 달라지며 평문 비밀번호 저장을 보장하지 않음 |
| SAM | 로컬 계정 자격 증명 DB | 로컬 계정은 도메인 전체 디렉터리가 아님 |
| LSA Secrets | 서비스·컴퓨터 관련 자료 등이 포함될 수 있는 보호된 시스템 비밀 | SAM·LSASS 전체 메모리와 동의어가 아님 |
| 캐시된 도메인 자격 증명 | 해당 오프라인 도메인 로그온용 로컬 검증값 | DCC2는 NTLM Pass-the-Hash에 바로 쓰는 NT 해시가 아님 |
| AD DB·복제 | 도메인 신원 비밀·복제 신뢰 | 로컬 저장소와 다른 DC·복제 범위 |
| 앱 비밀·인증서 | 앱별 토큰·일반 저장 자격 증명·개인키 사용 권한 | 별도 저장·정책·대응 필요 |

분류는 [SAM](https://attack.mitre.org/techniques/T1003/002/), [LSA Secrets](https://attack.mitre.org/techniques/T1003/004/), [캐시된 자격 증명](https://attack.mitre.org/techniques/T1003/005/)을 참고하세요. 검증값·NT 해시·Kerberos 티켓·인증서/개인키는 용도가 다르며 “해시”라는 말로 모두 바꿔 쓸 수 없습니다.

같은 도메인 계정이라는 이유만으로 해당 호스트에 사용 가능한 자료를 노출하지 않은 계정까지 피해 목록에 넣지 마세요. 반대로 호스트 정리가 이미 외부로 복사된 자료를 무효화하지도 않습니다.

## 3. 보호 표면별 통제 구성

![서로 다른 통제는 서로 다른 자격 증명 표면을 보호]({{ '/assets/diagrams/credential-boundaries-ko.svg' | relative_url }})

| 통제 | 의도한 경계 | 추정하면 안 되는 것 |
| --- | --- | --- |
| LSA 보호 / PPL | 보호된 LSASS 상호작용·플러그인 로드 제한 | 디스크의 모든 비밀 격리 |
| Credential Guard | 지원 자격 증명의 VBS 격리 | SAM·AD DB·모든 앱 비밀 보호 |
| LSASS ASR 규칙 | 지원 Defender 조건에서 메모리 접근 제한 | 모든 자격 증명 접근 경로 차단 |
| 최소 권한·보호된 관리 | 민감 호스트·신원 접근 축소 | 인증한 관리자 계정이 무해함 |
| 고유 로컬 자격 증명·관리 서비스 신원 | 재사용·미관리 비밀 축소 | 교체만으로 악성 코드 종료 |
| 앱/드라이버 제어·패치 | 미신뢰 실행·커널 공격 표면 축소 | 유효 서명이 안전을 보장 |

범위가 겹치더라도 다릅니다. 기능 이름 개수를 보안 점수처럼 합산하지 말고 유효 조합을 평가하세요. 자산 역할·허용 인증 흐름별로 공백을 기록합니다.

## 4. LSA 보호: 설정과 보호된 시작 구분

추가 LSA 보호는 LSASS를 보호된 프로세스로 실행하고 플러그인 요건을 적용합니다. 레지스트리 값만으로 현재 부팅의 유효 상태를 입증하지 못합니다. Microsoft는 보호된 시작의 확인 자료로 **System / WinInit 이벤트 12**를 안내합니다. [추가 LSA 보호 구성](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection).

변경 전에 지원 OS/빌드·정책·부팅 문맥·UEFI Lock·플러그인 호환성을 검토하세요. 메시지·Provider·부팅 시각을 보존합니다. 과거 시작 기록은 독립적인 실시간 상태 점검이 아닙니다.

조사 도구를 작동시키려고 보호를 끄지 마세요. 실제로 그 접근이 필요한지 판단하고 승인된 호환 절차를 사용합니다. 자격 증명 Provider·스마트카드·인증 확장은 통제된 호환 시험이 필요합니다.

## 5. Credential Guard: 명시적 한계를 가진 격리

Credential Guard는 지원되는 NTLM·Kerberos TGT·도메인 자격 증명을 VBS로 격리합니다. **SAM·AD DB는 보호하지 않습니다.** 에디션·하드웨어·역할·명시적 정책·적용 자격에 따라 다르므로 모든 Windows 11·Server 2025에서 실행 중이라고 가정하지 마세요. Microsoft는 DC에 추가 보안 이점이 없고 호환성 문제를 일으킬 수 있어 DC에서의 활성화를 권장하지 않습니다. [개요](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/).

검증에는 설정뿐 아니라 **실행 중 서비스 배열**을 확인합니다. `SecurityServicesRunning`의 1은 Credential Guard입니다. VBS 실행만으로 같은 주장을 할 수는 없습니다. [상태 검증](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure).

일반 저장 자격 증명·일부 레거시 인증/위임은 별도 한계가 있습니다. 실패 원인을 모른 채 약화하기보다 Wi-Fi/VPN·원격 관리·인증 확장 의존성을 시범 시험하세요. [호환성 고려사항](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues).

활성화 전에 유출된 자격 증명은 소급 해지되지 않습니다. 이전 노출 구간을 별도로 다루세요.

## 6. LSASS ASR 규칙과 차단의 의미

Defender의 **Block credential stealing from the Windows local security authority subsystem** 규칙 ID는 `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`이며 Warn 모드를 지원하지 않습니다. 현재 Microsoft 지침은 LSA 보호가 활성화된 경우 추가 보호를 제공하지 않고 Defender 관리에서 적용 대상 아님으로 표시될 수 있다고 설명합니다. 모든 PPL 장치에 필수 추가 계층으로 제시하지 마세요. [ASR 규칙 정의](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference).

차단 대상은 해당 메모리 접근 작업이며 수행 프로세스 자체가 반드시 종료되지는 않습니다. Audit는 Block이 아닙니다. 한 번의 차단으로 과거 접근·다른 방식·잔존 침해가 모두 없다고 입증할 수 없습니다.

정확한 규칙·동작·출발 프로세스·장치·시각·정책 적용 여부를 기록하세요. 정상 앱도 불필요한 접근을 할 수 있으므로 제품 폴더 전체 제외보다 행위·담당자로 판단합니다. 대표 소수 장치에서 호환·복구를 측정하며 적용하세요.

## 7. 증거: 접근·추출·후속 악용

| 자료 | 뒷받침할 수 있는 것 | 단독으로 입증하지 못하는 것 |
| --- | --- | --- |
| Sysmon 1 / Security 4688 | 프로세스 생성·수집된 실행 맥락 | 덤핑 성공 |
| Sysmon 10 | 기록된 프로세스 접근 | 읽은 바이트·재사용 자격 증명 획득·유출 |
| Sysmon 11 / EDR 파일 | 생성/덮어쓰기·수행 맥락 | .dmp 안에 LSASS 자료 존재 |
| Defender/ASR | 규칙별 감사·차단 | 전체 차단·프로세스 종료 |
| 정책·상태 목록 | 관측 시점 상태 | 과거 사고 전체 구간 상태 |
| 대상 로그온·DC 이벤트 | 후속 인증·접근 | 해당 호스트에서 얻은 자료 사용 |
| 승인 포렌식 분석 | 내용·근거 있는 노출 평가 | 무관 계정까지 침해 |

[Sysmon 정의](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Security 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)을 참고하세요. 이벤트 부재를 해석하기 전에 감사·명령줄 정책·Sysmon 필터·보존·전달을 검증해야 합니다.

4688의 `NewProcessId`는 새 프로세스, `ProcessId`는 생성자입니다. 16진수·10진수를 명시적으로 정규화하세요. Sysmon 10의 **SourceProcessGUID와 TargetProcessGUID를 분리**하고 출발 호스트+출발 GUID로 수행자를 조사합니다. 대상 LSASS GUID는 수행자 GUID가 아닙니다.

레지스트리 값 변경은 전체 읽기 이력이 아닙니다. 4657·Sysmon 13이 없어도 저장소 접근을 배제할 수 없습니다. 오프라인 획득·다른 경로는 선택한 라이브 수집 범위 밖일 수 있습니다.

## 8. 접근 권한과 오탐 관리

`GrantedAccess`는 권한 마스크이지 악성 점수가 아닙니다. Provider의 의미와 Windows 권한 정의에 따라 요청·기록된 작업을 해석하세요. 메모리 읽기 능력이 유용한 비밀 추출의 증거는 아닙니다. 특정 16진수 하나를 보편적 악성 판정으로 삼지 마세요. [프로세스 접근 권한](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

출발 이미지·서명/해시·전체 명령·부모·계정·토큰·가능한 Call Trace·빈도·변경 승인을 확인하고 원본 값을 보존합니다. 서명·경로는 후보 식별을 돕지만 행위를 승인하지는 않습니다.

EDR·백업·진단·신원 도구를 담당자와 기준선으로 관리하세요. 안정된 승인 패턴은 우선순위를 낮출 수 있지만 익숙한 이름의 새 파일은 조사 대상입니다. 필요한 상호작용을 숨기는 넓은 제외를 피하세요.

## 9. 읽기 전용 상태·로그 점검

승인된 Windows 호스트에서 적절한 권한·관리 구성 요소로 실행합니다. 비밀 값·프로세스 메모리를 읽지 않습니다. 접근 거부·미지원 클래스도 가시성 한계로 기록하세요.

### A. Credential Guard 실행 상태

```powershell
$credentialGuardState = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
$credentialGuardState |
  Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning
[pscustomobject]@{
  CredentialGuardRunning = @($credentialGuardState.SecurityServicesRunning) -contains 1
}
```

배열 포함 여부로 다른 Device Guard 서비스와 구분합니다. OS/빌드·수집 시각·정책 문맥도 저장하세요. 설정되었지만 실행되지 않으면 보호 중이라고 주장하지 말고 조사합니다.

### B. 선택한 LSA 설정·부팅 기록

```powershell
Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select-Object RunAsPPL,LsaCfgFlags

$credentialBootWindow = (Get-Date).AddDays(-2)
Get-WinEvent -FilterHashtable @{
  LogName='System'
  ProviderName='Microsoft-Windows-Wininit'
  Id=12,13,14
  StartTime=$credentialBootWindow
} -MaxEvents 30 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
```

LSA Secrets 저장소가 아닌 LSA 구성 키의 일부 값을 읽습니다. 값 부재·기본 정책·펌웨어 기반 설정은 문서에 따라 해석하세요. 2일·30건 제한으로 현재 부팅이나 이전 기록이 누락될 수 있어 실제 부팅 시각·메시지와 연결해야 합니다. 12와 13/14는 다른 질문에 답합니다.

### C. ASR 규칙 하나의 설정 동작

```powershell
$credentialAsrId = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
$credentialPreferences = Get-MpPreference -ErrorAction Stop
$credentialRuleIds = @($credentialPreferences.AttackSurfaceReductionRules_Ids)
$credentialRuleActions = @($credentialPreferences.AttackSurfaceReductionRules_Actions)
if ($credentialRuleIds.Count -ne $credentialRuleActions.Count) {
  throw 'ASR ID/action array lengths differ; inspect the source before mapping.'
}
for ($credentialRuleIndex = 0; $credentialRuleIndex -lt $credentialRuleIds.Count; $credentialRuleIndex++) {
  if ([string]$credentialRuleIds[$credentialRuleIndex] -eq $credentialAsrId) {
    [pscustomobject]@{
      RuleId = $credentialRuleIds[$credentialRuleIndex]
      ConfiguredAction = $credentialRuleActions[$credentialRuleIndex]
    }
  }
}
```

배열 위치로 ID·동작을 연결하며 길이가 다르면 중단합니다. 해당 API에서 0/1/2는 Disabled/Block/Audit이며 이 규칙에 Warn을 권하지 마세요. 행이 없으면 반환된 설정에서 찾지 못했다는 뜻이지 유효 보호·부재의 확정은 아닙니다. 적용 대상·실효 Defender 정책을 확인하세요. [Get-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/get-mppreference), [ASR 모드 정의](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure).

### D. 제한된 Sysmon 표본

```powershell
$credentialSince = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'
  Id=1,10,11
  StartTime=$credentialSince
} -MaxEvents 100 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
```

2시간 내 최대 100건입니다. 사건별 이름 기반 XML 필드를 확인하세요. 화면 메시지는 세부 정보가 생략되거나 지역화될 수 있습니다. 원본 EVTX/XML은 승인 절차로 보존합니다. 수집을 시험하려고 실제 덤프를 만들지 마세요.

## 10. Splunk 조사 템플릿

실제 인덱스·채널/Provider·GUID 필드를 매핑하세요. Computer는 원래 호스트여야 하며 host 대체는 그 의미일 때만 가능합니다. 채널 누락은 검색에서 제외되므로 파서 공백을 따로 확인하세요.

### A. LSASS 파일명 대상 프로세스 접근

```spl
index=sysmon (EventCode=10 OR EventID=10)
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| regex TargetImage="(?i)\\\\lsass[.]exe$"
| table _time endpoint SourceImage SourceProcessGUID SourceProcessGuid SourceProcessId
    TargetImage TargetProcessGUID TargetProcessGuid TargetProcessId GrantedAccess CallTrace
| sort 0 _time
```

대소문자 무시 접미사는 파일명 후보이지 검증된 신원이 아닙니다. 실제 경로·프로세스·출발/대상 GUID를 확인하세요. 특정 “악성” 마스크만으로 필터하지 않으며 메모리 추출을 증명하지 않습니다.

### B. 프로세스·접근·파일 이벤트의 같은 수행자

```spl
index=sysmon (EventCode IN (1,10,11) OR EventID IN (1,10,11))
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| eval actor_guid=lower(coalesce(SourceProcessGUID,SourceProcessGuid,ProcessGuid,ProcessGUID))
| where endpoint="WS02" AND actor_guid="{00000000-0000-0000-0000-000000000102}"
| eval event_id=coalesce(EventCode,EventID)
| table _time endpoint event_id actor_guid Image SourceImage CommandLine
    TargetImage GrantedAccess TargetFilename
| sort 0 _time
```

가상 호스트·GUID를 바꾸세요. 10의 수행자는 출발 필드, 1/11은 해당 이벤트의 프로세스 필드입니다. 별칭 정규화 시 원본을 유지하세요. 타임라인은 조사용이며 내용·인과 확정·계정 노출을 보장하지 않습니다.

### C. 덤프 확장자 파일 후보

```spl
index=sysmon (EventCode=11 OR EventID=11)
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| where like(lower(TargetFilename),"%.dmp")
| table _time endpoint Image ProcessGuid ProcessGUID TargetFilename
| sort 0 _time
```

확장자 기반 후보 검색으로 정상 충돌·진단 파일도 포함하고 다른 이름·파일 없는 방식은 누락합니다. 같은 수행자 GUID·근접 시각은 가설을 강화하지만 내용 검증은 보호된 포렌식 절차가 필요합니다. 미확인 덤프를 공개 평판 서비스에 올리지 마세요.

### D. 내보낸 Defender ASR 관측

```spl
index=endpoint_protection sourcetype=defender_deviceevents_normalized
    ActionType IN ("AsrLsassCredentialTheftAudited","AsrLsassCredentialTheftBlocked")
| table _time DeviceName ActionType InitiatingProcessFileName
    InitiatingProcessCommandLine InitiatingProcessAccountName
    InitiatingProcessId ReportId
| sort 0 _time
```

**Defender DeviceEvents 내보내기의 설명용 정규화 스키마**이며 Windows 원본 XML·KQL이 아닙니다. `_time`은 출처의 발생 시각으로 매핑하고 다른 필드도 수집 과정에서 매핑하세요. ActionType은 ASR 정의에 문서화되어 있습니다. Sysmon GUID가 기본 제공된다고 가정하지 않습니다. 독립 검증한 장치·프로세스 신원/수명으로 연결하며 PID·근접 시간만으로는 부족합니다.

운영 검증된 경보가 아닌 조사 시작점입니다. 추출·정상 업무·중복·규칙 적용 여부를 검증한 뒤 사용하세요.

## 11. 가상 자격 증명 접근 조사

[가상 관측 12건 다운로드]({{ '/assets/labs/windows-credential-protection-events.csv' | relative_url }}). 영어 공통 워크시트로 이벤트·상태 표본·분석가 메모를 함께 담았으며 빈 이벤트 번호는 의도된 것입니다. 원본 XML·바로 사용할 탐지 데이터셋은 아닙니다. `actor_guid`는 정규화 필드이며 Defender 행의 GUID는 명시적 가상 보강입니다.

| UTC | 관측 | 첫 해석 |
| --- | --- | --- |
| 05:00 | WS01의 보호된 LSASS·Credential Guard 시작 | 별도 부팅 상태이며 모든 저장소 보호 아님 |
| 05:05 | WS02의 CG 설정 배열에 1, 실행 배열에는 없음 | 설정은 실행 증거 아님 |
| 05:10 | WS01 진단 수행자의 LSASS 접근 | 승인된 조회 맥락 확인, 추출 입증 없음 |
| 05:12 | WS02 support 수행자·접근·ASR 차단·support.dmp | 내용·전체 차단을 단정하지 말고 조사 |
| 05:14 | APP01의 reader_lab 로그온 | 자격 증명 출처·방식 미확인 |
| 05:15 | 별도 보안 에이전트 후보 접근 | 다른 수행자, 승인 별도 확인 |
| 05:20 | 분석가가 파일 격리·검토 | 처리 행위이며 비밀 추출 증거 아님 |

**해설:** WS02 설정·실행 불일치를 조사해야 합니다. support 프로세스 순서는 보존·조사할 만큼 의심스럽지만 권한 세부·파일 내용·계정 노출은 제공되지 않았습니다. 차단과 파일 생성이 함께 있어도 LSASS 메모리가 담겼다는 증거는 아닙니다. APP01 로그온이 자동으로 후속 악용이 되지 않습니다. WS01의 PPL·CG 시작은 WS02를 보호하지 않으며 별도 에이전트를 support 수행자와 합치면 안 됩니다.

사실·가설·미확인을 구분하세요. 원본 접근 필드·출발 생성·규칙 기록·활성 정책/상태·보호된 파일 분석·대상 인증 증거를 확보합니다. 누락을 채우려고 대상을 실행하거나 자격 증명을 추출하지 마세요.

## 12. 차단과 자격 증명 대응 범위

![호스트 차단, 노출 평가, 신원 대응과 복구 검증]({{ '/assets/diagrams/credential-response-ko.svg' | relative_url }})

1. 호스트·신원·시각·출발/대상·수집 공백을 기록하고 가능한 증거를 보존합니다.
2. 실제 위험에는 격리·즉시 차단을 조정합니다. ASR 차단만으로 사고를 종료하지 않습니다.
3. 노출 구간의 저장소·계정/세션·실제 파일·보호 상태를 확인합니다.
4. 신뢰하는 관리 환경에서 신원 담당자의 복구 계획에 따라 관련 자격 증명을 교체·해지합니다.
5. 관련 자료에 맞춰 세션·티켓·토큰·인증서·서비스 의존성을 처리합니다.
6. 초기 침입·지속성을 제거하고 무결성을 확립하지 못하면 복구/재구축한 뒤 통제·로그를 검증합니다.
7. 관련 호스트·신원 재발을 감시하고 미확인을 기록합니다.

비밀번호 교체가 모든 세션·토큰·인증서를 무효화하지는 않습니다. 의존성 없이 서비스 비밀번호만 바꾸면 장애가 날 수 있습니다. DC 비밀·복제 악용 의심은 신원 사고 책임자가 주도해야 하며 LSASS 접근 하나로 파괴적인 도메인 전체 복구를 적용하지 마세요.

임의 차단 수단으로 LSASS를 종료하지 마세요. 진단 파일 자체에 비밀이 담길 수 있어 제한된 접근·보존·전송 통제가 필요합니다.

## 13. 강화와 완료 증거

| 우선순위 | 조치 | 완료 증거 |
| --- | --- | --- |
| 노출 축소 | 특권 관리 분리·불필요한 특권 로그온 축소 | 접근 경로·로그온 정책 검토 |
| 지원 자료 보호 | 적용 가능한 PPL·Credential Guard 검증 | 현재 상태/부팅 증거·호환 시험 |
| 실행 제어 | 패치·앱/드라이버 제한·로컬 관리자 관리 | 시험된 정책·승인 예외 |
| 재사용 축소 | 고유 관리 로컬 자격 증명·지원 관리 서비스 신원 | 교체·의존성 검증 |
| 가시성 | Sysmon/EDR·ASR 적용·감사·보존 검증 | 정상 시험의 전체 수집 |
| 신원 복구 | 영향 자격 증명·의존 서비스 범위 확정 | 신뢰 환경의 교체/해지·세션 검토 |

관리자 권한이 모든 보호 비밀 접근을 보장하거나 PPL 설정이 실행 상태를 입증하거나 CG가 SAM을 보호하거나 덤프 파일 부재가 접근 부재를 뜻한다고 보지 마세요.

입증된 행위만 [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/), [T1003.002 SAM](https://attack.mitre.org/techniques/T1003/002/), [T1003.004 LSA Secrets](https://attack.mitre.org/techniques/T1003/004/), [T1003.005 Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/)에 매핑합니다. 후속 자격 증명 사용은 별도 증거가 필요한 별도 행위입니다.

## 14. 학습 완료 점검과 관련 문서

LSASS·SAM·LSA Secrets·캐시 검증값을 구분하고 보호 한계 하나를 설명하세요. 설정·실행과 출발·대상 상호작용을 구분하고 추출을 과장하지 않아야 합니다. 도메인 전체 노출을 가정하지 않는 대응 범위도 제시하세요.

[NTLM]({{ '/ko/wiki/ntlm-authentication/' | relative_url }}), [Kerberos]({{ '/ko/wiki/kerberos-authentication/' | relative_url }}), [AD CS]({{ '/ko/wiki/ad-cs-security/' | relative_url }}), [횡적 이동]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }}), [Sysmon]({{ '/ko/wiki/sysmon-investigation/' | relative_url }})을 함께 복습하세요. [Windows 사고 대응 통합 실습]({{ '/ko/wiki/windows-incident-response-lab/' | relative_url }})의 가상 타임라인·증거 워크시트·대응 결정에 적용해보세요.

**출처 검토: 2026년 10월 22일.** Microsoft는 제품·필드·현재 보호 지침, MITRE는 행위 범위의 근거입니다. 도표·검색·가상 실습은 직접 구성한 교육 자료입니다. 게시 검사는 문서 일치·구문·제공 상태를 확인하며 자격 증명 덤핑·보호 변경·실제 공격·운영 Splunk 시험을 수행하지 않았습니다.
