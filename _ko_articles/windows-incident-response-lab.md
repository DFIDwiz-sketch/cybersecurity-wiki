---
title: "Windows 사고 대응 통합 실습: 인증, 원격 접근, 지속성과 자격 증명 접근 증거"
description: "가상 관측 20건과 대응 기록 6건으로 Windows 사건을 분석합니다. 근거 있는 타임라인, 호스트별 상관분석, 사실·가설 구분과 복구 기준을 작성합니다."
category: dfir
tags: [Windows Security, Incident Response, DFIR, Blue Team, Active Directory, Kerberos, SMB, Persistence, Credential Access, Sysmon, Splunk]
level: Intermediate
updated: "2026-10-22"
translation_url: /wiki/windows-incident-response-lab/
---

> **통합 조사 실습.** [횡적 이동]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }}), [지속성]({{ '/ko/wiki/windows-persistence/' | relative_url }}), [Sysmon]({{ '/ko/wiki/sysmon-investigation/' | relative_url }}), [자격 증명 보호]({{ '/ko/wiki/windows-credential-protection/' | relative_url }})를 연결합니다. 가상 자료를 분석하는 실습이며 악성코드·실제 자격 증명·메모리 덤프·실행 페이로드·호스트 변경 명령을 제공하지 않습니다.

## 1. 목표와 대응 관점

증거가 뒷받침하는 사실을 설명하고 적절한 대응과 복구 전에 필요한 자료를 제시하세요. 긴급 조사가 필요하다고 판단하면서도 자격 증명 탈취·유출 성공은 미확인이라고 결론 내릴 수 있습니다.

2025년 4월 발표된 [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)은 Rev. 2를 대체하며 CSF 2.0 위험 관리에 사고 대응을 통합합니다. 준비·탐지·대응·복구·개선을 연결된 조직 업무로 다루세요. 아래 절차·채점은 직접 구성한 교육 자료입니다.

결과물은 근거 있는 타임라인, 호스트·계정 범위표, 사실·가설 평가, 대응 의사결정 기록, 복구·종료 점검표의 다섯 가지입니다. 누락을 채우려고 완성된 공격 이야기를 만들어내지 마세요.

## 2. 가상 환경과 범위

![통합 사례의 호스트와 증거 역할]({{ '/assets/diagrams/windows-ir-scope-ko.svg' | relative_url }})

| 자산 | 역할·문서용 주소 | 제공 자료 |
| --- | --- | --- |
| WS01 | 워크스테이션, 192.0.2.10 | 프로세스 A·DNS·통신 |
| FILE01 | 멤버 파일 서버, 192.0.2.20 | 로그온·공유 검사·작업·프로세스·접근 |
| DC01 | 도메인 컨트롤러, 192.0.2.30 | 서비스 티켓 요청 |
| WS02 | 별도 관리 워크스테이션 | 같은 작업 경로·로그온 번호의 혼동 사례 |
| APP01 | 앱 멤버 서버, 192.0.2.40 | 후속 네트워크 로그온 |
| 수집 시스템 | 전달·인덱싱 계층 | 원래 이벤트 호스트를 대체하지 않음 |

외부 주소 192.0.2.50·192.0.2.60과 `example.test` 이름은 문서용입니다. 실제 대상·차단할 침해 지표가 아닙니다. 사례 계정은 `LAB\reader_lab`이며 배포·인벤토리·대응 계정은 별도 역할입니다.

구간은 **2026년 10월 22일 06:00–06:35 UTC**이며 가상 구간에서 주소가 고정되어 있습니다. 실제로는 주소 이력·NAT/프록시·호스트 신원·시계·자료 공백을 먼저 확인하세요.

## 3. 증거 묶음과 출처

두 워크시트를 내려받습니다.

- [가상 관측 20건]({{ '/assets/labs/windows-ir-evidence.csv' | relative_url }})
- [대응 의사결정·작업 6건]({{ '/assets/labs/windows-ir-actions.csv' | relative_url }})

공통 CSV 설명은 영어입니다. 정규화한 교육 워크시트이며 원본 EVTX/XML·패킷·운영 파서 시험 자료가 아닙니다. E001–E020·R001–R006은 실습 키이며 Windows EventRecordID가 아닙니다. 정규화 내보내기 행의 빈 이벤트 번호는 의도된 것입니다.

| 필드 | 의미·한계 |
| --- | --- |
| case_id / evidence_id | 실습 내 안정된 참조 |
| time_utc / host / channel | 명시된 발생 시각·출처, 정규화 채널 포함 |
| account | 행에 관련된 선택 계정, 공통 원본 필드 아님 |
| logon_id | 4624는 TargetLogonId, 5145/4698/4699는 SubjectLogonId |
| actor_guid | 이벤트별 자신의/출발 프로세스를 정규화 |
| object / source_ip | 사람이 읽는 요약, 원본 속성명을 보장하지 않음 |
| detail | 가상 맥락·보강·명시적 미확인 |

Defender 행의 GUID는 가상 보강입니다. 실제 내보내기마다 Sysmon GUID가 있다고 기대하지 마세요. 작업 XML도 요약이며 전체 파일은 아닙니다. 서명 상태·전체 명령·파일 내용·접근 권한 원본은 제공하지 않습니다.

실제 사건에는 출처·수집자·획득 시각·도구/버전·해시·접근 이력·변환을 기록한 보호된 증거 목록을 유지합니다. 해시만으로 출처·완전성·증거 인계 이력이 입증되지는 않습니다.

## 4. 첫 판단: 사실과 긴급 질문

06:05 FILE01에서 helper 프로세스의 LSASS 접근·정규화 ASR 차단·.dmp 생성이 관측됩니다. 보존·확대 조사가 필요하지만 자격 증명 덤프 성공·모든 계정 침해·유출을 입증하지는 않습니다.

즉시 확인할 질문은 다음과 같습니다.

1. 출발 수행자가 기록 사이에서 일관되게 식별되나요?
2. ASR이 무엇을 차단했으며 프로세스는 계속 실행되었나요?
3. 현재 호스트·보호 상태·업무 의존성은 무엇인가요?
4. WS01 활동과 FILE01 세션을 신뢰할 증거로 연결할 수 있나요?
5. 어떤 수집 공백이 판단을 제한하나요?
6. 차단이 실제 완료되었나요?

사고 책임자·시스템 담당자와 실제 위험을 우선합니다. 가능한 휘발성 증거를 보존하되 완벽한 타임라인을 위해 필요한 차단을 지연하지 마세요. 결정 이유·비용도 기록합니다.

## 5. 의도 판단 전에 타임라인 만들기

| UTC·근거 | 관측 | 뒷받침되는 주장 |
| --- | --- | --- |
| 06:00 E001–E003 | WS01 A 생성·DNS·통신 | 같은 수행자의 엔드포인트 관측, 내용·의도 미확인 |
| 06:03 E004–E006 | DC 티켓·FILE01 로그온·공유 검사 | 인증·접근 맥락이며 파일 내용 전송 증거 아님 |
| 06:04 E007–E008 | HealthCheckLab·승인 InventoryLab 등록 | 별도 작업·수행자 |
| 06:05–06:06 E009–E013 | FILE01 B·LSASS 접근·차단·파일·종료 | 조사 필요, 추출 미확인 |
| 06:08 E014–E016 | PID 재사용 C·WS02의 같은 작업 경로 | 다른 수명·다른 호스트 객체 |
| 06:12–06:13 E017–E018 | 작업 삭제·Sysmon 오류 | 범위가 제한된 정리·가시성 문제 |
| 06:15–06:16 E019–E020 | APP01 로그온·FILE01 C 통신 | 격리 완료 전의 후속 활동 |
| 06:20 R004 | 격리 완료 응답 | 제공된 최초 완료 응답, 실제 범위 검증 필요 |

정렬은 시작점입니다. 발생·수집 수신·대응 시각을 구분하세요. 늦게 수신된 행이 과거 사건을 설명할 수 있습니다. 워크시트에는 발생/작업 시각만 있어 전달 지연을 계산할 수 없습니다.

## 6. 올바른 호스트에서 인증 연결하기

Security **4624**는 대상 호스트에 로그온 세션을 만듭니다. FILE01의 TargetLogonId `0x7a01`과 같은 호스트 공유·작업 기록의 SubjectLogonId를 후보로 연결합니다. Type 3은 네트워크 로그온이며 대화형 데스크톱 접근이 아닙니다. [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624).

DC **4769**는 서비스 티켓 요청입니다. 서비스 계정명이 전체 SPN이나 특정 원격 실행 프로토콜을 자동 입증하지 않습니다. 성공 상태가 요약되어 있어도 신뢰할 호스트 간 Logon GUID 연결은 제공되지 않습니다. [Microsoft 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769).

**5145**는 접근 검사 관측입니다. 공유·상대 대상·요청 권한·결과를 확인해야 하며 행 하나에 파일 내용·전송량 증거가 있지는 않습니다. [Microsoft 5145](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145).

공유 대상 helper.txt와 작업 동작 helper.exe는 다른 이름이며 내용·해시 연결은 제공되지 않습니다. 비슷한 이름만으로 페이로드 전송·이름 변경을 추정하지 마세요.

DC01·FILE01·WS02·APP01을 같은 로그온 숫자로 합치지 마세요. 사용자명·근접 시각도 특정 프로세스·탈취 자료를 식별하는 키는 아닙니다.

## 7. 지속성 등록과 트리거 실행 구분

E007은 로그온 트리거가 활성화되고 `C:\Lab\helper.exe`를 참조하는 작업입니다. E009에는 같은 실행 파일명의 B가 뒤이어 등장합니다. 유용한 후보지만 작업 실행을 입증하는 자료는 아닙니다.

전체 XML·트리거/Principal/조건·작업 이력·호환 실행 식별자를 확보하세요. 앞선 Type 3 로그온만으로 작업의 로그온 트리거 발동을 입증하지 못합니다. 실제 트리거 의미·실행 이력을 확인해야 하며 생성 권한·승인도 미해결입니다.

E008의 InventoryLab 승인 번호는 기준선 단서이며 주변 모든 프로세스 승인은 아닙니다. E016의 같은 경로·세션 숫자는 **WS02**이므로 별개입니다. E017은 삭제 기록이며 완전 제거가 아닙니다. [Microsoft 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698), [지속성 가이드]({{ '/ko/wiki/windows-persistence/' | relative_url }}).

## 8. 자격 증명 접근과 프로세스 수명

FILE01 GUID 끝 **0202**는 B, **0203**은 이후 인벤토리 C입니다. 둘 다 PID 5200이지만 B 종료 E013 뒤 C가 생성됩니다. C의 DNS·통신을 B에 붙이지 마세요.

이벤트 10의 수행자는 대상 LSASS가 아니라 **출발 프로세스**입니다. Defender E011의 GUID는 보강이며 제품 간 기본 키가 아닙니다. 원본·출처를 재검증한 뒤 연결 확정 여부를 판단합니다.

E010은 접근, E012는 파일 생성이며 자격 증명·파일 내용은 제공하지 않습니다. ASR은 특정 작업을 차단하며 수행자를 반드시 종료하지는 않습니다. 이후 APP01의 NTLM 로그온도 Pass-the-Hash나 자료 출처를 입증하지 않습니다. [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [ASR 정의](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference), [자격 증명 보호]({{ '/ko/wiki/windows-credential-protection/' | relative_url }}).

E018은 오류의 범위를 조사해야 합니다. 전체 수집 유실의 증거도 아니며 오류 뒤 검색이 조용하다고 활동 부재를 입증하지도 않습니다.

## 9. 읽기 전용 워크시트 점검

두 다운로드를 실습 폴더에 게시된 파일명으로 저장하세요. 로컬 파일만 읽으며 호스트 에이전트와 상호작용하지 않습니다.

### A. 시간순 보기

```powershell
$irEvidence = Import-Csv -LiteralPath '.\windows-ir-evidence.csv'
$irEvidence |
  Sort-Object time_utc,evidence_id |
  Select-Object evidence_id,time_utc,host,event_id,account,logon_id,actor_guid,object
```

이 자료의 ISO UTC 형식은 문자열 정렬로 시간순이 됩니다. 화면에 열이 잘릴 수 있어 필요한 행은 전체 확인하세요. object에 적힌 대상을 실행하지 마세요.

### B. 로컬 파일 무결성 기록

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\windows-ir-evidence.csv'
Get-FileHash -Algorithm SHA256 -LiteralPath '.\windows-ir-actions.csv'
```

해시와 함께 획득 시각·출처를 기록합니다. 값이 달라지면 파일 변경·새 다운로드 여부와 정확한 버전을 비교하세요. 공개 교육 파일이며 실제 사건 원본은 아닙니다.

## 10. Splunk 사례 검색

처음 네 검색은 정확한 파일명·헤더로 **직접 설치한 실습용 CSV Lookup**을 사용합니다. 다운로드가 Lookup 설치를 뜻하지 않습니다. 적절한 권한이 있는 승인 실습 공간을 사용하고 운영 인덱스에 이미 존재한다고 가정하지 마세요.

### A. 전체 증거 타임라인

```spl
| inputlookup windows-ir-evidence.csv
| where case_id="IR-LAB-01"
| eval _time=strptime(time_utc,"%Y-%m-%dT%H:%M:%SZ")
| table _time evidence_id host channel event_id account logon_id actor_guid object source_ip detail
| sort 0 _time evidence_id
```

시간 파서는 제공 UTC 형식에 맞습니다. 모든 결과에 근거 ID를 남겨 주장을 추적하세요. 대응 작업은 자동으로 합쳐지지 않습니다.

### B. FILE01 로컬 세션

```spl
| inputlookup windows-ir-evidence.csv
| where case_id="IR-LAB-01" AND host="FILE01" AND logon_id="0x7a01"
| table time_utc evidence_id host event_id account logon_id object detail
| sort 0 time_utc evidence_id
```

예상 결과는 **E005·E006·E007**입니다. WS02의 E016은 제외되어야 합니다. E004에는 이 로컬 키가 없으므로 DC를 억지로 연결하지 마세요.

### C. B의 정규화 수행자 순서

```spl
| inputlookup windows-ir-evidence.csv
| where case_id="IR-LAB-01" AND host="FILE01"
    AND actor_guid="{00000000-0000-0000-0000-000000000202}"
| table time_utc evidence_id channel event_id actor_guid object detail
| sort 0 time_utc evidence_id
```

예상 결과는 **E009–E013**입니다. Defender 행이 포함되는 이유는 실습에서 가상 보강을 명시했기 때문이며 운영에서도 같은 GUID 연결이 제공된다는 증거가 아닙니다. C·WS01 수행자는 분리합니다.

### D. 완료되지 않은 대응 기록

```spl
| inputlookup windows-ir-actions.csv
| where case_id="IR-LAB-01" AND status!="completed"
| table time_utc action_id host action status evidence_ref detail
| sort 0 time_utc action_id
```

예상 결과는 **R001·R005·R006**입니다. R004에서 격리 완료 응답이 와도 R001은 과거 요청 행으로 남습니다. 현재 상태를 자동 갱신하는 표가 아니므로 관련 작업·시간을 함께 검토한 뒤 최종 격리가 미완료인지 판단하세요.

### E. 실제 Windows 세션 조사 템플릿

```spl
index=windows (EventCode IN (4624,5145,4698,4699) OR EventID IN (4624,5145,4698,4699))
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Security" AND endpoint="FILE01"
| eval event_id=coalesce(EventCode,EventID)
| eval local_session=case(event_id=4624,TargetLogonId,
    in(event_id,5145,4698,4699),SubjectLogonId)
| where local_session="0x7a01"
| table _time endpoint event_id local_session TargetUserName SubjectUserName
    LogonType AuthenticationPackageName IpAddress ShareName RelativeTargetName TaskName
| sort 0 _time
```

마지막 검색은 CSV가 아닌 실제 Windows 수집을 가정합니다. 파서·호스트 이름을 매핑하세요. 4624는 TargetLogonId, 나머지는 SubjectLogonId를 명시적으로 선택합니다. 누락은 파싱·수집 질문이지 무관 ID를 대신 넣을 이유가 아닙니다.

운영 검증된 탐지 규칙이 아닙니다. 데이터·권한·필드 형식·수집기 호스트 의미를 확인한 뒤 사용하세요.

## 11. 분석 과제와 해설

| 과제 | 최소한의 근거 있는 답 |
| --- | --- |
| WS01에서 직접 관측된 것은? | E001–E003의 생성·쿼리·연결, 최초 침해 증거는 제공되지 않음 |
| FILE01 0x7a01 연결 범위는? | E005–E007, 서로 다른 원본 Logon ID 필드 설명 |
| 4769가 SMB 파일 전송을 증명하나요? | 아니며 티켓 요청·서비스 사용·내용 전송은 다름 |
| 작업이 B를 실행했나요? | 후보이며 트리거·작업 실행·동작 연결 자료 없음 |
| LSASS 덤프 성공인가요? | 접근·차단·파일명만으로는 미확인 |
| C는 B의 다른 실행인가요? | 다른 GUID·수명이므로 같은 PID여도 별개 |
| 작업 삭제로 차단 완료인가요? | E017은 제한된 정리이며 완료 응답은 R004 |
| APP01은 FILE01 자격 증명 재사용 증거인가요? | 자료 출처·구체 방식·승인 여부가 미확인 |

근거 있는 작업 평가는 **대응이 필요한 다중 호스트 의심 활동이며 지속성·자격 증명 접근 우려가 있으나 최초 침입·추출 성공·유출은 미확인**입니다. 증거를 과장하지 않아도 확대 대응을 정당화할 수 있습니다.

정상 지원/배포, 정상 계정의 악용, 무관 기준선 활동을 대안으로 두세요. 담당자·변경·파일 출처·원본 인증/호스트 자료로 구분합니다. 작업 하나의 승인 번호만으로 사건 전체를 정상 처리하지 마세요.

## 12. 대응 기록과 범위

![증거 평가에서 차단·복구 조건으로 이어지는 결정 흐름]({{ '/assets/diagrams/windows-ir-decisions-ko.svg' | relative_url }})

워크시트는 **요청·완료·대기·계획**을 구분합니다. 요청은 적용 시각이 아닙니다. E019·E020은 06:20 응답 전이므로 격리 후 우회 증거가 아닙니다.

| 결정 | 필요한 범위·확인 |
| --- | --- |
| 호스트 격리 | 개별 장치·완료 응답·허용 관리 경로 |
| 증거 보존 | 원래 호스트·자료·목록·접근 제한·수집 공백 |
| 작업 정리 | 전체 경로/호스트·정의 백업·의존성·별도 프로세스 조사 |
| 신원 대응 | 노출 구간·실제 자료·신뢰 관리 환경·세션/토큰 |
| 도메인 확대 | 도메인/복제/CA 근거, 모든 LSASS 경보에 일괄 적용 금지 |
| 재연결 | 승인 복구·감시 조건·업무 수용·되돌리기 |

즉흥적으로 LSASS 종료·보호 비활성화·도메인 전체 자격 증명 복구를 수행하지 마세요. 신원 담당자와 신뢰 환경에서 범위를 정해 교체·해지합니다. 비밀번호 교체가 모든 세션·인증서를 해지하지는 않습니다.

APP01·WS02 차단, 신원 대응 완료, 파일 내용 검증, 텔레메트리 복구는 입증되지 않았습니다. 인계에 이 공백을 남기세요.

## 13. 복구·소통·종료

재연결 전에 무결성/재구축 결정, 초기 침입·지속성 조사, 관련 신원/세션 조치, 업무 의존성 시험, 정상 모니터링을 기록합니다. E018의 원인을 해결하고 대표 정상 활동의 전체 수집을 확인하세요.

짧은 상태 보고에는 다음을 담습니다.

- **관측:** 근거 ID·호스트·시각·구체 행위.
- **평가:** 가설·신뢰도·대안.
- **조치:** 요청/완료 구분·범위·담당자·시각.
- **미확인:** 영향·자격 증명 노출·누락 자료·수집 공백.
- **다음 결정:** 책임자·필요 증거·복구 허용 조건.

제공된 시점에서 **조사·복구 결정을 위해 열려 있는 사건**입니다. R005는 대기, R006은 계획입니다. 이 자료만으로 성공 종료 보고서를 만들지 마세요.

사후 검토에서는 감사/보존·작업 실행 가시성·신원/호스트 정규화·보호 적용·완료 응답 추적을 담당자가 있는 개선 과제로 만듭니다. 경보 수·작업 삭제만으로 성공을 측정하지 마세요.

## 14. 채점과 관련 학습

다섯 결과물을 각각 0–4점, **총 20점**으로 평가합니다. 타임라인 추적성, 올바른 연결 범위, 사실/가설 분리, 적절한 대응, 정직한 복구 기준이 대상입니다. 만점에는 미확인 유지·요청/완료 구분이 필요합니다.

[Kerberos]({{ '/ko/wiki/kerberos-authentication/' | relative_url }}), [NTLM]({{ '/ko/wiki/ntlm-authentication/' | relative_url }}), [SMB]({{ '/ko/wiki/smb-security/' | relative_url }}), [Windows 로그]({{ '/ko/wiki/windows-logs/' | relative_url }}), [지속성]({{ '/ko/wiki/windows-persistence/' | relative_url }}), [Sysmon]({{ '/ko/wiki/sysmon-investigation/' | relative_url }}), [자격 증명 보호]({{ '/ko/wiki/windows-credential-protection/' | relative_url }})를 복습하세요. 인증서·디렉터리 범위의 근거가 있으면 AD CS·LDAP도 관련되지만 이 사례는 그 침해 증거를 제공하지 않습니다.

**출처 검토: 2026년 10월 22일.** NIST는 조직 대응 관점, Microsoft는 이벤트·통제 해석의 근거입니다. 환경·행·작업·도표·질문·채점은 직접 구성한 가상 교육 자료입니다. 게시 검사는 일치·검색 스키마·구문·제공 상태를 확인하며 실제 사고·호스트 차단·자격 증명 추출·운영 SIEM 실행을 수행하지 않았습니다.
