---
title: "Windows 프로세스 생성 조사 · 4688과 4689 연결하기"
description: "생성 요청자와 실행 주체를 구분하고, PID 수명을 확인하는 Windows 이벤트 XML 오프라인 실습입니다."
category: dfir
tags: [Windows, Windows Security, Event Logs, Process Creation, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/windows-process-creation-evidence/
---

**학습 목표.** Windows에서 무엇이 시작됐고, 누가 생성을 요청했으며, 어느 프로세스가 생성 주체 후보인지 판단합니다. 이후 파일 변경이나 통신 같은 결과를 확인하려면 어떤 증거가 필요한지도 구분합니다.

## 1. 생성 기록에서 역할 나누기

**프로세스**는 프로그램이 실행되는 인스턴스입니다. **PID**는 같은 호스트에서 동시에 실행되는 프로세스를 구별하는 번호입니다. 프로세스가 끝나면 다른 프로세스가 같은 번호를 받을 수 있습니다. **로그온 세션**은 인증 후 만들어진 보안 맥락입니다. **Logon ID**는 해당 시스템과 부팅 범위의 세션을 식별하는 값이며 PID와는 별개입니다. **액세스 토큰**에는 프로세스의 신원, 그룹, 특권 등의 보안 정보가 담깁니다.

| 기록 또는 필드 | 확인할 수 있는 내용 | 보존할 값 |
| --- | --- | --- |
| 보안 로그 4688 | 프로세스 생성 성공 감사가 적용된 환경에서 프로세스가 시작됐습니다. | 호스트, UTC 시각, 버전, 레코드 ID, 새 PID와 실행 파일 경로 |
| Creator Subject | 생성을 요청한 계정과 세션입니다. | 요청자의 SID와 Logon ID |
| Target Subject | 버전 2에서 기록된 경우, 요청자와 구분되는 실행 맥락입니다. | 요청자와 분리한 대상 SID와 Logon ID |
| Creator Process ID·Name | 이벤트에 기록된 생성자 PID와 확인 가능한 실행 파일 경로입니다. | 4688 XML의 `ProcessId`와 `ParentProcessName` |
| 보안 로그 4689 | 프로세스 종료 성공 감사가 적용된 환경에서 종료가 관측됐습니다. | 종료 시각, `ProcessId`, `ProcessName`, 기록된 종료 상태 |
| Sysmon 1·5 | Sysmon이 설치돼 있고 해당 이벤트를 수집할 때의 생성·종료 기록입니다. | `ProcessGuid`, 호스트, UTC 시각, PID, 이미지 경로 |

4688 원본 XML에서 새 프로세스 PID는 `EventData/NewProcessId`이고, 생성자 PID는 `EventData/ProcessId`입니다. `EventData` 아래의 이름 있는 `Data` 요소를 읽어야 합니다. `System/Execution`의 속성은 이벤트 공급자의 실행 메타데이터입니다. Microsoft 문서상 `CommandLine`은 버전 1부터 있고 대상 주체, 무결성 레이블, 생성자 경로는 버전 2에 추가됐습니다. 필드 순서 대신 이름을 사용하고 빈 값과 누락을 구분하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-process-creation-ko.svg' | relative_url }}" alt="같은 호스트와 부팅에서 생성자 후보가 먼저 시작하고, 다음 4688에 새 프로세스와 생성자가 기록됩니다. 4689는 PID의 종료 시각을 알려 줍니다. 이후 같은 번호를 받은 프로세스는 별도의 실행입니다.">
  <figcaption>같은 호스트와 부팅에서 시작해 생성과 종료를 대조하며, 생성자 PID가 어느 실행에 해당하는지 판단합니다.</figcaption>
</figure>

## 2. 정상적인 실행 따라가기

가상의 `workstation-a.example`에서 보고서 서비스가 상태를 읽는 프로그램을 시작한다고 가정합니다.

1. 08:00 UTC의 4688에 보고서 실행 도구가 PID `0x410`(10진수 1040)으로 기록됩니다. 08:02의 다른 4688에는 생성자 PID `0x410`과 새 PID `0x5b0`(10진수 1456), 두 실행 파일의 경로가 나타납니다. 경로, 호스트, 부팅과 시각을 맞추고 생성자 후보와 충돌하는 다른 기록이 있는지 확인합니다.
2. 요청자 SID는 서비스 계정입니다. 버전 2의 Target Subject에는 다른 실행 맥락이 기록될 수 있습니다. 유효한 대상이 있다면 대상 SID와 Logon ID를 이용해 해당 4624를 요청자의 세션과 따로 확인합니다. `S-1-0-0` 같은 자리표시 SID나 0인 Logon ID만으로 별도 세션이 있다고 판단할 수 없습니다. 대상이 기록되지 않았고 판단에 꼭 필요하다면 미확인으로 남깁니다.
3. 08:04의 4689에 작업 종료가 기록됩니다. 08:09 편집기가 같은 PID `0x5b0`을 받습니다. 두 기록은 별도의 실행 수명입니다. 이후 1456으로 남은 기록은 시각과 실행 파일을 다시 맞춰야 합니다. 수집 범위 안에서 Sysmon의 ProcessGuid로 더 안정적으로 연결할 수 있습니다. 4688 원본에는 ProcessGuid가 없으므로 GUID를 다른 로그와 연계할 때는 단말, 시각, PID, 이미지 경로를 먼저 확인합니다.
4. 명령줄에는 시작할 때 전달한 인수가 들어 있습니다. 모든 인수가 실행에 사용됐는지, 스크립트의 각 명령이 성공했는지, 파일이나 통신 작업이 완료됐는지는 별도 기록에서 확인합니다. 높은 무결성이나 상승된 토큰은 실행 환경의 정보이며 특정 특권을 썼다는 증거는 아닙니다.

## 3. 수집, 탐지, 대응하기

평소와 다른 생성자–자식 조합은 정상 관리 도구를 쓴 오용의 단서가 될 수 있습니다. 승인된 배포, 접근성 도구, 예약 작업도 드문 조합을 남깁니다. 실행 파일 경로, 생성자, 세션, 장비 역할과 변경 창을 함께 확인하세요.

1. **원본 수집 범위를 점검합니다.** 유효한 고급 감사 정책에서 Audit Process Creation과 필요한 경우 Audit Process Termination을 확인합니다. 명령줄 수집에는 별도의 **Include command line in process creation events** 설정과 해당 이벤트 버전이 필요합니다. 빈 값은 인수가 없었다는 증거가 아닙니다. 원본 XML과 전달본을 대조하고 정책, 버전, 채널 보존 기간과 필드 변환을 검토합니다. 명령줄에는 비밀번호와 개인정보 등이 평문으로 들어갈 수 있으므로 원본 접근을 제한하고 공유본은 필요한 내용을 가립니다.
2. **식별자와 시각을 보존합니다.** 공급자, 채널, 발생 컴퓨터, 원본 UTC 시각, 버전, 레코드 ID를 남깁니다. 수집기 이름과 수집 시각은 전달 과정의 정보입니다. 4688에는 부팅 ID가 없으므로 별도 자료에서 부팅 구간을 확인합니다. PID는 16진수와 10진수를 맞추되 원래 표기도 보존합니다. 앞선 생성, 관측된 종료, 뒤이은 재사용으로 실행 범위를 좁힙니다. 종료 로그는 정책이나 보존 범위 때문에 빠질 수 있으므로 PID만의 연결은 조건부로 다룹니다.
3. **의심한 동작을 별도 확인합니다.** 처음 보는 조합은 평소 경로, 서비스·예약 작업 목록, 승인된 변경 이력과 대조합니다. 쓰기가 의심되면 수집된 파일 이벤트를, 연결이 의심되면 단말이나 네트워크 기록을 확인합니다. 기록이 없다는 이유로 동작을 배제하기 전에 수집 범위를 점검합니다. 생성자 이름이나 토큰 수준, 인수 하나만으로 침해를 확정할 수 없습니다.
4. **근거를 확보한 뒤 대응합니다.** 워크로드를 변경하기 전에 원본 타임라인과 관련 로그를 보존합니다. 침해를 뒷받침하는 경우 영향받은 프로세스 수명과 세션 범위를 찾고 자산 담당자와 격리 여부를 결정합니다. 정책이나 파서를 수정했다면 정상 프로그램 실행으로 같은 이벤트와 연결 조건이 유지되는지 재검증합니다.

### 읽기 전용 이벤트 조회

승인된 Windows 호스트에서 이벤트 감사 정책이 적용되고 보안 로그를 읽을 권한이 있을 때 PowerShell로 조회합니다. 예시는 최근 15분을 대상으로 합니다. 실제 조사 시 조회 시간을 바꾸세요. 결과는 승인된 위치에만 보존하며, `Properties` 순서에 의존하기보다 XML의 필드 이름을 확인합니다.

```powershell
$end = Get-Date
$start = $end.AddMinutes(-15)
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  ProviderName = 'Microsoft-Windows-Security-Auditing'
  Id = 4688, 4689
  StartTime = $start
  EndTime = $end
} | ForEach-Object { $_.ToXml() }
```

이 명령은 이벤트별 XML 문자열을 출력합니다. EVTX 내보내기나 아래 사례 형식과는 다릅니다. 대조 시험은 승인된 시스템에서 정상 프로그램 하나를 실행하고 호스트와 시각을 적어 진행합니다. 기대한 생성·종료가 보이지 않으면 전달 경로보다 원본 정책과 로컬 기록을 먼저 확인합니다. 현재의 대조 시험이 과거의 수집 공백을 복구하지는 않습니다.

## 4. 가상 이벤트 XML 실습

승인된 작업 공간의 같은 폴더에 <a href="{{ '/assets/labs/windows-process-creation-evidence.py' | relative_url }}" download="windows-process-creation-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/windows-process-creation-cases.xml' | relative_url }}" download="windows-process-creation-cases.xml">사례 XML</a>을 저장합니다. Python 3.9 이상이 필요합니다. 사례에는 실제 스키마 이름을 쓰는 축약 가상 이벤트가 들어 있습니다. 사례 이름, 부팅 주석, 기대값은 실습 형식이 추가한 항목이며 4688의 원본 필드가 아닙니다. 스크립트는 파일만 읽고 Windows 프로그램을 실행하거나 감사 정책을 바꾸지 않습니다.

```bash
python3 windows-process-creation-evidence.py windows-process-creation-cases.xml
```

| 사례 | 기대 결과 |
| --- | --- |
| `routine_creator` | 앞선 생성자 후보 한 건과 기록된 인수 확인 |
| `reuse_after_exit` | 같은 PID의 이전 종료를 확인하고 새 실행 수명과 연결 |
| `different_target` | 요청자와 실행 대상의 세션 식별자가 다름 |
| `blank_command` | 명령줄 필드는 있으나 값은 비어 있음 |
| `older_schema` | 버전 0에 명령줄 필드가 없음 |
| `different_boot` | 다른 부팅의 같은 PID를 연결하지 않음 |
| `reuse_without_exit` | 같은 PID의 뒤이은 시작이 이전 실행과 구분됨. 정확한 이전 종료는 미관측 |
| `creator_image_mismatch` | 앞선 PID 기록은 있으나 생성자 경로가 일치하지 않음 |

여덟 사례가 모두 PASS여야 합니다. 복사한 XML의 `routine_creator`에서 생성자의 부팅 주석을 바꾸고 새 프로세스의 부팅은 그대로 두세요. 생성자 후보가 사라져 원래 기대값과 달라져야 합니다. 파일을 읽지 못하면 이름과 경로를 확인하세요. 연결이 예상과 다르면 부팅 주석, UTC 순서, 이름 있는 PID 필드와 생성자 경로를 다시 확인합니다.

가상 XML 실습은 클라우드에서 실행했습니다. PowerShell 조회와 감사 정책, Sysmon 동작은 Microsoft 문서로 검토했습니다. 실제 Windows 감사 설정이나 Sysmon 수집기를 대상으로 실행한 것은 아닙니다.

## 5. 판단 확인하기

- **4688에 새 PID, 생성자 PID, System Execution PID가 있습니다. 생성자를 찾으려면 어느 값을 쓰나요?** 이름이 `ProcessId`인 `EventData` 필드로 실행 수명을 확인합니다. System Execution은 이벤트 기록 쪽의 메타데이터입니다.
- **현재 작업 목록의 10진수 PID가 어제 로그와 같습니다. 같은 프로세스인가요?** 호스트, 부팅, 실행 수명과 경로를 비교하세요. 종료된 프로세스의 PID는 재사용될 수 있습니다.
- **원본 명령줄이 비어 있으면 인수가 없었나요?** 이벤트 버전, 명령줄 감사 설정과 수집 범위를 봅니다. 인수가 있어도 값이 비어 있을 수 있습니다.

여덟 사례를 통과하면 무엇이 시작됐는지, 어느 계정이 요청했고 어느 실행 맥락이 기록됐는지 정리하세요. 생성자 후보와 후속 동작을 확인할 별도 증거 한 가지를 함께 기록하면 완료입니다.

## 공식 참고자료

2026년 11월 26일 검토. 이벤트 필드와 버전은 Microsoft Windows 감사 문서에 따릅니다. 환경에 적용된 Windows와 Sysmon 빌드, 실제 정책과 이벤트 버전을 확인하세요.

- 이벤트 XML, 버전과 필드. [4688 프로세스 생성](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) · [Execution 요소](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-execution-systempropertiestype-element) · [4689 프로세스 종료](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4689)
- 감사 정책과 명령줄 설정. [Audit Process Creation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-process-creation) · [Audit Process Termination](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-process-termination) · [IncludeCmdLine 정책](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-auditsettings#includecmdline)
- 보완 기록과 필터 조회. [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) · [Get-WinEvent FilterHashtable](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)

[이전 글 · Windows 보안 이벤트 조사 입문]({{ '/ko/wiki/windows-logs/' | relative_url }}) · [다음 글 · Sysmon 프로세스 조사]({{ '/ko/wiki/sysmon-investigation/' | relative_url }}) · [관련 글 · Windows 특권 로그온 조사]({{ '/ko/wiki/windows-privileged-logon-evidence/' | relative_url }})

## 레지스트리 쓰기와 변경한 프로세스 연결하기

[Windows 레지스트리 변경 조사]({{ '/ko/wiki/windows-registry-change-evidence/' | relative_url }})에서 Security 4657과 Sysmon의 레지스트리·프로세스 수명 기록을 대조하는 방법을 확인하세요.
