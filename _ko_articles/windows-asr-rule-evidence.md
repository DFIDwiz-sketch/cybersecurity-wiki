---
title: "Microsoft Defender ASR · 감사·차단·경고 해제 기록 읽기"
description: "공격 표면 감소 규칙의 판정과 적용 설정을 확인하고, 시도한 자식 프로세스가 시작됐는지 별도 증거로 대조합니다."
category: blue-team
tags: [ASR, Microsoft Defender, Windows, Event Logs, Blue Team, Detection Engineering]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/windows-asr-rule-evidence/
---

Excel에서 보고서 도우미가 열리지 않았다는 문의가 들어왔습니다. 해당 단말의 Defender 로그에는 1121 이벤트가 있습니다. 이때는 어느 규칙이 어떤 시도에 적용됐는지 확인하고, 재시도에서 프로세스가 시작됐는지 따로 살펴봐야 합니다. 세 질문에 쓰이는 증거가 각각 다릅니다.

## 1. 정책이 단말에서 적용되는 과정을 따라가기

Microsoft Defender Antivirus의 **공격 표면 감소(ASR)** 규칙은 Office 앱의 자식 프로세스 생성처럼 사전에 정의된 위험 행동을 Windows에서 평가합니다. 정상 파일만 사용해도 위험한 행동은 일어날 수 있으므로 행동 단위 통제가 필요합니다. 반면 승인된 Office 추가 기능도 도우미 프로세스를 실행할 수 있습니다. 규칙에 걸렸다면 업무 맥락과 보안 맥락을 함께 확인하세요.

규칙마다 고유한 식별자 **GUID**와 설정된 동작 모드가 있습니다. Intune 같은 관리 서비스는 단말에 정책을 할당합니다. 단말은 실제 적용 설정과 규칙별 요구 조건, 해당하는 예외를 바탕으로 행동을 평가합니다. 과거 판정을 조사할 때는 당시 정책 자료와 단말 이벤트 시각을 함께 보존하세요. 중앙에서 할당한 정책이나 현재 설정만으로는 당시 단말 상태를 충분히 설명하기 어렵습니다.

<figure>
  <img src="{{ '/assets/diagrams/windows-asr-rule-evidence-ko.svg' | relative_url }}" width="560" height="332" alt="할당된 정책과 단말의 요구 조건을 바탕으로 규칙이 평가됩니다. Defender는 판정을 기록하며, 별도의 프로세스 생성 기록으로 해당 자식 프로세스가 시작됐는지 확인합니다." />
  <figcaption>정책, Defender 판정, 프로세스 시작은 각각 따로 관측합니다.</figcaption>
</figure>

| Defender Operational에서 확인한 기록 | 뒷받침하는 판단 | 더 확인할 점 |
| --- | --- | --- |
| **1122**, 감사(Audit, 모드 2) | 행동이 감사 모드인 규칙에 걸렸습니다. 이 모드에서 ASR은 해당 동작을 차단하지 않습니다. | 자식 프로세스가 시작됐는지, 다른 통제가 개입했는지 확인합니다. |
| **1121**, 차단(Block, 모드 1) | Defender가 ASR 규칙에 따라 특정 동작을 차단했다고 기록했습니다. | 규칙과 차단 동작을 식별하고 별도 시도가 성공했는지 확인합니다. |
| **1129**, 경고 해제(Warn, 모드 6) | 경고 모드에서 해제 조치가 기록됐습니다. | 해당 재시도의 자식 시작 여부와 필요한 경우 승인 주체를 확인합니다. |
| **5007**, 설정 변경 | Defender 설정 변경을 기록했습니다. | 이전 값과 새 값이 조사 중인 ASR 규칙에 해당하는지 확인합니다. |
| 수집 범위에 규칙 기록 없음 | 확보한 소스에 일치 기록이 없었습니다. | 적용 설정, 예외, 센서·전달 상태, 조회 시간과 보존 범위를 확인합니다. |

**현재와 과거의 경고 모드.** 지원되는 규칙과 버전에서는 경고 해제가 24시간 동안 임시로 적용된다고 Microsoft는 설명합니다. Defender 플랫폼 **4.18.26060**부터 해제(Unblock)에 관리자 승인이 필요합니다. 과거 배포 자료에는 다른 승인 절차가 나올 수 있으므로 사건 당시의 플랫폼과 규칙 지원 조건을 확인하세요. 경고 해제 기록은 최초 경고와 이후 프로세스 시작 기록과 각각 구분합니다.

## 2. 한 번의 시도를 시간순으로 재구성하기

가상의 시험 배포에서 09:04 UTC에 `LAB-REPORT-01`의 정상 월간 보고서 작업이 Office 자식 프로세스 규칙에 걸렸습니다. Defender에는 1122가 남았고, 별도 프로세스 로그는 동일 Excel 인스턴스 아래 승인된 도우미가 시작됐음을 보여 줍니다. 규칙을 차단 모드로 전환한 뒤 10:15 UTC에 같은 작업을 했더니 1121이 기록됐습니다. 해당 시도의 시험 로그는 빠짐없이 수집됐고 일치하는 자식 생성은 없었습니다. 업무 담당자도 이 도우미가 해당 기능에 필요하다고 확인했습니다. 이제 담당자와 업무 흐름 및 정책을 검토할 수 있습니다.

Office 자식 프로세스 규칙의 GUID는 `d4f940ab-401b-4efc-aadc-ad5f3c50688a`입니다. Microsoft의 현재 규칙 문서에는 Office 설치 위치 조건(`%ProgramFiles%` 또는 `%ProgramFiles(x86)%`)이 명시돼 있습니다. 의심스러운 Office 문서에서 같은 행동이 관측됐다면 파일의 출처, 부모 프로세스와 대상 실행 파일, 전후의 네트워크·파일 활동을 확인하세요. 예상 밖의 정책 변경으로 관측·차단 범위가 줄어들 수도 있습니다. 의도를 판단하기 전에 승인된 정책 할당과 예외, 관리자의 작업 기록을 대조합니다.

## 3. 원본을 수집하고 별도 증거를 대조하기

1. **범위와 수집 상태를 확인합니다.** 단말, UTC 시각 범위, 이벤트 소스를 기록합니다. Defender Antivirus가 주 백신으로 활성 모드에서 동작하는지, 실시간 보호와 해당 규칙이 지원되는지, 규칙별 클라우드 요건을 충족하는지 확인합니다. OS, Defender 플랫폼·엔진, 정책 출처와 적용 시점, 예외, 로컬 보존 범위와 수집 공백을 남깁니다. 여러 Defender 기능이 채널을 함께 쓰므로 이벤트 ID를 제공자와 채널 범위 안에서 읽습니다.
2. **원본을 보존합니다.** 해당 구간의 EVTX 또는 원본 XML과 소스 정보를 확보합니다. 있는 경우 규칙 GUID, 원본 경로, 사용자, 프로세스와 대상 필드도 보존하세요. 5007은 이전 값과 새 값을 비교하고 관리 측 정책 배포 기록에 연결합니다. 5007 한 건으로 변경 주체나 자식 프로세스의 허용을 알 수는 없습니다.
3. **실행은 별도 기록으로 확인합니다.** 동일 단말에서 프로세스 시작 식별자를 쓰거나, 부모 PID를 **생성 시각과 함께** 비교합니다. 가능한 경우 경로, 시각, 세션도 맞춰 보고 실제 자식 프로세스와 재시도를 구분하세요. Sysmon 이벤트 1은 해당 수집이 구성된 곳에서, Security 4688은 프로세스 생성 감사가 켜진 곳에서 사용합니다. 4688의 명령줄은 별도 정책이 필요합니다. 관측 범위가 불완전하면 이벤트 누락만으로 실행 여부를 결론 내릴 수 없습니다.
4. **증거에 맞춰 대응합니다.** 정상 업무임이 확인되면 업무 담당자, 규칙, 배포 그룹, 영향받는 앱을 기록하고 범위를 한정해 정책을 검토합니다. 설명되지 않는 반복, 의심스러운 프로세스 시작, 예상 밖의 정책 변경이 함께 보이면 관련 자료를 보존하고 정책 출처를 확인한 뒤 단말 사고 대응 절차를 따릅니다. Microsoft는 표준 보호 규칙에 차단을 권장하고, 다른 규칙에는 적용 전 감사 모드 시험을 권장합니다.

Windows에서 로컬 채널을 읽을 권한이 있으면 다음 **읽기 전용** 예제로 최근 24시간의 후보 기록을 찾을 수 있습니다. 사건 기록은 XML에서 다시 확인하세요. 결과가 0건이면 로그나 수집 문제도 점검합니다.

```powershell
$filter = @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  ProviderName = 'Microsoft-Windows-Windows Defender'
  Id = 1121, 1122, 1129, 5007
  StartTime = (Get-Date).AddHours(-24)
}
Get-WinEvent -FilterHashtable $filter |
  Select-Object TimeCreated, MachineName, Id, RecordId, Message
```

Advanced Hunting 권한이 있고 Defender for Endpoint에 온보딩된 단말에서 데이터가 전송되는 경우, 아래 검색으로 해당 Office 규칙의 문서화된 감사·차단 기록을 조회합니다. 경고 해제는 로컬 채널을 확인합니다. `ReportId`는 `DeviceName`과 `Timestamp`를 함께 사용해 식별하세요. 로컬 `RecordId`와 포털의 `ReportId`는 서로 다른 소스의 식별자입니다.

```kusto
DeviceEvents
| where Timestamp >= ago(24h)
| where ActionType in ("AsrOfficeChildProcessAudited", "AsrOfficeChildProcessBlocked")
| project Timestamp, DeviceId, DeviceName, ReportId, ActionType,
    InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime,
    FileName, FolderPath
| order by Timestamp asc
```

## 4. 오프라인으로 방어 판정 검증하기

자기 소유 또는 명시적으로 승인된 작업 환경에서 가상 데이터와 Python 3만 사용합니다. 이 예제는 CSV를 읽으며 네트워크 호출이나 Windows 정책 변경을 하지 않습니다. <a href="{{ '/assets/labs/windows-asr-rule-evidence/asr-cases.csv' | relative_url }}" download="asr-cases.csv">asr-cases.csv</a>를 내려받고, 같은 폴더에 아래 코드를 `review_asr.py`로 저장한 다음 `python3 review_asr.py`를 실행하세요.

예제는 로그 소스를 단순한 이름으로 표기합니다. `attempt`는 사례에 주어진 연결 키이며 Windows 원본 필드가 아닙니다. 실제 조사에서는 독립된 기록의 공통 단서를 바탕으로 연결 근거를 남겨야 합니다.

```python
import csv
from collections import defaultdict

with open("asr-cases.csv", encoding="utf-8", newline="") as stream:
    cases = defaultdict(list)
    for row in csv.DictReader(stream):
        cases[row["case"]].append(row)

decision_names = {"1121": "blocked", "1122": "audited", "1129": "warn-override"}
expected = {
    "audit-and-start": ("audited", True),
    "block": ("blocked", False),
    "warn-only": ("warn-override", False),
    "warn-and-start": ("warn-override", True),
    "other-host": ("audited", False),
    "different-attempt": ("blocked", False),
    "config-only": ("config-only", False),
    "no-rule-evidence": ("no-rule-evidence", False),
}

def review(rows):
    defender = [row for row in rows if row["source"] == "defender-operational"]
    decisions = [row for row in defender if row["event_id"] in decision_names]
    if not decisions:
        changed = any(
            row["event_id"] == "5007" and row["detail"] == "confirmed-asr-setting"
            for row in defender
        )
        return ("config-only" if changed else "no-rule-evidence", False)
    if len(decisions) != 1:
        raise ValueError("Fixture cases must have at most one ASR decision")
    decision = decisions[0]
    started = any(
        row["source"] == "process"
        and row["detail"] == "child-start"
        and decision["attempt"]
        and (row["host"], row["attempt"]) == (decision["host"], decision["attempt"])
        for row in rows
    )
    return decision_names[decision["event_id"]], started

actual = {name: review(rows) for name, rows in cases.items()}
assert actual == expected, f"Expected {expected!r}, got {actual!r}"
for name, (decision, start_seen) in actual.items():
    print(f"{name}: {decision}, matched child start={start_seen}")
```

**기대 결과.** 사례 8건이 검증을 통과합니다. 감사와 경고 해제 사례 중 프로세스 기록까지 같은 단말·시도로 연결되는 두 건만 자식 시작이 확인됩니다. 단말이 다르거나 시도가 다르면 프로세스 기록이 있어도 그 시도의 실행을 뒷받침하지 않습니다. ASR 값이 변한 5007은 설정 변경 증거입니다. 다른 설정을 바꾼 5007이나 다른 소스의 1121에서는 ASR 판정을 도출할 수 없습니다.

**실패 점검.** 두 파일이 있는 폴더에서 실행하고 UTF-8 형식과 열 이름을 유지하세요. 실패도 확인하려면 복사한 CSV에서 `warn-and-start`의 프로세스 행에 있는 단말 이름만 바꾸세요. 해당 프로세스가 다른 단말의 기록이므로 검증에 실패해야 합니다. 비교할 때는 원본 CSV를 복원하세요. Python 실습은 클라우드에서 실행했고, Windows·Defender XDR 예제는 제품 문서와 대조했습니다.

## 5. 확인 문제와 완료 기준

1. **1129가 있으면 자식 프로세스가 실행됐나요?** 경고가 해제됐다는 기록입니다. 해당 시도의 실행은 별도 자료로 확인합니다.
2. **1121 직전의 5007이 차단의 이유를 설명하나요?** 먼저 변경 값과 규칙 GUID를 비교합니다. 시간상 가까워도 다른 설정의 변경일 수 있습니다.
3. **1121이 있고 프로세스 로그가 없으면 사건을 종결해도 되나요?** 수집 범위, 재시도와 전후 활동까지 확인하세요. 1121은 특정 동작에 관한 차단 기록입니다.

규칙과 판정을 설명하고, 근거로 쓴 이벤트 소스와 시각을 제시하고, 어떤 독립 기록이 실행을 뒷받침하는지와 수집 공백 때문에 남는 질문을 말할 수 있으면 학습을 마친 것입니다.

## 공식 참고자료

**검토일 2026-11-27.** 지원되는 Windows의 Microsoft Defender ASR과 수집 가능한 Defender XDR 데이터를 다룹니다. 경고 해제 승인 요구 사항은 Defender 플랫폼 4.18.26060부터 적용됩니다.

- [Microsoft Learn · ASR 개요, 요구 사항과 동작 모드](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
- [Microsoft Learn · Windows 이벤트 채널과 ID](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)
- [Microsoft Learn · Office 규칙 세부 조건과 ASR 규칙 목록](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Learn · ASR 배포 가이드](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment)
- [Microsoft Learn · Get-WinEvent 필터 매개변수](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)
- [Microsoft Learn · Defender XDR DeviceEvents 스키마](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)

- [Microsoft Learn · Security 이벤트 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft Learn · Sysmon 이벤트 1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

[이전 · Defender Antivirus 탐지와 조치]({{ '/ko/wiki/windows-defender-remediation-evidence/' | relative_url }}) · [다음 · Windows App Control 감사와 차단]({{ '/ko/wiki/app-control-evidence/' | relative_url }}) · [프로세스 생성 이벤트와 대조]({{ '/ko/wiki/windows-process-creation-evidence/' | relative_url }})
