---
title: "Linux systemd 타이머 조사 · 예약, 실행, 작업 결과"
description: "디스크 설정, 타이머 상태, 서비스 실행과 작업 결과를 가상 사례 여섯 건과 실제 달력 계산으로 구분합니다."
category: dfir
tags: [Linux, systemd, Journald, DFIR, Blue Team, Purple Team]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/systemd-timer-evidence/
---

서버에 02:00 타이머가 보이는데 백업 보고서가 없습니다. 관리자가 어떤 설정을 읽었는지, 타이머가 발동했는지, 서비스가 실제로 실행됐는지, 백업 시스템이 결과를 받았는지 차례로 확인하세요. 질문마다 필요한 증거가 다릅니다.

## 1. 타이머와 서비스, 한 번의 실행 구분하기

**유닛**은 systemd가 관리하는 단위입니다. `.timer` 유닛은 정해진 시점에 다른 유닛의 활성화를 요청합니다. 보통 이름이 같은 `.service`가 대상이지만 타이머의 `Unit=` 설정으로 다른 대상을 지정할 수 있습니다. `.service` 유닛은 실행할 작업과 실행 방식, systemd가 성공이나 실패로 판단할 조건을 정의합니다. **호출**(invocation)은 유닛의 한 번의 실행 주기입니다. 같은 서비스가 다음에 다시 시작되면 다른 호출 ID가 붙을 수 있습니다.

한 Linux 호스트에 시스템 관리자와 사용자별 관리자가 함께 있을 수 있습니다. 호스트, 부팅, 관리자 범위, 해당 사용자의 UID, 유닛 이름을 같이 기록하세요. 이름이 같아도 관리자 범위가 다르면 별개의 유닛입니다. **드롭인**은 기본 유닛 파일에 합쳐지는 추가 설정 조각입니다. 타이머뿐 아니라 대상 서비스의 기본 파일과 드롭인도 확인하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/systemd-timer-evidence-ko.svg' | relative_url }}" alt="올바른 관리자에서 로드한 타이머와 대상을 확인합니다. 실행 기록이 있으면 서비스 호출을 대조하고, 기록이 없으면 관리자 상태와 저널 수집 범위를 확인합니다. 작업 결과는 앱 기록에서 확인합니다.">
  <figcaption>예약 시각, 관리자 상태, 서비스 실행, 실제 작업 결과에는 각각 다른 증거가 필요합니다.</figcaption>
</figure>

| 질문 | 확인할 자료 | 자료가 보여 주는 범위 |
| --- | --- | --- |
| 무엇이 설치되어 있나요? | `list-unit-files`, `cat`, 기본 파일과 드롭인 경로 | 수집 시점의 유닛 파일과 활성화 설정입니다. 자동 시작을 위한 설정인 `enabled`와 현재 동작 상태인 `active`는 별개입니다. |
| 관리자는 무엇을 사용하나요? | `show` 속성과 `list-timers` | 로드 상태, 활성화 대상, 확인 가능한 다음·이전 타이머 시각입니다. 마지막 발동 시각은 서비스 종료 상태를 보여 주지 않습니다. |
| 무엇이 실행됐나요? | 서비스 저널과 호스트·부팅 ID·범위·호출 ID | 실제로 관측한 실행과 결과입니다. 시각이 가깝다는 사실만으로 시작 원인을 알 수는 없습니다. |
| 작업이 성공했나요? | 해당 실행과 연결된 작업 수신 기록, 대상 시스템의 감사 로그 또는 검증한 산출물 | 증거 범위 안의 애플리케이션 결과입니다. 서비스가 정상 종료해도 기대한 파일은 없을 수 있습니다. |

## 2. 늦게 실행됐다고 판단하기 전에

| 설정 | 시각의 기준 | 조사할 때 확인할 점 |
| --- | --- | --- |
| `OnCalendar=` | 표현식에 지정한 시간대의 시계 시각. 시간대를 생략하면 로컬 시간대 | 실제 시간대를 기록합니다. 일광 절약 시간제(DST) 전후에는 UTC 기준 시각이 달라질 수 있습니다. |
| `OnBootSec=`, `OnStartupSec=` | 각각 부팅 또는 관리자 시작 후 경과 시간 | 사용자 관리자 시작 시점은 호스트 부팅과 다를 수 있습니다. 컨테이너의 시스템 관리자에서는 `OnBootSec=`가 `OnStartupSec=`로 매핑됩니다. |
| `OnUnitActiveSec=`, `OnUnitInactiveSec=` | 대상 유닛의 마지막 활성화 또는 비활성화 후 경과 시간 | 마지막 서비스 상태 전이가 기준입니다. 달력 예약과 경과 시간 조건이 함께 있으면 모두 확인합니다. |
| `AccuracySec=`, `RandomizedDelaySec=` | 여러 타이머의 실행을 묶는 시간 범위와 선택적 임의 지연 | 설정된 두 값을 확인한 뒤 시각 차이가 예상 범위인지 판단합니다. |
| 달력 타이머의 `Persistent=` | 마지막 발동 시각을 저장해, 다시 활성화할 때 비활성 기간의 누락을 보완 | 누락 기간 이후 한 번 발동할 수 있고 지연 설정이 적용될 수 있습니다. 빠진 횟수만큼 모두 실행됐다는 뜻은 아닙니다. |

타이머가 만료되는 순간 대상 서비스가 이미 활성 상태라면 다시 시작되지 않습니다. 타이머 발동 뒤 새 호출이 보이지 않으면 오래 실행되는 작업이나 `RemainAfterExit=`를 확인하세요. 절전, 부팅, 관리자 시작 시점을 예약 구간과 비교하고, 예정값인지 타이머가 기록한 값인지 서비스나 앱이 남긴 값인지 구분하세요.

## 3. 정상 실행을 따라가고 다른 가능성 살피기

가상 사례 `T01`에서 `report-index.timer`는 시스템 관리자에서 활성 상태입니다. 예정 시각은 02:00 UTC입니다. 실행을 묶는 구간이 1분이고 별도 임의 지연이 0일 때, 마지막 타이머 이벤트가 02:00:42라면 설정 범위와 맞습니다. 서비스 역시 02:00:42에 시작했습니다. 실습표에서 호출 `inv-a`가 정상 종료됐고, 보고서 저장소의 수신 기록도 독립적으로 이 호출과 일치합니다. 따라서 보고서가 만들어졌다고 판단할 근거가 있습니다. 두 시각이 같다는 이유만으로는 서비스의 직접적인 시작 계기를 확정할 수 없습니다.

`T03`에서는 타이머 이벤트와 서비스 호출이 모두 있지만 서비스가 0이 아닌 종료 코드로 실패했습니다. 타이머 미실행으로 분류하기 전에 호출의 오류와 앱 출력을 확인하세요. `T06`에서는 타이머 이벤트 시각에 승인된 운영자의 수동 실행 요청도 별도 기록에서 확인됐습니다. 양쪽에서 같은 서비스의 시작을 요청할 수 있으므로 무엇이 관측됐는지 각각 기록하고, 시각만으로 시작 원인을 하나로 단정하지 않습니다.

스케줄러는 기존 계정 권한으로 승인되지 않은 작업을 실행하는 데에도 악용될 수 있습니다. 대상 유닛, 실행 계정, 실행 파일이 예상과 다르면 신뢰할 수 있는 기준 상태와 비교하세요. 패키지 업데이트, 자동 배포, 복구 도구, 관리자 작업에서도 구성 변경은 일어납니다. 익숙한 타이머 이름보다 실제로 로드된 서비스 설정을 먼저 확인하고 변경 출처를 대조하세요.

## 4. 상태를 바꾸지 않고 수집과 대응하기

승인된 systemd 호스트에서 관리자에 연결할 수 있고 저널을 읽을 권한이 있을 때 아래 조회 명령을 사용합니다. 예시 이름은 조사 중인 타이머와 실제 대상으로 바꾸세요. 사용자 타이머는 해당 사용자 관리자에 연결되는 세션에서 `systemctl --user`와 `journalctl --user`를 사용하고, `journalctl --user`에 필요한 영구 저널 저장과 읽기 권한을 확인합니다. 먼저 목록에서 연결 대상을 찾으세요. 타이머 이름의 확장자만 바꿔 추측하면 다른 서비스를 조사할 수 있습니다.

```bash
systemctl --no-pager list-timers --all
systemctl --no-pager list-unit-files --type=timer

timer=report-index.timer
service=report-index.service
systemctl --no-pager cat "$timer" "$service"
systemctl --no-pager show "$timer" \
  -p FragmentPath -p DropInPaths -p LoadState -p UnitFileState \
  -p ActiveState -p SubState -p Unit -p NeedDaemonReload \
  -p TimersCalendar -p TimersMonotonic -p LastTriggerUSec \
  -p NextElapseUSecRealtime -p NextElapseUSecMonotonic
systemctl --no-pager show "$service" \
  -p FragmentPath -p DropInPaths -p ActiveState -p Result \
  -p ExecMainStatus -p InvocationID -p User -p DynamicUser -p ExecStart
journalctl --no-pager --utc -o json -u "$timer" -u "$service" \
  --since '2026-11-21 01:45:00 UTC' --until '2026-11-21 02:20:00 UTC'
```

1. **수집 범위를 남깁니다.** 수집 시각, 시간대, 호스트, 부팅과 systemd 버전을 기록합니다. 시스템 관리자와 사용자 관리자는 별도 확인이 필요합니다. `list-timers --all`은 관리자가 메모리에 보유한 타이머를 보여 주고, `list-unit-files`는 유닛 파일과 자동 시작 설정을 보여 줍니다. `cat`은 디스크를 읽고 `show`는 관리자가 로드한 속성과 현재 상태를 보여 줍니다. 속성이 없거나 시각이 비어 있거나 상태가 `inactive`인 것은 서로 다른 관측입니다. 다시 읽기가 필요하다는 표시는 단서로 활용하고, 양쪽 설정을 실제로 비교해 보존하세요.
2. **해당 실행을 찾습니다.** 예상 지연, 가동 중단, 로그 전달 지연을 고려해 검색 구간을 넓힙니다. `Result`와 `ExecMainStatus`는 조회 시점의 속성이므로 과거 실행은 시각이 있는 저널로 찾습니다. JSON에서 `_BOOT_ID`, `__REALTIME_TIMESTAMP`, `__MONOTONIC_TIMESTAMP`와 확인 가능한 호출 ID를 보존합니다. 단조 시계 타임스탬프는 같은 부팅 안에서 비교하세요. 앱 프로세스 메시지에는 `_SYSTEMD_INVOCATION_ID`가 있을 수 있고 관리자 메시지는 다른 필드를 사용할 수 있습니다. 기록이 빠졌다면 [Linux 저널 수집 조사]({{ '/ko/wiki/linux-journal-coverage/' | relative_url }})로 로컬과 중앙 수집 범위를 확인합니다.
3. **변경 근거와 실제 효과를 대조합니다.** 로드된 대상, 서비스 계정, 실행 파일을 배포 이력과 시스템 기준 상태에 맞춰 봅니다. 차이가 예상 밖이면 파일 원본과 소유권, 해시, 심볼릭 링크, 수집 중인 파일 변경 감사 자료를 확보합니다. 수정 시각만으로 변경자를 식별할 수는 없습니다. 앱의 작업 ID, 쓰기 기록, 검증 가능한 산출물 등을 서비스 호출과 연결합니다.
4. **근거에 맞게 대응합니다.** 예상된 작업의 서비스 실패라면 담당자에게 호출 ID와 오류를 전달합니다. 여러 증거가 예상 밖 대상을 뒷받침하면 사고 대응 절차로 넘깁니다. 당시 로드 상태를 먼저 보존하고, 정상 유지보수 작업에 미칠 영향을 검토해 격리 범위를 조율합니다. 복구 후에는 승인된 설정과 저널 수집, 다음 예정 실행의 실제 결과를 다시 확인합니다.

## 5. 오프라인 사례 실습과 실제 시각 계산

[가상 기록표]({{ '/assets/labs/systemd-timer-cases.csv' | relative_url }})와 [Python 확인 스크립트]({{ '/assets/labs/systemd-timer-review.py' | relative_url }})를 같은 폴더에 내려받으세요. 기록표는 수집 결과를 요약한 실습 자료입니다. `loaded_matches_disk`와 `journal_coverage`는 조사자가 비교해서 채운 열입니다. 빈 칸은 이 실습에서 증거가 없다는 뜻이며, `inv-a`, `inv-c`, `inv-f`는 실습용 호출 이름입니다. 스크립트는 이 파일만 읽습니다.

1. CSV를 열고 행마다 설치·동작 상태, 호출, 앱 결과, 시작 계기의 증거, 저널 수집 범위를 따로 적습니다.
2. Python 3으로 결론을 확인합니다. 마지막에 `6 synthetic cases checked.`가 나옵니다.

```bash
python3 systemd-timer-review.py
```

| 사례 | 기대 결과와 다음 확인 |
| --- | --- |
| `T01` | 서비스 실행과 수신 기록이 있습니다. 정확한 시작 계기는 결론을 보류합니다. |
| `T02` | 자동 시작 설정은 되어 있으나 현재 비활성입니다. 언제 왜 비활성화됐는지 확인합니다. |
| `T03` | 서비스 호출이 있었고 실패했습니다. 해당 호출의 오류를 읽습니다. |
| `T04` | 사용자 타이머 발동이 기록됐고 서비스 실행 증거가 비어 있습니다. UID 1001의 관리자 범위, 부팅, 저널 접근을 확인합니다. |
| `T05` | 로드 설정과 디스크 설정이 다릅니다. 두 자료를 보존한 뒤 변경 이력을 확인합니다. |
| `T06` | 실행과 수신 기록, 수동 실행 요청이 각각 확인됩니다. 어느 요청이 실행과 연결됐는지 추가 증거를 찾습니다. |

`systemd-analyze`와 해당 옵션을 지원하는 Linux에서는 서비스를 실행하지 않고 **예정 시각** 두 개만 계산할 수 있습니다.

```bash
LC_ALL=C TZ=UTC systemd-analyze --base-time='2026-11-21 01:55:00 UTC' \
  --iterations=2 calendar '*-*-* 02:00:00 UTC'
```

UTC 결과는 `2026-11-21 02:00:00`과 `2026-11-22 02:00:00`입니다. “From now” 상대 시간 대신 이 시각을 읽으세요. 스크립트가 CSV를 찾지 못한다면 원래 파일 이름과 저장 위치를 확인합니다. 달력 계산 옵션을 지원하지 않으면 설치 버전과 로컬 매뉴얼을 확인하세요. 컨테이너나 systemd를 쓰지 않는 환경에서 관리자 조회가 실패하면 기록표로 연습합니다. 관리자에 연결하지 못했다는 사실만으로 타이머 상태를 판단할 수는 없습니다.

**검증 범위.** Python으로 가상 사례 여섯 건을 확인했고 systemd 257.13에서 달력 계산 명령을 실행했습니다. 실제 관리자·저널 조회 명령은 업스트림 문서에서 확인했습니다. 실습표의 서비스 실행과 앱 작업 결과는 가상입니다.

## 6. 확인 문제와 해설

1. **타이머 파일이 `enabled`인데 타이머가 `inactive`입니다. 오늘 서비스가 실행됐나요?** 현재의 설정과 상태로 과거 실행을 알 수는 없습니다. 같은 관리자 범위에서 해당 부팅과 서비스 이력을 확인하세요.
2. **타이머와 서비스 시작 시각이 같습니다. 타이머가 서비스를 실행했다는 증거인가요?** 조사 단서로 활용합니다. 수동 요청이나 다른 시작 경로가 가능하다면 관리자 메시지나 감사 기록처럼 별도의 증거를 대조합니다.
3. **서비스는 성공했는데 보고서 수신 기록이 없습니다. 작업 성공으로 종결해도 되나요?** 관측된 서비스 결과를 남기고 해당 호출의 산출물이나 대상 시스템 기록을 별도로 검증합니다.
4. **디스크 설정의 대상과 `show`의 대상이 다릅니다. 무엇을 보존하나요?** 수집 시각과 함께 둘 다 보존합니다. 로드 상태는 관리자에 남은 설정을, 파일은 그 시점 디스크에 놓인 내용을 보여 줍니다. 사건 시점과 수집 시점 사이 변경은 별도 증거가 필요합니다.

**완료 기준.** 여섯 사례를 각각 설명하고 도구가 있다면 예정 시각 두 개를 계산합니다. 사례 하나를 골라 타이머 발동, 서비스 호출, 앱 결과와 아직 불확실한 점을 구분해 짧은 조사 메모로 남깁니다.

## 7. 공식 참고 자료와 다음 학습

**2026-11-21**에 업스트림 systemd **262** 매뉴얼을 검토했습니다. 달력 계산은 **257.13**에서 실행했습니다. 운영 환경에서는 호스트 설치 버전에 맞는 매뉴얼로 옵션과 필드를 확인하세요.

- 시계 기준, 지연, 누락 보완, 대상이 이미 활성 상태일 때의 동작. [systemd.timer](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html) · [systemd.time](https://www.freedesktop.org/software/systemd/man/latest/systemd.time.html)
- 관리자 조회, 유닛 파일 검색 경로, 관리자 속성과 서비스 설정. [systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html) · [systemd.unit](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) · [관리자 D-Bus 속성](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html) · [systemd.service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- 유닛별 저널 필터, 저널 메타데이터, 예정 시각 계산. [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html) · [저널 필드](https://www.freedesktop.org/software/systemd/man/latest/systemd.journal-fields.html) · [systemd-analyze](https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html)

이전 학습 · [Linux 저널 수집 조사]({{ '/ko/wiki/linux-journal-coverage/' | relative_url }})  
다음 학습 · [Linux 프로세스 조사]({{ '/ko/wiki/linux-process-evidence/' | relative_url }})

한 번의 실행을 더 자세히 추적하려면 [systemd 서비스 호출 조사]({{ '/ko/wiki/systemd-service-invocation-evidence/' | relative_url }})를 참고하세요.
