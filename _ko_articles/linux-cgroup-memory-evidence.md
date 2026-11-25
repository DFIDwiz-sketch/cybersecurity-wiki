---
title: "Linux cgroup 메모리 조사 · 압박과 OOM 종료 구분하기"
description: "cgroup v2 카운터, 로그, 오프라인 실습으로 메모리 회수와 한도 압박, 프로세스 종료를 구분합니다."
category: dfir
tags: [Linux, cgroup v2, OOM, systemd, DFIR, Blue Team]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/linux-cgroup-memory-evidence/
---

**학습 목표.** 워크로드가 느려지거나 갑자기 종료됐을 때 메모리 카운터의 의미를 설명합니다. 영향을 받은 프로세스와 cgroup을 찾고, OOM 종료와 다른 종료 원인을 구분합니다.

## 1. 메모리 cgroup은 무엇을 측정하나요?

**제어 그룹(cgroup)**은 프로세스를 계층으로 묶어 자원을 관리합니다. **cgroup v2**에서는 워크로드의 말단 그룹이 서비스나 슬라이스 아래에 놓일 수 있고, 상위 그룹의 한도도 영향을 줄 수 있습니다. 메모리 사용량에는 프로세스의 전용 할당량 외에 그룹에 귀속된 페이지 캐시 등이 포함될 수 있습니다. **메모리 회수(reclaim)**는 메모리를 확보하거나 재사용하게 하는 작업입니다. **PSI(Pressure Stall Information)**는 자원 경합으로 작업이 지연된 시간을 기록합니다. **OOM(Out of Memory)**은 적용되는 제약 안에서 커널이 특정 메모리 할당을 만족시키기 어려운 상태입니다. 커널은 메모리를 확보하려고 프로세스를 종료할 수 있습니다.

| 증거 | 뒷받침하는 내용 | 다음 확인 |
| --- | --- | --- |
| `memory.current`, `memory.stat` | 현재 메모리 사용량과 구성 | 이전 샘플과 평소 사용량 비교 |
| `memory.high`, `high` 이벤트 | 경계를 넘어 실행이 느려지고 메모리 회수 작업이 일어남 | PSI와 응답 지연을 비교합니다. 이 경계 초과 자체로 커널 OOM killer가 실행되지는 않습니다. |
| `memory.max`, `max` 이벤트 | 하드 한도를 넘으려는 시도가 있었음 | 회수에 성공할 수 있으므로 `oom`과 실제 종료 기록을 확인합니다. |
| `oom`, `oom_kill` 이벤트 | 각각 한도 근처에서의 할당 압박, 커널 OOM killer에 종료된 그룹 소속 프로세스 수 | 대상 프로세스와 한도를 적용한 범위를 로그에서 확인합니다. |
| `memory.pressure` | 일부 작업 또는 유휴 상태가 아닌 모든 작업이 메모리 때문에 지연된 시간 | 같은 시간대의 서비스 영향과 압박 지속 여부를 확인합니다. 종료 건수를 세는 값은 아닙니다. |

기본 설정에서 `memory.events`는 하위 그룹의 이벤트를 집계합니다. `memory_localevents` 마운트 옵션을 쓰면 이 동작이 달라집니다. `memory.events.local`에는 해당 그룹 자체의 이벤트가 기록됩니다. 카운터는 그룹이 존재하는 동안 누적되므로 호스트, 부팅, cgroup 인스턴스가 모두 같은 두 기록을 비교합니다. 커널이 필드를 추가할 수 있으니 항목의 줄 위치 대신 키를 읽습니다. 필드나 파일이 없으면 해당 상태는 미확인으로 남깁니다. PSI의 `some`은 적어도 한 작업이 지연된 시간, `full`은 유휴 상태가 아닌 모든 작업이 동시에 지연된 시간입니다. 평균은 10초, 60초, 300초를 기준으로 표시합니다. `total`은 마이크로초 단위의 누적 지연 시간입니다. 비슷한 구간에서 같은 지표를 비교하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-cgroup-memory-ko.svg' | relative_url }}" alt="워크로드가 메모리를 사용하면 감속 경계나 하드 한도에 닿을 수 있습니다. 카운터와 PSI는 자원 상태를, 커널과 서비스 로그 및 프로세스 신원은 종료 대상과 원인을 확인하는 데 쓰입니다.">
  <figcaption>자원 상태와 서비스 영향을 연결한 뒤 독립적인 증거로 종료 여부와 원인을 확인합니다.</figcaption>
</figure>

## 2. 정상적인 사용량 증가와 재시작 따라가기

가상의 `report.slice`에 속한 보고서 작업이 평소보다 큰 데이터를 처리합니다. 처음 설정된 감속 경계는 256 MiB, 하드 한도는 384 MiB입니다. 상태 파일의 바이트 수를 읽을 때 1 MiB는 1,048,576바이트입니다. 설정값 `max`는 해당 그룹의 해당 설정에 제한이 없다는 뜻입니다. 상위 그룹의 한도도 확인하세요.

1. 작업 중 사용량이 300 MiB에 가까워집니다. 말단 그룹의 `high` 카운터가 5에서 18로 늘고 `oom_kill`은 0입니다. PSI에서 지연이 나타난 시간대에 서비스 응답도 느려졌습니다. 이후 사용량이 내려가고 기존 프로세스는 계속 동작합니다. 이 기록은 해당 시간의 회수와 감속을 뒷받침합니다.
2. 배포 이후 별도 사건에서는 부모와 말단 그룹 모두 `oom_kill`이 증가했지만 부모의 로컬 카운터는 그대로입니다. 기본 집계 방식에서는 같은 종료가 두 파일에 나타날 수 있습니다. 어느 하위 그룹에 영향이 있었는지 확인합니다.
3. 같은 시간대의 커널 로그는 종료된 호스트 PID와 제한을 적용한 그룹을 기록하고, 워크로드는 종료 후 재시작을 기록합니다. 부팅, 프로세스 수명, cgroup 인스턴스와 시간을 기준으로 대조하세요. 종료된 프로세스의 소속 그룹만으로 어느 상위 그룹이 한도를 적용했는지 알 수 없습니다. 작업이 재시작하면 현재 사용량이 낮아지거나 cgroup이 새로 생길 수 있습니다. 새 카운터는 해당 인스턴스의 상태입니다.

감독 프로세스는 `SIGKILL`에 의한 종료를 기록할 수 있습니다. 종료 상태 137도 널리 쓰이는 `128 + 9` 표현과 일치하지만, 어디서 신호를 보냈는지 알려주지는 않습니다. `systemd-oomd`가 활성화된 환경에서는 메모리 압박이나 스왑 정책에 따라 그룹을 선택해 사용자 공간에서 `SIGKILL`을 보낼 수 있습니다. oomd 저널을 찾아 종료된 그룹과 맞춰 보고 커널 OOM 종료와 구분하세요.

## 3. 수집, 탐지, 대응하기

평소보다 큰 부하, 배포 오류, 지나치게 낮은 한도는 비슷한 메모리 압박 신호를 남깁니다. 누군가 자원 소모가 큰 서비스에 의도적으로 과도한 수요를 일으킨 경우도 같은 현상으로 이어질 수 있습니다. 메모리 자료로 영향받은 워크로드와 종료 경로를 확인하고, 수요가 바뀐 이유는 요청량, 배포 이력, 독립적인 접근 기록을 함께 살핍니다.

1. **그룹이 사라지기 전에 기록합니다.** 노드 식별자, 부팅 ID, UTC 조회 범위, 서비스나 컨테이너 식별자, cgroup 경로와 인벤토리에서 확인 가능한 수명 식별 정보를 남깁니다. 말단 그룹과 관련 상위 그룹의 한도, 사용량, 압박, 로컬 및 집계 카운터를 수집합니다. 파일을 어디서 읽었는지도 적습니다. 컨테이너 내부의 cgroup 네임스페이스에서는 상위 그룹이 보이지 않을 수 있습니다. 같은 인스턴스의 두 시점에서 값을 얻고 원본을 보존합니다.
2. **증거를 연결합니다.** `high` 증가와 지속적인 PSI, 응답 지연이 같은 시간대에 있으면 압박으로 인한 성능 저하를 뒷받침합니다. 사용량이 이미 내려갔더라도 `oom_kill`이 반복 증가하면 커널 로그를 확인합니다. OOM의 제약 범위와 종료 대상을 찾고, 호스트 PID와 cgroup 경로를 프로세스 수명, 서비스 재시작 기록과 맞춥니다. 부팅과 시간 필터를 기록하고 로컬·중앙 수집 공백도 남깁니다.
3. **정책을 바꾸기 전에 원인을 좁힙니다.** 해당 범위가 기록된 커널 로그는 그룹 한도 때문에 종료됐는지, 시스템 전체의 OOM인지 구분하는 근거입니다. 일치하는 oomd 로그는 사용자 공간 정책으로 종료됐음을 뒷받침합니다. 종료 코드만 있다면 감독 프로세스의 시간 제한과 운영자 조치 등 다른 가능성도 열려 있습니다. 컨테이너 플랫폼의 종료 요약은 단서입니다. 어떤 한도나 압박 정책이 영향을 줬는지 노드 기록으로 확인합니다.
4. **대응 후 대조 시험을 합니다.** 서비스·호스트 담당자와 배포 오류 수정, 부하 감소, 자원 예산 조정 중 증거에 맞는 조치를 선택합니다. 변경 전 기록을 보존하고 유사한 부하에서 응답 시간, 메모리 압박, 카운터와 예상된 재시작을 비교합니다. 하나의 하위 이벤트가 상위 그룹마다 반복 집계되지 않도록 주의합니다.

### systemd 호스트에서 읽기 전용으로 수집하기

승인된 호스트의 실행 중 유닛에서 사용합니다. cgroup v2가 `/sys/fs/cgroup`에 마운트돼 있고, 루트가 아닌 대상 그룹에 메모리 컨트롤러가 노출돼 있으며, 파일과 저널을 읽을 권한이 필요합니다. 예시 유닛과 UTC 조회 시간을 바꾸세요. 컨테이너 환경이라면 런타임의 워크로드 식별자를 별도로 보존합니다.

```bash
date -u
cat /proc/sys/kernel/random/boot_id
systemctl show -p ControlGroup -p MainPID report-worker.service
wiki_cgroup=$(systemctl show -p ControlGroup --value report-worker.service)
if [ -n "$wiki_cgroup" ] && [ "$wiki_cgroup" != / ]; then
  for entry in memory.current memory.high memory.max memory.events memory.events.local memory.pressure; do
    printf '\n%s\n' "$entry"
    cat "/sys/fs/cgroup${wiki_cgroup}/$entry"
  done
fi
journalctl -k -b --since '2026-11-26 01:00:00 UTC' --until '2026-11-26 01:15:00 UTC' --utc
journalctl -b -u systemd-oomd.service --since '2026-11-26 01:00:00 UTC' --until '2026-11-26 01:15:00 UTC' --utc
```

사건이 발생한 부팅의 저널을 선택하세요. 이전 부팅이나 삭제된 그룹은 보존된 로그와 지표에만 남아 있을 수 있습니다. 파일을 읽지 못하면 오류를 기록하고 마운트 방식, 컨트롤러, 네임스페이스, 그룹 수명과 권한을 확인합니다. 같은 관점에서 정상 그룹을 읽어 볼 수 있는지 확인한 뒤 수집 공백을 판단합니다.

## 4. 가상 스냅샷으로 실습하기

승인된 작업 공간의 같은 폴더에 <a href="{{ '/assets/labs/linux-cgroup-memory-evidence.py' | relative_url }}" download="linux-cgroup-memory-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/linux-cgroup-memory-cases.json' | relative_url }}" download="linux-cgroup-memory-cases.json">사례 파일</a>을 저장합니다. Python 3.9 이상이 필요합니다. 가상 ID와 함께 커널 카운터 형식의 텍스트, 이미 대상과 시점을 맞춰 본 로그의 요약을 제공합니다. 스크립트는 선택한 파일만 읽고 메모리 부하를 일으키거나 신호를 보내지 않습니다.

```bash
python3 linux-cgroup-memory-evidence.py linux-cgroup-memory-cases.json
```

| 사례 | 기대 결과 |
| --- | --- |
| `high_reclaim` | 감속 관측, 종료 원인 미확인 |
| `max_without_kill` | 한도 압박 관측, 종료 원인 미확인 |
| `memcg_kill` | 일치하는 커널 기록에서 cgroup 한도에 따른 OOM 종료 확인 |
| `system_oom_kill` | 피해 그룹 카운터는 늘었지만 일치하는 커널 기록은 시스템 전체 OOM을 가리킴 |
| `oomd_userspace` | 일치하는 oomd 기록이 사용자 공간 종료를 뒷받침 |
| `parent_only` | 집계 건수 증가, 영향을 받은 하위 그룹 미확인 |
| `instance_recreated` | 다른 인스턴스의 카운터는 비교 불가 |
| `status_137_only` | 독립 증거가 없어 종료 주체 미확인 |

각 결과는 어떤 카운터를 어느 범위에서 비교할 수 있는지, 변화량은 얼마인지, 종료 주체가 확인됐는지 별도로 보여 줍니다. 여덟 사례 모두 PASS여야 합니다. 복사한 사례 파일의 `high_reclaim`에서 `high 18`을 `high 5`로 바꿔 보세요. 원래 기대와 달라져 FAIL이 나와야 합니다. 누락된 필드는 미확인으로 남습니다. 파일을 열 수 없다면 두 파일 이름과 작업 폴더를 확인하고, 예상과 다른 변화량이 나오면 두 스냅샷의 범위 식별자와 파일 종류를 비교하세요.

오프라인 사례는 클라우드 작업 공간에서 실행했습니다. 수집 명령과 제품 동작은 공식 자료로 검토했습니다. 실제 OOM, systemd-oomd 이벤트, Kubernetes 워크로드는 실습에서 유발하지 않았습니다.

## 5. 판단 확인하기

- **부모 집계와 말단 로컬 카운터가 각각 1 증가했습니다. 종료는 몇 건인가요?** 같은 종료가 두 곳에 기록됐을 수 있습니다. 집계 구조와 커널 기록을 대조한 뒤 셉니다.
- **말단의 `oom_kill`이 하나 늘었습니다. 말단 자체 한도 때문인가요?** 커널 OOM killer가 해당 그룹의 구성원을 종료했다는 단서입니다. 상위 그룹을 포함해 커널이 기록한 제약과 적용 대상을 확인하세요. 시스템 전체 OOM도 이 값에 반영될 수 있습니다.
- **재시작 기록의 상태가 137입니다. oomd와 커널 OOM은 어떻게 구분하나요?** 같은 워크로드 인스턴스와 시간대를 기준으로 oomd 유닛 저널과 커널 종료 기록을 확인합니다. 자료가 없으면 종료 주체를 미확인으로 남깁니다.

모든 사례가 통과하고, 작업 지연과 종료를 서로 다른 증거로 설명하며 각각의 판단 한계와 필요한 추가 자료를 말할 수 있으면 완료입니다.

## 공식 참고자료

2026년 11월 26일 검토. 현재 문서화된 cgroup v2 인터페이스와 커널 PSI를 대상으로 합니다. 적용 전에 배포된 커널, systemd 버전, 런타임의 동작을 확인하세요.

- 메모리 컨트롤러, 한도와 카운터. [Linux 커널 cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory)
- 압박 시간 측정. [Linux 커널 PSI](https://docs.kernel.org/accounting/psi.html)
- 사용자 공간 메모리 정책과 종료 신호. [systemd-oomd](https://www.freedesktop.org/software/systemd/man/latest/systemd-oomd.service.html) · [systemd 자원 제어](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
- 저널의 부팅·유닛 조회. [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- 컨테이너 메모리 요청, 한도, 종료 상태. [Kubernetes 컨테이너 자원](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

[이전 글 · Linux 프로세스 수명 식별]({{ '/ko/wiki/linux-process-evidence/' | relative_url }}) · [관련 글 · Linux 저널 수집 조사]({{ '/ko/wiki/linux-journal-coverage/' | relative_url }})
