---
title: "systemd 서비스 호출 조사 · 재시작과 실행 결과 구분하기"
description: "Linux 서비스의 한 번의 실행을 저널에서 추적하고, 관리자 메시지와 서비스 출력을 구분한 뒤 오프라인 사례로 검증합니다."
category: dfir
tags: [Linux, systemd, Journald, Service Investigation, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/systemd-service-invocation-evidence/
---

08:01 UTC에 보고서 서비스가 오류를 남겼습니다. 08:02에는 같은 이름의 유닛에 ‘보고서 전송’ 기록이 보입니다. 장애를 종결하기 전에 두 기록이 같은 실행의 것인지, systemd가 어디까지 확인했는지, 수신 시스템이 보고서를 받았는지 살펴봅니다.

## 1. 유닛, 호출, 프로세스를 구분하기

**유닛**은 systemd가 관리하는 객체입니다. 서비스 유닛은 관리자가 어떤 작업을 실행하고 어떻게 감독할지 정의합니다. 시스템 관리자와 각 사용자의 관리자는 같은 이름의 서비스를 따로 가질 수 있습니다. **서비스 호출**(invocation)은 유닛의 한 번의 실행 주기입니다. 새 주기에는 고유한 128비트 호출 ID가 주어지며 한 주기에 여러 프로세스가 참여할 수 있습니다. **PID**는 특정 PID 네임스페이스의 프로세스 번호이고 재사용될 수 있습니다. **MainPID**는 관리자가 현재 추적하는 주 프로세스의 PID를 보여 주는 속성입니다.

관리자는 설정을 로드하고 시작 작업을 처리합니다. 시작 성공의 기준은 `Type=`에 따라 달라집니다. 그 뒤 실제 애플리케이션 작업이 이어질 수 있습니다. 재시작되면 같은 유닛 이름 아래 새 실행 주기가 생깁니다. 저널을 읽을 때는 서비스가 **직접 남긴** 기록인지, 다른 주체가 그 서비스**에 대해 남긴** 기록인지 먼저 확인하세요.

<figure>
  <img src="{{ '/assets/diagrams/systemd-service-invocation-evidence-ko.svg' | relative_url }}" width="560" height="326" alt="같은 서비스 이름 아래 호출 A와 B가 있습니다. 두 실행에 각각 관리자 메시지와 서비스 출력이 남을 수 있습니다. 업무 결과는 수신 시스템에서 별도로 확인합니다." />
  <figcaption>같은 실행의 기록을 묶고, 기대한 작업이 실제로 반영됐는지 별도로 대조합니다.</figcaption>
</figure>

| 출처 또는 필드 | 뒷받침하는 내용 | 확인할 점 |
| --- | --- | --- |
| `_SYSTEMD_UNIT`과 `_SYSTEMD_INVOCATION_ID` | 필드가 있는 경우 journald가 부여한 발신 서비스의 실행 맥락입니다. | 출처와 원본 시스템, 부팅을 보존합니다. 사용자 서비스라면 있는 경우 `_SYSTEMD_USER_UNIT`과 `_SYSTEMD_OWNER_UID`도 남깁니다. |
| `UNIT`·`USER_UNIT`과 `INVOCATION_ID`·`USER_INVOCATION_ID` | systemd가 대상 유닛과 실행에 관한 메시지에 이 값을 넣을 수 있습니다. | 원본 저널의 신뢰 필드로 발신자를 검증합니다. 앞에 밑줄이 없는 필드는 일반 클라이언트도 제공할 수 있습니다. |
| `OBJECT_SYSTEMD_INVOCATION_ID` | 메시지가 가리키는 프로세스에 대한 추가 정보입니다. | 대상 유닛과 범위를 확인합니다. 이 필드는 메시지를 보낸 주체와 별개의 대상을 설명합니다. |
| `systemctl show`와 `systemctl cat` | 각각 조회 시점의 관리자 속성과 현재 디스크에 있는 유닛 파일 내용을 보여 줍니다. | 수집 시각을 보존합니다. 디스크 파일과 로드된 설정이 다를 수 있으며 이 명령만으로 과거 실행을 복원할 수 없습니다. |
| 애플리케이션 또는 수신 시스템 | 작업 수행, 수신 확인, 이후 상태 변경의 증거입니다. | 트랜잭션이나 산출물의 식별자를 대조하고 그 시간의 데이터가 수집됐는지 확인합니다. |

systemd는 유닛 프로세스에 환경 변수 `$INVOCATION_ID`를 제공합니다. 애플리케이션이 이 값을 메시지에 적었다면 연결 단서로 활용할 수 있습니다. 밑줄로 시작하는 필드는 journald가 관리하는 원본 저널에서 특별한 출처를 갖습니다. 임의의 수집기 JSON에 같은 이름이 있다고 해서 무결성이 보장되지는 않습니다. 자식 프로세스의 표준 출력·오류도 스트림을 처음 연 프로세스의 자격 정보로 기록될 수 있습니다. 전송 방식과 출처를 보존하고, 중앙 수집기가 원본 필드를 애플리케이션 필드와 섞지 않았는지 확인하세요.

## 2. ‘시작했다’는 기록의 기준 확인하기

| 서비스 유형 | 관리자가 기다리는 시작 조건 | 추가로 확인할 증거 |
| --- | --- | --- |
| `simple` | 주 프로세스가 생성되면 시작 단계가 성공할 수 있습니다. 서비스 바이너리가 실행되기 전일 수 있습니다. | 예상한 실행 이미지가 시작됐는지, 앱이 실제로 동작했는지 확인합니다. |
| `exec` | 주 바이너리의 실행이 성공할 때까지 기다립니다. | 앱의 준비 상태와 이후 작업 결과를 확인합니다. |
| `notify` | 예상된 준비 완료 알림을 받을 때까지 기다립니다. | 뒤이은 요청이나 전송의 완료를 확인합니다. |
| `oneshot` | 설정에 따라 시작 명령이 성공적으로 끝날 때까지 기다립니다. | 수신 시스템에 보고서가 도착했는지처럼 프로세스 밖에 있는 업무 결과를 확인합니다. |

**가상의 정상 복구 사례**에서 `reports.service`의 호출 A는 상위 API 시간 초과 뒤 종료 상태 1로 실패합니다. 승인된 정책은 실패 시 재시작을 허용합니다. 08:02 UTC에 시작한 호출 B는 참조 번호 R-417의 보고서를 ‘전송했다’고 남깁니다. 나중에 수신 시스템도 같은 번호를 수락했다고 기록합니다. 이때는 실패한 실행과 별도의 성공한 전송을 설명할 수 있습니다. 송신 측 메시지만 있다면 애플리케이션이 전송을 보고했다고 판단할 수 있습니다. 또 작업을 정상 완료한 oneshot 서비스는 수집 시점에 비활성으로 보일 수 있습니다.

승인된 유지보수 밖에서 변경된 서비스가 반복 실행된다면 확인이 필요합니다. 새 드롭인 설정이나 예상 밖의 실행 이미지 때문에 익숙한 이름의 서비스가 다른 작업을 실행할 수 있습니다. 배포 오류나 의존 서비스 장애도 반복 실패를 일으킵니다. 의도를 판단하기 전에 프로세스와 출력이 승인된 변경 기록과 기준 상태에 맞는지 확인하세요.

## 3. 한 번의 실행에 필요한 증거 수집하기

1. **출처의 범위를 정합니다.** 원본 자산 식별자, 머신 ID, 부팅 ID, 관리자 범위, 유닛과 호출 ID를 남깁니다. 사용자 서비스는 소유 UID를 함께 보존하고 권한이 있는 범위에서 해당 사용자 관리자를 조회하세요. 시스템 간 비교에는 실제 시각을, 단조 시계는 같은 원본 부팅 내 비교에만 씁니다. 원본 레코드와 시간대, 재시작, 도착 지연, 보존 범위를 남깁니다.
2. **관리자 정보와 저널을 비교합니다.** 로드된 속성, 디스크 파일과 메타데이터, 드롭인을 수집해 승인된 배포·패키지 기록과 대조합니다. 중앙 쪽 필터링, 전달, 잘림, JSON 정규화 과정에서 호출 필드가 사라졌는지도 확인합니다. 발신자가 확인된 관리자 메시지로 시작과 종료를 재구성하세요. 같은 실행에 속하더라도 관리자 메시지와 서비스 출력이 각각 뒷받침하는 내용은 다릅니다.
3. **실제 효과를 확인하고 대응합니다.** 프로세스·cgroup 기록, 앱의 작업 번호와 수신 시스템 기록을 대조합니다. 설명 가능한 반복 실패라면 담당자에게 범위를 확인한 호출 ID와 오류를 전달합니다. 설정이나 실행 파일에 설명되지 않는 변경이 있다면 승인된 격리 전에 적용 상태와 산출물을 보존하세요. 복구 후에는 실제 실행과 이후 업무 결과를 모두 확인합니다.

권한이 있는 Linux에서 systemd 관리자가 동작하고 저널을 읽을 수 있을 때 다음 명령으로 이미 알고 있는 유닛을 조회할 수 있습니다. 설정 변경은 하지 않습니다. 사용자 유닛은 해당 사용자의 관리자에 `systemctl --user`로 접근하고, 저널은 권한을 확인한 뒤 `--user-unit`으로 선택합니다. 상대 번호는 실행이 추가되면 가리키는 대상이 바뀔 수 있어 증거 보존 시에는 명시적인 부팅·호출 ID를 사용하세요. 두 호출 조회 옵션은 systemd 257에 추가됐습니다. 넓게 조회하면 발신자·관리자·대상 필드가 모두 검색될 수 있어 각 기록의 출처를 확인합니다. 마지막 직접 필드 조회는 관리자나 대상 필드에만 있는 기록을 제외합니다.

```bash
systemctl cat reports.service
systemctl show reports.service \
  -p Type -p InvocationID -p MainPID -p Result \
  -p ExecMainCode -p ExecMainStatus -p FragmentPath -p DropInPaths
journalctl --list-boots --no-pager

# Fictional sample IDs. Replace with the originating boot and run IDs.
boot=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
run=11111111111111111111111111111111

# systemd 257+ (check journalctl --version)
journalctl -b "$boot" -u reports.service --list-invocations --no-pager
journalctl -b "$boot" -u reports.service --invocation="$run" -o json --no-pager

# Direct field match for unit-origin records only, where the field exists
journalctl -b "$boot" -o json --no-pager \
  _SYSTEMD_UNIT=reports.service "_SYSTEMD_INVOCATION_ID=$run"
```

접근이 거부되거나 결과가 비어 있다면 사용자와 관리자 범위, 부팅 선택, 로컬 보존과 중앙 전송, 서비스의 저널 출력 설정, 설치 버전의 필드와 옵션 지원 여부를 확인하세요. 관리자 로그에 시작 작업이 있다는 사실만으로 서비스 출력도 저널에 수집됐다고 볼 수는 없습니다.

## 4. 오프라인으로 방어 판단 검증하기

자기 소유 또는 명시적으로 승인된 디렉터리에서 Python 3를 사용하세요. <a href="{{ '/assets/labs/systemd-service-invocation-evidence/invocation-cases.jsonl' | relative_url }}" download="invocation-cases.jsonl">invocation-cases.jsonl</a>을 내려받고, 아래 코드를 같은 폴더에 `review_invocation.py`로 저장한 뒤 `python3 review_invocation.py`를 실행합니다. 서비스나 네트워크는 필요 없습니다.

가상 데이터는 각 로그를 실습용 객체로 감쌉니다. 이 실습은 시스템 서비스가 대상입니다. `manager_verified`는 분석자가 발신자를 확인했다는 뜻의 실습용 표시입니다. systemd 원본 필드가 아니며 메시지 문구만 보고 자동으로 정하는 값도 아닙니다.

```python
import json

machine_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
boot_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
invocation_id = "11111111111111111111111111111111"
unit = "reports.service"

def classify(row):
    fields = row["fields"]
    if (fields.get("_MACHINE_ID"), fields.get("_BOOT_ID")) != (machine_id, boot_id):
        return "outside-scope"

    if fields.get("_SYSTEMD_UNIT") == unit and "_SYSTEMD_USER_UNIT" not in fields:
        invocation = fields.get("_SYSTEMD_INVOCATION_ID")
        if not invocation:
            return "id-missing"
        return "unit-member" if invocation == invocation_id else "other-invocation"

    if (fields.get("UNIT"), fields.get("INVOCATION_ID")) == (unit, invocation_id):
        return "manager-related" if row.get("manager_verified") is True else "unverified-related"

    if (fields.get("OBJECT_SYSTEMD_UNIT"), fields.get("OBJECT_SYSTEMD_INVOCATION_ID")) == (unit, invocation_id):
        if "OBJECT_SYSTEMD_USER_UNIT" not in fields:
            return "object-related"

    return "outside-scope"

with open("invocation-cases.jsonl", encoding="utf-8") as stream:
    cases = [json.loads(line) for line in stream if line.strip()]
for row in cases:
    actual = classify(row)
    assert actual == row["expected"], f"{row['case']}: expected {row['expected']}, got {actual}"
    print(f"{row['case']}: {actual}")
assert len(cases) == 9, f"Expected nine cases, got {len(cases)}"
```

**기대 결과.** 사례 9건이 통과합니다. 발신 유닛의 해당 호출과 직접 일치하는 기록은 한 건입니다. 관리자 기록과 대상 프로세스 기록은 같은 실행에 관한 자료로 남습니다. 발신자를 확인하지 않은 관리자 주장에는 별도 표시가 붙습니다. 재시도나 다른 머신·부팅·사용자 범위의 기록은 해당 실행의 로그로 합치지 않습니다. 호출 ID가 빠졌다면 미확정으로 남습니다.

**실패 점검.** 복사한 자료에서 `unit-record`의 호출 ID를 재시도 ID로 바꾸고 그 파일을 입력으로 사용하세요. 해당 행이 `other-invocation`으로 판정되면서 검증에 실패해야 합니다. 다시 비교할 때는 원본을 복원합니다. Python이 파일을 열 수 없다면 작업 디렉터리와 이름을 확인하세요. 오프라인 실습은 클라우드에서 실행했고, 서비스 조회 예제는 systemd 공식 문서와 대조했습니다.

## 5. 확인 문제와 완료 기준

1. **이전 호출이 실패한 뒤 새 호출이 성공을 기록했습니다. 이전 실행도 성공한 건가요?** 성공 기록은 새 호출에 속합니다. 각 작업의 수신이나 그에 준하는 결과를 따로 확인합니다.
2. **내보낸 로그에 `INVOCATION_ID`가 있으면 발신자를 알 수 있나요?** 연결 단서로 쓸 수 있습니다. 출처와 전송 정보가 어떻게 검증됐는지 확인합니다.
3. **프로세스가 예전 설정을 쓰는데 `systemctl cat`은 새 설정을 보여 줄 수 있나요?** 이 명령은 현재 디스크의 설정을 보여 줍니다. 실행 상태와 설정이 바뀐 시각도 확인합니다.

호출의 범위를 설명하고, 관리자 메시지와 서비스 출력을 구분하고, 수집 공백 때문에 남는 질문 하나와 업무 결과를 확인한 독립 증거를 제시할 수 있다면 학습을 마친 것입니다.

## 공식 참고자료

**검토일 2026-11-27.** 업스트림 systemd **261** 문서를 기준으로 확인했습니다. 발신 유닛의 호출 필드는 **233**, 호출 조회 옵션은 **257**에 추가됐습니다. 사용 중인 배포판의 버전과 백포트도 확인하세요.

- [systemd.journal-fields(7) · 필드 출처와 의미](https://www.freedesktop.org/software/systemd/man/261/systemd.journal-fields.html)
- [systemd.service(5) · 시작 유형과 재시작 동작](https://www.freedesktop.org/software/systemd/man/261/systemd.service.html)
- [systemd.exec(5) · 서비스 실행 환경](https://www.freedesktop.org/software/systemd/man/261/systemd.exec.html)
- [journalctl(1) · 유닛·부팅·호출 필터](https://www.freedesktop.org/software/systemd/man/261/journalctl.html)
- [systemctl(1) · 실행 속성과 디스크 설정](https://www.freedesktop.org/software/systemd/man/261/systemctl.html)

[이전 · systemd 타이머 조사]({{ '/ko/wiki/systemd-timer-evidence/' | relative_url }}) · [다음 · 저널 수집 범위 조사]({{ '/ko/wiki/linux-journal-coverage/' | relative_url }}) · [프로세스 식별 정보와 대조]({{ '/ko/wiki/linux-process-evidence/' | relative_url }})
