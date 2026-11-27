---
title: "S3 Object Lock 이벤트 홀드 · 버전의 보존 기간 확인하기"
description: "이벤트 홀드의 활성 상태, 해제 이후의 보존 기간, 독립적인 법적 보존을 버전별 증거로 확인합니다."
category: cloud
tags: [AWS, Amazon S3, Object Lock, CloudTrail, Blue Team, DFIR]
level: Beginner
updated: "2026-11-28"
translation_url: /wiki/s3-object-lock-event-hold-evidence/
---

감사가 끝나 보관 워크플로가 S3 이벤트 홀드를 해제했습니다. 이제 해당 버전을 삭제할 수 있을까요? 먼저 정확한 버전의 보존 메타데이터, 해제 기록, 법적 보존 상태를 확인하세요. 해제한 뒤에도 보존 기간이 이어지는 경우가 일반적입니다.

## 1. 어떤 버전을 보호하는지 확인하기

**S3 Object Lock**은 버전 관리를 사용하는 버킷에 저장된 버전에 한 번 쓰고 여러 번 읽는 방식(WORM)의 보호를 제공합니다. *키*는 객체의 이름이고, *버전 ID*는 같은 키 아래에 저장된 개별 버전을 구분하는 값입니다. 조사 범위는 버킷·키·버전 ID로 잡습니다. 버전마다 보호 설정이 다를 수 있습니다.

**고정 보존**은 버전에 보존 종료 시각을 저장하며 권한이 있는 변경의 영향을 받을 수 있습니다. **가변 보존**은 *이벤트 홀드*가 켜져 있는 동안 버전을 보호하고, 홀드를 해제한 뒤에도 설정한 기간 동안 보존을 이어갑니다. 별도 제어인 **법적 보존(legal hold)**은 예정된 종료 시각이 없으며 승인된 권한으로 해제할 때까지 계속됩니다. AWS는 2026년 9월 가변 보존을 발표했고, 10월에 AWS GovCloud(미국) 리전의 지원도 발표했습니다. 이전 문서는 고정 보존과 법적 보존만 설명할 수 있습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/s3-object-lock-event-hold-evidence-ko.svg' | relative_url }}" width="360" height="413" alt="이벤트 홀드가 켜진 동안 보존 종료 시각이 이동합니다. 해제할 때는 해제 시각에 기간을 더한 값과 기존 보존 종료 시각 중 더 늦은 시각으로 고정합니다. 법적 보존 상태는 따로 확인합니다." />
  <figcaption>이벤트 홀드를 해제하면 보존 종료 시각이 정해집니다. 법적 보존은 독립된 상태입니다.</figcaption>
</figure>

| 제어 | 확인할 값 | 증거가 말해 주는 것 |
| --- | --- | --- |
| 버킷 기본값 | Object Lock 설정, 모드, 기본 기간이나 이벤트 홀드 | 당시 새 업로드에 적용할 기본 규칙입니다. 버전별로 명시한 보존 설정이 우선할 수 있습니다. |
| 고정 보존 | 버전의 모드와 `RetainUntilDate` | 해당 종료 시각까지 적용되는 시간 기반 WORM 보호입니다. |
| 가변 보존 | 모드, `EventHold`, `EventHoldDuration`, `RetainUntilDate` | 홀드가 켜져 있을 때의 보존 종료 시각은 지금 해제한다고 가정한 값으로, 기존 시각 및 최소값보다 앞서지 않습니다. 해제하면 시각이 고정됩니다. |
| 법적 보존 | 버전별 법적 보존 `Status` | 만료 시각이 없는 독립 제어입니다. `OFF`는 이 제어의 상태를 뜻합니다. |
| 키의 현재 표시 상태 | 버전 목록과 삭제 마커 | 보호된 버전이 남아 있어도 마커 때문에 일반 조회에서 숨겨질 수 있습니다. 버전 ID를 지정해 확인합니다. |

보존 방식이 고정인지 가변인지와 별개로 보존 모드는 `GOVERNANCE`(거버넌스) 또는 `COMPLIANCE`(규정 준수)입니다. 거버넌스는 특별히 승인된 조건에서 예외 변경이 가능합니다. 규정 준수 모드에서 보존이 진행 중이면 계정 루트 사용자도 기간을 단축하거나 해당 버전을 삭제할 수 없습니다. 조사할 때는 모드와 법적 보존 상태를 함께 남기세요. 거버넌스 예외는 독립된 법적 보존에 영향을 주지 않습니다.

## 2. 변경을 해석하기 전에 시간순으로 맞춰 보기

가상의 감사 보고서 버전 `v-a`에는 30일 이벤트 홀드와 규정 준수 모드가 적용돼 있습니다. **2026-11-10 00:00 UTC**에 메타데이터를 조회하면 종료 시각은 12월 10일입니다. 11월 12일에 다시 조회하면 12월 12일입니다. 홀드가 켜져 있는 동안에는 시각이 앞으로 움직이므로 두 관측 모두 정상일 수 있습니다. 기간을 줄여 계산한 시각이 서비스가 이미 정한 시각보다 이르다면 기존 시각을 유지합니다. 짧아진 기간으로 계산한 시각이 그 값을 넘어간 뒤에 다시 앞으로 이동합니다.

승인된 워크플로가 30일을 유지한 채 **2026-11-15 00:00 UTC**에 홀드를 해제했다면, 위 관측과 더 늦은 최소 시각이 없다는 조건에서 **12월 15일 00:00 UTC**가 종료 시각입니다. 명시한 최소 시각이 **2027년 1월 1일 00:00 UTC**라면 그보다 늦출 이유가 없는 한 1월 1일까지 유지됩니다. 종료 시각이 지나도 법적 보존이 켜져 있으면 버전은 보호됩니다. 업무 티켓이 닫혔다면 해제할 사유가 생겼다는 뜻일 수 있습니다. 해제가 실제로 적용됐는지는 성공한 S3 작업과 버전별 메타데이터 조회로 확인하세요.

S3 Replication을 사용한다면 대상도 따로 확인합니다. AWS 문서에 따르면 원본의 이벤트 홀드 해제가 복제될 때 대상은 복제 시각과 설정된 기간을 기준으로 자체 종료 시각을 계산합니다. 원본과 대상의 버전 식별자, 해제 시각, 관측값을 각각 보존합니다.

## 3. 세 가지 증거 수집하기

### 현재 버전 상태

승인된 읽기 전용 역할과 이벤트 홀드 필드를 지원하는 AWS CLI를 사용합니다. `BUCKET`, `KEY`, `VERSION`에 승인된 범용 버킷, 정확한 키, 데이터 버전 ID를 지정합니다. 계정·버킷 범위를 먼저 확인하고 원본 출력과 UTC 관측 시각을 함께 기록하세요. 세 명령에는 순서대로 `s3:GetBucketObjectLockConfiguration`, `s3:GetObjectRetention`, `s3:GetObjectLegalHold` 권한이 필요합니다.

```bash
aws s3api get-object-lock-configuration --bucket "$BUCKET"
aws s3api get-object-retention --bucket "$BUCKET" --key "$KEY" --version-id "$VERSION"
aws s3api get-object-legal-hold --bucket "$BUCKET" --key "$KEY" --version-id "$VERSION"
```

응답이 거절되거나 필요한 값이 빠지면 버전, 계정이나 역할, 기능 지원, 권한을 확인합니다. 읽지 못한 상태는 미확인으로 남깁니다. 명령은 AWS 문서를 대조했고, 아래 실습은 AWS 환경을 사용하지 않습니다.

### 변경 이력

조사 기간 전에 해당 버킷이나 객체 ARN 범위에 CloudTrail S3 객체 데이터 이벤트를 설정해야 수집할 수 있습니다. AWS는 `PutObjectRetention` API 호출을 `PutObjectLockRetention` 데이터 이벤트로 기록합니다. `additionalEventData.objectRetentionInfo`가 있다면 변경 후의 모드, 종료 시각, 이벤트 홀드와 기간을 확인합니다. 이벤트 시각, 실행 주체, 요청이나 이벤트 ID, 성공 여부, 그리고 확인 가능한 버전 ID를 함께 남기세요. 실패했거나 버전이 기록되지 않은 이벤트는 별도 근거로 보완합니다. 버킷 수준의 관리 이벤트는 `PutBucketObjectLockConfiguration`입니다. CloudTrail 이벤트 기록 화면에서는 최근 관리 이벤트를 볼 수 있으며 객체 데이터 이벤트는 별도 수집·조회 경로가 필요합니다.

### 여러 버전의 상태 비교

S3 Inventory에서 Object Lock 필드를 사용하고 이전 버전이 조사 대상이라면 모든 버전을 포함합니다. 보고서에는 최대 48시간의 지연이 있을 수 있습니다. 이동하는 종료 시각은 보고서 생성 시점을 기준으로 읽습니다. 명시적인 보존 변경 호출에는 `s3:ObjectRetention:Put` 알림이 생길 수 있습니다. 업로드에 기본값을 적용하거나 생성 요청에서 직접 보존을 설정했을 때는 이 알림이 없을 수 있습니다. 현재 버전의 상태는 최신 메타데이터로, 그 설정이 생긴 경위는 CloudTrail이나 생성 기록으로 확인합니다.

## 4. 보호 설정이 어긋났을 때 조사하기

- 성공한 해제를 정확한 버전의 승인 기록과 대조합니다. 예상치 못한 `ON`에서 `OFF`로의 변경, 정해진 범위를 벗어난 기간, 대상 버전의 생성 전후에 바뀐 버킷 기본값을 살펴봅니다. 의도를 판단하기 전에 역할 세션과 배치 작업을 확인하세요. 모니터링은 수집 선택기가 포함하는 범위로 한정하고, 예상 이벤트 이름이 실제로 기록되는지 검증합니다.
- 오래된 보고서와 실제 설정 변경을 구분합니다. 출처와 UTC 관측 시각을 맞춰 본 뒤 버전의 최신 상태를 확인합니다. 원래 관측값, 변경 이벤트, 최신 응답을 함께 보존합니다. 홀드가 켜져 있는 동안 보존 종료 시각이 앞으로 이동하는 것은 정상입니다.
- 복구 가능성은 별도 근거로 판단합니다. 보호된 버전도 삭제 마커에 가려지거나, 스토리지 클래스 때문에 복원이 먼저 필요하거나, 암호화 키에 접근할 수 없어 읽히지 않을 수 있습니다. 증거를 다룰 때 버전과 승인 범위를 기록하고 승인된 복사본이나 무결성 검사로 확인하세요. 종료 시각이 지났다는 사실만으로 삭제를 승인할 수는 없습니다.

## 5. 오프라인 실습 · 가상 관측 열 가지 확인하기

본인 소유 또는 사용 승인을 받은 폴더에서 Python 3을 사용합니다. <a href="{{ '/assets/labs/s3-object-lock-event-hold-evidence/object-lock-cases.csv' | relative_url }}" download="object-lock-cases.csv">object-lock-cases.csv</a>를 내려받고 같은 폴더에 아래 코드를 `review_object_lock.py`로 저장한 뒤 `python3 review_object_lock.py`를 실행하세요. CSV는 한 행에 한 가지 상황을 담은 가상 학습 자료입니다. `prior_until`은 실습에서 이전에 확정됐다고 가정한 하한이고 `minimum_until`은 명시한 최소 시각입니다. 실습은 UTC와 정수 일수로 계산합니다. 실제 조사에서는 관측이나 해제 시각에 대응하는 서비스 값을 비교하고 시각의 정밀도 차이도 고려합니다. 프로그램은 로컬 파일만 읽습니다.

```python
import csv
from datetime import datetime, timedelta
from pathlib import Path
import sys


def utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def review(row):
    observed = utc(row["observed_at"])
    reported = utc(row["reported_until"])
    released = utc(row["released_at"])
    hold = row["event_hold"]
    legal = row["legal_hold"]
    if row["mode"] not in {"GOVERNANCE", "COMPLIANCE"}:
        raise ValueError("Fixture must specify a retention mode")
    if hold not in {"ON", "OFF"} or legal not in {"ON", "OFF", "UNKNOWN"}:
        raise ValueError("Unrecognized hold status")
    if not observed or (released and (released > observed or hold == "ON")):
        raise ValueError("Inconsistent observation and release times")

    if hold == "ON" or released:
        day_count = int(row["duration_days"])
        if day_count < 1:
            raise ValueError("Expected a positive duration in days")
        computed = (released or observed) + timedelta(days=day_count)
        floors = [utc(row["minimum_until"]), utc(row["prior_until"])]
        effective = max([computed] + [value for value in floors if value])
    else:
        effective = reported

    if reported is None or legal == "UNKNOWN":
        status = "needs-evidence"
    elif effective != reported:
        status = "date-disagrees"
    elif legal == "ON":
        status = "legal-hold-active"
    elif hold == "ON":
        status = "event-hold-active"
    elif effective > observed:
        status = "retention-active"
    else:
        status = "no-lock-in-model"
    return effective, status


def main(path):
    discrepancies = 0
    with path.open(encoding="utf-8", newline="") as fixture:
        for row in csv.DictReader(fixture):
            until, status = review(row)
            correct = (until, status) == (utc(row["expected_until"]), row["expected_status"])
            discrepancies += int(not correct)
            mark = "OK" if correct else "MISMATCH"
            print(f"{mark} {row['case_id']}: {until} {status}")
    return int(discrepancies > 0)


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("object-lock-cases.csv")
    raise SystemExit(main(path))
```

| 사례 | 기대 결과 |
| --- | --- |
| `active-first`, `active-later`, `shorter-duration` | 두 사례에서는 시각이 이동하고, 기간을 줄인 사례는 이전 하한을 유지합니다. 세 건 모두 홀드가 유지됩니다. |
| `released`, `released-with-floor`, `fixed-retention` | 시간 기반 보호가 진행 중입니다. 종료 시각은 각각 12월 15일, 1월 1일, 입력에 주어진 12월 1일입니다. |
| `expired-legal-hold`, `expired-no-hold` | 첫 사례는 법적 보존으로 계속 보호됩니다. 둘째는 이 모델의 잠금 조건에 남은 항목이 없습니다. |
| `missing-legal-hold`, `stale-observation` | 첫 사례는 증거를 추가로 수집하고, 둘째는 종료 시각 불일치의 원인을 확인합니다. |

정상 출력은 `OK`가 열 줄입니다. CSV를 찾지 못하면 내려받은 폴더에서 실행하거나 CSV 경로를 인수로 넘기세요. CSV 사본에서 `released-with-floor`의 기대 시각을 같은 UTC 형식의 2026년 12월 15일로 바꾸고 `python3 review_object_lock.py altered.csv`를 실행하면, 불일치와 종료 코드 1이 나와야 합니다. 실행 범위는 날짜 계산과 증거 상태 분류입니다. IAM, KMS, 버킷 상태, 수집 및 실제 AWS 동작은 공식 문서와 승인된 환경에서 별도로 확인할 영역입니다.

## 6. 확인 문제와 완료 기준

1. **오늘 조회한 종료 시각이 어제 Inventory 값과 달라도 정상일까요?** 이벤트 홀드가 켜져 있으면 관측 시점에 따라 달라질 수 있습니다. 같은 버전인지 먼저 확인합니다.
2. **이벤트 홀드를 해제하면 즉시 보호가 끝날까요?** 예시에서는 미래의 보존 종료 시각이 고정됩니다. 법적 보존이 켜져 있으면 그 시각이 지난 뒤에도 보호될 수 있습니다.
3. **오늘 바뀐 버킷 기본값으로 이전 버전의 상태를 알 수 있나요?** 버킷 설정이 바뀐 사실을 알 수 있습니다. 이전 버전의 보호 상태는 해당 버전의 메타데이터와 이력을 조회해야 확인할 수 있습니다.

보존 종료 시각이 해제 시점에 어떻게 정해지는지 설명하고, 알 수 없는 홀드 상태를 `OFF`와 구분하고, 정확한 버전의 상태에 필요한 증거를 짚을 수 있다면 학습을 마쳤습니다.

## 공식 참고자료

검토일은 **2026-11-28**입니다. 2026년 9월과 10월 AWS 발표, 범용 S3 버킷과 관련 AWS 공식 설명서를 확인했습니다.

- [AWS S3 · Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [AWS S3 · Inventory, 복제와 보존 모니터링](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
- [AWS S3 · CloudTrail 이벤트 이름과 수집](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)
- [AWS Storage Blog · 이벤트 홀드 기반 가변 보존](https://aws.amazon.com/blogs/storage/flexibly-control-amazon-s3-object-lock-retention-based-on-real-business-events/)
- [AWS CLI · get-object-retention](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-retention.html)
- [AWS CLI · get-object-legal-hold](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-legal-hold.html)
- [AWS CLI · get-object-lock-configuration](https://docs.aws.amazon.com/cli/latest/reference/s3api/get-object-lock-configuration.html)
- [AWS · 2026년 9월 가변 보존 발표](https://aws.amazon.com/about-aws/whats-new/2026/09/amazon-s3-object-lock-variable-retention/)
- [AWS · 2026년 10월 GovCloud 지원 발표](https://aws.amazon.com/about-aws/whats-new/2026/10/s3-object-lock-variable-retention-event-holds-aws-govcloud/)

[이전 · S3 버전 복구]({{ '/ko/wiki/s3-version-recovery-evidence/' | relative_url }}) · [다음 · 백업과 복구 증거]({{ '/ko/wiki/backup-restore-evidence/' | relative_url }}) · [CloudTrail 로그 무결성]({{ '/ko/wiki/cloudtrail-log-integrity/' | relative_url }})
