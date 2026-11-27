---
title: "CloudTrail 로그 무결성 · 전달된 파일 검증과 수집 공백 조사"
description: "서명된 CloudTrail 다이제스트와 SHA-256으로 로그 파일을 검증하고, 조사에 필요한 이벤트가 수집 범위에 있었는지 확인합니다."
category: cloud
tags: [AWS, CloudTrail, Amazon S3, SHA-256, Cloud Security, DFIR, Blue Team]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/cloudtrail-log-integrity/
---

**학습 목표.** 조사 중에 겉보기에는 정상인 로그 파일을 열었다고 가정해 봅시다. 그 파일이 AWS에서 전달한 당시와 바이트 단위로 같은지 어떻게 확인할까요? 서명된 다이제스트를 따라 로그를 검증하고, 조사에 필요한 이벤트가 당시 추적의 수집 범위에 들어 있었는지도 따로 확인합니다.

## 1. 로그를 볼 때 확인할 세 가지 질문

**추적(trail)**은 CloudTrail에서 어떤 이벤트를 모아 S3 버킷 같은 목적지로 전달할지 정하는 설정입니다. S3의 **객체(object)**는 버킷과 그 안에서의 이름인 **키(key)**로 찾습니다. **다이제스트 파일**은 전달된 로그 목록과 각 로그의 해시를 담은 별도 파일입니다. **SHA-256 해시**는 파일의 바이트를 바탕으로 계산한 지문입니다. 누구든 해시를 다시 계산할 수 있으므로 비교 대상인 해시를 어디서 얻었는지가 중요합니다. **전자서명**은 신뢰하는 공개키로 다이제스트가 해당 키 쌍으로 서명됐는지 확인하는 데 쓰입니다.

| 확인할 질문 | 필요한 증거 | 어디까지 말할 수 있나요? |
| --- | --- | --- |
| 이 다이제스트를 신뢰할 수 있나요? | 서명, 원래 S3 위치, 해당 리전과 시점에 맞는 CloudTrail 공개키 | 검증된 다이제스트를 로그 해시와 이전 다이제스트 위치의 근거로 사용할 수 있습니다 |
| 전달된 파일과 일치하나요? | 다이제스트의 로그 항목과 압축을 푼 바이트에서 계산한 SHA-256 | 확인한 바이트가 다이제스트에 기록된 파일과 일치합니다 |
| 찾는 이벤트를 수집할 수 있었나요? | 당시 추적 설정, 이벤트 선택기, 계정·리전, 전달 기록 | 이벤트가 보이지 않을 때 어느 범위까지 해석할 수 있는지 판단합니다 |

이 장은 무결성 검증을 활성화한 추적이 S3에 전달한 로그 파일을 다룹니다. Event history, CloudTrail Lake 질의 결과, SIEM 내보내기에는 각각의 수집 범위와 출처가 있습니다. 전달된 파일의 무결성을 판단할 때는 원래 추적의 증거를 확보하세요.

## 2. 정상적인 로그 전달을 따라가 보기

가상의 계정과 리전에서 10:14 UTC에 EC2 `DescribeInstances` 이벤트가 발생했고, 이 이벤트를 담은 압축 로그가 10:21에 S3에 도착했다고 합시다. 10:00~11:00 UTC 다이제스트에는 이 로그와 SHA-256 값이 들어갑니다. CloudTrail은 리전별 RSA 키로 다이제스트에 서명하고 현재 파일의 서명을 S3 객체 메타데이터에 넣습니다. 앞선 다이제스트가 있다면 새 다이제스트의 본문에 그 위치와 서명도 들어갑니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/cloudtrail-integrity-ko.svg' | relative_url }}" alt="S3 메타데이터의 서명과 AWS 공개키로 최신 다이제스트를 검증한 뒤 로그 해시를 대조하고 이전 다이제스트로 이동합니다.">
  <figcaption>다이제스트를 검증한 다음 그 파일에 담긴 해시로 로그를 확인하고 이전 다이제스트를 따라갑니다.</figcaption>
</figure>

1. 조사 범위에서 적용할 수 있는 가장 최근 다이제스트에서 시작합니다. S3 위치와 서명 메타데이터를 보존하세요. 다이제스트에 적힌 공개키 지문으로 해당 리전과 시점에 맞는 CloudTrail 공개키를 찾습니다.
2. 다이제스트 서명을 확인한 뒤 로그 위치와 기대 해시를 사용합니다. JSON을 파싱하거나 보기 좋게 정렬하기 전에 **압축을 푼 바이트 그대로** 해시를 계산하세요.
3. 이전 다이제스트를 가리키는 정보를 따라가 앞선 로그도 검사합니다. 체인의 시작점인 다이제스트에는 이전 파일이 없어도 정상입니다.
4. 실제로 확인한 구간을 기록하세요. 예시에서 10:14는 이벤트 시각, 10:21은 전달 시각, 11:00은 다이제스트 구간 종료 시각입니다. 한 시간 동안 전달된 파일에도 그 시간 밖에 발생한 이벤트가 포함될 수 있습니다.

## 3. 증거 공백의 원인을 구분하기

보관소에 부당하게 접근한 사용자가 객체를 수정하거나 삭제할 수 있습니다. 탈취된 관리자 권한으로 이벤트 선택기를 바꾸거나 기록을 멈춰 수집 범위가 줄어드는 일도 있습니다. 이 둘은 조사할 증거가 다릅니다. 정상적인 권한 변경이나 보존 정책, 점검 작업, 일시적인 전달 지연도 비슷한 흔적을 남길 수 있습니다.

| 관측 결과 | 다음에 확인할 내용 |
| --- | --- |
| 다이제스트의 서명이 유효하지 않음 | 파일과 메타데이터를 보존하세요. 원래 위치, 리전, 공개키 지문, 내보내기 과정의 메타데이터 누락·대체 여부를 확인합니다 |
| 검증된 다이제스트가 가리키는 로그를 읽을 수 없음 | 정확한 키, 읽기 권한과 필요한 경우 복호화 키 권한, 객체 버전이나 삭제 마커, 수명 주기 기록을 확인합니다 |
| 로그 해시가 일치하지 않음 | 참조된 객체의 압축 해제 바이트를 검사했는지 확인하세요. 보관된 버전 및 별도 경로에서 확보한 증거와 대조한 뒤 원인을 판단합니다 |
| 예상했던 다이제스트가 보이지 않음 | 추적 상태, 전달 오류와 재시작 시간을 확인합니다. 지연된 로그를 포함하기 위한 보충(backfill) 다이제스트가 늦게 도착하면 일시적으로 순서가 뒤바뀔 수 있습니다. 서명이 유효한 빈 다이제스트에는 해당 구간의 로그 파일 항목이 없습니다 |
| 검증한 로그에서 특정 요청이 보이지 않음 | 당시 선택기를 확인합니다. 관리 이벤트를 수집하고 있었더라도 데이터 이벤트가 선택 범위에 없었다면 S3 객체 읽기는 빠질 수 있습니다 |

무결성 검증을 켜면 CloudTrail이 다이제스트를 전달합니다. 실제로 파일을 확인하려면 검증 절차를 실행해야 합니다. AWS 문서에 따르면 기능을 끄면 한 시간 후 다이제스트 연결이 끊기며, 꺼진 기간에 전달된 로그는 다이제스트로 확인할 수 없습니다. 기록 중지나 추적 삭제도 수집을 끊을 수 있습니다. 재시작 경계를 표시하고 검증하지 못한 구간을 남기세요.

## 4. 블루팀의 수집·탐지·대응

1. **범위를 정합니다.** 추적 ARN, 계정, 리전, 버킷, 접두사, UTC 시간 범위를 적습니다. 현재 이벤트 선택기와 추적 상태를 보존한 뒤 변경 기록에서 조사 당시 설정을 복원합니다. 관심 이벤트가 전달 구간 경계에 가까우면 인접 구간까지 확인합니다.
2. **설정과 전달 상태를 감시합니다.** 독립적으로 모으는 관리 이벤트에서 `cloudtrail.amazonaws.com`의 `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`를 살펴봅니다. 추적, 요청 파라미터, 처리 결과, 세션과 변경 승인 내역을 맞춰봅니다. 추적과 리전별 정상 전달 패턴에서 벗어난 공백이 이어지면 경보를 내고 해당 리전의 `get-trail-status`에서 `LatestDigestDeliveryError`를 확인합니다. 상태 조회는 최근 상태를 보여주므로 조회 시각도 적어 둡니다.
3. **보존하고 대응합니다.** 원본 압축 로그, 다이제스트 본문, S3 위치와 버전, 서명 메타데이터를 읽기 전용 사본으로 보존합니다. 오프라인 검토가 필요하다면 해당 구간의 리전별 공개키도 확보합니다. 검증 출력과 도구 버전을 수집 기록에 넣고, 보관소 관리 권한과 조사 권한을 분리합니다. 미승인 변경이 다른 증거로 확인되면 사고 담당자와 격리를 조율하고, 승인 범위에서 정상 시험 이벤트를 사용해 전달이 복구됐는지 확인합니다.

다음은 승인된 추적에서 UTC 전달 구간을 확인하는 **읽기 전용 AWS CLI v2 예시**입니다. 값은 해당 환경에 맞게 바꾸세요. AWS에 연결할 수 있고 추적 정보와 CloudTrail 공개키를 조회할 수 있는 승인된 계정으로 실행합니다. 원래 S3 위치의 목록과 객체를 읽고 버킷 위치를 조회할 권한이 필요합니다. 암호화된 로그에는 KMS 복호화 권한이 필요할 수 있습니다. 조직 추적은 조직 정보 조회 권한이 추가로 필요하며, 특정 멤버 계정으로 좁힐 때는 `--account-id`를 사용합니다.

```bash
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-2:111122223333:trail/ExampleTrail \
  --region us-east-2 \
  --start-time 2026-11-20T10:00:00Z \
  --end-time 2026-11-20T12:00:00Z \
  --verbose
```

요청한 구간과 실제로 찾은 구간을 비교하고 다이제스트와 로그의 개수 및 실패 항목을 적습니다. 여러 리전이라면 실제로 확인한 리전을 남깁니다. 접근 오류가 나면 보관소 담당자와 수집에 사용한 계정과 정책부터 확인하세요. 내려받은 사본을 검사할 때는 서명 메타데이터와 원래 S3 경로의 대응 관계를 보존하고, AWS 문서의 형식에 맞는 검증 절차를 사용합니다. 위 CLI 명령은 원래 S3 위치에서 검증합니다.

## 5. 오프라인 실습 · 아홉 가지 검증 결과 읽기

<a href="{{ '/assets/labs/cloudtrail-integrity-lab.js' | relative_url }}" download>cloudtrail-integrity-lab.js</a>를 내려받아 본인 작업 공간에서 Node.js 18 이상으로 `node cloudtrail-integrity-lab.js`를 실행하세요. 실행할 때 임시 RSA 키와 가상 자료를 메모리에 만들며, 네트워크 연결이나 추가 패키지, AWS 계정이 필요하지 않습니다. 서명 입력과 JSON 구조는 실습을 위해 단순화했습니다.

| 살펴볼 상황 | 기대 결과 |
| --- | --- |
| 정상 체인과 gzip 압축 설정만 바꾼 체인 | 둘 다 `VALID_FILES_1`입니다. 압축 결과는 달라도 압축을 푼 바이트는 같습니다 |
| 압축을 푼 로그에 공백 한 바이트 추가 | JSON은 여전히 읽히지만 해시는 달라져 `LOG_HASH_MISMATCH`가 나옵니다 |
| 로그 또는 이전 다이제스트 누락 | 각각 `LOG_UNAVAILABLE` 또는 `DIGEST_UNAVAILABLE`이 나옵니다 |
| 서명된 다이제스트 본문 변경 | 로그 해시를 사용하기 전에 `BAD_DIGEST_SIGNATURE`가 나옵니다 |
| 최신 객체의 서명 메타데이터 누락 | 그 지점에서 검증을 시작할 수 없어 `NO_ANCHOR_SIGNATURE`가 나옵니다 |
| 서명된 다이제스트를 예상과 다른 경로에서 읽음 | 서명 확인은 통과하지만 `WRONG_DIGEST_PATH`가 나옵니다 |
| 서명이 유효하고 항목이 없는 시작 다이제스트 | `VALID_FILES_0`입니다. 다이제스트는 유효하며 목록에는 파일이 없습니다 |

먼저 공백을 한 바이트 추가했을 때의 결과를 예상해 보세요. 실행 후 마지막 줄이 `9 synthetic cases passed.`인지 확인합니다. 파일을 찾을 수 없다는 오류가 나면 다운로드 폴더에서 실행하는지, 파일명이 같은지 확인하세요. 예상과 결과가 다르면 오류 메시지에 나온 사례를 먼저 살펴봅니다. 가상 실습은 Node.js 24에서 실행했습니다. 실제 AWS의 전달, IAM 권한, CLI 동작은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **다이제스트의 서명이 유효한데 로그 해시를 왜 다시 계산할까요?** 서명은 기대 해시 목록의 출처를 검증합니다. 현재 확보한 로그의 바이트는 그 해시와 직접 대조해야 합니다.
- **최신 다이제스트가 비어 있고 서명은 유효합니다. 그 시간에 계정 활동이 없었다고 보고해도 될까요?** 해당 다이제스트에 나열된 로그 파일이 없었다고 기록하세요. 계정 활동을 판단하려면 선택기, 리전, 전달 지연과 별도 증거를 확인해야 합니다.
- **참조된 로그를 읽지 못했습니다. 변조라고 보고해도 될까요?** 읽기 실패와 검증하지 못한 범위를 기록하세요. 접근 권한, 보존 정책, 일시적 오류를 실제 삭제나 수정 증거와 구분합니다.
- **찾은 구간의 파일은 전부 유효하지만 요청한 구간보다 짧습니다. 무엇을 남길까요?** 요청·관측 구간을 모두 적고 나머지는 미검증으로 표시합니다. 인접 다이제스트와 전달 상태를 확인한 뒤 판단을 갱신합니다.

**완료 기준.** 추적, 리전, 요청·관측 구간, 처음 검증할 수 없었던 연결이나 객체, 현재 가설을 확인할 증거 출처를 한 건의 조사 기록으로 작성하세요.

[이전 · Amazon S3 객체 읽기 증거]({{ '/ko/wiki/s3-object-read-evidence/' | relative_url }}) · [다음 · 디지털 증거 보존]({{ '/ko/wiki/evidence-preservation/' | relative_url }}) · [배경 · 공개키와 전자서명]({{ '/ko/wiki/public-key-cryptography/' | relative_url }})

## 공식 참고자료

2026년 11월 21일 검토했습니다. 아래 자료는 검토일 기준 AWS CloudTrail 추적의 S3 전달 및 AWS CLI v2 동작을 다룹니다. AWS 가이드에 실린 예전 날짜의 샘플은 파일 형식을 보여주는 예시입니다.

- [CloudTrail · 로그 무결성 검증 개요](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)와 [다이제스트 구조, 빈 파일과 보충 파일](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-digest-file-structure.html)
- [CloudTrail · 자체 검증 구현 및 오프라인 보존 요건](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-custom-validation.html)
- [AWS CLI v2 · validate-logs](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/validate-logs.html), [get-trail-status](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-trail-status.html), [list-public-keys](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/list-public-keys.html)
- [CloudTrail · 이벤트 종류와 추적 범위](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html)

## AWS VPC Flow Logs 조사

[AWS VPC Flow Logs 조사]({{ '/ko/wiki/vpc-flow-log-evidence/' | relative_url }}). 클라우드 흐름을 관측 지점별로 읽고 네트워크 처리 결과와 기록 누락을 구분합니다.

## Google Cloud Storage 읽기 증거와 비교하기

[Google Cloud Storage 객체 읽기 조사]({{ '/ko/wiki/gcs-object-read-evidence/' | relative_url }})에서 목록·메타데이터·본문 전송과 감사 로그 수집 범위를 비교합니다.

수집 범위를 확인한 뒤 역할 세션을 조사하는 예시는 [AWS STS SourceIdentity 문서]({{ '/ko/wiki/aws-sts-source-identity-evidence/' | relative_url }})를 참고하세요.

[CloudTrail에서 S3 Object Lock 이벤트 홀드 해제 추적하기]({{ '/ko/wiki/s3-object-lock-event-hold-evidence/' | relative_url }})
