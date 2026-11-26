---
title: "Amazon S3 객체 읽기 조사 · 요청과 전송 바이트 대조하기"
description: "CloudTrail 데이터 이벤트와 서버 액세스 로그를 연결해 메타데이터 조회, 거절, 부분 응답과 수집 누락을 구분합니다."
category: cloud
tags: [AWS, Amazon S3, CloudTrail, Cloud Security, DFIR, Blue Team]
level: Beginner
updated: "2026-11-20"
translation_url: /wiki/s3-object-read-evidence/
---

**학습 목표.** S3 읽기 경보에서 요청과 기록에 나타난 호출자를 찾고, S3가 전송했다고 보고한 바이트를 확인합니다. S3 로그로 답하기 어려운 질문에는 어떤 자료가 더 필요한지도 판단합니다. 이 장은 범용 버킷에 직접 보낸 객체 요청을 다룹니다.

## 1. 버킷은 저장 공간이고 키는 객체 이름입니다

**버킷**은 객체를 담는 공간입니다. **객체 키**는 그 버킷 안에서 객체를 가리키는 이름입니다. `reports/daily.csv`에서 슬래시도 키의 일부입니다. 조사할 때는 `reports/`처럼 공통으로 시작하는 **접두사**를 기준으로 묶을 수 있습니다. 버전 관리가 켜져 있다면 요청이나 보조 자료에 기록된 **버전 ID**로 같은 키의 여러 저장 버전을 구분할 수 있습니다.

**관리 영역**에서는 버킷 정책처럼 설정을 읽거나 바꿉니다. **데이터 영역**에서는 저장된 객체에 작업합니다. `GetObject`는 객체 데이터를 가져오고, `HeadObject`는 본문 없이 메타데이터를 조회하며, `PutObject`는 데이터를 씁니다. 역할 세션은 요청에 쓰인 자격 증명을 식별합니다. 실제로 그 자격 증명을 사용한 사람이나 작업은 따로 확인해야 할 수 있습니다.

| 자료 | 확인할 항목 | 수집과 해석 |
| --- | --- | --- |
| CloudTrail 관리 이벤트 | 버킷 정책 변경, 역할 수임 등 관련 작업 | 조사 시점의 설정과 신원 이력 확인 |
| CloudTrail S3 데이터 이벤트 | `eventName`, `requestID`, `userIdentity`, `errorCode`, 기록에 있는 버킷과 키 | 해당 리소스 범위를 선택해 수집. Event history에는 데이터 이벤트가 표시되지 않음 |
| S3 서버 액세스 로그 | Request ID, 작업, HTTP 상태, Bytes Sent, Object Size | 원본 버킷에 수집을 설정. 전달이 늦거나 일부가 빠지거나 중복될 수 있음 |
| 앱·프록시·단말 기록 | 호출한 작업과 받은 응답의 처리 결과 | 별도 수집. 서버의 전송 기록만으로 클라이언트의 저장 여부를 확인할 수 없음 |

![S3 객체 요청은 수집 설정에 따라 CloudTrail과 서버 액세스 로그에 기록됩니다. 요청 ID로 연결한 뒤 객체와 응답 결과를 대조합니다.]({{ '/assets/diagrams/s3-object-read-ko.svg' | relative_url }})

두 로그는 같은 요청의 서로 다른 측면을 보여 줍니다. 전달 시각도 서로 다를 수 있습니다.

## 2. 정상 객체 읽기를 단계별로 따라가세요

11시 01분 UTC에 승인된 보고서 작업이 임시 세션 `report-reader/session-a`를 사용합니다. 가상의 `wiki-training` 버킷에서 `reports/daily.csv`를 읽습니다. CloudTrail에는 `eventSource=s3.amazonaws.com`과 `eventName=GetObject`가 해당 API 호출을 보여 주고, 신원 정보에는 역할 세션이 나옵니다. 액세스 로그에는 작업 `REST.GET.OBJECT`, HTTP 200, Bytes Sent 8,192, Object Size 8,192가 기록됩니다.

CloudTrail의 **`requestID`**와 액세스 로그의 **Request ID**부터 비교하세요. CloudTrail **`eventID`**는 CloudTrail의 개별 기록을 식별합니다. 액세스 로그의 **Host ID**는 S3 확장 요청 ID이므로 다른 항목입니다. ID가 맞으면 버킷·키·작업·시간을 대조하고, 버전 정보도 있으면 확인합니다. 요청 시각, API 이벤트 시각, 분석 시스템에 들어온 시각은 서로 다를 수 있습니다. 계정 여러 곳에서 수집한다면 기록을 받은 계정을 보존하고, `sharedEventID`가 있을 때 같은 작업에서 나온 CloudTrail 기록들을 구분하는 데 활용합니다. 원본 표기를 보존한 뒤 자료의 형식에 맞춰 필요한 인코딩을 한 번만 정규화하세요.

11시 02분에는 같은 작업이 바이트 범위를 지정해 요청합니다. 새 요청 ID에 **206 Partial Content**가 기록됐고, 8,192바이트 객체에 대해 Bytes Sent는 1,024입니다. S3가 HTTP 오버헤드를 제외하고 응답 바이트 1,024개를 보냈다는 뜻입니다. 저장 객체 크기는 8,192바이트입니다. 신뢰할 수 있는 요청 범위나 응답 범위 기록이 있다면 어느 부분인지 더 정확히 알 수 있습니다. 재시도나 범위 요청은 서로 겹칠 수 있으므로 응답 바이트 합계는 관찰된 전송량입니다. 중복을 뺀 데이터 노출량은 별도로 계산해야 합니다.

| 관측 자료 | 해석 가능한 범위 |
| --- | --- |
| 일치하는 GET, 200, Bytes Sent 8,192 | S3가 성공 응답 8,192바이트를 전송했다고 보고. 수신·저장 여부는 클라이언트 자료에서 확인 |
| 일치하는 GET, 206, Bytes Sent 1,024 | S3가 부분 응답을 보냈다고 보고. 서로 다른 노출 데이터를 계산하려면 범위와 버전 확인 |
| 일치하는 GET, 403과 `AccessDenied` | 해당 읽기는 거절됨. 0보다 큰 응답 바이트는 오류 본문일 수 있음 |
| 일치하는 HEAD, 200 | 메타데이터 요청에 대한 성공 응답. 객체 본문은 포함하지 않음 |
| CloudTrail이나 액세스 로그 한쪽만 있음 | 관측된 근거를 기록하고, 전송량 산정이나 호출자 판단 전에 수집 범위를 확인 |

## 3. 오용과 비슷해 보이는 정상 동작을 구분하세요

역할 세션을 탈취한 사람이 그 작업의 정상 호출과 비슷한 요청을 보낼 수 있습니다. 권한이 의도보다 넓게 설정되어 있으면 예상하지 못한 주체가 민감한 객체를 읽을 수 있습니다. 사전 서명 URL은 유효 시간과 권한 등 조건을 충족하면 URL을 가진 사람이 사용할 수 있습니다. 서버 액세스 로그에 `Authentication Type=QueryString`이 있으면 이 유형을 식별하는 데 도움이 됩니다. URL 서명자와 실제 사용자는 다를 수 있습니다. 조사 기록에서 전체 사전 서명 URL, 쿼리 문자열, 고객 객체 키는 민감 자료로 다루세요.

정상 작업의 실행 시간, 신원, 대상 접두사를 관측값과 비교하세요. 예상 밖 세션이 처음 보는 접두사에서 계속 성공적으로 읽었다면 조사할 근거가 됩니다. 정기 내보내기, 백업, 반복 재시도로도 비슷한 요청량이 나올 수 있습니다. IP는 프록시나 NAT 주소일 수 있고 User-Agent는 클라이언트가 제공할 수 있습니다. 두 값은 상황을 이해하는 데 쓰고, 역할 발급 기록과 작업 및 목적지 자료로 확인하세요. 낯선 IP나 403 급증만으로 성공적인 전송을 확정할 수는 없습니다.

## 4. 블루팀 수집·탐지·대응

1. **사건 당시의 수집 범위를 확인합니다.** 계정·리전·버킷 유형·시간대·이벤트 선택 조건을 확인합니다. 범용 버킷의 해당 버킷 또는 접두사에 대해 `AWS::S3::Object` 데이터 이벤트를 선택하고 읽기가 범위에 들어 있었는지 봅니다. CloudTrail의 실제 전달 또는 수집 목적지에 쿼리합니다. 액세스 로그의 전달, 권한, 보존과 색인도 확인하세요. AWS가 문서화한 VPC 엔드포인트 정책 거절처럼 두 로그에 모두 나타나지 않는 경우도 있습니다.
2. **두 원본을 보존하고 필요한 맥락을 추가합니다.** 이벤트와 수집 시각은 UTC로 맞추고, 리전·계정·버킷·키·작업·요청 ID·응답 상태를 남깁니다. CloudTrail에서 세션 ARN과 발급 주체가 제공되면 함께 보존하세요. 원본 접근을 통제하고, 빠졌거나 상충하거나 잘린 필드는 조사 항목으로 남깁니다. 따옴표로 둘러싸인 일부 필드에는 이스케이프되지 않은 따옴표가 들어갈 수 있으므로 형식에 맞는 파서가 필요합니다. 요청 ID가 없는 기록끼리 빈 문자열을 기준으로 합치지 마세요.
3. **비슷한 조건의 기준값과 비교합니다.** 작업·버킷 또는 민감 접두사·시간대별로 성공 GET, 거부 요청, 로그 수집량을 비교합니다. 수집 범위 변경과 예상하지 못한 성공 읽기도 함께 확인하세요. 동일 액세스 기록의 복사본은 검증하고 한 번만 집계합니다. 다른 요청 ID의 재시도는 별도 요청으로 남기고, 한쪽 로그만 확보된 건은 따로 기록합니다. 수집이 누락된 시간대에는 집계 신뢰도를 낮춰야 합니다.
4. **근거를 보존한 뒤 차단 효과까지 확인합니다.** 예상 밖 읽기가 다른 자료로도 뒷받침되면 IAM과 버킷 담당자와 당시 정책과 세션 자료를 보존합니다. 승인 절차에 따라 추가 읽기를 제한하거나 관련 접근 권한을 회수하고 정상 작업이 계속 작동하는지 확인하세요. 다른 객체 읽기·버전·호출자 로그·다운스트림 목적지도 조사합니다. 관측한 응답 바이트, 노출 가능 버전, 클라이언트에서 실제로 확인한 수신 내용을 구분해 기록합니다.

## 5. 오프라인 실습 · 가상 S3 요청 10건

[CloudTrail 실습 CSV]({{ '/assets/labs/s3-cloudtrail-projection.csv' | relative_url }}), [서버 액세스 실습 CSV]({{ '/assets/labs/s3-access-projection.csv' | relative_url }}), [Python 검토 스크립트]({{ '/assets/labs/s3-read-review.py' | relative_url }})를 같은 폴더에 내려받으세요. 버킷·세션·요청 ID는 모두 가상 값입니다. CSV는 학습용으로 추린 형식입니다. 실제 AWS 내보내기 형식과는 다릅니다. 스크립트는 Python 3 표준 라이브러리와 실습 파일만 사용하고 AWS에 접속하지 않습니다.

먼저 LAB-01과 LAB-02를 버킷과 요청 ID로 직접 맞춰 보세요. 키와 작업이 일치하는지 확인한 뒤, 서버 쪽 HTTP 상태와 응답 바이트를 비교합니다. 그다음 실행하세요.

```sh
python3 s3-read-review.py
```

| 사례 | 예상 판단 |
| --- | --- |
| LAB-01과 LAB-02 | 성공 응답 8,192바이트, 부분 응답 1,024바이트 |
| LAB-03과 LAB-04 | 읽기 거절, 이어서 짝이 되는 전송 기록을 찾을 수 없는 CloudTrail 단독 기록 |
| LAB-05와 LAB-06 | 액세스 로그 단독 기록, 이어서 메타데이터 응답 |
| LAB-07과 LAB-08 | 동일한 중복은 한 번만 세어 4,096바이트로 기록. 서로 다른 중복은 검토 보류 |
| LAB-09와 LAB-10 | ID는 같지만 키가 다름. 마지막 건은 비어 있는 객체의 성공 GET이라 0바이트 |

마지막 줄은 `Paired successful GET bytes in this fixture: 13312`입니다. 짝을 확인한 성공 GET 응답의 합입니다. 액세스 로그에만 있는 2,048바이트와 오류 응답 214바이트는 이 소계에 들어가지 않습니다. 값이 다르면 파일 이름 세 개를 확인한 뒤 요청 ID와 LAB-08의 두 행을 비교하세요. 스크립트는 실습 데이터의 일치 조건을 검사합니다. 실제 로그 형식, 신원이나 수신 여부는 따로 확인해야 합니다. 승인된 AWS 환경에서는 빈 테스트 자료를 한 번 읽고 SDK의 요청 ID를 전달된 두 로그와 대조해 수집 범위를 검증할 수 있습니다. 오프라인 실습은 실행했습니다. AWS 서비스의 로그 전달과 정책 집행은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **LAB-02에서 왜 8,192가 아니라 1,024바이트를 세나요?** 저장된 객체 크기는 Object Size를, 실제 응답 바이트는 Bytes Sent를 봅니다. 206은 부분 응답입니다.
- **LAB-03의 214바이트는 왜 빼나요?** 읽기가 거절됐고, S3는 오류 본문을 보낼 수 있습니다. 이 값만으로 객체 노출을 입증할 수 없습니다.
- **LAB-04의 전송량은 0인가요?** CloudTrail에는 요청이 있지만 짝이 되는 응답 기록이 빠졌습니다. 로그 범위와 요청 결과를 더 확인해야 합니다.
- **세션 이름으로 누가 요청했는지 알 수 있나요?** 사용된 세션의 이름을 알 수 있습니다. 실제 호출자는 역할 발급 기록, 작업 로그 등과 대조하세요.

**완료 기준.** 버킷, 키, 요청 ID, 기록에 나타난 세션, 응답 상태, S3가 보고한 전송량을 한 건의 조사 기록으로 작성하세요. 불확실한 점 한 가지와 확인할 자료를 적으면 완료입니다.

[이전 · AWS IAM 역할과 CloudTrail]({{ '/ko/wiki/aws-iam-role-evidence/' | relative_url }}) · [다음 · CloudTrail 로그 무결성]({{ '/ko/wiki/cloudtrail-log-integrity/' | relative_url }}) · [관련 · 디지털 증거 보존]({{ '/ko/wiki/evidence-preservation/' | relative_url }})

## 공식 참고자료

2026년 11월 20일 AWS 범용 S3와 CloudTrail 공식 자료를 검토했습니다. 운영 환경에서는 버킷 유형, 수집 설정과 보존 기간을 확인하세요.

- [Amazon S3 · 로그 수집 옵션과 제한](https://docs.aws.amazon.com/AmazonS3/latest/userguide/logging-with-S3.html)
- [Amazon S3 · CloudTrail 이벤트 종류, 지원 API와 리소스 유형](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html)
- [AWS CloudTrail · 이벤트 레코드 필드](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) · [신원 필드](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [Amazon S3 · 서버 액세스 로그 형식](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html) · [로그 전달 방식](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html)
- [Amazon S3 API · GetObject와 범위 응답](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)

## 이어서 읽기

[AWS KMS 조사 입문]({{ '/ko/wiki/aws-kms-evidence/' | relative_url }}) · 키를 사용한 호출과 S3 객체를 읽은 요청에서 각각 어떤 증거를 얻는지 살펴보세요.

[S3 객체 삭제와 복구 증거]({{ '/ko/wiki/s3-version-recovery-evidence/' | relative_url }}) · 삭제 마커와 영구 삭제를 구별하고 복구 후보 버전을 확인하세요.

## Google Cloud Storage 읽기 증거와 비교하기

[Google Cloud Storage 객체 읽기 조사]({{ '/ko/wiki/gcs-object-read-evidence/' | relative_url }})에서 목록·메타데이터·본문 전송과 감사 로그 수집 범위를 비교합니다.

## S3 퍼블릭 액세스 설정 조사

[S3 퍼블릭 액세스 차단]({{ '/ko/wiki/s3-block-public-access-evidence/' | relative_url }})에서 적용된 제한과 버킷 직접 요청의 증거를 대조하세요.

[심화 학습. S3 사전 서명 URL의 발급, 사용, 만료를 추적합니다.]({{ '/ko/wiki/s3-presigned-url-evidence/' | relative_url }})
