---
title: "Amazon S3 퍼블릭 액세스 차단 · 설정에서 객체 읽기 증거까지"
description: "S3의 유효 차단 설정과 ACL·정책의 차이를 읽고, 가상 요청으로 객체 데이터가 반환됐는지 확인합니다."
category: cloud
tags: [AWS, Amazon S3, Block Public Access, CloudTrail, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/s3-block-public-access-evidence/
---

점검 도구는 버킷 정책을 퍼블릭으로 표시합니다. 버킷 소유자는 계정에서 퍼블릭 액세스를 차단한다고 말합니다. S3 액세스 로그에서는 쿼리 문자열 서명을 사용한 성공 요청이 보입니다. 세 관측은 동시에 성립할 수 있습니다. 범용 버킷을 예로 들어 무엇이 설정됐는지, S3가 어떤 요청을 제한하는지, 어떤 데이터가 실제로 반환됐는지 살펴봅니다.

## 1. 차단 설정과 적용 범위를 이해하세요

**ACL**은 버킷이나 객체에 붙는 권한 목록입니다. **버킷 정책**은 버킷에 붙는 리소스 기반 정책입니다. **액세스 포인트 정책**은 해당 액세스 포인트로 들어오는 요청을 제어할 수 있습니다. **퍼블릭 액세스 차단**(BPA)은 이런 인가 경로에 제한을 추가합니다. 그 자체로 권한을 부여하지 않습니다. 어떤 설정에서 차단하지 않아도 해당하는 신원 정책과 리소스 정책 등 다른 검사는 계속 적용됩니다.

| 설정 | 어떤 동작을 바꾸나요? | 기존 권한에 미치는 영향 |
| --- | --- | --- |
| `BlockPublicAcls` | 퍼블릭 ACL 설정과 해당 ACL을 포함한 업로드를 거부 | 이 설정만으로 기존 퍼블릭 ACL을 무효화하지 않음 |
| `IgnorePublicAcls` | 권한 평가에서 퍼블릭 ACL을 제외 | ACL을 삭제하지 않음. ACL 쓰기를 거부할지는 다른 설정의 영향도 받음 |
| `BlockPublicPolicy` | S3가 퍼블릭으로 분류한 정책을 설치하려는 해당 요청을 거부 | 이 설정만으로 기존 퍼블릭 정책을 무효화하지 않음 |
| `RestrictPublicBuckets` | 적용 대상 버킷이나 액세스 포인트에 퍼블릭 정책이 있으면 요청 시 액세스를 제한 | 버킷에 직접 접근할 때는 다른 검사를 전제로 소유 계정의 인가된 주체와 AWS 서비스 주체로 제한. 이름이 명시된 외부 계정의 권한도 차단될 수 있음 |

S3는 적용 가능한 설정 가운데 가장 엄격한 조합을 사용합니다. **버킷 직접 경로**에서는 버킷과 **유효한 계정** 설정을 비교합니다. 액세스 포인트 경로에서는 해당 설정과 관련 소유 계정을 포함하세요. AWS Organizations의 S3 정책은 멤버 계정의 로컬 설정을 네 가지가 한 묶음인 정책으로 덮어쓸 수 있습니다. 이 경우 적용되지 않는 로컬 값을 다시 합치지 않고 유효 계정 설정을 봅니다. 범위와 시점도 중요합니다. 계정 설정은 모든 리전에 적용되며, 변경 내용이 모든 리전에 반영되기까지 시간이 걸릴 수 있습니다.

**Object Ownership**도 따로 확인하세요. `Bucket owner enforced`에서는 인가에 ACL을 사용하지 않고 정책이 액세스를 결정합니다. AWS는 2023년에 모든 생성 방식에서 새 버킷에 기본적으로 BPA를 적용하고 ACL을 비활성화하도록 바꿨습니다. 기존 버킷 설정은 당시 변경 대상에서 빠졌습니다. 오래된 버킷과 최근에 만든 버킷 모두 조사 시점의 실제 설정을 확인하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/s3-block-public-access-evidence-ko.svg' | relative_url }}" alt="버킷 및 유효 계정 설정으로 적용되는 차단을 확인합니다. 설정 변경, 인가 판단, 객체 응답은 서로 다른 자료를 조사합니다." style="max-width: 100%; height: auto;">
  <figcaption>그림 1. 설정을 확인한 뒤 개별 요청을 따라갑니다. 설정 기록과 객체 데이터 전송 기록은 서로 다른 사실을 보여 줍니다.</figcaption>
</figure>

## 2. 정상적인 비공개 읽기를 따라가세요

가상 환경의 계정에는 네 설정이 모두 켜져 있고 버킷에는 `Bucket owner enforced`가 적용됩니다. 소유 계정의 워크로드가 `reports/summary.csv`를 읽기 위해 서명된 `GetObject`를 보냅니다. 워크로드 정책이 허용하고 적용되는 명시적 거부, 엔드포인트 정책이나 키 정책이 가로막지 않는다고 가정합니다. 인증되지 않은 요청은 제한되지만 이 워크로드에는 객체가 반환될 수 있습니다.

승인된 업무 절차에서 동료에게 유효 기간을 제한한 사전 서명 URL을 전달할 수도 있습니다. S3 서버 액세스 로그에서는 `Authentication Type=QueryString`으로 나타날 수 있습니다. URL에는 서명 주체의 인증 정보가 담기며 유효한 동안 소지자가 사용할 수 있습니다. 받는 사람에게 AWS 로그인이 필요하지 않을 수 있습니다. URL 유출은 별도의 액세스 위험으로 보고 공유하는 증거에서는 서명과 쿼리 문자열을 가리세요. 이 요청의 성공만으로 버킷이 퍼블릭이거나 인증 없이 읽을 수 있다고 판단할 수 없습니다.

## 3. 어떤 제한이 문제를 설명하는지 확인하세요

가상의 버킷에 퍼블릭으로 분류된 정책이 있고, 그 정책에는 특정 파트너 계정을 허용하는 문장도 있다고 가정합니다. `BlockPublicPolicy`만 켜도 이미 저장된 정책은 그대로입니다. `RestrictPublicBuckets`가 적용되면 **정책 전체**가 퍼블릭으로 분류되므로, 특정 파트너에게 준 권한도 작동하지 않을 수 있습니다. 보안 제어를 바꾸기 전에 어느 경로에 어떤 제한이 적용됐는지 확인하세요. 정책과 실패 요청을 보존하고 승인된 설계의 신뢰 범위와 대조합니다.

S3는 자체 규칙으로 정책이 퍼블릭인지 분류합니다. 주체 범위가 넓더라도 요건을 충족하는 고정 조건이 있으면 제한이 없는 문장과 다르게 판정될 수 있습니다. S3가 반환한 정책 상태와 정책의 실제 적용 범위를 함께 보세요. 버킷 정책 상태만으로 객체 ACL, 액세스 포인트 정책이나 다른 전달 경로의 효과를 판단할 수 없습니다. S3용 IAM Access Analyzer는 명시된 외부 계정 등을 포함해 신뢰 영역 밖에서 접근할 수 있는 구성을 보고합니다. 분석기의 범위와 갱신 시각, 액세스 포인트 분석 범위를 확인하세요. 발견 항목은 구성에 관한 증거입니다.

허가 없이 차단 설정을 바꾸면 이전에 막혀 있던 넓은 권한이 다시 적용될 수 있습니다. 정상적인 이전 작업이나 긴급 변경에도 비슷한 감사 기록이 남습니다. 반대로 외부 읽기 시도는 거부됐을 수 있습니다. 변경 주체와 승인 여부, 실제 효과를 따로 확인하세요. CDN이 인증을 거쳐 비공개 S3 오리진에서 가져온 콘텐츠를 사용자에게 반환할 수 있습니다. CDN의 성공 응답만으로 버킷의 익명 접근을 판단하기는 어렵습니다.

## 4. 블루팀 수집·탐지·대응

| 출처 | 보존할 증거 |
| --- | --- |
| 유효 설정 | 버킷 소유자, 리전, 계정·버킷 BPA, Object Ownership, 정책, 관련 ACL, 요청 경로. 해당되는 경우 Organizations 정책과 액세스 포인트 확인. 설정이 없음, 요청이 거부됨, API 사용 불가를 각각 구분 |
| CloudTrail 관리 이벤트 | `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock`과 ACL·소유권 변경의 성공 및 실패. 권한과 수집 범위가 있다면 계정 및 조직의 변경 증거도 확보 |
| S3 요청 증거 | 대상 객체가 수집 범위에 있을 때 S3 데이터 이벤트를, 구성된 경우 서버 액세스 로그를 사용. 작업, 객체 키·버전, 시각, 요청 ID, 요청자 및 인증 방식, 상태, 전송 바이트를 보존. 기본 CloudTrail 이벤트 기록에는 데이터 이벤트가 없고 서버 액세스 로그 전달은 최선형 |

다음은 범용 버킷에 직접 적용하는 읽기 전용 AWS CLI v2 예입니다. 승인된 계정의 검증된 프로필을 사용하세요. `BUCKET`과 `OWNER`에는 승인받은 버킷과 12자리 소유 계정 ID를, `REGION`에는 버킷 리전을 지정합니다. 순서대로 `s3:GetAccountPublicAccessBlock`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus`, `s3:GetBucketOwnershipControls` 권한이 필요합니다. 첫 명령은 유효 계정 설정을 읽습니다.

```bash
aws s3control get-public-access-block --account-id "$OWNER" --region "$REGION"
aws s3api get-public-access-block --bucket "$BUCKET" --expected-bucket-owner "$OWNER" --region "$REGION"
aws s3api get-bucket-policy-status --bucket "$BUCKET" --expected-bucket-owner "$OWNER" --region "$REGION"
aws s3api get-bucket-ownership-controls --bucket "$BUCKET" --expected-bucket-owner "$OWNER" --region "$REGION"
```

정상 변경 시간대를 벗어난 성공한 설정 변경을 찾은 뒤 외부 액세스 발견 항목과 인증·미인증 트래픽을 비교하세요. 시각, 버킷, 엔드포인트, 가능한 경우 요청 ID로 연결합니다. S3 서버 액세스 로그의 인증 방식 `-`는 미인증 요청을 나타낼 수 있습니다. `REST.GET.OBJECT`에 `200` 또는 `206`과 양수의 전송 바이트가 있다면 그 요청에서 본문이 반환됐다는 근거입니다. `206`은 부분 응답입니다. 403이나 성공한 HEAD는 다른 증거를 제공합니다. 전송 바이트만으로 모든 바이트의 수신 여부나 읽은 사람의 신원을 확정할 수 없습니다.

정책 변경 전후의 내용과 당시 로그 수집 범위를 보존하세요. 노출이 계속 의심되면 승인된 최소 권한 조치로 차단하고, 필요한 비공개 연동이 유지되는지 해당 경로에서 승인된 절차로 검증합니다. 이전 읽기 가능성은 별도로 추적하세요. 확인을 위해 퍼블릭 권한을 다시 열 필요는 없습니다. 콘텐츠가 이미 공유됐다면 버킷과 전달 경로를 모두 확인합니다.

## 5. 승인된 오프라인 실습

<a href="{{ '/assets/labs/s3-block-public-access-evidence.py' | relative_url }}" download>Python 판정 도구</a>와 <a href="{{ '/assets/labs/s3-block-public-access-cases.json' | relative_url }}" download>가상 사례</a>를 같은 폴더에 저장하세요. 소유하거나 사용을 승인받은 환경에서 Python 3으로 실행합니다. 도구는 파일만 읽고 AWS에 접속하지 않습니다. 자료에는 적용 범위의 설정이 모두 있으며 필요할 때 퍼블릭 정책 분류는 미리 확인한 값으로 제공됩니다. 선택한 제한 규칙을 시험하는 도구로, 전체 IAM 인가는 계산하지 않습니다.

```bash
python3 s3-block-public-access-evidence.py
```

| 비교할 사례 | 기대 결과 |
| --- | --- |
| 퍼블릭 ACL·정책 쓰기와 기존 권한 | 쓰기 거부와 요청 시 적용 여부는 서로 다른 제어에 따름 |
| 버킷 설정이 꺼져 있지만 유효 계정에서 제한 | 해당 제한은 여전히 적용 |
| ACL 비활성화와 퍼블릭 정책의 명시적 파트너 | 소유권 설정으로 ACL 경로가 비활성화됨. 정책 전체에 대한 제한은 파트너도 차단할 수 있음 |
| 미인증, 사전 서명, 거부, 메타데이터만 확인한 관측 | 인증 방식과 객체 본문 증거를 각각 확인 |

기대 출력은 `12/12 evidence cases matched.`입니다. 대조 시험에서 C의 유효 계정 `BlockPublicPolicy`를 `false`로 바꾸고 기대 판정은 그대로 두면, 도구가 차이를 검출하고 종료 코드 1을 반환해야 합니다. 원본에서 실패하면 두 파일이 같은 판인지 확인하고 실패한 사례 ID를 살펴보세요. 정의된 경로와 정규화한 기록만 실습 범위에 들어갑니다. 실제 AWS 계정, S3 요청, CLI 인가 동작은 공식 문서를 기준으로 검토했습니다.

## 6. 확인 문제와 완료 기준

1. **버킷 설정이 false면 실제 퍼블릭 액세스가 가능한가요?** 유효 계정 설정과 요청 경로, 정책, 소유권 설정 및 기타 인가 조건을 확인해야 합니다.
2. **사전 서명 URL로 성공한 읽기는 익명인가요?** 쿼리 문자열로 인증한 요청입니다. S3에서 인증하지 않은 요청과 구분하세요.
3. **별개 문장이 퍼블릭이면 특정 파트너도 거부되나요?** 그 정책에 `RestrictPublicBuckets`가 적용된다면 가능합니다. 외부 계정을 명시해도 이 제한이 해제되지는 않습니다.

**완료 기준.** 열두 가지 사례와 대조 시험을 재현하고, 설정을 쓸 때의 제한과 객체를 요청할 때의 제한, 실제 데이터 전송 증거를 구분해 설명하세요. 이어서 [S3 객체 읽기 조사]({{ '/ko/wiki/s3-object-read-evidence/' | relative_url }})에서 객체 수준 기록을 연관 분석해 보세요.

## 공식 참고자료

2026-11-26에 검토했습니다. 2023년 기본값 변경은 과거 변경 이력입니다. 제품 동작과 AWS CLI v2 명령은 검토일의 공식 문서를 기준으로 합니다.

- [S3 퍼블릭 액세스 차단과 정책 분류](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html), [AWS Organizations의 Amazon S3 정책](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_s3.html)
- [Object Ownership](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html), [2023년 4월 기본값 변경 공지](https://aws.amazon.com/about-aws/whats-new/2022/12/amazon-s3-automatically-enable-block-public-access-disable-access-control-lists-buckets-april-2023/)
- [AWS CLI v2의 유효 계정 설정 조회](https://docs.aws.amazon.com/cli/latest/reference/s3control/get-public-access-block.html), [버킷 정책 상태](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html), [S3용 IAM Access Analyzer](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-analyzer.html)
- [S3 CloudTrail 이벤트](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html), [서버 액세스 로그 수집](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html), [로그 필드](https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html)

## AWS Organizations 정책 경로 확인하기

[AWS 서비스 제어 정책 증거]({{ '/ko/wiki/aws-scp-evaluation-evidence/' | relative_url }})에서 실제 호출자 계정의 조직 경로와 SCP 거부를 조사하는 방법을 살펴보세요.
