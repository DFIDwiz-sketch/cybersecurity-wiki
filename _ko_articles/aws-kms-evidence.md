---
title: "AWS KMS 조사 입문 · 키 사용, CloudTrail, S3 객체 읽기"
description: "봉투 암호화를 이해하고 키 정책 변경, 복호화 호출, 애플리케이션의 실제 데이터 사용을 구분합니다."
category: cloud
tags: [AWS, AWS KMS, CloudTrail, Amazon S3, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/aws-kms-evidence/
---

**학습 목표.** KMS 이벤트와 애플리케이션 경보를 받으면 어떤 키가 관련됐는지, 그 호출로 어디까지 판단할 수 있는지, 다음에 어떤 증거를 찾을지 설명할 수 있습니다. 역할 세션이 낯설다면 [AWS 역할과 CloudTrail]({{ '/ko/wiki/aws-iam-role-evidence/' | relative_url }})부터 읽어 보세요.

## 1. 데이터 하나를 왜 키 두 개로 보호할까요?

AWS Key Management Service(**KMS**)는 키를 관리하고 승인된 요청에 암호화 작업을 수행합니다. **KMS 키**는 ARN, 키 상태, 접근 정책을 갖는 리소스입니다. **별칭(alias)**은 바꿀 수 있는 키 이름입니다. 조사할 때는 리전, 계정, 실제 키 ARN을 확보하세요. 연결 대상이 바뀐 별칭의 현재 값만으로 과거에 사용된 키를 알아낼 수 없습니다.

**봉투 암호화(envelope encryption)**에서는 **데이터 키**로 본문을 암호화하고, KMS 키로 데이터 키의 사본을 암호화합니다. 예를 들어 보고 작업은 대칭 KMS 키를 지정해 `GenerateDataKey`를 호출합니다. KMS는 평문 데이터 키와 그 키를 암호화한 사본을 반환합니다. 보고 작업은 평문 데이터 키로 파일을 암호화하고, 이 키를 가능한 한 빨리 메모리에서 제거합니다. 암호화된 데이터 키는 암호화된 파일과 함께 보관합니다. 나중에 읽을 때는 암호화된 데이터 키를 `Decrypt`에 보내고, 돌아온 평문 데이터 키로 파일을 복호화합니다. 이 흐름에서 보고 작업에 KMS 키 자체의 키 재료를 넘기지 않습니다.

<figure style="margin-inline:0">
  <img src="{{ '/assets/diagrams/kms-cloudtrail-ko.svg' | relative_url }}" width="400" height="396" alt="암호화된 데이터 키를 KMS Decrypt에 보냅니다. 권한을 확인한 KMS가 데이터 키를 복호화하고 호출 측에서 본문을 읽습니다. 조사자는 각 단계의 증거를 비교합니다.">
  <figcaption>그림 1. KMS 호출 결과와 데이터 본문 처리는 서로 다른 단계입니다. 그림은 KMS를 호출하는 대칭 봉투 암호화 예시입니다.</figcaption>
</figure>

**암호화 컨텍스트(encryption context)**는 비밀이 아닌 키와 값의 묶음입니다. 대칭 KMS 암호화는 이를 추가 인증 데이터로 암호문에 결합합니다. 암호화할 때 사용했다면 복호화 시 대소문자까지 같은 쌍을 제출해야 합니다. 정책 조건으로 기대한 컨텍스트에서만 키를 쓰도록 제한하는 것은 별도의 권한 판단입니다. `purpose=daily-report` 같은 값은 CloudTrail에서 평문으로 보일 수 있으니 자격 증명이나 민감한 식별자를 넣지 않습니다. 애플리케이션이 제출한 라벨은 조사 단서이며, 파일의 실제 상태나 동작은 별도 증거로 확인해야 합니다.

## 2. 누가 키를 관리하거나 사용할 수 있나요?

| 통제 | 역할 | 조사할 항목 |
| --- | --- | --- |
| 키 정책 | 해당 리전의 특정 키에 붙는 리소스 정책 | 허용된 주체·동작·조건과 IAM 정책을 통한 권한 부여를 허용하는지 |
| IAM 정책 | 호출 주체에 적용하는 권한 | 실제 역할·세션과 관련 제약. 키 정책이 IAM 정책을 통한 허용을 지원하지 않으면 IAM의 허용만으로 사용할 수 없음 |
| 권한 부여(grant) | 단일 키에서 지정한 동작을 허용. 서비스 연동에 자주 사용 | 권한을 받는 주체, 허용 동작, 조건, 생성부터 종료까지의 이력. 거부를 지정하는 기능은 없음 |
| 키 상태 | 암호화 작업을 수행할 수 있는지 결정하는 요소 | 활성, 비활성, 삭제 대기 등과 사건 전후의 상태 변경 |

서로 다른 계정 사이에 **정책으로** 접근을 허용하려면 키 소유자 측 정책과 호출자 계정의 권한이 모두 필요합니다. grant는 별도의 권한 부여 수단입니다. 해당 요청에 영향을 주는 명시적 거부, 조직 정책, 권한 경계, 세션 정책, 엔드포인트 정책을 함께 확인하세요. 키를 관리하는 권한과 그 키로 복호화하는 권한은 별개입니다.

고객 관리형 키는 팀에서 정책을 관리하고 사용을 모니터링할 수 있습니다. AWS 관리형 키는 연동 서비스에 대해 AWS가 관리하며 고객 계정에 표시됩니다. AWS 소유 키는 AWS 서비스가 고객 계정 밖에서 소유하고 관리하므로 고객 측 통제와 증거가 다릅니다. 이 장은 고객 관리형 대칭 암호화 KMS 키를 기준으로 설명합니다.

## 3. 성공한 호출과 실패한 호출을 읽어 보기

**가상 사례** K01에서는 `TrainingReport` 역할 세션이 `us-west-2`에서 `Decrypt`에 성공했습니다. 먼저 `eventSource=kms.amazonaws.com`, `eventName=Decrypt`, 시각, 리전, 역할 세션을 확인하세요. `resources[].ARN`이 있으면 실제 리소스 ARN을 확인하고, 요청에 `requestParameters.keyId`가 있으면 비교합니다. 앞의 값은 기록된 리소스, 뒤의 값은 요청에 들어간 식별자입니다. 요청 식별자만 확인할 수 있다면 근거의 범위를 기록하세요. CloudTrail은 암호화 작업의 응답 내용을 생략하므로 `responseElements: null`이어도 성공일 수 있습니다. 결과는 오류 필드와 동작 맥락에서 확인합니다.

K02에는 `IncorrectKeyException`이 있습니다. 지정한 KMS 키로 해당 암호문을 복호화할 수 없었다는 뜻입니다. 권한을 바꾸기 전에 암호화된 데이터 키의 생성 내역과 요청 키 ID를 확인합니다. `InvalidCiphertextException`은 다른 오류이며 암호문이 유효하지 않거나 컨텍스트가 없거나 맞지 않을 때 나타날 수 있습니다. `AccessDenied`라면 인가 경로를 살펴봅니다. 모든 실패를 IAM 설정 문제로 판단하지 말고 오류와 정확한 호출 범위를 남기세요.

계정이 달라지면 결과에 따라 보이는 위치도 다릅니다. K03은 서로 다른 `eventID`와 `recipientAccountId`를 가진 레코드 두 건이 `sharedEventID` 하나를 공유합니다. CloudTrail이 같은 동작을 두 계정에 따로 기록한 것입니다. 원본은 둘 다 보존하고 호출량은 한 건으로 계산합니다. 계정 간 호출이 권한 부족으로 거부되면 AWS 문서에 따르면 **호출자 계정에만** 기록됩니다. K04에서 키 소유자 쪽에 해당 기록이 없어도 설명 가능한 결과입니다. 호출자 기록을 확인하고 실제 확보한 계정별 증거를 남기세요.

## 4. 키 사용과 S3 객체 읽기 구분하기

S3의 **SSE-KMS**는 서버 측 암호화 과정에 KMS를 사용합니다. S3 Bucket Key를 쓰지 않는 SSE-KMS 객체의 기본 암호화 컨텍스트는 객체 ARN입니다. 객체가 **S3 Bucket Key**를 사용하면 버킷 ARN이 컨텍스트에 들어갑니다. S3는 일정 시간 동안 버킷 수준 키를 재사용하므로 객체마다 KMS에 요청할 필요가 줄어듭니다. AWS 문서에 따르면 이 키를 재사용하는 후속 요청은 KMS를 호출하거나 그 요청에 대해 KMS 키 정책을 다시 평가하지 않습니다. S3 쪽 접근 판단은 여전히 중요합니다.

| 증거 | 여기서 알 수 있는 것 | 한계와 추가 확인 |
| --- | --- | --- |
| 성공한 KMS `Decrypt` | KMS가 해당 암호화 요청을 성공적으로 처리함 | 워크로드, 데이터 경로, 처리 결과를 별도로 확인. CloudTrail은 복호화한 바이트를 제공하지 않음 |
| 성공한 S3 `GetObject` 데이터 이벤트 | S3가 지정된 객체에 대한 요청을 오류 없이 기록함 | 필요하면 전송 바이트, 범위 읽기, 클라이언트의 처리를 확인 |
| 비슷한 시각의 버킷 수준 KMS 컨텍스트 | 해당 버킷의 맥락에서 KMS 동작을 기록함 | 객체를 특정할 수 없음. 시각이 가깝다는 이유만으로 어떤 `GetObject`와 짝지을 수 없음 |
| `GetObject`는 있고 대응하는 KMS 이벤트가 없음 | S3 데이터 이벤트가 확인됐고 KMS 호출은 관측되지 않음 | 이유를 판단하기 전에 해당 객체의 Bucket Key 사용 상태와 KMS 읽기 이벤트 수집 범위를 확인 |

K05에는 성공한 객체 요청과 확인된 Bucket Key 사용 사실이 있지만 KMS 이벤트가 없습니다. 읽기마다 KMS 호출이 생길 필요는 없습니다. K08에는 비슷한 시간의 버킷 수준 `Decrypt`가 있어도 객체 수준의 연결은 여전히 확인되지 않습니다. 암호화 설정은 해당 객체나 버전에서 확인하세요. 현재 버킷 기본값만으로 기존 객체나 개별 재정의 객체의 설정을 알 수 없습니다. 요청 ID와 전송 바이트는 [S3 객체 읽기 증거]({{ '/ko/wiki/s3-object-read-evidence/' | relative_url }})에서 이어서 다룹니다.

## 5. 수집, 탐지, 대응 순서

트레일의 과거 기록을 볼 때는 계정, 리전, 보존 기간, 전달 상태, 사건 당시 이벤트 선택기를 확인하세요. 애플리케이션이 데이터를 쓰는 과정에서 발생했더라도 CloudTrail은 `Decrypt`와 `GenerateDataKey`를 **읽기 관리 이벤트**로 분류합니다. 쓰기 전용 트레일이나 KMS 제외 설정에서는 이 호출들이 빠질 수 있고, 별도 소스에는 S3 데이터 이벤트가 보일 수 있습니다. S3 객체 이벤트의 경우 데이터 선택기가 해당 ARN과 시기를 포함하는지 확인하세요. 이벤트 기록(Event history)은 선택한 리전의 최근 90일 관리 이벤트를 보여 주는 별도 화면입니다. 콘솔에서 암호화 호출을 조사하려면 기본 `읽기 전용=false` 필터를 해제하세요. 원본 전달 파일을 보존하고 `eventID`, 있는 경우 `sharedEventID`, 계정, 시각, 리전, 세션 발급자, 요청·오류를 남깁니다.

아래 **조회 전용** AWS CLI v2 명령은 승인된 조사 프로필과 `cloudtrail:LookupEvents`, `cloudtrail:GetEventSelectors` 권한이 있을 때 사용할 수 있습니다. 프로필, 트레일 ARN, 리전, 조사 시각을 실제 범위로 바꾸세요. 첫 명령에는 활동이 일어난 리전을, 두 번째에는 트레일의 홈 리전을 지정합니다. 첫 명령은 관리 이벤트를 조회하며 S3 객체 데이터 이벤트는 포함하지 않습니다. 두 번째 명령은 현재 선택기를 봅니다. 과거 설정은 구성 이력이나 변경 기록을 통해 확인하세요.

```sh
aws cloudtrail lookup-events --profile YOUR_AUDIT_PROFILE --region us-west-2 \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=kms.amazonaws.com \
  --start-time 2026-11-21T05:00:00Z --end-time 2026-11-21T05:20:00Z
aws cloudtrail get-event-selectors --profile YOUR_AUDIT_PROFILE --region us-west-2 \
  --trail-name YOUR_TRAIL_ARN
```

| 신호 | 대조할 증거 | 대응 |
| --- | --- | --- |
| 중요한 키에서 처음 본 호출 계정이나 역할 | 키 ARN, 소유자·호출자 쪽 기록, 세션 발급, 예정된 서비스 연동과 승인 이력 | 양쪽 기록을 보존하고 데이터 노출을 판단하기 전에 후속 워크로드 활동을 확인 |
| 거부되거나 잘못된 키를 사용한 호출 증가 | 오류·호출자·키·리전별로 묶고 배포, 키 상태, 별칭 변경, 평소 호출량과 대조 | 확인된 원인을 수정. 첫 대응으로 권한을 넓히지 않음 |
| 예상 밖 `PutKeyPolicy`, `CreateGrant`, 키 비활성화 | 변경 전후의 접근 상태, 부여한 동작, 승인 기록, 키 소유자, 의존 서비스 | 공용 키를 수정하기 전에 소유자와 조율하고 증거를 보존. 변경 성공 자체로 후속 키 사용을 확인할 수 없음 |

역할 세션이 오용되거나 grant의 권한이 과도하면 정상 호출과 비슷한 형태로 암호화 작업이 기록될 수 있습니다. 기대한 서비스·키·역할의 관계와 워크로드의 실제 사용 기록을 비교하세요. 정상 서비스 배포에서도 grant 생성과 호출량 증가가 발생할 수 있습니다. 운영 통제 확인은 본인 소유 또는 명시적 승인 샌드박스에서 계정 소유자와 함께 진행하고, 일회용 훈련 데이터에 대한 허용·거부 사례와 수집기에 들어올 예상 결과를 먼저 정하세요. 아래 실습은 키 생성이나 정책 변경, AWS 접속 없이 진행합니다.

## 6. 오프라인 실습과 확인 문제

<a href="{{ '/assets/labs/kms-cloudtrail-cases.json' | relative_url }}" download="kms-cloudtrail-cases.json">가상 사례 JSON</a>과 <a href="{{ '/assets/labs/kms-cloudtrail-review.py' | relative_url }}" download="kms-cloudtrail-review.py">Python 분석 스크립트</a>를 같은 디렉터리에 저장하세요. Python 3.10 이상과 표준 라이브러리만 있으면 됩니다. 로그는 필요한 필드만 추린 가상 자료입니다. 이벤트 바깥의 참·거짓 필드는 따로 확인한 수집 범위나 객체 설정을 실습에 제공합니다. 실제 조사에서는 원본에서 그 사실도 직접 확인해야 합니다. 스크립트는 사례별로 복호화 기록을 묶는 교육용이며 AWS 권한 판정이나 데이터 흐름을 재현하지 않습니다.

```sh
python3 kms-cloudtrail-review.py kms-cloudtrail-cases.json --check
```

| 사례 | 예상 해석 | 자료에서 관측한 Decrypt 동작 |
| --- | --- | --- |
| K01 | KMS 복호화 성공. 앱 결과는 별도 확인 | 1건 |
| K02 | 잘못 지정한 키로 복호화가 거부됨 | 시도 1건 |
| K03 | 두 계정에 같은 성공 동작이 기록됨 | 1건 |
| K04 | 계정 간 권한 거부. 호출자에 기록됨 | 시도 1건 |
| K05 | S3 읽기는 확인. 읽기마다 KMS 호출이 필요한 구조가 아님 | 관측 0건 |
| K06 | 읽기 이벤트 수집 범위가 빠져 사용 여부 판단 불가 | 관측 0건 |
| K07 | 키 정책 변경. 이 사례에 Decrypt 기록은 없음 | 관측 0건 |
| K08 | S3 읽기와 가까운 시각의 버킷 수준 KMS 호출. 같은 객체에 연결할 근거 부족 | 1건 |

2026-11-21에 Python 3.12.14로 실행해 `8/8 synthetic cases matched.`를 확인했습니다. CLI 예시, 권한 평가, 서비스 동작은 AWS 문서로 검토했습니다. 실습에서는 실제 AWS 계정을 사용하지 않았습니다. 실패하면 두 파일명과 현재 디렉터리, Python 버전을 확인하세요. 자료를 일부러 바꿔 보려면 `--check`를 빼고 실행하고, 예상 결과를 다시 확인할 때는 처음 내려받은 자료를 사용합니다.

1. **K01의 `responseElements: null`은 복호화 실패인가요?** 응답 내용은 생략됩니다. 오류 필드와 어떤 호출이었는지 함께 확인하세요.
2. **K03을 복호화 두 건으로 세어도 될까요?** 두 계정 기록을 보존하되 공통 식별자로 호출 한 건을 계산합니다.
3. **K06과 K05의 0건은 같은 뜻인가요?** K06은 수집 공백입니다. K05는 Bucket Key를 활용할 수 있는 객체의 S3 요청이 관측된 경우입니다. 둘 다 실제 KMS 호출 총량은 확정할 수 없습니다.
4. **K01 뒤에 데이터가 외부로 나갔는지 확인하려면 무엇이 필요한가요?** KMS 기록에 애플리케이션·객체 접근, 서버 응답, 전송 기록, 클라이언트나 엔드포인트의 증거를 더해야 합니다.

여덟 결과를 재현하고, 중복된 계정 기록과 S3 객체 기록의 의미를 설명하며, 각 사례에서 다음 증거를 고를 수 있으면 학습을 마친 것입니다. [S3 객체 읽기 증거]({{ '/ko/wiki/s3-object-read-evidence/' | relative_url }})와 [CloudTrail 로그 무결성]({{ '/ko/wiki/cloudtrail-log-integrity/' | relative_url }})에서 이어서 학습하세요.

## 공식 참고자료

검토일은 2026-11-21입니다. AWS 클라우드 서비스 및 AWS CLI v2 문서이며, 과거 사건에는 당시 구성과 보존 정책을 적용합니다.

- [AWS KMS 키 유형](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html).
- [KMS 데이터 키](https://docs.aws.amazon.com/kms/latest/developerguide/data-keys.html), [암호화 컨텍스트](https://docs.aws.amazon.com/kms/latest/developerguide/encrypt_context.html), [Decrypt API](https://docs.aws.amazon.com/kms/latest/APIReference/API_Decrypt.html).
- [KMS 키 정책](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html), [계정 간 접근](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying-external-accounts.html), [grant](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html).
- [KMS CloudTrail 로깅](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html), [Decrypt 기록 예시](https://docs.aws.amazon.com/kms/latest/developerguide/ct-decrypt.html), [CloudTrail 필드](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html). 일부 과거 관리 기록에는 2022년 12월에 추가된 리소스 속성이 빠질 수 있습니다.
- [S3 SSE-KMS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)와 [S3 Bucket Key](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html).
- [CloudTrail 관리 이벤트 수집](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html), [이벤트 기록](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events-console.html), AWS CLI v2의 [lookup-events](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/lookup-events.html)와 [get-event-selectors](https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/get-event-selectors.html).
