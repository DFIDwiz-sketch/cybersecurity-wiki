---
title: "AWS 서비스 제어 정책(SCP) · 액세스 거부 원인 추적하기"
description: "호출자 계정에서 루트와 OU를 따라 정책을 확인하고 SCP의 명시적 거부와 허용 누락을 구분합니다."
category: cloud
tags: [AWS, IAM, AWS Organizations, CloudTrail, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/aws-scp-evaluation-evidence/
---

배포 역할의 IAM 정책에는 API 작업이 허용되어 있습니다. 그런데 같은 작업이 AWS 계정 한 곳에서만 실패합니다. 역할 권한을 추가하기 전에 **실제 호출한 세션**이 어느 계정에 속하는지 확인하고, 요청 당시 그 계정의 AWS Organizations 정책 경로를 복원해 보세요.

## 1. SCP의 역할과 적용 범위

AWS Organizations는 조직 **루트**와 그 아래에 중첩할 수 있는 **조직 단위(OU)**에 계정을 배치합니다. 여기서 루트는 조직의 최상위 컨테이너이며 AWS 계정의 루트 사용자와 별개입니다. **서비스 제어 정책(SCP)**은 적용 대상인 멤버 계정 주체의 최대 권한을 제한합니다. SCP 자체로 권한이 부여되지는 않습니다. 멤버 계정의 루트 사용자도 문서화된 일부 예외를 제외하면 적용 대상입니다. 관리 계정과 서비스 연결 역할에 붙은 권한은 이 제한의 적용 범위 밖입니다. 서비스가 일반 역할을 맡았다는 이유만으로 서비스 연결 역할이라고 판단하면 안 됩니다.

| 계층 | 무엇을 확인하나요? | 수집할 근거 |
| --- | --- | --- |
| 역할·세션 | 누가 요청했으며 어떤 신원·세션 제한이 적용되나요? | 호출자 계정, 맡은 역할과 세션, 관련 정책과 권한 경계 |
| SCP | 호출자의 조직 경로에서 이 요청 조건에 해당 작업을 허용하나요? | 루트와 직계 OU 경로, 계층마다 직접 연결된 정책, 일치한 조건 |
| 리소스 측 제어 | 리소스 정책과 서비스 제한상 접근할 수 있나요? | 리소스 정책, 지원되는 경우 리소스 제어 정책(RCP), 서비스별 설정 |
| 서비스 응답 | 이 호출의 실제 결과는 무엇인가요? | 응답 상태, 오류의 문맥, 요청 ID, 확인 가능한 감사 기록 |

SCP를 조사할 때는 **호출자의 멤버 계정 경로**부터 봅니다. 외부 계정의 주체가 리소스에 직접 요청한 경우, 리소스 소유 계정의 SCP가 그 외부 주체를 제한하지는 않습니다. 호출자 자신의 제어와 리소스 측 제어는 별도로 적용될 수 있습니다. RCP는 지원되는 멤버 계정 리소스에 대해 외부 주체의 요청도 제한할 수 있습니다. STS를 썼다면 처음 역할을 맡은 호출자와 이후 API 작업을 실행한 역할 세션을 구분합니다. 호출마다 적용되는 주체와 조건이 다를 수 있습니다.

## 2. 조직 경로를 따라 평가하기

SCP가 활성화되어 있고 적용 대상인 요청이라면 루트부터 각 직계 OU를 거쳐 계정까지 확인합니다. **각 계층마다** 직접 연결된 SCP 중 적어도 한 곳에 요청과 일치하는 `Allow`가 있어야 합니다. 같은 계층에 붙은 여러 정책은 그 계층의 허용을 보완할 수 있습니다. 경로 어디에서든 일치하는 명시적 `Deny`가 있으면 허용보다 우선합니다. 조건이 맞지 않는 문은 이번 요청을 허용하거나 거부하지 않습니다. 관리형 `FullAWSAccess`가 붙은 계층은 허용 조건을 충족할 수 있지만 별도의 명시적 거부는 여전히 유효합니다. 같은 상위 OU에 속하는 다른 OU는 호출자 경로에 포함되지 않습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/aws-scp-evaluation-evidence-ko.svg' | relative_url }}" alt="멤버 계정의 역할에 대해 조직 루트, 각 상위 OU, 계정을 확인합니다. 각 계층에 일치하는 허용이 필요하고 경로에 일치하는 명시적 거부가 하나라도 있으면 SCP 계층에서 막힙니다. 통과 후에는 다른 권한 조건을 확인합니다." style="max-width: 100%; height: auto;">
  <figcaption>그림 1. 호출자 계정의 조직 경로를 확인한 뒤 나머지 권한 제어를 확인합니다.</figcaption>
</figure>

## 3. 정상 요청과 두 가지 거부 비교하기

가상의 조직에서 멤버 계정의 역할 세션 `InventoryJob`이 `eu-west-1`에서 `ec2:DescribeInstances`를 호출합니다. 루트와 계정에는 일치하는 허용이 있습니다. Production OU에 직접 연결된 정책 중 하나는 이 작업을 허용하고 다른 하나는 관련 없는 서비스만 다룹니다. 일치하는 SCP 거부도 없습니다. 신원 권한과 다른 제어도 작업을 허용하면 서비스가 인벤토리를 반환할 수 있습니다.

UTC 10:05에 승인된 정책 배포가 루트에 해당 리전과 일치하는 명시적 거부를 추가합니다. Production OU에 허용이 있어도 호출은 거부될 수 있습니다. 별도 사례에서는 루트 거부를 추가하지 않았지만, 계정을 일치하는 허용이 없는 OU로 옮겼습니다. 계정의 정책 문서는 그대로여도 경로에서 필요한 허용이 빠져 실패할 수 있습니다. 두 경우 모두 그 호출을 당시 조직 상태와 성공한 설정 변경 이벤트에 연결해 확인합니다.

관리 실수나 승인되지 않은 정책 편집은 조직의 큰 범위에 접근을 열거나 제한할 수 있습니다. 배포 시차, OU 이동 또는 호출 세션 변경도 서로 다른 결과의 원인이 될 수 있습니다. 오류 문구는 해당 요청에 대한 근거로 사용하세요. AWS가 SCP 관련 설명을 제공하면 명시적 거부와 허용 누락을 구분할 수 있습니다. 일부 호출은 일반적인 거부 메시지만 줍니다. 상세 메시지도 여러 원인 중 하나를 보여 줄 수 있어서, 그 원인을 해결한 뒤 다른 거부가 드러날 수 있습니다. 실패만으로 행위자의 의도나 침해를 확정하지 않습니다.

## 4. 블루팀 수집·탐지·대응

1. **요청 한 건을 식별합니다.** UTC 시각, 실제 호출자 계정과 역할 세션, API 작업, 해당하는 경우 대상 리소스, 리전, 오류 원문과 요청 ID를 보존합니다. 이 정보로 감사 이벤트를 찾습니다. 제공되는 필드와 수집 여부는 서비스와 이벤트 유형에 따라 다릅니다. CloudTrail 이벤트 기록은 계정·리전별 최근 90일의 관리 이벤트를 조회할 수 있습니다. 더 오래된 기록이나 필요한 데이터 이벤트는 미리 구성한 추적 또는 이벤트 데이터 스토어를 확인합니다. 이벤트 부재를 해석하기 전에 수집 범위를 기록합니다.
2. **조직 경로와 정책 본문을 확인합니다.** AWS CLI와 승인된 프로필이 필요합니다. 관리 계정이나 위임 관리자 계정에서 이 API를 읽을 권한이 있어야 합니다. 호출마다 관련 값을 `ACCOUNT_OR_OU_ID`, `ROOT_OU_OR_ACCOUNT_ID`, `POLICY_ID`에 설정합니다. 호출자 계정에서 시작해 루트에 닿을 때까지 각 OU의 상위 항목을 조회합니다. 계층마다 직접 연결된 정책을 나열하고 SCP 본문을 읽습니다. 페이지네이션을 유지합니다. `DescribeEffectivePolicy`는 관리 정책용이며 SCP를 합산해 주지 않습니다.

~~~bash
aws organizations list-parents --child-id "$ACCOUNT_OR_OU_ID"
aws organizations list-policies-for-target \
  --target-id "$ROOT_OU_OR_ACCOUNT_ID" --filter SERVICE_CONTROL_POLICY
aws organizations describe-policy --policy-id "$POLICY_ID"
~~~

3. **사고 시점의 상태를 복원합니다.** 위 명령은 현재 상태를 읽습니다. 상용 AWS 파티션에서 Organizations 변경 이력은 `us-east-1`의 CloudTrail 관리 이벤트에서 `organizations.amazonaws.com`을 기준으로 확인합니다. 경로와 관련된 성공한 `AttachPolicy`, `DetachPolicy`, `UpdatePolicy`, `MoveAccount`를 찾습니다. 대상 ID와 호출자, 파라미터를 승인 내역과 비교합니다. 당시 정책 본문은 보관한 스냅샷이나 검토된 버전에서 확보합니다. 관리 이벤트는 변경이 일어났음을 보여 주지만 당시 요청의 권한 평가 전체를 담지는 않습니다.
4. **가설을 좁혀 검증합니다.** 실제 작업, 리소스와 요청 조건을 확인합니다. 허용 누락과 명시적 거부를 각각 검사하고 다른 계층에서 필요한 증거를 기록합니다. 운영 변경 전에는 대표성 있는 테스트 계정에서 승인된 무해한 요청을 확인합니다. 계정 경로와 서비스별로 예상치 못한 정책 변경이나 유사 거부 증가를 관찰합니다. 원본 정책 스냅샷을 남기고 승인된 수정 뒤에는 동일한 호출자의 같은 작업을 재확인합니다.

## 5. 승인된 오프라인 실습

<a href="{{ '/assets/labs/aws-scp-evaluation-evidence.py' | relative_url }}" download>Python 검사기</a>와 <a href="{{ '/assets/labs/aws-scp-evaluation-evidence.json' | relative_url }}" download>가상 사례 JSON</a>을 같은 폴더에 저장하세요. 본인이 소유하거나 사용 승인을 받은 환경에서 Python 3으로 실행합니다. 입력의 `matches`는 가상 요청 한 건에 각 정책 문이 일치하는지를 미리 기록한 값입니다. 검사기는 SCP 경로만 다룹니다. AWS 정책 문법을 해석하거나 자격 증명을 읽거나 AWS에 연결하지 않습니다.

~~~bash
python3 aws-scp-evaluation-evidence.py
~~~

| 사례 | 기대 관측 |
| --- | --- |
| A, E, F | 전 계층 허용, 같은 계층의 다른 정책이 허용을 제공하는 경우, 일치하지 않은 거부의 무효 |
| B, G, H | 각각 OU, 계정, 루트 계층에서 허용 누락 |
| C, D, I | 다른 허용이 일치해도 각각 루트, 바깥쪽 OU, 계정의 명시적 거부가 우선 |
| J, K, L | 관리 계정과 서비스 연결 역할의 예외, 경로 근거 부족 |

`12/12 cases matched.`가 나오는지 확인합니다. 대조 실험에서는 JSON을 복사한 뒤 A 사례의 루트 `Allow` 문에 있는 `matches`만 `false`로 바꿉니다. 기대 결과는 그대로 둔 채 검사기에 사본 파일명을 전달합니다. A에서 루트의 `missing-allow`가 표시되고 종료 코드 1이 나와야 합니다. 기본 파일이 실패하면 이름이 같은지, JSON의 불리언 값에 따옴표가 붙지 않았는지 확인합니다. Python 실습은 가상 데이터로 실행했습니다. AWS CLI와 서비스 동작은 공식 문서로 검토했으며 실제 AWS 조직에 연결하지 않았습니다.

## 6. 확인 문제와 완료 기준

1. **계정에서 허용이 일치하지만 루트의 거부도 일치하면 어떻게 되나요?** 명시적 거부가 적용 대상인 하위 계정에도 영향을 줍니다. 하위 계층의 허용으로 덮을 수 없습니다.
2. **OU에 정책 세 개가 붙고 하나만 허용하면 나머지 둘도 허용해야 하나요?** 같은 계층에서는 일치하는 허용 하나로 충분합니다. 해당 경로에 일치하는 거부가 없어야 하고 다른 계층에도 각각 허용이 필요합니다.
3. **IAM 역할 정책은 허용하지만 계정이 지난주에 이동했습니다. 무엇을 더 봐야 하나요?** 요청 시점의 OU 경로와 연결된 정책을 복원합니다. 현재 모습과 다를 수 있습니다.
4. **SCP 검사를 통과했는데 서비스에서 거부할 수 있나요?** 가능합니다. 실제로 부여된 권한, 세션 제한, 적용되는 리소스 및 서비스별 제어도 점검합니다.

**완료 기준.** 12건과 대조 실험을 재현합니다. 원인 미상의 거부 한 건을 보고 실제 호출자 계정, 당시 조직 경로, 가설을 확인하는 정책과 요청 근거를 설명합니다. 이어서 [AWS 역할과 세션 증거]({{ '/ko/wiki/aws-iam-role-evidence/' | relative_url }})와 [S3 퍼블릭 액세스 차단 증거]({{ '/ko/wiki/s3-block-public-access-evidence/' | relative_url }})를 읽어 보세요.

## 공식 참고자료

검토일 2026-11-26. 현재 AWS Organizations의 권한 평가 문서를 따릅니다. AWS는 2025-09-19에 SCP 언어 지원을 확장해 `Allow`의 조건과 작업·리소스 일치 표현을 추가했습니다. 이전 자료에 나온 지원 범위는 현재 문법과 다를 수 있습니다.

- [AWS Organizations · SCP 적용 범위](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html), [평가](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html), [권한 정책 유형](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_authorization_policies.html)
- [AWS · 2025년 9월 SCP 언어 확장](https://aws.amazon.com/about-aws/whats-new/2025/09/aws-organizations-iam-language-service-control-policies/), [IAM 액세스 거부 문제 해결](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html)
- [AWS Organizations · ListParents](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListParents.html), [ListPoliciesForTarget](https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPoliciesForTarget.html), [DescribePolicy](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribePolicy.html), [DescribeEffectivePolicy의 적용 범위](https://docs.aws.amazon.com/organizations/latest/APIReference/API_DescribeEffectivePolicy.html)
- [AWS Organizations CloudTrail 연동](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_cloudtrail-integration.html), [CloudTrail 이벤트 기록](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
