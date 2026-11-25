---
title: "Google Cloud 서비스 계정 위임 조사"
description: "Cloud Audit Logs와 오프라인 실습으로 토큰 발급, 리소스 접근, 원래 호출자 확인을 구분합니다."
category: cloud
tags: [Google Cloud, IAM, Audit Logs, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/gcp-service-account-impersonation-evidence/
---

**학습 목표.** 승인된 단기 토큰 발급 요청과 그 뒤에 일어난 API 호출을 추적합니다. 어떤 로그가 발급, 사용, 호출자 식별을 뒷받침하는지 살펴보고 두 기록을 어디까지 연결할 수 있는지 판단합니다.

## 1. 신원, 권한, 토큰

**주체(principal)**는 사용자나 워크로드처럼 요청을 보낼 수 있는 신원입니다. **서비스 계정**은 소프트웨어가 쓰는 Google Cloud 신원입니다. **서비스 계정 위임(impersonation)**에서는 권한을 가진 주체가 서비스 계정으로 동작할 수 있는 단기 자격 증명을 받습니다. 예를 들어 장기간 유효한 개인키를 배포하지 않고도 승인된 작업에 일정 시간 동안 접근을 허용할 수 있습니다. 이 장은 IAM Service Account Credentials API로 발급한 OAuth 2.0 액세스 토큰을 다룹니다.

| 권한 또는 자격 증명 | 결정하는 것 | 확인할 항목 |
| --- | --- | --- |
| 토큰 발급 권한 | 대상 계정의 액세스 토큰을 누가 요청할 수 있는지 | `iam.serviceAccounts.getAccessToken`과 이를 허용한 역할과 정책. 대표적으로 Service Account Token Creator가 있습니다. |
| Service Account User 역할 | 리소스 API가 허용하는 경우 서비스 계정을 리소스에 연결해 실행할 수 있는지 | `iam.serviceAccounts.actAs`는 토큰 발급 권한과 별개입니다. |
| OAuth 액세스 토큰 | 부여된 범위와 유효 시간 안의 API 호출을 인증합니다. | 리소스에서 작업할 권한은 서비스 계정에 실제로 적용되는 정책에 따릅니다. |
| 리소스 인가 | 대상 리소스에서 그 작업이 허용되는지 | 호출 당시의 메서드, 리소스, 정책, 작업 결과를 확인합니다. |

`GenerateAccessToken`의 기본 최대 수명은 1시간입니다. 조직 정책에서 연장을 허용한 서비스 계정은 최대 12시간을 요청할 수 있습니다. 실제 만료 시각이 확인되면 그 값을 쓰세요. 기본 최대 수명으로 조사 범위를 잡을 때는 실제 만료 시각과 적용 정책이 미확인이라는 점을 기록합니다. 액세스 토큰은 보유자가 API에 제시할 수 있으므로 비밀로 취급합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/gcp-service-account-impersonation-ko.svg' | relative_url }}" alt="승인된 호출자가 IAM Credentials API에 서비스 계정 토큰을 요청합니다. 별도의 호출이 리소스 API에 토큰을 제시합니다. 첫 감사 기록은 발급 요청을, 두 번째는 리소스 작업 결과와 기록된 경우 위임 신원을 보여줍니다.">
  <figcaption>발급 요청자, 대상 서비스 계정, 리소스 작업을 각 단계의 감사 증거에 연결합니다.</figcaption>
</figure>

## 2. 두 프로젝트에 걸친 정상 작업 따라가기

가상의 정기 품질 점검을 가정합니다. 민아가 사용하는 서비스 계정은 A 프로젝트에 있고, B 프로젝트의 비공개 테스트 버킷에는 읽기 권한이 있습니다. 작업 담당자가 승인한 작업은 메타데이터 조회 한 건입니다.

1. 09:00 UTC에 민아가 서비스 계정 토큰을 요청합니다. Credentials API는 대상 계정에 대한 호출자의 권한을 검사하며 성공하면 토큰을 발급합니다. A 프로젝트 또는 라우팅된 로그 목적지에서 `GenerateAccessToken` 감사 이벤트를 찾습니다. Google의 예시에서는 `protoPayload.authenticationInfo.principalEmail`이 요청자이고 `resource.labels.email_id`가 대상 서비스 계정입니다.
2. 09:03 UTC에 점검 작업이 Cloud Storage API에 토큰을 제시합니다. B 프로젝트 또는 해당 로그 목적지에서 메서드, 버킷, 시각, 작업 결과를 확인합니다. 메서드가 위임 맥락을 기록하는 경우 `protoPayload.authenticationInfo.principalEmail`에 서비스 계정이, `serviceAccountDelegationInfo`에 민아 또는 다른 위임 신원 정보가 나타날 수 있습니다. 연합 ID 주체는 `principalSubject`로 나타날 수 있습니다. 여러 단계를 거친 위임은 원래 필드 구조를 보존합니다.
3. 두 기록을 승인된 작업의 실행 기록과 결과에 대조합니다. 메타데이터 조회 성공은 조회의 증거입니다. 객체 본문 전송을 확인하려면 별도의 증거가 필요합니다. 신원과 시각이 일치해도 유효한 토큰이 여러 개였다면 특정 토큰까지 연결하기 어렵습니다. 위임 정보가 담긴 리소스 로그는 해당 호출에 기록된 신원 연결을 뒷받침합니다.

Google은 App Engine과 GKE처럼 원래 요청자를 기록하지 않는 서비스가 있다고 안내합니다. 호출 주체가 서비스 계정으로만 표시되면 워크로드에 연결된 서비스 계정, 키 기반 인증, 또는 위임 필드를 생략하는 서비스의 호출 등 여러 설명이 가능합니다. 실제 제품과 메서드의 로그 동작을 확인합니다.

## 3. 수집, 탐지, 대응

토큰 발급 권한을 지나치게 넓게 주면 권한이 큰 서비스 계정을 통해 여러 리소스가 위험해집니다. 누군가 이미 발급된 토큰을 얻었다면 유효한 시간 안에 재사용할 수 있습니다. 처음 보는 발급 요청자나 다른 프로젝트에서 온 읽기는 새 배포나 승인된 교차 프로젝트 작업에서도 나타납니다.

1. **사건 당시의 로그 범위를 확인합니다.** 발급을 보려면 IAM API(`iam.googleapis.com`)의 Data Access `DATA_READ`를 켜거나 모든 서비스에 적용되는 동등한 설정이 필요합니다. 로그에 기록되는 발급 서비스 이름은 `iamcredentials.googleapis.com`입니다. 리소스 API의 감사 범위는 따로 확인하세요. 이 예의 비공개 객체 메타데이터 조회에는 Cloud Storage의 Data Access `DATA_READ`가 필요합니다. 상속 설정과 제외 주체, 로그 라우팅과 제외 필터, 보존 기간과 로그 뷰를 확인합니다. 기본 로그 버킷에서는 `roles/logging.privateLogViewer`처럼 Data Access 조회가 가능한 권한이 필요합니다. 다른 버킷으로 라우팅했다면 해당 뷰의 접근 권한을 확인합니다.
2. **원본을 보존하고 비교합니다.** 이벤트 시각과 수신 시각, `logName`, `insertId`, 대상 계정과 확인 가능한 고유 ID, 호출자와 전체 위임 경로, 메서드, 리소스, 요청 맥락과 작업 결과를 남깁니다. `insertId`는 로그 항목을 식별하는 데 쓰입니다. 호출 IP나 User-Agent는 비교 단서이며 공통 요청이나 사용자를 확정하기에는 부족합니다. 조사 메모에 토큰 값이나 인증 헤더를 저장하지 않습니다.
3. **정책 변경과 실제 사용을 따로 확인합니다.** 요청자와 서비스 계정 조합을 승인된 작업, 예상 범위와 리소스, 계정이나 상위 리소스의 최근 IAM 정책 변경과 대조합니다. 개별 권한 검사의 허용 여부와 전체 작업 결과를 구분합니다. 발급 실패와 후속 API 호출도 별도로 찾습니다. 평소에 없던 발급 뒤에 낯선 민감 리소스 작업까지 나타나면 우선순위를 높일 근거가 됩니다. Google Security Command Center에도 Data Access 로그에서 비정상 위임 요청자를 찾는 탐지 항목이 있습니다. 확대 대응 전에 원본 이벤트와 예정된 작업을 담당자에게 확인합니다.
4. **승인된 범위에서 두 경로를 차단합니다.** 계정 담당자와 영향받는 워크로드를 확인합니다. 불필요한 발급 권한을 회수하면 정책 반영 후 해당 권한을 통한 추가 발급을 막을 수 있습니다. 이미 발급된 토큰의 리소스 권한은 별도로 제한합니다. 영향이 크고 사고 절차가 허용하면 서비스 계정 비활성화도 검토합니다. Google의 API 문서에 따르면 비활성 상태에서는 기존 액세스 토큰도 거부되며, 아직 유효한 토큰은 계정을 다시 활성화하면 허용될 수 있습니다. 차단 결과와 정상 워크로드 접근은 각각 대조 시험으로 확인합니다.

### Logs Explorer에서 두 번 나누어 검색하기

승인된 시험 시각을 포함하는 UTC 범위를 지정합니다. 첫 번째 식은 발급 대상 계정의 프로젝트나 해당 로그 뷰에서 실행합니다. 검색된 발급 시도는 원본의 상태 필드로 결과를 확인하세요. 해당되는 Policy Denied 이벤트 등 다른 유형은 별도로 검색합니다.

```text
log_id("cloudaudit.googleapis.com/data_access")
protoPayload.serviceName="iamcredentials.googleapis.com"
protoPayload.methodName="GenerateAccessToken"
```

두 번째 식은 리소스 프로젝트 또는 해당 로그 뷰에서 실행합니다. 예시 계정과 서비스는 실제 조사 대상으로 바꾸세요. Cloud Storage의 여러 감사 유형을 대상으로 하므로 확인된 메서드와 리소스로 범위를 좁힐 수 있습니다. 위임 정보가 없는 기록도 원인 확인을 위해 남겨 두세요.

```text
protoPayload.serviceName="storage.googleapis.com"
protoPayload.authenticationInfo.principalEmail="report-reader@wiki-iam-lab.iam.gserviceaccount.com"
```

두 검색식은 Google 문서로 검토했습니다. 아래 오프라인 실습은 Cloud Logging을 조회하지 않습니다. 검색 결과가 비면 예상대로 기록될 승인된 요청을 기준으로 서비스 이름, 로그 범위, 조회 권한, 시간과 수집 지연을 확인하세요. 오늘 대조 시험이 성공해도 과거 사고 당시의 수집 범위는 별도로 확인해야 합니다.

## 4. 오프라인에서 조사 실습하기

본인이 소유하거나 사용 승인을 받은 작업 공간의 같은 폴더에 <a href="{{ '/assets/labs/gcp-service-account-impersonation.py' | relative_url }}" download="gcp-service-account-impersonation.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/gcp-service-account-impersonation-cases.json' | relative_url }}" download="gcp-service-account-impersonation-cases.json">가상 사례</a>를 저장합니다. Python 3.9 이상이면 됩니다. 네트워크와 자격 증명은 필요 없습니다. 실습은 가상 자료에 정리된 필드와 UTC 만료 시각을 씁니다. 실제 로그에서는 값이 빠질 수 있습니다. 같은 계정에 대해 호출 전에 성공한 발급 기록을 후보로 보고, 확인된 만료 시각이 호출 이전이거나 호출 시각과 같으면 제외합니다. 후보가 하나여도 특정 토큰 사용이 확정되지는 않습니다. 만료 시각을 모르면 후보로 남기되 연결의 확실성은 낮습니다.

```bash
python3 gcp-service-account-impersonation.py gcp-service-account-impersonation-cases.json
```

| 사례 | 기대 결과 |
| --- | --- |
| `issued_only` | 발급 관측, 리소스 호출 미관측 |
| `mint_denied` | 발급 거부 |
| `delegated_use` | 리소스 작업 성공, 위임 신원 기록, 발급 후보 1건 |
| `resource_denied` | 토큰은 발급됐지만 리소스 작업은 거부 |
| `two_candidates` | 리소스 작업 성공과 위임 신원 기록, 발급 후보 2건 |
| `expired_candidate` | 리소스 작업 성공, 원래 호출자 미확인, 이전 토큰은 만료되어 후보에서 제외 |
| `issuance_gap` | 리소스 작업 성공과 위임 신원 기록, 발급 로그 수집 공백 |
| `unknown_lifetime` | 리소스 작업 성공, 원래 호출자 미확인, 만료 시각을 모르는 발급 후보 1건 |
| `empty_with_coverage` | 제공된 수집 범위 안에서 해당 이벤트가 관측되지 않음 |

스크립트는 사례별로 작업 결과, 위임 신원, 발급 후보 수, 발급 로그 수집 여부를 출력합니다. 기대값이 하나라도 다르면 실패로 종료합니다. 파일을 읽지 못하면 현재 폴더와 파일 이름 두 개를 확인합니다. 후보 수가 예상과 다르면 먼저 대상 계정과 UTC 시각을 확인하고 위임 필드를 검토하세요. 경계 조건을 확인하려면 사례 파일을 복사하고 `expired_candidate`의 리소스 호출 시각을 만료 1초 전으로 바꿔 보세요. 발급 후보가 생겨 원래 기대값과 달라져야 합니다. 스크립트는 클라우드 작업 공간에서 실행했습니다. 실제 IAM 프로젝트나 서비스 계정, Security Command Center 탐지기는 구동하지 않았습니다.

## 5. 판단 확인하기

- **Token Creator 부여 직후 발급이 성공했습니다. 버킷에 접근했나요?** 버킷의 로그와 승인 작업의 기록에서 리소스 호출과 작업 결과를 따로 확인해야 합니다.
- **동일한 계정의 토큰 두 개가 유효한 시간에 민아가 위임 신원으로 기록된 호출이 성공했습니다. 어느 토큰을 썼나요?** 민아가 위임 경로에 기록됐다는 점은 확인할 수 있습니다. 두 발급 기록만으로 어떤 토큰인지 결정할 수 없습니다.
- **서비스 계정으로 리소스 작업을 한 기록은 있지만 호출자와 발급 로그가 없습니다. 연결된 서비스 계정을 사용했나요?** 여러 인증 경로가 같은 결과를 남길 수 있습니다. 서비스의 위임 기록 범위, 사건 당시 감사 설정, 워크로드의 인증 기록을 대조하세요.

아홉 사례가 모두 통과하고, 작업 결과와 확인된 신원 또는 식별 공백, 발급 후보의 확실성, 다음으로 확인할 자료를 짧은 조사 메모로 정리하면 실습을 완료한 것입니다.

## 공식 참고자료

2026년 11월 26일 검토. Google Cloud IAM Credentials v1 액세스 토큰과 Cloud Audit Logs를 대상으로 합니다. Credentials 감사 문서는 2026년 11월 17일 UTC, 서비스 계정 로그 예시는 2026년 11월 13일 UTC에 갱신됐습니다.

- 발급과 수명. [GenerateAccessToken v1](https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken) · [서비스 계정 위임](https://docs.cloud.google.com/iam/docs/service-account-impersonation) · [서비스 계정 권한](https://docs.cloud.google.com/iam/docs/service-account-overview)
- 감사 분류와 신원 필드. [Credentials 감사 로깅](https://docs.cloud.google.com/iam/docs/audit-logging/audit-logging-iamcreds) · [서비스 계정 로그 예시](https://docs.cloud.google.com/iam/docs/audit-logging/examples-service-accounts) · [연합 ID 로그 예시](https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity)
- 수집 범위와 조회. [Data Access 감사 로그 구성](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) · [Cloud Audit Logs 개요](https://docs.cloud.google.com/logging/docs/audit) · [Logging 검색식](https://docs.cloud.google.com/logging/docs/view/logging-query-language) · [Cloud Storage 감사 로깅](https://docs.cloud.google.com/storage/docs/audit-logging)
- 탐지와 차단. [Security Command Center 탐지](https://docs.cloud.google.com/security-command-center/docs/findings/threats/anomalous-sa-delegation-impersonator-data-access) · [자격 증명 노출 대응](https://docs.cloud.google.com/docs/security/compromised-credentials) · [서비스 계정 비활성화](https://docs.cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/disable)

[다음 글 · Cloud Storage 객체 읽기 조사]({{ '/ko/wiki/gcs-object-read-evidence/' | relative_url }}) · [비교 · AWS IAM 역할과 CloudTrail]({{ '/ko/wiki/aws-iam-role-evidence/' | relative_url }})
