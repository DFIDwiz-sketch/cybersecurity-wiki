---
title: "AWS IAM 역할과 CloudTrail 조사 입문"
description: "AWS 역할 신뢰, STS 임시 자격 증명, CloudTrail 발급·사용 기록을 가상 로그 8건으로 분석합니다."
category: cloud
tags: [AWS, Cloud Security, IAM, CloudTrail, STS, Blue Team, DFIR]
level: Beginner
updated: "2026-11-20"
translation_url: /wiki/aws-iam-role-evidence/
---

**학습 목표.** 누가 역할을 요청했는지, 세션이 발급됐는지, 그 세션이 어떤 작업을 했는지 CloudTrail에서 확인합니다. IAM이 처음이라면 1–3절을 읽고 6절 실습에서 가상 사건을 따라가세요.

## 1. 계정, 역할, 세션은 무엇인가요?

AWS 계정은 자원과 관리 경계를 담습니다. **IAM**은 그 안에서 누가 어떤 작업을 할 수 있는지 관리하는 서비스입니다. **프린시펄(principal)**은 API 요청을 하는 AWS 신원입니다. 사람에게 연결된 IAM 사용자, 워크로드나 연동 신원이 사용하는 역할 세션 등이 여기에 해당합니다.

**역할(role)**은 필요한 사람이 잠시 맡을 수 있도록 만든 AWS 신원입니다. 예를 들어 운영자는 일상 계정으로 작업하다 승인을 받은 시간 동안 보고서 읽기 역할을 맡을 수 있습니다. 역할을 맡을 때 AWS STS(Security Token Service)가 **임시 자격 증명**을 발급합니다. 액세스 키 ID는 식별자이고, 비밀 액세스 키와 세션 토큰은 함께 사용하는 비밀입니다. 임시 자격 증명에는 만료 시각이 있습니다.

| 용어 | 예시 | 조사에서의 역할 |
| --- | --- | --- |
| 호출자 | Mina의 AWS 신원 | 역할 요청자가 누구인지 |
| IAM 역할 | ReportReader | 요청한 권한과 신뢰의 대상 |
| 세션 이름 | daily-report | 세션 표시 이름. 동일 이름 재사용 가능 |
| 역할 세션 ARN | assumed-role/ReportReader/daily-report | 기록된 역할 세션의 이름 경로 |
| 임시 키 ID | LAB-KEY-A | 발급과 후속 요청을 연결할 후보 키 |
| 만료 시각 | 01:00 UTC | 연결 후보의 유효 시간 범위 확인 |

ARN은 AWS 자원이나 신원을 지정하는 이름입니다. 역할의 IAM ARN과 역할을 맡은 뒤 CloudTrail에 기록되는 STS 세션 ARN을 구분하세요.

## 2. 역할을 맡고 자원에 접근하는 순서

![호출자 · 기존 AWS 신원 → STS · 역할 요청 평가와 발급 → 임시 역할 세션 · 키 ID 확인 → S3 요청 · 권한 판단과 결과]({{ '/assets/diagrams/aws-role-flow-ko.svg' | relative_url }})

보고서가 있는 계정 B의 ReportReader 역할을 계정 A의 Mina가 맡는 예입니다.

1. Mina가 기존 AWS 신원으로 STS에 AssumeRole을 요청합니다. 호출자 계정의 권한과 대상 역할의 **신뢰 정책**이 요청에 맞아야 합니다. 이 예는 계정 간 요청입니다. 같은 계정의 신뢰 방식에는 별도 정책 규칙이 적용될 수 있습니다.
2. 신뢰 정책에서 허용된 주체, 추가 조건, 명시적 거절 여부 등을 확인합니다. 요청이 수락되면 STS는 만료 시각이 있는 자격 증명을 발급합니다.
3. Mina가 발급된 세션으로 S3 GetObject를 요청합니다. 이 단계에서는 역할 세션의 권한과 자원 정책 등 적용되는 정책에 따라 결정됩니다.
4. ReportReader가 쓰기 권한을 갖지 않는 구성이라면 PutObject가 거절될 수 있습니다. 역할을 맡을 수 있는지와 S3 작업이 허용되는지는 별개의 판단입니다.

| 정책 | 답하는 질문 | 예 |
| --- | --- | --- |
| 역할 신뢰 정책 | 이 역할을 누가 어떤 조건에서 맡을 수 있나? | 승인된 계정·프린시펄만 신뢰 |
| 역할 권한 정책 | 이 역할로 어떤 자원에 어떤 작업이 가능한가? | 보고서 읽기 허용 |
| 세션 정책 | 해당 세션의 권한을 어디까지 줄이나? | 역할의 권한 범위 안에서 더 제한 |
| 자원 정책 및 조직 통제 | 자원·계정·조직 차원의 허용이나 제한은? | 버킷 정책과 적용되는 제어 정책 점검 |

정책 평가에는 명시적 거절, 권한 경계와 조직 정책, 자원 정책 등이 함께 작용할 수 있습니다. 거절을 해석할 때는 해당 동작, 자원, 시간의 정책을 확인하세요. 동일한 원인으로 모든 AccessDenied가 생기지는 않습니다.

## 3. CloudTrail에서 어떤 필드를 읽나요?

**CloudTrail**은 AWS API 활동의 감사 기록을 제공합니다. 같은 세션이라도 모든 작업이 같은 수집 범위에 들어오지는 않습니다.

| 기록 | 볼 필드 | 해석 |
| --- | --- | --- |
| STS 역할 요청 | eventSource, eventName, userIdentity, requestParameters.roleArn | 요청 시점의 호출자와 대상 |
| STS 응답 | errorCode, responseElements.assumedRoleUser, responseElements.credentials.accessKeyId | 거절과 발급 구분. 기록에 제공된 필드만 사용 |
| 후속 API | userIdentity.type, userIdentity.arn, userIdentity.accessKeyId | 실제 API에 쓰인 세션과 임시 키 |
| 역할 정보 | userIdentity.sessionContext.sessionIssuer.arn | 발급 역할을 식별. 이 필드만으로 최초 호출자를 알 수 없음 |
| 수신·시점 | recipientAccountId, awsRegion, eventTime, eventID | 계정·리전·UTC·이벤트 맥락 보존 |
| 결과 | errorCode, requestParameters, 서비스의 응답·감사 자료 | 권한 실패 및 대상 확인. 오류 필드 부재만으로 영향 판단 불가 |

발급 응답에 키 ID가 기록돼 있으면 후속 요청의 userIdentity.accessKeyId와 대조하세요. 세션 ARN, 발급·만료 시각, 계정과 리전도 확인합니다. 필드가 없거나 기록을 찾지 못했다면 **미연결**로 남깁니다. sourceIdentity가 구성되고 로그에 남는 환경에서는 추가 단서가 됩니다. 발급 단계에서 입력을 누가 설정할 수 있는지까지 확인하세요. 연쇄 역할 사용에서는 중간 세션을 차례로 따라갑니다.

Event history는 **리전별 최근 90일의 관리 이벤트**를 보여 줍니다. STS 발급을 찾는 출발점이지만, S3 객체 접근 등 데이터 이벤트는 해당 자원에 맞춰 데이터 이벤트를 선택한 트레일이나 이벤트 데이터 저장소 등에서 확인해야 합니다. 기록이 없으면 계정·리전·지원 범위·선택 조건·시간·보존·전달부터 확인하세요. 역할 요청이 계정 경계를 넘으면 양쪽 관측을 함께 검토합니다.

## 4. 정상 작업과 권한 오용 가설

| 관측 | 가능한 정상 설명 | 추가로 확인할 증거 |
| --- | --- | --- |
| 새 호출자가 정기 작업 역할을 맡음 | 승인된 배치 전환 | 변경 승인, 배포 결과, 호출자 정책 |
| 익숙하지 않은 주소에서 세션 사용 | NAT·새 실행 환경 | 공급자 로그, 네트워크 경로, 기존 기준선 |
| 동일 세션 이름으로 여러 발급 | 정기 작업 이름 재사용 | 각 발급 키, 발급 시각, 호출자 |
| 읽기 이후 쓰기 거절 | 작업 설정 오류 | 실제 요청 대상, 정책 평가, 인접 API |
| 민감한 정책 변경 | 승인된 운영 변경 또는 권한 오용 | 변경 전후 정책, 승인 기록, 해당 변경을 한 세션 |

공격자가 유효한 자격 증명을 악용하면 정상 서비스와 같은 API를 호출할 수 있습니다. 짧은 만료 시간은 노출 기간을 줄여 줍니다. 이미 발급된 자격 증명은 유효 기간과 정책 범위 안에서 사용될 수 있으므로 영향 범위를 조사하세요. IP나 User-Agent는 단서이며 사람, 감염, 의도를 판정하려면 추가 자료가 필요합니다.

## 5. 블루팀 조사와 대응 순서

1. 발급과 자원 동작을 각각 질문합니다. “누가 역할을 맡았나?”와 “어떤 객체 동작이 관측됐나?”는 다른 검색입니다.
2. 원본 JSON, UTC, 계정·리전, 이벤트 ID, 수집 범위를 승인된 위치에 보존합니다. 키 ID를 조사 목적으로 다루되 비밀 키나 세션 토큰을 복사하지 않습니다.
3. 발급과 후속 요청을 위 필드로 연결하고, 정상 작업과 비교하세요. 신규 호출자·민감한 대상·정책 변경·거절 후 성공을 조합해 우선순위를 정합니다.
4. 의심이 뒷받침되면 원래 호출자의 접근, 역할 신뢰, 기존 세션을 각각 범위에 넣습니다. 새 발급을 제한하는 것과 이미 발급된 세션의 접근을 막는 것은 별도 조치입니다. AWS의 역할 세션 폐기 기능은 특정 시점보다 오래된 역할 세션을 정책으로 제한할 수 있으며 정상 작업에도 영향을 줄 수 있습니다. 영향을 검토하고 승인된 사고 대응 절차에 따라 조치 후 기록을 확인하세요.
5. 필요하면 자원 자체의 접근·변경 결과를 조사합니다. 서비스가 요청을 받았다는 기록에서 파일 전체가 외부로 유출됐는지까지 확정하지 않습니다.

## 6. 가상 CloudTrail 이벤트 8건 연결하기

[aws-role-events.json]({{ '/assets/labs/aws-role-events.json' | relative_url }}) · [aws-role-evidence.py]({{ '/assets/labs/aws-role-evidence.py' | relative_url }})

두 파일을 같은 폴더에 저장하고 Python 3에서 실행하세요. AWS 로그인 없이 작동합니다. 계정 번호·이벤트 ID·키 ID는 모두 가상 값이고 실제 비밀은 들어 있지 않습니다. JSON은 교육용으로 필요한 CloudTrail 형식만 발췌했습니다.

~~~bash
python3 aws-role-evidence.py
~~~

| 관측 | 결과와 해설 |
| --- | --- |
| lab-01, lab-02 | 서로 다른 호출자의 성공 발급. 세션 ARN이 같고 키 ID는 다름 |
| lab-03 | 역할 요청 거절. 이 사건에서 세션 생성 증거 없음 |
| lab-04, lab-05 | 둘 다 lab-01에 연결. 읽기에는 오류 기록이 없고 쓰기는 AccessDenied |
| lab-06 | 같은 세션 이름이지만 키 ID로 lab-02에 연결 |
| lab-07, lab-08 | 키 ID가 없거나 일치하는 발급이 없어서 미연결 |

마지막에 `PASS: two issuances, one denied request, five API observations`가 나옵니다. 파일 오류가 나면 이름·위치를 확인하세요. 조인이 예상과 다르면 키 ID, 세션 ARN, 시간대, 발급 이전 또는 만료 이후 여부를 확인합니다. 분석기는 이 데이터에 맞춘 교육용입니다. 실제 로그에는 중복 기록과 누락이 있을 수 있으며 운영 분석에서 조인 단정 전 검토해야 합니다. 이 장에서는 오프라인 실행을 검증했습니다. AWS 계정에서 역할 발급과 데이터 이벤트 수집은 시험하지 않았습니다.

## 7. 확인 문제와 완료 기준

- **역할 요청이 거절됐으면 S3도 접근했나요?** 이 사건에는 발급 증거가 없습니다. 다른 세션·자격 증명의 별도 활동은 수집 범위 안에서 조사합니다.
- **세션 ARN이 같으면 하나로 묶어도 되나요?** 같은 이름이 재사용될 수 있습니다. 발급 키와 시간 범위로 비교합니다.
- **Event history에 GetObject가 안 보이면 접근이 없었나요?** 해당 데이터 이벤트 수집 설정과 보존·전달을 확인해야 합니다.
- **역할 신뢰를 수정하면 기존 세션도 끝나나요?** 새 역할 요청과 기존 세션 접근은 각각 확인합니다.

lab-04와 lab-06의 발급 주체를 각각 찾고, lab-07을 왜 연결하지 않았는지 설명하세요. 조사 메모에 확인된 기록 한 문장과 확인에 필요한 추가 증거 한 문장을 적으면 완료입니다.

[블루팀 기초]({{ '/ko/wiki/blue-team-basics/' | relative_url }}) · [Linux 인증 로그]({{ '/ko/wiki/linux-auth-evidence/' | relative_url }})

## 공식 자료

2026년 11월 20일 검토한 AWS 공식 제품 문서입니다. 실제 수집 범위와 보존 정책은 배포 환경에서 확인하세요.

- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [CloudTrail identity fields](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [IAM and STS CloudTrail examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)
- [Event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html) · [Data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)
- [Revoke IAM role sessions](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html)

## Microsoft Entra 로그인 조사 · MFA와 조건부 액세스

[Entra 로그인과 실제 리소스 행위를 구분하는 실습]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }})

## Kubernetes API 감사 증거

[Kubernetes API 요청의 신원, 응답과 실제 객체 상태를 확인합니다]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }})

## Amazon S3 객체 읽기와 전송 바이트 조사

[역할 세션의 S3 요청을 액세스 로그와 대조하는 실습]({{ '/ko/wiki/s3-object-read-evidence/' | relative_url }})

## 이어서 읽기

[AWS KMS 조사 입문]({{ '/ko/wiki/aws-kms-evidence/' | relative_url }}) · 키를 사용한 호출과 S3 객체를 읽은 요청에서 각각 어떤 증거를 얻는지 살펴보세요.

## AWS 보안 그룹 조사

[AWS 보안 그룹 조사 · 규칙 변경부터 실제 통신까지]({{ '/ko/wiki/aws-security-group-evidence/' | relative_url }})에서 규칙 변경, ENI 연결, 실제 트래픽 증거를 대조하는 방법을 실습합니다.

[비교 · Google Cloud 서비스 계정 위임]({{ '/ko/wiki/gcp-service-account-impersonation-evidence/' | relative_url }})
