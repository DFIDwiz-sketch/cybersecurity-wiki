---
title: "AWS STS SourceIdentity · CloudTrail에서 역할 연쇄 추적하기"
description: "임시 자격 증명을 역할 발급 기록에 연결하고 SourceIdentity의 출처와 CloudTrail 수집 공백을 확인합니다."
category: cloud
tags: [AWS, IAM, STS, SourceIdentity, CloudTrail, Blue Team, DFIR]
level: Intermediate
updated: "2026-11-27"
translation_url: /wiki/aws-sts-source-identity-evidence/
---

CloudTrail에 `Reader/report-job`이 보고서 객체를 읽은 기록이 있습니다. 여러 요청에 같은 세션 이름이 보이고, 한 기록의 `sourceIdentity`에는 `example-workload-417`이 남아 있습니다. 먼저 요청에 쓰인 자격 증명과 발급 경로를 확인한 다음, 최초의 출처 식별 값을 누가 정했는지 따로 대조합니다.

## 1. 각 식별 값이 가리키는 범위

**AWS Security Token Service(STS)**는 임시 자격 증명을 발급합니다. 역할의 **신뢰 정책**은 누가 어떤 조건에서 그 역할을 맡을 수 있는지 정합니다. **역할 세션**은 그 역할을 쓰기 위해 자격 증명이 한 번 발급된 단위입니다. 이미 맡은 역할의 자격 증명으로 다른 역할을 맡는 것을 **역할 연쇄**(role chaining)라고 합니다. 다음 세션에는 별도 자격 증명과 세션 이름이 있습니다. 출처 식별 값이 설정되면 STS가 이후 역할 세션에 전달하고, 연쇄 도중 다른 값으로 바꾸지 못하게 합니다.

<figure>
  <img src="{{ '/assets/diagrams/aws-sts-source-identity-evidence-ko.svg' | relative_url }}" width="560" height="326" alt="확인된 브로커는 Entry 역할을 맡아 키 A를 받습니다. Entry는 A로 Reader 역할을 맡아 키 B를 받고, Reader는 B로 객체를 요청합니다. 두 번의 발급에서 키가 달라지고 SourceIdentity는 이어집니다." />
  <figcaption>API 사용 기록에서 발급을 역추적하고, 최초 식별 값은 그 출처에서 별도로 대조합니다.</figcaption>
</figure>

| 값 또는 필드 | 뒷받침하는 내용 | 해석할 때 확인할 점 |
| --- | --- | --- |
| 발급 키 ID와 세션 ARN | 발급의 `responseElements.credentials.accessKeyId`와 `responseElements.assumedRoleUser.arn`을 사용 기록의 `userIdentity.accessKeyId`와 `userIdentity.arn`에 대조합니다. | 계정과 역할, 발급·만료 시각도 대조합니다. 키나 발급 기록이 없으면 연결에 빈 구간이 남습니다. |
| `roleSessionName` | 역할 세션 ARN에 들어가는 이름입니다. | 다른 발급에도 같은 이름을 쓸 수 있습니다. ARN이 같아도 키와 시각을 확인합니다. |
| `sourceIdentity` | 역할을 맡을 때 연결돼 후속 세션에도 전달되는 출처 식별 값입니다. | 값을 제공한 호출자나 ID 공급자와 그 값을 검증한 정책을 알아야 의미를 판단할 수 있습니다. 여러 세션에서 같을 수 있습니다. |
| `sessionContext.sessionIssuer` | 현재 역할 세션의 맥락을 발급한 IAM 역할입니다. | 역할을 보여 주는 값입니다. 이전 호출자의 확인에는 발급 기록이 필요합니다. |
| `sharedEventID` | 필드가 있을 때 같은 AWS 동작을 각 계정에서 본 기록들을 연결합니다. | 계정별 기록의 `eventID`와 `recipientAccountId`는 별개입니다. 이 필드로 서로 다른 역할 발급을 연결할 수 없습니다. |

발급 기록에는 있는 경우 `requestParameters.sourceIdentity`와 `responseElements.sourceIdentity`를 확인합니다. API 사용 기록에서는 `userIdentity.sessionContext.sourceIdentity`를 봅니다. 연쇄 중의 `AssumeRole` 한 건은 앞 세션 자격 증명의 **사용**과 새 세션의 **발급**을 함께 기록합니다. 그 이벤트에서 호출자와 새로 발급된 세션 정보를 나눠 읽으세요.

## 2. 정상 연쇄를 따라가고 출처 식별 값의 근거 확인하기

가상의 정상 사례에서 브로커가 승인된 보고서 작업을 시작합니다. 09:00 UTC에 계정 A의 `Entry` 역할을 맡습니다. STS는 `Entry/report-job`에 키 A를 발급합니다. 브로커가 붙인 출처 식별 값은 작업 417에 대응합니다. 09:02에 키 A로 계정 B의 `Reader` 역할을 맡아 키 B를 받고, 09:03의 `GetObject`에 키 B와 같은 출처 식별 값이 남습니다. 키 B의 발급 기록에서 호출자 키 A를 찾고, 키 A의 앞선 발급과 브로커·작업 기록을 대조해 최초 연결을 확인하세요.

**값이 정해진 뒤에는 바뀌지 않습니다.** AWS가 최초 문자열의 의미까지 독립적으로 검증해 주지는 않습니다. 형식만 맞으면 어떤 값이든 받는 정책은 잘못된 값도 이후 역할에 전달할 수 있습니다. 유출된 임시 자격 증명을 누군가 쓰더라도 기존 값은 남을 수 있습니다. 일치 기록으로 활동에 쓰인 세션을 확인할 수 있고, 사람이나 작업의 식별에는 별도 증거가 필요합니다.

방어 관점에서 정책을 검토할 때는 어느 주체가 역할을 맡고 출처 식별 값을 설정하거나 전달할 수 있는지 확인합니다. 인증된 ID 공급자 또는 신뢰할 수 있는 브로커가 통제된 식별자에 연결하는 방식도 검토하세요. `sts:SourceIdentity`는 역할을 맡는 요청의 조건 키이고, 설정 후 정책 평가에는 `aws:SourceIdentity`를 사용할 수 있습니다. `sts:SetSourceIdentity`는 권한을 나타내는 동작입니다. AWS 문서에 따르면 연쇄 역할이나 계정 간 전달에는 호출하는 주체의 권한과 대상 역할의 신뢰 정책 양쪽에 허용이 필요합니다. 값이 있는지만 검사하면 기록은 채워져도 출처를 입증하기 어렵습니다.

## 3. 블루팀 수집과 대응

1. **동작과 결과부터 확인합니다.** 원본 이벤트와 리소스, 관측 계정, 리전, UTC 시각과 오류를 보존합니다. 연쇄 세션이라면 키 ID, 세션 ARN과 발급 역할을 기록하세요. 이벤트가 시도인지 성공한 API 응답인지 구분합니다. 객체 API가 성공했더라도 이후 결과물이 어디에 쓰였는지까지는 알 수 없습니다.
2. **각 발급을 찾습니다.** 발급 키와 ARN으로 거슬러 올라가며 계정과 역할, 발급·만료 시각을 확인합니다. 호출자 계정과 역할 계정도 함께 확인하세요. AWS는 거부된 계정 간 STS 요청은 대상 계정에 기록되지 않는다고 명시합니다. STS 전역 엔드포인트 요청은 다른 리전에서 처리됐더라도 `us-east-1`에 기록됩니다. 리전별 엔드포인트 요청은 해당 리전에 기록됩니다. 있는 경우 `endpointType`과 `awsServingRegion`을 보존하세요. 두 계정 기록의 `sharedEventID`가 같다면 원본은 둘 다 남기고 공통 필드를 확인해 동작 한 건으로 셉니다. 연결이 안 되거나 충돌하는 증거는 따로 남깁니다.
3. **수집 범위와 식별 근거를 대조합니다.** 이벤트 기록(Event history)은 선택한 계정과 리전의 최근 90일 관리 이벤트를 보여 줍니다. S3 객체 `GetObject`는 트레일이나 이벤트 데이터 스토어에 당시 데이터 이벤트 선택기와 대상 리소스 범위가 적용됐는지 확인합니다. AWS 문서에 따르면 일부 AWS 서비스나 서비스 연결 역할이 인력 또는 연동 ID를 대신해 수행한 요청에는 출처 식별 값이 기록되지 않습니다. 지원하는 서비스에서는 Identity Center 활동의 별도 `onBehalfOf` 정보도 확인할 수 있습니다. ID 공급자나 브로커의 인증·작업 이력, 사건 당시 정책을 함께 대조합니다.
4. **증거가 맞을 때 대응합니다.** 키와 리소스, 시각이 맞는데 출처 값이 어긋난다면 계정별 원본과 파싱을 먼저 확인합니다. 관련 설정과 로그를 보존하고, 별도 증거가 무단 사용을 뒷받침할 때 승인된 접근 차단 절차를 따릅니다. 신뢰 정책과 권한 변경은 담당자와 검토하세요. 키 ID와 식별 값은 승인된 증거 저장소에서 다루고, 세션 토큰과 비밀 키는 분석 보고에 넣지 않습니다.

## 4. 오프라인으로 방어 판단 검증하기

자기 소유 또는 명시적으로 승인된 작업 환경에서 Python 3를 사용합니다. <a href="{{ '/assets/labs/aws-sts-source-identity-evidence/sts-chain-cases.json' | relative_url }}" download="sts-chain-cases.json">sts-chain-cases.json</a>을 내려받고 아래 코드를 같은 폴더의 `review_chain.py`에 저장한 뒤 `python3 review_chain.py`를 실행하세요. 데이터와 키 ID는 실습용이며 AWS나 네트워크를 호출하지 않습니다.

이 자료는 `AssumeRole`만 사용하고 시각은 UTC 오프셋이 있는 ISO 8601 형식으로 통일했습니다. 실제 조사에서는 원본을 보존하고 내보내기 형식에 맞춰 시간을 정규화하세요. 실습 코드는 역할 세션이 아닌 호출 기록에 도달하면 종료합니다. 호출자를 인증하거나 모든 AWS ID 유형을 검사하지 않으며 계정별 기록을 자동으로 합치지도 않습니다.

```python
import json
from datetime import datetime

def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def trace(activity, issuances):
    seen = set()
    current = activity
    while current["userIdentity"].get("type") == "AssumedRole":
        caller = current["userIdentity"]
        key = caller.get("accessKeyId")
        arn = caller.get("arn")
        if not key or not arn or key in seen:
            return "unlinked-hop"
        seen.add(key)
        observed = instant(current["eventTime"])
        candidates = []
        for event in issuances:
            if (event.get("eventSource"), event.get("eventName")) != ("sts.amazonaws.com", "AssumeRole"):
                continue
            if event.get("errorCode"):
                continue
            response = event.get("responseElements") or {}
            credentials = response.get("credentials") or {}
            session = response.get("assumedRoleUser") or {}
            expiration = credentials.get("expiration")
            if credentials.get("accessKeyId") != key or session.get("arn") != arn or not expiration:
                continue
            if instant(event["eventTime"]) <= observed < instant(expiration):
                candidates.append(event)
        if not candidates:
            return "unlinked-hop"
        if len(candidates) > 1:
            return "ambiguous-hop"
        issued = candidates[0]
        issued_source = issued["responseElements"].get("sourceIdentity")
        used_source = (caller.get("sessionContext") or {}).get("sourceIdentity")
        if issued_source and used_source and issued_source != used_source:
            return "source-conflict"
        current = issued
    return "chain-complete"

with open("sts-chain-cases.json", encoding="utf-8") as stream:
    cases = json.load(stream)
for case in cases:
    result = trace(case["activity"], case["issuances"])
    assert result == case["expected"], f"{case['name']}: {result} != {case['expected']}"
    print(f"{case['name']}: {result}")
assert len(cases) == 8
```

**기대 결과.** 8건이 통과합니다. 원래 호출 기록까지 이어지는 사례는 두 건입니다. 그중 하나는 세션 이름이 같고 키만 다른 발급을 구분합니다. 중간 발급이 없거나 최종 호출 키가 없거나, 만료 시각에 호출됐거나 발급이 거부된 사례에서는 연결이 끊깁니다. 대조하지 않은 두 계정 기록은 모호하게 남고, 발급과 사용의 출처 값이 다르면 충돌로 표시됩니다.

**실패 점검.** 복사한 자료의 첫 사례에서 API 호출 키 ID를 `SIM-READER`에서 `SIM-ENTRY`로 바꾸세요. ARN은 Reader 그대로이므로 해당 사례가 `unlinked-hop`으로 판정되어 검증에 실패해야 합니다. 파일을 열 수 없으면 작업 폴더와 파일 이름을 확인하세요. 오프라인 사례는 클라우드에서 실행했고 실제 AWS 동작은 공식 문서와 대조했습니다.

## 5. 확인 문제와 완료 기준

1. **서로 다른 발급 두 건의 ARN과 SourceIdentity가 같으면 합쳐도 될까요?** 발급 키, 시각과 계정·역할 맥락을 대조합니다. 같은 이름이 여러 세션을 가리킬 수 있습니다.
2. **연쇄가 전부 이어지면 실제 키보드를 사용한 사람을 알 수 있나요?** 기록된 연쇄는 확인할 수 있습니다. 최초 값을 누가 통제했는지, 자격 증명이 어떻게 쓰였는지는 별도 자료로 조사합니다.
3. **이벤트 기록에 발급만 있고 `GetObject`가 없으면 읽기가 없었나요?** 객체 데이터 이벤트의 수집과 리소스 범위를 확인합니다. 관리 이벤트만으로 판단할 수 없습니다.

발급 두 단계를 근거와 함께 연결하고, 기록된 출처 값과 검증된 귀속을 구분하고, 수집 공백 하나를 활동이 없었다는 결론 없이 설명할 수 있으면 학습을 마친 것입니다.

## 공식 참고자료

**검토일 2026-11-27.** 현재 AWS IAM·STS·CloudTrail의 역할 세션 문서를 기준으로 했습니다. 공식 문서 속 과거 로그는 필드 위치를 설명하는 예시입니다. 실제 필드와 수집 범위는 인증 흐름과 이벤트에 따라 달라집니다.

- [AWS IAM · 역할 세션 활동 모니터링과 통제](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- [AWS IAM · IAM·STS CloudTrail 기록과 역할 연쇄](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)
- [AWS CloudTrail · userIdentity 스키마](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html)
- [AWS CloudTrail · 이벤트 필드](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html)
- [AWS CloudTrail · 이벤트 기록의 범위](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- [AWS IAM Identity Center · ID 정보가 추가된 역할 세션](https://docs.aws.amazon.com/singlesignon/latest/userguide/trustedidentitypropagation-identity-enhanced-iam-role-sessions.html)

[이전 · IAM 역할과 CloudTrail]({{ '/ko/wiki/aws-iam-role-evidence/' | relative_url }}) · [다음 · CloudTrail 전달과 수집 범위]({{ '/ko/wiki/cloudtrail-log-integrity/' | relative_url }}) · [AWS KMS 조사에 적용]({{ '/ko/wiki/aws-kms-evidence/' | relative_url }})
