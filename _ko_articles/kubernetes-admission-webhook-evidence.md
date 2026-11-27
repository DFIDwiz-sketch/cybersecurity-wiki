---
title: "Kubernetes 어드미션 웹훅 · 정책 거부, 시간 초과, Fail-open 구분"
description: "AdmissionReview 결정, API 감사 애너테이션, 제어 플레인 지표를 함께 읽어 웹훅 장애 시 요청 처리 결과를 확인합니다."
category: cloud
tags: [Kubernetes, Admission Webhook, Cloud Security, Audit Logs, Detection Engineering, Blue Team]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/kubernetes-admission-webhook-evidence/
---

배포 요청이 API에서 거부됐지만 웹훅의 대시보드에는 HTTP 200이 찍혀 있습니다. 두 기록 모두 맞을 수 있습니다. 클라이언트는 Kubernetes API를 호출하고, API 서버는 별도로 웹훅을 호출합니다. 웹훅의 통신 상태, 웹훅이 내린 정책 결정, API 서버가 클라이언트에 보낸 최종 응답은 각각 다른 질문에 답합니다.

## 1. 두 통신을 따라가 보기

**어드미션 컨트롤러**는 인증과 인가가 끝난 뒤, 요청에 따른 쓰기가 저장되기 전에 요청을 평가합니다. **변경 웹훅(mutating webhook)**은 소유자 라벨 추가 같은 객체 변경을 제안할 수 있습니다. **검증 웹훅(validating webhook)**은 변경을 거친 요청을 검사하고 필요하면 거부합니다. 특정 웹훅이 호출되는지는 매칭 규칙과 조건에 따라 달라집니다. 웹훅 하나가 허용했다는 기록만으로는 이후 검사 결과를 알 수 없습니다.

API 서버는 매칭된 웹훅에 `AdmissionReview` 본문을 담은 HTTPS 요청을 보냅니다. `admission.k8s.io/v1`에서 규격에 맞는 결정은 웹훅의 HTTP 200과 `AdmissionReview.response` 본문으로 전달됩니다. 웹훅은 `request.uid`를 `response.uid`에 복사하고 `allowed` 값을 설정합니다. 거부 응답에는 `status`로 사유를 담을 수 있습니다. **AdmissionReview UID**는 웹훅과의 해당 통신을 식별합니다. API 감사 이벤트의 **`auditID`**는 전체 API 요청을 여러 감사 단계에서 연결하는 값입니다. 계측에서 검증된 매핑을 제공하는 경우에 두 기록을 연결하세요. 이름이나 형식이 비슷하다는 이유로 같은 값이라고 가정하면 안 됩니다.

<figure>
  <img src="{{ '/assets/diagrams/kubernetes-admission-webhook-evidence-ko.svg' | relative_url }}" width="560" height="350" alt="클라이언트가 API 서버를 호출하고, API 서버는 웹훅을 별도로 호출합니다. 규격에 맞는 결정은 허용 또는 거부이고, 호출 오류에는 failurePolicy가 적용됩니다. 이후 검사와 저장 여부에 따라 최종 API 결과가 결정됩니다.">
  <figcaption>클라이언트에 전달한 API 응답과 웹훅이 API 서버에 전달한 HTTPS 응답을 각각 확인하세요.</figcaption>
</figure>

## 2. 정상 흐름과 네 가지 결과 비교

**가상의 정상 흐름.** 팀이 `training` 네임스페이스에 ConfigMap을 만듭니다. API 서버가 요청자의 권한을 확인한 뒤, 변경 웹훅이 소유자 라벨을 추가하고 검증 웹훅이 결과 객체를 평가합니다. 두 웹훅은 각각 요청에 맞는 리뷰 UID와 `allowed: true`를 담아 응답합니다. 이 예에서 일반 생성이 성공하면 API는 201을 반환합니다. 감사 애너테이션으로 어느 호출이 라벨을 추가했는지 확인할 수 있습니다. 이후 객체를 조회할 때는 반환됐던 객체 UID도 비교하세요. 이름이 같은 객체가 나중에 다시 생성됐을 수 있습니다.

| 웹훅 통신에서 관측한 내용 | 어드미션 처리 | 이어서 확인할 항목 |
| --- | --- | --- |
| 웹훅 HTTP 200, 규격에 맞는 응답, `allowed: true` | 이 웹훅은 요청을 허용했습니다. 변경 웹훅은 패치를 반환할 수도 있습니다. | 남은 검사, 최종 API 결과, 필요한 경우 객체 상태 |
| 웹훅 HTTP 200, 규격에 맞는 응답, `allowed: false` | 정책에 따른 명시적 거부입니다. 호출 실패 정책은 이 결정을 바꾸지 않습니다. | 원래 API 응답의 정책 사유와 일치하는 웹훅 또는 감사 증거 |
| 연결 실패, 시간 초과, 잘못된 응답 등 호출 오류에 유효한 정책 `Fail` 적용 | 해당 호출 실패 때문에 API 요청이 거부됩니다. 정책을 생략하면 기본값은 `Fail`입니다. | 웹훅 이름이 포함된 API 서버 오류, 서비스 가용성, TLS, 당시 유효했던 설정 |
| 호출 오류에 유효한 정책 `Ignore` 적용 | API 서버가 오류를 지나 다음 처리를 진행합니다. 해당 웹훅이 **fail-open**됐다고 부릅니다. | 이후 검사에서 거부됐는지, 드라이런인지, 실제로 저장된 객체가 있는지 |

클라이언트의 403은 인가나 다른 어드미션 검사에서도 발생할 수 있습니다. API 201만으로는 어떤 웹훅이 실행됐는지 알 수 없습니다. `dryRun=All`인 서버 측 드라이런에서는 저장하지 않고도 성공 응답이 반환될 수 있습니다. 조사 메모에 통신, 웹훅 결정, API 결과, 저장 여부를 각각 적으세요.

## 3. 요청별 증거와 시간 구간의 지표 수집하기

| 출처 | 수집 조건과 확인할 필드 | 뒷받침하는 판단 |
| --- | --- | --- |
| API 감사 이벤트 | 관련 규칙이 활성화되어 있고 `ResponseComplete` 이벤트가 보존돼야 합니다. 클러스터, `auditID`, 시각, `verb`, `user.username`, `objectRef`, `responseStatus`, `requestURI`, 관련 애너테이션을 확인합니다. | 최종 API 응답, 기록된 요청자와 요청별 어드미션 근거. 앞선 `RequestReceived`에는 어드미션 중 추가한 정보가 아직 없을 수 있습니다. |
| 웹훅 서비스 또는 API 서버 로그 | 승인된 구조화 로깅에서 웹훅 이름, 리뷰 UID, 요청 범위와 시각, 처리 결과 또는 오류 유형을 확인합니다. 지원되는 계측에서만 감사 요청과 호출 사이의 명시적 매핑을 사용합니다. | 개별 호출과 그 호출이 보고한 결과. 검증된 매핑이 없으면 시각과 객체 범위를 단서로 사용하고 불확실성을 남깁니다. |
| API 서버 지표 | 클러스터 버전과 지표 노출 여부, API 서버별 스크레이프 범위, 레이블을 확인합니다. 시간 구간별 증가량을 보고 카운터 초기화를 고려합니다. | 웹훅별 시간 구간의 추세. 지표에는 개별 요청의 감사 ID가 없습니다. |
| 정책 또는 저장 증거 | 당시 유효했던 설정 버전과 매칭 규칙을 보존합니다. 승인 범위에서 객체 UID나 조회 결과를 확인하고 이후 동작에는 컨트롤러·워크로드 기록을 사용합니다. | 평가 대상, 저장된 객체, 이후 실행된 작업을 각각 확인합니다. |

Kubernetes v1.36 업스트림 문서에서 변경 웹훅 호출은 감사 수준 `Metadata` 이상일 때 `mutation.webhook.admission.k8s.io/round_<n>_index_<n>` 애너테이션을 남길 수 있습니다. 문자열 값을 JSON으로 해석하면 설정 이름, 웹훅 이름, `mutated` 여부를 확인할 수 있습니다. `mutated: false`는 호출에서 변경이 없었다는 뜻입니다. `Request` 이상에서는 `patch.webhook.admission.k8s.io/round_<n>_index_<n>` 애너테이션으로 적용된 패치를 확인할 수 있습니다. 패치나 요청 본문에는 민감한 설정이 포함될 수 있으므로 수집 대상과 시간을 좁히세요.

업스트림 v1.36.0 구현에서는 해당 fail-open 경로에서 `failed-open.mutation.webhook.admission.k8s.io/` 또는 `failed-open.validating.webhook.admission.k8s.io/`로 시작하는 애너테이션을 기록합니다. 값은 웹훅 이름입니다. 이 정보는 v1.36.0 소스에서 확인한 구현 세부 사항입니다. 사용 중인 빌드와 관리형 로깅 경로가 해당 값을 제공하는지 확인하세요. 애너테이션이 없다는 이유만으로 웹훅이 호출됐거나 정상 동작했거나 정책을 적용했다고 판단하기 어렵습니다.

제어 플레인의 두 카운터로 조사 우선순위를 정할 수 있습니다. `apiserver_admission_webhook_rejection_count`의 `error_type="no_error"`는 규격에 맞게 반환된 정책 거부를 뜻하고, `calling_webhook_error`는 거부로 이어진 관련 호출 오류를, `apiserver_internal_error`는 API 서버 내부 오류를 나타냅니다. `apiserver_admission_webhook_fail_open_count`는 웹훅 이름과 어드미션 유형별로 기록된 fail-open 건수를 셉니다. 두 지표 모두 v1.36 레퍼런스에서 알파입니다. 승인된 환경에서 노출되는 경우 API 서버 지표를 수집하고, 증가량을 개별 객체에 연결하려면 감사 이벤트와 로그로 근거를 보강하세요.

## 4. 장애 조사와 관측 복구

웹훅 하나의 장애인지, 제어 플레인 전반의 문제인지부터 구분합니다. 오류 시각을 배포, 인증서와 CA 변경, 서비스 엔드포인트 상태, API 서버에서의 연결 상태와 비교하세요. 정책 버전과 상태 지표를 함께 보존합니다. 예기치 않은 웹훅 설정 변경, 지나치게 넓거나 빠진 적용 범위, 장애 시간대의 예상 밖 객체 변경도 조사하세요. 장애는 정상 쓰기를 막거나 검사를 수행하지 못하게 할 수 있습니다. 어느 결과든 악용 여부는 별도 증거가 필요합니다. 승인된 변경 이력과 영향을 받은 리소스를 대조하세요.

승인된 변경 절차로 웹훅의 가용성을 복구하고 정책이 의도한 범위에 적용되는지 확인합니다. 분리된 테스트 환경에서 정상 요청과 정책에 따라 거부돼야 하는 테스트 요청을 사용하고, 양쪽의 API 결과와 로그를 확인하세요. 사고 조사에서는 요청별 기록으로 영향을 받은 쓰기를 찾고 실제 저장 상태를 대조합니다. 연결이 불확실하거나 수집이 빠진 범위도 표시하세요. 지표 증가는 영향 시간대와 범위를 좁히는 데 사용합니다.

## 5. 오프라인 실습 · 일곱 가지 결과 분류하기

본인이 관리하는 디렉터리에서 Python 3.9 이상을 사용하고, 파일은 표시된 이름으로 저장하세요. 자료는 모두 가상입니다. Kubernetes 감사 이벤트의 형태를 따른 기록과, 일부 사례에서만 명시적으로 연결된 간소화 진단 기록을 제공합니다. 스크립트는 클러스터를 실행하거나 매니페스트를 적용하거나 요청을 보내지 않습니다.

- <a href="{{ '/assets/labs/kubernetes-admission-webhook-evidence/review_admission.py' | relative_url }}" download="review_admission.py">review_admission.py 다운로드</a>
- <a href="{{ '/assets/labs/kubernetes-admission-webhook-evidence/cases.json' | relative_url }}" download="cases.json">가상 관측 자료 다운로드</a>

```sh
python3 review_admission.py cases.json
```

| 사례 | 기대 결과 |
| --- | --- |
| 변경과 일반 생성 | 변경 한 건이 보이며 일반 요청의 API 201이 기록됩니다. |
| 명시적 거부 | 웹훅 통신은 200이고 규격에 맞는 결정은 거부입니다. API 거부는 별도로 기록됩니다. |
| 시간 초과와 API 거부 | 명시적으로 연결된 호출 오류로 API 거부를 설명할 수 있습니다. |
| Fail-open 뒤 201, fail-open 뒤 403 | 애너테이션으로 결정이 수행되지 않은 웹훅을 찾을 수 있습니다. 두 최종 API 결과는 다릅니다. |
| API 성공과 집계 지표만 있음 | 해당 요청에서의 웹훅 결과는 미확정입니다. |
| 드라이런에서 변경 | 요청에 패치가 적용됐고 API는 201을 반환합니다. 드라이런이므로 저장되지는 않습니다. |

일곱 비교가 모두 통과해야 합니다. 실패 사례를 확인하려면 JSON 복사본에서 명시적 거부 사례의 진단 기록 `audit_id`만 바꾸고, 감사 이벤트의 `auditID`는 그대로 둡니다. 스크립트가 해당 웹훅에 거부를 연결하지 못하면서 기대값 검사에 실패하고, 종료 코드는 1이 됩니다. 원본에서 실패한다면 두 파일이 같은 실습용인지, JSON 형식이 유효한지 확인하세요. Python에서 가상 증거를 실제로 비교했습니다. Kubernetes 동작은 공식 문서와 업스트림 소스로 확인했습니다.

## 6. 확인 문제와 해설

1. **웹훅 응답이 HTTP 200이고 `allowed: false`입니다. 객체가 허용됐나요?** HTTP 상태는 웹훅과의 통신 결과입니다. 규격에 맞는 결정은 명시적 거부입니다.
2. **같은 감사 이벤트에 fail-open과 최종 403이 함께 남을 수 있나요?** 가능합니다. 한 웹훅의 호출 오류를 지나쳤고, 이후 검사에서 전체 API 요청이 거부된 상황입니다.
3. **배포 중 카운터가 올랐습니다. 어떤 객체가 그 검사 없이 허용됐나요?** 지표 자체에는 객체가 없습니다. 요청별 증거에서 확인하고 저장 여부는 별도로 대조하세요.

**완료 기준.** 일곱 비교와 실패 사례를 재현합니다. 각 결과에서 개별 호출, 전체 API 요청, 최종 응답을 어떤 필드로 확인하는지 설명하고 저장 여부에 남은 질문을 적으세요.

## 공식 참고자료

2026년 11월 27일 검토. API와 지표 설명은 Kubernetes v1.36 문서를 기준으로 했습니다. Fail-open 애너테이션은 업스트림 v1.36.0 소스에서 확인했습니다.

- Kubernetes [동적 어드미션 컨트롤](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/), [어드미션 웹훅 운영 지침](https://v1-36.docs.kubernetes.io/docs/concepts/cluster-administration/admission-webhooks-good-practices/), [Kubernetes 지표 레퍼런스](https://v1-36.docs.kubernetes.io/docs/reference/instrumentation/metrics/).
- Kubernetes [감사 로깅](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/), [드라이런 동작](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/#dry-run).
- Kubernetes v1.36.0 업스트림 [검증 웹훅 디스패처](https://github.com/kubernetes/kubernetes/blob/v1.36.0/staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/validating/dispatcher.go), [변경 웹훅 디스패처](https://github.com/kubernetes/kubernetes/blob/v1.36.0/staging/src/k8s.io/apiserver/pkg/admission/plugin/webhook/mutating/dispatcher.go), [AdmissionReview API 타입](https://github.com/kubernetes/kubernetes/blob/v1.36.0/staging/src/k8s.io/api/admission/v1/types.go).

[이전 · Kubernetes 감사 증거]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }}) · [다음 · 내장 Pod Security Admission과 비교]({{ '/ko/wiki/kubernetes-pod-security-admission-evidence/' | relative_url }}) · [쿼터와 어드미션 거부 비교]({{ '/ko/wiki/kubernetes-quota-evidence/' | relative_url }})
