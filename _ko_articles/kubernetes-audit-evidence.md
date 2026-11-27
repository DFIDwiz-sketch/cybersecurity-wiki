---
title: "Kubernetes API 감사 로그 · 권한 확인부터 실제 결과까지"
description: "Kubernetes 감사 단계와 응답을 읽고, 권한 허용과 실제 상태 변경을 가상 요청 10건으로 구분합니다."
category: cloud
tags: [Kubernetes, Cloud Security, Audit Logs, RBAC, Blue Team, DFIR]
level: Beginner
updated: "2026-11-20"
translation_url: /wiki/kubernetes-audit-evidence/
---

**학습 목표.** 감사 레코드 한 건에서 누가 무엇을 요청했고 API가 어떤 결과를 반환했는지 찾습니다. 객체가 실제로 바뀌었거나 워크로드가 실행됐다고 판단하려면 어떤 자료를 더 봐야 하는지 설명할 수 있습니다.

## 1. API 서버는 무엇을 기록하나요?

**제어 영역(control plane)**은 클러스터가 원하는 상태를 유지하도록 관리합니다. 그중 **API 서버**는 관리자, CI 작업, 컨트롤러 같은 소프트웨어로부터 요청을 받습니다. **컨트롤러**는 객체를 관찰하고 실제 상태를 요청된 상태에 맞추는 구성 요소입니다. **네임스페이스**는 ConfigMap 같은 여러 객체의 이름과 접근 범위를 구분합니다. **서비스 계정**은 클러스터에서 작업하는 소프트웨어가 사용할 수 있는 신원입니다. 예를 들어 `system:serviceaccount:audit-lab:observer`는 `audit-lab` 네임스페이스의 `observer` 서비스 계정을 가리킵니다.

**API 감사 이벤트**는 정책에서 기록하도록 정한 API 요청 처리 단계의 기록입니다. 워크로드 로그는 프로세스가 표준 출력이나 표준 오류로 남긴 메시지입니다. Kubernetes의 Event 객체는 스케줄링 실패 같은 운영 관측을 남깁니다. 감사 로그를 보면 누가 API에 무엇을 요청했는지, 서버가 어떤 결과를 반환했는지, 어느 단계가 수집됐는지 조사할 수 있습니다. 최초 쓰기에 반응한 컨트롤러가 별도 요청을 보내면 컨트롤러 자신의 신원과 새 감사 ID가 기록됩니다.

| 조사 질문 | 먼저 볼 증거 | 이어서 확인할 자료 |
| --- | --- | --- |
| 누가 호출했고 어떤 권한을 검사했나요? | `user`, 해당되는 경우 `impersonatedUser`, 동작, 대상, 인가 주석 | 신원 제공자, 서비스 계정 소유자, 당시 정책 |
| API는 무엇을 반환했나요? | `stage`와 관측된 결과의 `responseStatus.code` | 원본 감사 레코드, 어드미션 또는 API 서버 진단 |
| 어떤 상태가 바뀌었나요? | 쓰기 성공 기록, 객체 UID, 확보할 수 있는 경우 리소스 버전과 당시 상태 | 승인된 상태 스냅샷, 버전이 남는 인벤토리, 후속 쓰기와 컨트롤러 기록 |
| 실제로 실행됐나요? | Pod 상태와 조건, 컨테이너 상태, 노드 또는 런타임 기록 | 워크로드나 객체 식별자를 실제 실행 기록과 대조 |

## 2. 정상 조회 한 건을 읽어 보세요

모니터링 워크로드가 `audit-lab`에 이미 존재하는 `settings` ConfigMap을 조회한다고 가정합니다. 이름을 지정한 조회이므로 Kubernetes 동작 이름인 verb는 `get`입니다. **인증**은 호출한 서비스 계정을 식별하고, **인가**는 그 계정에 해당 대상을 조회할 권한이 있는지 검사합니다. **역할 기반 접근 제어(RBAC)**는 역할과 바인딩으로 리소스에 대한 동작을 허용하는 인가 방식 중 하나입니다. 이 가상 예시에서는 인가가 조회를 허용했고 API가 HTTP 200으로 응답했습니다. 정책이 메타데이터만 기록한다면 ConfigMap 내용은 감사 로그에 나타나지 않을 수 있습니다.

![API에서 인증과 인가를 마친 쓰기 요청은 어드미션과 검증을 거칩니다. 일반 요청은 저장소에 반영될 수 있고, 서버 드라이런은 결과만 반환합니다.]({{ '/assets/diagrams/kube-audit-decisions-ko.svg' | relative_url }})

*그림은 허용된 쓰기 요청의 처리 경로를 보여 줍니다. 인가에서 거부하면 어드미션에 도달하지 않습니다. get과 list 같은 읽기는 어드미션을 거치지 않습니다. 허용된 쓰기도 이후 정책, 잘못된 입력, 충돌 등의 이유로 실패할 수 있습니다.*

가상 조회의 일부 필드를 뽑은 예시입니다. 완료 레코드 한 건에서 호출자, 동작, 대상, 응답을 찾아보세요.

~~~json
{
  "stage": "ResponseComplete",
  "user": {"username": "system:serviceaccount:audit-lab:observer"},
  "verb": "get",
  "objectRef": {
    "namespace": "audit-lab",
    "resource": "configmaps",
    "name": "settings"
  },
  "annotations": {"authorization.k8s.io/decision": "allow"},
  "responseStatus": {"code": 200}
}
~~~

**응답 코드보다 단계를 먼저 읽으세요.** `RequestReceived`는 요청이 감사 처리 지점에 도착해 다음 핸들러로 전달되기 전입니다. `ResponseStarted`는 watch 같은 장시간 요청에서 헤더를 보낸 뒤에 생성됩니다. 이 단계의 200은 스트림이 시작됐다는 단서입니다. 종료 시점과 데이터 전달 여부는 추가 증거가 필요합니다. `ResponseComplete`는 API 응답이 끝난 단계입니다. `Panic`은 해당 단계가 수집될 때 서버 패닉을 기록합니다. 예를 들어 Deployment 생성 응답만으로는 배포된 워크로드가 이후 정상 상태에 도달했는지 알 수 없습니다.

## 3. 인가와 응답, 저장을 구분하세요

| 같은 요청 묶음에서 관측한 값 | 판단할 수 있는 범위 | 다음 확인 |
| --- | --- | --- |
| 완료 403과 인가 `forbid` | 인가에서 해당 API 작업을 거부함 | 호출자, 동작, 네임스페이스, 하위 리소스를 확인 |
| 완료 403과 인가 `allow` | 인가는 통과했지만 API가 403을 반환함 | 거부 상세 메시지나 정책 로그를 확인. 403만으로 어느 어드미션 정책이 거부했는지 확정할 수 없음 |
| 완료 409와 인가 `allow` | 인가는 통과했고 API가 충돌을 보고함 | 오류 상세, 기존 객체와 동시 쓰기 기록을 확인 |
| 생성 요청의 완료 201과 `dryRun=All` | API가 서버 드라이런 결과를 성공으로 반환함 | 원본 URI를 보존하고 이후 실제 생성 요청을 별도로 확인 |
| 일반 생성 요청의 완료 201 | API가 생성에 성공했다고 응답함 | 객체 UID, 조사 시점의 상태, 후속 조정 또는 삭제를 확인 |
| 접수나 응답 시작만 있음 | 해당 초기 단계까지 관측함 | 제외된 단계, 수집 지연, 스트림이 계속 열려 있는지 확인 |

서버 **드라이런(dry run)**은 일반적인 쓰기 요청 처리 과정에서 객체 저장을 생략합니다. 응답은 실제 생성 결과와 비슷할 수 있습니다. 따라서 API 경로는 시험할 수 있지만 이후 컨트롤러가 동작했는지는 확인할 수 없습니다. `pods/log` 조회와 Pod 객체 조회도 의미가 다릅니다. 레코드에 하위 리소스가 있으면 함께 보존하세요. `list`처럼 목록 전체를 대상으로 한 동작에서는 `objectRef`가 없을 수 있습니다. 원래 URI에서 리소스와 필터 범위를 확인하세요. 감사 수준이 Metadata이면, 성공한 목록 조회에서 어느 객체들이 반환됐는지까지 알 수 없습니다.

## 4. 블루팀 수집·탐지·대응

**수집 시작점을 확인하세요.** 직접 운영하는 클러스터에서는 API 서버에 적용된 감사 정책과 활성화된 로그 또는 웹훅 백엔드를 확인합니다. 규칙은 위에서부터 평가하며 처음 일치하는 규칙이 감사 수준을 결정합니다. `None`은 기록하지 않습니다. `Metadata`는 요청·응답 본문 없이 신원, 대상, 기록된 주석 같은 문맥을 남깁니다. 리소스 요청에서 `Request`는 요청 본문까지, `RequestResponse`는 두 본문 모두를 남깁니다. 신원과 응답을 조사하는 데는 Metadata부터 시작하세요. 본문을 수집하면 Secret 값이나 민감한 워크로드 설정이 포함될 수 있으므로 범위, 접근 권한, 보존 기간과 저장 비용을 먼저 검토합니다. URI와 계정 정보도 보호 대상입니다. 관리형 예로 Amazon EKS에서는 제어 영역의 `audit` 로그 유형을 활성화하면 CloudWatch Logs로 내보냅니다. 유형, 클러스터, 리전, 로그 스트림과 대상의 보존 기간을 확인하세요. 애플리케이션 로그와 CloudTrail은 이 Kubernetes 요청 기록을 대체할 수 없습니다.

**묶기 전에 필드를 보존하세요.** 신뢰할 수 있는 수집기 메타데이터의 클러스터 식별자, 원본 로그, API 버전, `auditID`, 단계, 원래 시각, 두 신원 필드, URI, 대상과 결과를 보존합니다. **클러스터 + auditID**로 묶고 `requestReceivedTimestamp`와 `stageTimestamp`로 API 처리 순서를 봅니다. 수집 도착 시각은 따로 기록하세요. 늦게 도착한 초기 단계가 마지막으로 색인됐다는 이유로 완료 기록을 덮어쓰면 결과를 놓칩니다. 내용이 다른 사본은 원인이 설명될 때까지 보존합니다. `userAgent`는 클라이언트가 보낸 문자열입니다. `sourceIPs`에는 전달 헤더와 연결의 원격 주소가 담길 수 있습니다. 신뢰하는 프록시의 경계를 확인하고 별도 접속 증거로 출발지를 대조하세요.

**구체적인 탐지 질문에서 시작하세요.** 예를 들어 네임스페이스의 RoleBinding에 대한 일반 쓰기 요청이 성공했고, 실제로 권한 평가에 사용된 신원이나 대상이 평소 배포 범위를 벗어났다면 검토 대상으로 표시할 수 있습니다. RoleBinding은 네임스페이스 안에서 권한을 부여할 수 있으므로 승인된 상태나 변경 기록에서 권한을 받은 주체와 참조 역할을 확인하세요. 탐지에 필요한 필드는 클러스터와 범위, 쓰기 동작, 완료 결과, 원본 URI의 드라이런 여부, 두 신원 필드입니다. 요청 단위로 중복도 제거합니다. 거부된 요청은 별도로 모아 승인된 방어 시험, 운영 설정 오류, 의심 활동을 구분하세요. 정상 작업, 지정된 실습 환경의 거부 사례, 완료가 누락된 가상 자료를 이용해 탐지 조건을 검증할 수 있습니다.

**예상 밖의 성공과 로그 공백은 각각 조사하세요.** 정상 컨트롤러도 배포나 복구 과정에서 쓰기를 수행합니다. 노출된 워크로드 자격 증명이나 과도한 권한으로 발생한 요청 역시 인가를 통과할 수 있습니다. 서비스 계정이 기록돼도 어떤 사람이 시작했는지는 모를 수 있습니다. `impersonatedUser`가 있으면 원래 인증된 호출자와 권한 평가에 사용된 신원을 모두 남깁니다. 변경 승인, CI·컨트롤러 실행 기록, 신원 로그, 실제 객체 상태를 대조하세요. 오용을 뒷받침하는 증거가 생기면 원본을 보존하고 영향 범위를 좁힌 다음, 승인된 절차로 자격 증명이나 바인딩을 조정합니다. 로그가 비었다면 감사 정책, 백엔드, 수집기, 색인을 차례로 확인합니다. 단계 제외, 보존 만료와 지연도 점검해야 요청이 없었던 경우와 수집 공백을 구분할 수 있습니다.

## 5. 오프라인 실습 · 가상 요청 10건

[kube-audit-samples.jsonl]({{ '/assets/labs/kube-audit-samples.jsonl' | relative_url }})과 [Python 검토 도구]({{ '/assets/labs/kube-audit-review.py' | relative_url }})를 같은 폴더에 받으세요. 한 줄에 JSON 객체 한 개가 들어 있습니다. 바깥의 `cluster`는 수집기가 붙였다고 가정한 메타데이터이고, `event`는 가상 감사 레코드입니다. 먼저 전체 ID를 사용해 요청을 직접 묶어 본 뒤 Python 3으로 실행합니다. 스크립트는 내려받은 파일만 읽으며 결과에는 읽기 쉽게 줄인 ID를 표시합니다.

~~~bash
python3 kube-audit-review.py
~~~

| training-east 요청 | 예상 해석 |
| --- | --- |
| 001 | 조회 성공. 파일에서 완료가 접수보다 먼저 나오고, 동일한 완료 레코드가 한 번 중복됨 |
| 002 / 003 | 둘 다 201. 앞은 드라이런이고 뒤는 객체 상태를 추가 조사해야 하는 일반 생성 |
| 004 / 005 | 둘 다 403. 앞은 인가 거부이고 뒤는 인가를 통과한 뒤 API가 403을 반환함 |
| 006 / 007 | watch 응답 시작 / 접수만 관측하고 완료는 미관측 |
| 008 | 조회 성공. 인증된 호출자와 권한 평가에 쓰인 신원이 달라 두 필드를 모두 보존 |
| 009 | 인가는 허용했지만 충돌 409를 반환 |

`training-west/000000000001`은 인가 거부입니다. 동쪽 클러스터의 같은 ID와 별도로 묶어야 합니다. 마지막에는 `Requests: 10; duplicate stage records: 1`이 나옵니다. 충돌이 보이면 클러스터가 묶음 기준에 포함됐고 동일 단계를 비교하고 있는지 확인하세요. JSON 오류가 발생하면 원본을 다시 받아 한 줄에 객체 하나가 들어 있는지 확인합니다. 이 스크립트는 제공된 표본에서 묶기와 단순 규칙을 보여 줍니다. 운영 데이터에 빠진 필드나 공급자가 덧붙인 구조가 있다면 별도의 파싱과 검증이 필요합니다.

**승인된 환경에서 선택 실습.** ConfigMap 읽기·쓰기의 감사 수집이 켜진 자가 소유 테스트 클러스터를 사용합니다. `audit-lab` 네임스페이스와 무해한 `settings` ConfigMap이 이미 있고, 테스트 자격 증명은 해당 공간에서 필요한 권한만 갖고 있어야 합니다. `OWNED_LAB`을 승인된 로컬 컨텍스트 이름으로 바꾸고, 두 명령 모두 실행 전에 클러스터를 확인하세요. 두 번째 명령은 새로운 테스트 이름으로 서버에 미리보기를 요청합니다.

~~~bash
kubectl --context OWNED_LAB -n audit-lab get configmap settings -o name
kubectl --context OWNED_LAB -n audit-lab create configmap audit-marker \
  --from-literal=purpose=audit-lab --dry-run=server -o name
~~~

UTC, 호출자, 컨텍스트, 대상과 결과를 기록하세요. 정책이 해당 단계와 필드를 남긴다면, 감사 백엔드에서 이름을 지정한 읽기와 `dryRun=All`이 붙은 생성 요청을 찾을 수 있습니다. 읽기 전용 인벤토리에서 미리보기 객체가 저장되지 않았는지 확인하세요. 거부된다면 결과를 기록하고 실습 역할, 네임스페이스의 어드미션 정책, 감사 설정을 살펴보세요. 실습을 통과시키기 위해 권한을 넓힐 필요는 없습니다. Python으로 가상 자료를 실행했고, kubectl·API 서버·EKS 동작은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **두 생성 요청 모두 완료 201이면 어느 쪽에서 실제 객체를 확인해야 하나요?** 일반 쓰기부터 확인합니다. URI의 `dryRun=All`은 미리보기를 뜻합니다. 나중의 일반 쓰기는 별도 요청으로 추적하세요.
- **왜 인가 `allow`와 403이 한 요청에 함께 나타날까요?** 인가가 다음 단계로 진행할 수 있다고 판단했고, 이후 처리에서 API가 오류를 반환한 것입니다. 어느 검사에서 거부됐는지 알려면 추가 기록이 필요합니다.
- **서비스 계정 이름이 있으면 작업을 시작한 사람을 특정할 수 있나요?** 해당 요청에 기록된 계정을 안 것입니다. 사람을 특정하기 전에 원래 인증된 호출자, 권한 평가에 사용된 신원, 컨트롤러나 CI 실행, 관련 신원 로그를 대조하세요.

두 201과 두 403의 차이를 설명하고 008의 두 신원을 적으세요. 사례 기록 한 건에 클러스터, 전체 감사 ID, 가장 확실하게 말할 수 있는 사실과 다음에 확인할 자료 하나를 적으면 완료입니다.

[다음 · 탐지와 수집 검증]({{ '/ko/wiki/detection-validation/' | relative_url }}) · [관련 · AWS 역할과 CloudTrail 조사]({{ '/ko/wiki/aws-iam-role-evidence/' | relative_url }})

## 공식 참고자료

2026년 11월 20일 검토. 핵심 사례는 Kubernetes v1.36 문서와 감사 API v1을 기준으로 합니다. 운영 환경에는 실제 클러스터 버전과 공급자의 설정을 적용하세요.

- [Kubernetes v1.36 · 감사 단계, 정책, 백엔드](https://v1-36.docs.kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes v1.36 · 감사 Event v1 스키마](https://v1-36.docs.kubernetes.io/docs/reference/config-api/apiserver-audit.v1/#event)
- [Kubernetes v1.36 · 인가 감사 주석](https://v1-36.docs.kubernetes.io/docs/reference/labels-annotations-taints/audit-annotations/)
- [Kubernetes v1.36 · API와 드라이런, v1.19부터 정식 기능](https://v1-36.docs.kubernetes.io/docs/reference/using-api/api-concepts/#dry-run)
- [Kubernetes v1.36 · 어드미션 제어](https://v1-36.docs.kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Amazon EKS 사용 설명서 · 제어 영역 감사 로그를 CloudWatch Logs로 내보내기](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html)
- [Kubernetes v1.36 · ConfigMap 서버 드라이런 명령](https://v1-36.docs.kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_configmap/)

정책 변경 뒤 Pod 연결에서 일어난 일을 확인하려면 [Kubernetes NetworkPolicy 증거]({{ '/ko/wiki/kubernetes-network-policy-evidence/' | relative_url }})로 이어서 살펴보세요.

## 워크로드 신원과 토큰 수명 확인

[Kubernetes 서비스 계정 토큰 증거]({{ '/ko/wiki/kubernetes-service-account-evidence/' | relative_url }})에서 Pod의 자격 증명 발급과 API 인증·인가를 따라갑니다.

## Pod 생성 단계의 보안 정책 조사

[Kubernetes Pod Security Admission 조사]({{ '/ko/wiki/kubernetes-pod-security-admission-evidence/' | relative_url }})에서 워크로드 템플릿의 수락, 컨트롤러의 Pod 생성 요청, 실제 실행 상태를 구분하는 방법을 익힙니다.

## RBAC 권한이 생긴 경로 확인

[Kubernetes RBAC 조사]({{ '/ko/wiki/kubernetes-rbac-evidence/' | relative_url }})에서 네임스페이스의 바인딩, 하위 리소스 규칙, 과거 사용 증거를 대조합니다.

## 할당량과 배치 증거 확인하기

배포가 멈췄다면 [Kubernetes 리소스 할당량]({{ '/ko/wiki/kubernetes-quota-evidence/' | relative_url }})에서 정책에 따른 생성 거부와 노드 배치 실패를 구분해 보세요.

[어드미션 웹훅의 정책 거부, 호출 오류, Fail-open 증거 구분하기]({{ '/ko/wiki/kubernetes-admission-webhook-evidence/' | relative_url }})
