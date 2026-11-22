---
title: "Kubernetes 서비스 계정 토큰 증거 · Pod에서 API 판단까지"
description: "토큰 마운트, audience, 만료와 객체 바인딩을 살펴보고 가상 사례 9건으로 인증·인가·API 응답을 구분합니다."
category: cloud
tags: [Kubernetes, Cloud Security, Service Accounts, RBAC, Audit Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/kubernetes-service-account-evidence/
---

**서비스 계정(ServiceAccount)**은 소프트웨어가 사용하는 네임스페이스 단위의 신원입니다. **서비스 계정 토큰**은 그 신원으로 요청할 때 제시하는 자격 증명입니다. 여러 Pod가 한 계정을 사용할 수 있습니다. 토큰은 가진 사람이 제시할 수 있는 자격 증명이므로, 요청에 기록된 계정으로 어떤 신원이 받아들여졌는지 확인하고 실제 호출 주체는 추가 증거로 조사합니다. 사용처와 수명이 제한된 토큰, 필요한 만큼만 부여한 권한은 유출 시 영향을 줄여 줍니다.

## 1. 자격 증명부터 권한 검사까지 따라가기

1. Pod의 `spec.serviceAccountName`은 같은 네임스페이스의 계정을 지정합니다. 지정이 없으면 그 네임스페이스의 `default` 계정을 씁니다. 배포 템플릿과 실제 구성이 다를 수 있으니 생성된 Pod를 확인하세요.
2. 현행 클러스터는 일반적으로 API 자격 증명을 제공하는 투영 볼륨(projected volume)을 추가합니다. kubelet은 TokenRequest API를 통해 Pod에 바인딩된 토큰을 받아 갱신합니다. 앱은 이 파일을 읽지만 이미 메모리에 저장한 사본을 계속 쓸 수 있습니다. 자동 마운트 여부는 Pod의 `automountServiceAccountToken` 값이 서비스 계정의 값보다 우선합니다. 명시적으로 구성한 토큰 투영 볼륨도 따로 확인하세요.
3. API 서버는 발급자와 서명, 유효 시간, 해당 API가 허용하는 대상(audience), 적용되는 객체 바인딩을 확인합니다. UID는 동일한 이름과 구별되는 객체 인스턴스의 식별자입니다. Pod나 서비스 계정을 지우고 같은 이름으로 다시 만들면 UID가 바뀝니다. 조사할 때는 실제 검증기가 남긴 판단과 객체 수명 주기 기록을 확인하세요.
4. 인증 후에는 `system:serviceaccount:reports:reader` 같은 신원으로 요청 동작의 인가를 판단합니다. RBAC에서는 역할 규칙이 허용하는 동작과 리소스를 정하고, 바인딩이 해당 주체에게 권한을 부여합니다. 네임스페이스 단위 권한을 볼 때는 요청 대상 쪽을 확인하세요. 인가 승인이 나도 어드미션 및 후속 처리에서 결과가 달라질 수 있습니다. 앞선 판단과 최종 감사 단계, 응답을 대조하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-service-account-evidence-ko.svg' | relative_url }}" alt="Pod가 서비스 계정을 지정하면 kubelet이 Pod에 바인딩된 토큰을 요청하고 앱이 마운트된 파일을 읽습니다. API가 인증하고 인가기가 동작을 확인한 뒤 결과가 감사 로그에 남습니다.">
  <figcaption>먼저 자격 증명의 소유 관계와 수명을 확인하고, 요청 동작과 기록된 결과를 이어서 봅니다.</figcaption>
</figure>

| 관측한 증거 | 뒷받침하는 판단 | 다음 확인 |
| --- | --- | --- |
| Pod 명세에 서비스 계정 이름이 있음 | 해당 Pod에 지정된 신원 | Pod UID, 실제 마운트, 토큰의 대상 |
| `serviceaccounts/token`에 대한 `create` | 발급 요청을 관측함 | 요청 주체, 발급 대상 계정, 응답 코드 |
| 오프라인에서 서명·대상·유효 시간 통과 | 해당 검증기의 JWT 검사 통과 | 필요하다면 현재 객체 바인딩 확인 |
| API 인가기의 이름 지정 조회 허용 | 해당 조회 동작의 인가 통과 | 최종 응답과 대상, 워크로드 맥락 |

## 2. 정상 조회 한 건과 서로 다른 실패 두 가지

가상 클러스터에서 `reports`의 Pod `reporter`는 서비스 계정 `reader`를 사용합니다. `reports`의 RoleBinding은 그 계정에 `render-options` ConfigMap을 이름으로 `get`할 수 있는 역할을 부여합니다. 09:02 UTC에 애플리케이션이 토큰 파일을 읽고, API가 예상한 audience의 토큰을 수락합니다. 감사에는 `verb=get`, 대상 ConfigMap, 수집되는 경우 인가 허용 주석, 그리고 `responseStatus.code=200`이 남습니다. 수락된 계정으로 조회한 사실을 확인할 수 있습니다. 어느 복제본이 요청했는지는 워크로드 로그와 컨트롤러 기록으로 좁힐 수 있습니다.

만료된 사본을 계속 쓰면 401을 받을 수 있습니다. 파일 갱신 여부, 클라이언트 시계, 확인 가능한 검증기 진단을 보세요. 유효한 토큰으로 권한 범위 밖의 리소스를 요청하면 403이 발생할 수 있습니다. 최종 상태와 인가 주석을 확인하세요. 인가 허용과 함께 403이 보이면 응답의 상세 사유와 해당 쓰기 요청의 어드미션 처리 등 후속 단계를 봅니다. 중간 프록시에서도 HTTP 상태를 반환할 수 있으므로 응답을 낸 구성 요소를 확인합니다.

## 3. 객체 바인딩을 확인하는 검증기와 그렇지 않은 검증기

**대상(audience)**은 특정 Kubernetes API나 외부 서비스처럼 토큰을 받을 곳을 나타냅니다. **만료 시각(expiry)**은 토큰 유효 시간의 끝을 정합니다. Kubernetes는 바인딩된 자격 증명에 해당 객체의 UID를 확인합니다. 공식 문서에 따르면 바인딩된 객체가 사라지거나 UID가 달라지면 인증에 실패합니다. 객체가 삭제 대기 중이면 해당 객체의 삭제 타임스탬프에서 60초가 지난 시점부터 인증에 실패합니다. 토큰이 아직 수락돼야 하는지 판단하려면 삭제 상태, 관측 시각, 실제 검증 결과를 함께 확인하세요.

외부 앱이 발견 문서의 공개키와 JWT 검사만 사용하면 Pod가 삭제된 뒤에도 서명, 대상, 유효 시간 조건을 만족하는 토큰을 받아들일 수 있습니다. 외부 검증기가 현재 바인딩의 유효성까지 확인해야 한다면 Kubernetes 문서의 **TokenReview** 방식이 필요합니다. 기대하는 audience를 명시하고 인증 결과와 응답에 포함된 audience를 확인합니다. 이 확인은 해당 검증기가 자격 증명을 수락할지 결정하며, 앱의 인가는 별도로 적용됩니다.

## 4. 수집, 탐지, 대응

- **대상과 수집 범위를 기록합니다.** 클러스터, 시각, 네임스페이스, 계정과 Pod UID, 승인된 워크로드 담당자를 남기세요. API 감사 저장소에서 `auditID`, 해당 단계, `user`, 해당될 때 `impersonatedUser`, 동작, 객체·서브리소스, 응답과 인가 주석을 확보합니다. 감사 정책과 보존 기간에 필요한 리소스·서브리소스·단계가 포함됐는지 확인하세요. 토큰 관련 엔드포인트는 지원되고 승인된 범위에 메타데이터 수준으로 수집합니다. TokenRequest 응답과 TokenReview 요청의 본문에는 자격 증명이 들어갈 수 있습니다. 원문 토큰을 티켓, 실습 자료, 진단 출력에 남기지 마세요.
- **발급과 사용의 이상 징후를 따로 확인합니다.** `serviceaccounts/token`에 대한 `create`와 워크로드 요청을 정상 kubelet 갱신, 승인된 자동화, 계정 담당자와 RBAC 변경 이력에 대조합니다. 평소 계정으로 성공한 조회라도 업무 범위 밖이라면 조사 대상입니다. 복제본 사이의 계정 공유, 롤아웃, 공유 송신 경로가 활동 변화를 설명할 수 있습니다. IP, User-Agent, 서비스 계정 이름 하나로 감염된 Pod나 행위자를 확정할 수 없습니다. 앱 로그, 배포 이력, 엔드포인트 증거를 함께 보세요.
- **담당자와 노출 범위를 줄입니다.** 이벤트와 바인딩 변경 이력을 보존하고, 자격 증명에 접근할 수 있던 주체와 이를 받아들이는 서비스를 확인합니다. API 접근이 필요 없는 워크로드는 자동 마운트 설정을 점검하고 권한은 실제 업무 범위에 맞춥니다. 격리나 교체는 담당자와 조율하고, 특히 외부 오프라인 검증을 쓰는 곳은 대응 후 토큰 수락 상태를 별도로 확인하세요. 장기 Secret 기반 토큰은 수명 주기가 다른 레거시 방식입니다. v1.24부터 기본 자동 생성이 중단됐으며, 수동으로 만든 토큰은 남아 있을 수 있습니다.

## 5. 오프라인 실습 · 가상 관측 아홉 건

두 파일을 같은 폴더에 내려받고 Python 3.10 이상으로 실행하세요. JSONL은 **정규화한 가상 관측**입니다. 실제 토큰 문자열을 포함하지 않으며, 스크립트는 인증이나 네트워크 접속을 하지 않습니다. `null`은 해당 사실을 확인할 증거가 없다는 뜻입니다. 각 행은 판단에 필요한 원본 로그 전체가 아니라 한 사례의 관측을 요약합니다.

<a href="{{ '/assets/labs/kubernetes-service-account-evidence.py' | relative_url }}" download="kubernetes-service-account-evidence.py">kubernetes-service-account-evidence.py</a> · <a href="{{ '/assets/labs/kubernetes-service-account-evidence-cases.jsonl' | relative_url }}" download="kubernetes-service-account-evidence-cases.jsonl">kubernetes-service-account-evidence-cases.jsonl</a>

```bash
python3 kubernetes-service-account-evidence.py kubernetes-service-account-evidence-cases.jsonl
```

```text
expected_read: read_observed
wrong_audience: wrong_audience
expired_copy: outside_validity
deleted_pod: pod_binding_rejected
recreated_account: account_binding_rejected
external_after_delete: jwt_checks_only
outside_grant: authorization_denied
admission_denied: inspect_after_allow
incomplete_binding: insufficient_evidence
```

`external_after_delete`에서 오프라인 검증기는 발급자·서명, 대상, 시간만 확인합니다. 실습 출력도 이 범위만 보고합니다. `admission_denied`는 인가 허용 후 403이 발생한 가상 사례입니다. 실제 조사에서는 응답 사유와 어드미션 또는 담당 구성 요소의 기록을 확보해야 원인을 확인할 수 있습니다. 실행이 안 되면 작업 폴더와 파일명부터 확인하세요. 분류가 예상과 다르면 검증기 유형과, 실패한 검사인지 확인 자료가 없는 검사인지부터 확인합니다. 가상 실습은 Python 3.12에서 실행했고, 클러스터 동작은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **같은 이름의 Pod를 다시 만들었는데 기존 토큰이 거부되는 이유는 무엇인가요?** 기존 토큰은 특정 객체 인스턴스에 바인딩됐습니다. 새 객체의 UID는 다릅니다.
- **오프라인 검증은 통과했는데 TokenReview는 왜 실패할 수 있나요?** 오프라인 방식은 실시간 바인딩을 확인하지 않습니다. TokenReview는 클러스터에서 객체 존재 여부와 신원을 확인할 수 있습니다.
- **403이면 RBAC 권한이 빠졌나요?** 먼저 어느 구성 요소가 응답했고 어떤 판단이 기록됐는지 보세요. 인가 이후 단계에서도 요청이 거절될 수 있습니다.

아홉 줄의 결과를 재현하고, `incomplete_binding`에 필요한 다음 증거 출처를 말해 보세요. `outside_grant`의 계정 신원, 토큰 유효성, 인가를 각각 설명하면 실습을 마친 것입니다.

## 공식 참고자료

검토일은 2026-11-22입니다. 객체에 바인딩된 토큰 투영은 v1.22부터 안정화됐습니다. 아래 Pod 설정 문서는 v1.36 기준입니다. 관리형 클러스터의 감사 내보내기와 정책은 공급자 문서 및 배포 버전에서 확인하세요.

- 서비스 계정 신원, 단기 토큰과 레거시 자격 증명. [Kubernetes · 서비스 계정](https://kubernetes.io/docs/concepts/security/service-accounts/)
- 바인딩 토큰 검증, UID·삭제 확인, 오프라인 검증 한계. [Kubernetes · 서비스 계정 관리](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)
- Kubernetes v1.36의 토큰 볼륨, audience와 kubelet 갱신. [Kubernetes · Pod에 서비스 계정 구성하기 (v1.36)](https://v1-36.docs.kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- 인가 결정과 어드미션의 순서. [Kubernetes · 인가](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- 감사 단계와 수준, 로그 저장 설정. [Kubernetes · 감사](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)

[이전 · Kubernetes API 감사 로그]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }}) · [관련 · OAuth와 OpenID Connect]({{ '/ko/wiki/oauth-oidc-evidence/' | relative_url }}) · [관련 · Kubernetes NetworkPolicy]({{ '/ko/wiki/kubernetes-network-policy-evidence/' | relative_url }})
