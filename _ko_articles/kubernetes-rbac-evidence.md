---
title: "Kubernetes RBAC 조사 · API 권한이 생긴 경로 따라가기"
description: "Role과 ClusterRole의 적용 범위, 하위 리소스 권한, 실제 사용을 보여 주는 감사 증거를 확인합니다."
category: cloud
tags: [Kubernetes, RBAC, Cloud Security, Audit Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /wiki/kubernetes-rbac-evidence/
---

한 서비스 계정은 `reports`에서 Pod를 조회할 수 있지만 해당 Pod의 로그는 읽을 수 없습니다. 다른 계정은 같은 규칙을 별도 네임스페이스에서 부여받았습니다. 차이를 설명하려면 정확히 어떤 API 작업을 요청했는지와 당시 호출자에게 적용된 바인딩을 확인해야 합니다.

## 1. 권한이 부여되는 방식

**인증**은 요청자와 소속 그룹을 식별합니다. **인가**는 그 신원이 해당 API 작업을 수행해도 되는지 판단합니다. **역할 기반 접근 제어(RBAC)**에서 규칙은 허용할 작업을 정의하고, 바인딩은 규칙을 적용할 **주체**(사용자, 그룹 또는 서비스 계정)를 지정합니다. **네임스페이스**는 클러스터 안에서 객체와 바인딩의 범위를 나눕니다. **API 그룹**은 리소스의 API 소속을 구분합니다. 코어 그룹은 빈 문자열로 표시하며, 예를 들어 Deployment는 `apps` 그룹에 속합니다. **하위 리소스**는 `pods/log`처럼 특정 리소스에 딸린 별도 API 대상입니다. 리소스 유형과 객체 이름은 별도 필드입니다.

| 객체 | 무엇을 담나요? | 어디에 권한을 부여하나요? |
| --- | --- | --- |
| Role | 한 네임스페이스에서 관리하는 규칙 | 같은 네임스페이스의 RoleBinding을 통해 적용 |
| ClusterRole | 정의 자체에는 네임스페이스가 없는 재사용 가능한 규칙 | 참조하는 바인딩에 따라 달라짐 |
| RoleBinding | 주체와 Role 또는 ClusterRole 참조 | 바인딩의 네임스페이스 안에서 적용. ClusterRole을 참조해도 범위는 동일 |
| ClusterRoleBinding | 주체와 ClusterRole 참조 | 규칙에 따라 클러스터 범위 리소스 또는 모든 네임스페이스의 리소스에 적용 |

적용 가능한 RBAC 권한은 합산됩니다. 한 경로에 규칙이 없어도 다른 경로로 권한을 얻을 수 있고, 좁은 바인딩이 넓은 바인딩을 취소하지 않습니다. API 서버는 RBAC 이외의 인가 모듈도 사용할 수 있습니다. 스냅샷에서 적용되는 RBAC 규칙을 찾지 못했다는 결론과 서버가 실제로 반환한 판단을 구분하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-rbac-evidence-ko.svg' | relative_url }}" alt="API 요청에서 주체와 대상을 확인합니다. 바인딩 주체와 적용 범위, 참조 규칙을 대조합니다. RBAC에서 찾은 권한을 실제 인가 결과와 감사 로그의 응답에 각각 대조합니다.">
  <figcaption>누구에게 어디서 어떤 규칙이 적용되는지 따라간 뒤, API가 실제로 어떤 응답을 반환했는지 따로 확인합니다.</figcaption>
</figure>

## 2. 정상적인 권한 부여를 따라가기

가상 예제에서 서비스 계정 `summarizer`는 `reports`에 있습니다. `reports`의 RoleBinding은 ClusterRole `pod-inventory`를 참조하며 해당 서비스 계정을 주체로 지정합니다. 참조된 규칙은 코어 그룹 `""`의 `pods`에 `get`과 `list`를 허용합니다.

1. `reports`의 `pods/daily`에 대한 `get`은 주체, 네임스페이스, 동작, 리소스가 모두 맞습니다. 여기서 `daily`는 객체 이름이고 규칙의 리소스 유형은 `pods`입니다.
2. `reports`의 Pod 목록 조회도 이 규칙에 해당합니다. 같은 네임스페이스에서도 `pods/log`에 대한 `get`은 해당하지 않습니다. 로그를 읽을 수 있는지 확인하려면 `log` 하위 리소스의 `get` 권한을 따로 확인하세요. 다른 바인딩이 필요한 권한을 줄 수도 있습니다.
3. 규칙이 ClusterRole에 있어도 기존 바인딩으로는 `archive`의 Pod를 읽을 수 없습니다. `archive`에 별도 RoleBinding을 두고 같은 계정을 지정할 수는 있습니다. 이때 주체의 네임스페이스는 `reports`로 표시하고, 권한 범위는 `archive` 바인딩을 따릅니다.
4. `reports`의 다른 Role은 `resourceNames`로 ConfigMap `public-settings`를 지정하고 `get`을 허용합니다. 같은 Role로는 다른 이름의 ConfigMap을 읽을 수 없습니다. 이름을 제한한 일부 `list`·`watch` 요청은 일치하는 `metadata.name` 필드 선택자를 포함해야 허용됩니다. 이름이 있는 객체 하나를 읽을 수 있다는 이유로 목록 조회도 가능하다고 가정하지 말고 실제 규칙과 요청을 확인하세요.

승인된 학습 클러스터에서는 담당자가 미리 설정한 실습용 계정으로 권한을 조회합니다. 먼저 올바른 컨텍스트인지 확인하세요. 다음 명령은 API 서버에 인가 판단을 물으며, 지정한 객체나 Pod 로그를 직접 가져오지는 않습니다.

```bash
kubectl config current-context
kubectl auth can-i get pods/daily -n reports
kubectl auth can-i get pods/daily --subresource=log -n reports
kubectl auth can-i get pods/daily -n archive
```

위에서 설명한 Pod 권한만 있다면 결과는 `yes`, `no`, `no`입니다. 결과가 다르면 컨텍스트, 로그인한 신원과 그룹, 다른 바인딩, 인가 모듈 구성을 확인하세요. 연결·인증·접근 검토 오류가 났다면 검사 자체가 실패한 것입니다. 검사가 성공해도 그 시점의 인가 판단만 알 수 있습니다. 과거 요청이 저장에 이르렀는지, 해당되는 경우 승인 제어(admission)를 통과했는지, 성공 응답을 받았는지는 각각 확인해야 합니다. 명령은 공식 문서로 검토했습니다.

## 3. 권한 변경과 실제 사용의 증거

워크로드의 접근 범위가 의도보다 넓어졌는지 확인하세요. 예를 들어 특정 네임스페이스에서만 부여하던 권한을 클러스터 전체 바인딩으로 교체하면 다른 네임스페이스에도 접근할 수 있습니다. 와일드카드나 공유 ClusterRole 변경도 의도보다 많은 리소스나 주체에 영향을 줄 수 있습니다. Kubernetes는 필요한 최소한의 권한 부여를 권고합니다. 위험도가 높은 변경은 조사 단서로 보고, 의도를 판단하기 전에 변경 소유자와 승인 내역을 확인하세요.

- **정책 변경부터 확인합니다.** 관련 Role, ClusterRole, 바인딩을 시각과 함께 내보내고 UID와 리소스 버전, 변경 이력, 당시 신원 공급자의 그룹 이력을 보존합니다. 바인딩과 참조 대상 양쪽을 살피세요. ClusterRole 수정은 여러 바인딩에 영향을 줄 수 있습니다. 집계형 ClusterRole은 개별 기여 역할이 바뀌어도 규칙이 달라질 수 있습니다. 현재 내보낸 자료는 현재 상태를 보여 줍니다.
- **API 활동과 대조합니다.** 관련 리소스와 단계에 대한 제어 영역 감사 수집을 설정했다면 클러스터와 `auditID`로 기록을 연결하세요. 인증된 `user`, 기록에 있으면 `impersonatedUser`, 시각, `verb`, `objectRef`의 그룹·리소스·하위 리소스·네임스페이스·이름, 관련 인가 주석, `ResponseComplete`의 `responseStatus`를 비교합니다. 가능하면 승인된 변경의 식별자와 연결합니다. 메타데이터 수준은 RBAC 객체에 어떤 작업을 요청했는지 보여 주지만 변경된 주체나 규칙은 보존하지 않습니다. 변경 전후 값이 필요하면 승인된 구성 이력이나 범위를 좁혀 수집한 감사 요청 본문을 쓰세요. 일반 조사용 내보내기에서 자격 증명과 응답 본문은 제외합니다.
- **실패한 단계를 찾습니다.** 403은 인가 실패 또는 이후 승인 제어 등의 거부일 수 있습니다. 제공되는 인가 판단과 사유를 오류 내용 및 작업 맥락과 대조합니다. 접근 검토가 알려 주는 것은 할 수 있는 작업입니다. 실제 작업의 성공 응답은 별도로 관측해야 합니다. 두 증거 모두 공유 신원이나 자동화 계정 뒤에 있는 개인까지 식별하지는 못합니다.
- **서비스 담당자와 대응합니다.** 주체와 접근 범위가 운영 의도와 맞는지 확인하세요. 승인된 수정 전에 당시 정책과 관련 기간의 증거를 보존합니다. 범위를 줄인 뒤 의도한 작업은 여전히 허용되는지, 이전의 과도한 작업은 차단되는지, 워크로드가 정상인지 확인합니다. 해당 신원이 이미 사용됐다면 노출 가능 기간의 실제 요청과 영향받은 리소스를 별도로 검토합니다.

## 4. 오프라인 실습

승인된 학습 환경에서 Python 3.8 이상을 사용하세요. <a href="{{ '/assets/labs/kubernetes-rbac-evidence.py' | relative_url }}" download="kubernetes-rbac-evidence.py">RBAC 추적 스크립트</a>와 <a href="{{ '/assets/labs/kubernetes-rbac-evidence.json' | relative_url }}" download="kubernetes-rbac-evidence.json">가상 스냅샷과 요청</a>을 같은 디렉터리에 저장합니다.

```bash
python3 kubernetes-rbac-evidence.py kubernetes-rbac-evidence.json
```

이 스냅샷은 학습용 필드로 단순화했으므로 Kubernetes 매니페스트로 사용할 수 없습니다. 스크립트는 리소스 규칙, 동작, API 그룹이 정확히 일치하는지 확인합니다. 이름이 있는 `get` 요청에 대해서는 규칙에 지정한 이름이나 이름 제한이 없는 경우를 처리합니다. 주체 그룹과 요청 범위는 입력에 주어진 값을 사용합니다. 인증, 와일드카드, 선택자, ClusterRole 집계, 승인 제어, 다른 인가 모듈의 동작은 모사하지 않습니다. 네트워크를 사용하지 않으며 요청별로 일치하는 바인딩 이름을 출력합니다.

| 가상 사례 | 기대 결과 |
| --- | --- |
| `pod_in_reports` | `reports/pod-inventory`가 이름으로 지정한 Pod 조회를 허용 |
| `pod_in_archive` | 이 서비스 계정에 대한 `archive` 권한을 찾지 못함 |
| `pod_log` | `log` 하위 리소스 권한을 찾지 못함 |
| `wrong_serviceaccount_namespace` | 이름이 같아도 다른 네임스페이스의 서비스 계정에 대한 권한을 찾지 못함 |
| `named_configmap` | `reports/public-config`가 지정된 이름의 조회를 허용 |
| `different_configmap` | 다른 ConfigMap을 읽을 권한을 찾지 못함 |
| `group_cluster_read` | 그룹 소속을 통해 `node-inventory`가 클러스터 범위 조회를 허용 |
| `overlapping_grants` | `reports/pod-inventory`와 `reports/support-read`가 동시에 허용 |

JSON을 열 수 없다면 두 파일 이름과 작업 디렉터리를 확인하세요. 의도와 달리 `no_grant_found`가 나오면 주체와 바인딩의 네임스페이스, 코어 그룹의 빈 문자열 표기, 하위 리소스를 확인하세요. `pod_in_archive`의 그룹에 가상의 `support`를 추가해 보세요. 바인딩의 네임스페이스를 그대로 두면 여전히 권한이 나오지 않습니다. 게시한 가상 사례 여덟 건을 오프라인에서 실행했습니다. 이 실습에서는 실제 클러스터를 변경하거나 조회하지 않았습니다.

## 5. 확인 문제와 완료 기준

1. **ClusterRole을 참조하는 RoleBinding은 모든 네임스페이스에 권한을 부여하나요?** RoleBinding 자체는 그 바인딩의 네임스페이스 안에 적용됩니다. 다른 바인딩 경로는 따로 확인합니다.
2. **Pod 객체를 조회할 수 있는데 왜 로그는 못 읽을까요?** `pods`와 `pods/log`는 서로 다른 규칙 대상입니다. 정확한 동작과 하위 리소스를 확인하세요.
3. **의도하지 않은 권한이 실제로 쓰였는지는 어떻게 확인하나요?** 해당 신원과 일치하는 과거 감사 활동과 응답 단계를 찾습니다. 당시 정책과 그룹 이력을 요청에 연결하고, 응답이 어디까지 보여 주는지 판단하세요.
4. **바인딩 하나를 제거했는데 조회 권한이 남아 있다면요?** 그룹 소속과 클러스터 전체 범위를 포함해 다른 바인딩을 확인합니다. 이어서 구성된 인가 모듈을 확인하고 현재 접근 검토를 실행합니다.

허용된 요청 한 건에 적용된 바인딩, 하위 리소스에서 부족한 권한, 권한 보유에서 실제 사용으로 결론을 옮길 때 필요한 증거를 설명할 수 있으면 완료입니다.

## 공식 참고자료

검토일 2026년 11월 23일. Kubernetes v1.37 문서를 기준으로 검토했습니다. 실제 클러스터 버전과 공급자의 감사 수집 지원을 확인하세요.

- [Kubernetes RBAC 인가](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)에서 규칙, 주체 및 바인딩 범위를 설명합니다.
- [인가](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)와 [kubectl auth can-i](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_auth/kubectl_auth_can-i/)에서 접근 검토를 확인합니다.
- [RBAC 권장 관행](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)에서 최소 권한 원칙을 설명합니다.
- [감사](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)에서 감사 단계와 정책을 설명합니다.

[이전 · Kubernetes 서비스 계정 신원]({{ '/ko/wiki/kubernetes-service-account-evidence/' | relative_url }}) · [다음 · Kubernetes API 감사 로그]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }}) · [관련 · Pod Security Admission]({{ '/ko/wiki/kubernetes-pod-security-admission-evidence/' | relative_url }})
