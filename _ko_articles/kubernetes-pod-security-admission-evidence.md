---
title: "Kubernetes Pod Security Admission 조사 · 템플릿에서 실행까지"
description: "경고와 감사 주석, Pod 생성 허용, 실제 실행을 구분하고 가상 증거 여덟 건을 분류합니다."
category: cloud
tags: [Kubernetes, Pod Security Admission, Audit Logs, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/kubernetes-pod-security-admission-evidence/
---

Deployment가 정상적으로 저장됐어도 컨트롤러가 Pod를 하나도 만들지 못할 수 있습니다. Deployment 템플릿 요청, 실제 Pod 생성 요청, 실행 중인 워크로드에서 확인한 기록을 따로 보면 원인을 좁힐 수 있습니다. 이 장은 Kubernetes의 내장 **Pod Security Admission(PSA)**과 그 감사 증거를 다룹니다.

## 1. PSA는 어느 단계에서 동작하나요?

**Pod**는 Kubernetes가 노드에 배치하는 단위입니다. **네임스페이스**는 Pod나 Deployment 등의 이름과 정책 범위를 정합니다. **어드미션(admission)**은 API 요청이 인증·인가를 거친 뒤 저장되기 전에 검사하는 단계입니다. PSA는 Pod에 선언된 보안 설정을 **Pod Security Standards(PSS)**와 비교합니다. RBAC는 누가 요청할 수 있는지 결정합니다. NetworkPolicy와 런타임 기록은 각각 허용된 네트워크 통신과 실제로 관찰한 동작을 보여 줍니다.

표준은 세 가지 수준을 정의합니다. **Privileged**에는 PSS 제한이 없습니다. **Baseline**은 일반 워크로드를 지원하면서 자주 발생하는 권한 상승 경로를 제한합니다. **Restricted**는 보호 요건을 더합니다. 예를 들어 최근 Restricted 정책을 적용한 Linux 컨테이너에는 `allowPrivilegeEscalation: false`와 루트 이외 사용자로 실행한다는 설정이 필요합니다. 이는 일부 예시이며 전체 조건은 정책 버전, 필드와 운영체제에 따라 달라집니다.

| PSA 모드 | 위반 시 처리 |
| --- | --- |
| `enforce` | 강제 적용 평가를 받은 Pod 요청이 정책을 위반하면 거부합니다. 워크로드 템플릿은 별도로 평가합니다. |
| `audit` | 감사 이벤트가 기록될 때 위반 주석을 추가합니다. 이 모드 자체는 요청을 계속 진행시킵니다. |
| `warn` | 요청자에게 경고를 반환합니다. 이 모드 자체는 요청을 계속 진행시킵니다. |

네임스페이스 라벨은 `pod-security.kubernetes.io/<mode>`와 선택 사항인 `pod-security.kubernetes.io/<mode>-version`을 사용합니다. 모드마다 수준과 버전을 다르게 둘 수 있습니다. 단계적으로 도입할 때 사용할 버전을 고정하면 같은 기준에서 비교할 수 있습니다. 라벨이 없는 네임스페이스에는 클러스터 기본값이 적용될 수 있습니다. 라벨만 보고 판단하기 전에 설정과 예외를 확인하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-pod-security-admission-evidence-ko.svg' | relative_url }}" alt="Deployment 템플릿은 경고와 감사 주석의 대상이 될 수 있습니다. 컨트롤러는 별도의 Pod 요청을 보냅니다. 강제 정책은 이 요청을 거부할 수 있습니다. 생성된 Pod는 이후 스케줄링과 실행 단계를 거칩니다.">
  <figcaption>Deployment와 Pod는 각각 수집하세요. 호출자와 감사 ID가 서로 다릅니다.</figcaption>
</figure>

## 2. 정상적인 단계별 적용을 따라가세요

가상의 `reports-lab`에서 팀이 Baseline을 강제하고 Restricted는 감사와 경고에 적용합니다. 세 모드는 지원되는 동일 정책 버전으로 고정했습니다. `month-end` Deployment의 Linux Pod 템플릿에는 Baseline을 충족하지만 루트 이외 실행을 요구하는 설정이 없습니다. 배포자는 Restricted 경고를 받지만 Deployment는 저장될 수 있습니다. 이후 컨트롤러가 Pod를 요청합니다. Pod가 Baseline을 충족하므로 PSA가 진행을 허용할 수 있고, 감사에는 Restricted 위반이 남을 수 있습니다. Pod 생성은 다른 제어도 통과해야 합니다. 이후 UID, 스케줄링, 컨테이너 상태를 별도로 확인하세요.

팀이 템플릿을 고치기 전에 강제 수준을 Restricted로 바꿨다고 가정해 보세요. PSA가 Deployment를 계속 수락할 수 있지만 컨트롤러가 다시 만들려는 Pod는 거부될 수 있습니다. 네임스페이스의 강제 적용 라벨을 바꾸면 기존 Pod에 대한 경고가 반환될 수 있습니다. 이 변경만으로 기존 Pod가 퇴거되지는 않습니다. 다음 생성 시도를 확인하고 현재 실행 중인 Pod는 따로 검토하세요.

## 3. 계층에 맞는 증거를 읽으세요

| 증거 | 확인할 내용 |
| --- | --- |
| 네임스페이스 설정과 변경 이력 | 당시 모드별 라벨, 정책 버전, 서버 기본값과 예외를 봅니다. 현재 라벨 화면은 지금 시점의 관측입니다. |
| API 감사 이벤트 | 클러스터, 감사 ID, 단계, 동작, 객체 참조, 요청자, 응답 코드, 주석을 봅니다. Pod 요청은 컨트롤러 신원일 수 있습니다. |
| CLI 경고 또는 API 상태 메시지 | 해당 요청의 실제 위반이나 거부 사유와 시각을 남깁니다. 인가 허용 뒤의 HTTP 403도 여러 원인이 있습니다. |
| 워크로드와 런타임 | Deployment·ReplicaSet의 소유자 참조, 컨트롤러 이벤트, Pod UID와 상태를 확인합니다. Pod가 없으면 컨트롤러의 생성 실패를 찾아보세요. |

API 감사 이벤트의 `pod-security.kubernetes.io/enforce-policy`는 평가에 사용된 강제 수준과 버전을 보여 줍니다. 주석이 있다는 사실만으로 거부를 확인할 수 없습니다. `pod-security.kubernetes.io/audit-violations`는 감사 정책 위반의 상세 내용입니다. `pod-security.kubernetes.io/exempt`는 사용자, 네임스페이스 또는 RuntimeClass 예외를 나타낼 수 있습니다. 예외에 해당하는 요청에서는 세 모드가 모두 생략됩니다. 컨트롤러 예외는 이를 통해 Pod 생성을 일으킬 수 있는 사용자 모두에게 영향을 줄 수 있으므로 예상 밖 예외는 플랫폼 운영자와 조사하세요. 이 주석은 API 감사 이벤트의 필드입니다. 워크로드 Event 객체는 별도 증거이며 보존 기간이 짧을 수 있습니다.

## 4. 수집·탐지·대응에 활용하세요

1. 클러스터, 네임스페이스, 워크로드, 정책 버전과 UTC 시간대를 정하세요. 라벨과 변경 이력을 확보합니다. 플러그인이 켜져 있는지 확인하고 제어 영역을 볼 권한이 없다면 운영자에게 기본값과 예외를 문의하세요.
2. 감사 정책과 백엔드가 관련 Pod·워크로드·네임스페이스 요청을 보존하는지 확인하세요. 완료 단계, 원래 응답 상태와 감사 주석을 확보합니다. 요청 본문 확보에는 Metadata보다 높은 감사 수준이 필요합니다. 승인 범위에서만 수집하고 민감한 본문은 보호하세요. 주석이 없으면 범위, 단계와 전달 누락도 확인합니다.
3. 정책 변경, 예상 밖 예외, 반복되는 거부를 배포 승인 기록과 대조하세요. 소유자 참조와 컨트롤러 상태로 Deployment에서 ReplicaSet과 Pod까지 찾고 해당 감사 기록을 연결합니다. Pod가 거부됐다면 거부 근거와 템플릿을 보존하세요. 수락됐다면 실제 상태와 런타임 기록을 확인합니다.
4. API 서버 메트릭을 수집하는 환경에서는 `pod_security_evaluations_total`, `pod_security_exemptions_total`, `pod_security_errors_total`의 평상시 수치를 파악하세요. 각각 평가·예외·오류를 집계합니다. 이 숫자로 특정 워크로드를 식별하거나 컨테이너 실행을 확인할 수 없습니다. 수정 후 정책을 충족하는 대조군을 확인하고 실제로 컨트롤러가 만든 Pod를 관찰하세요.

승인된 클러스터에서 다음 읽기 전용 명령을 사용하세요. `reports-lab`과 `month-end`를 대상 이름으로 바꾸세요. `kubectl`과 해당 네임스페이스, Deployment, ReplicaSet, Pod 및 이벤트를 읽을 권한이 필요합니다.

```bash
kubectl config current-context
kubectl get namespace reports-lab --show-labels
kubectl -n reports-lab describe deployment month-end
kubectl -n reports-lab get replicasets,pods
kubectl -n reports-lab events --types=Warning
```

승인된 폐기용 실습 네임스페이스에서는 Linux의 루트 이외 실행 요건만 다른 검토된 Pod 매니페스트 두 개를 비교하세요. 생성 권한이 있고 관련 어드미션 플러그인이 드라이런을 지원한다면 파일마다 `kubectl -n reports-lab create --dry-run=server -f pod-reviewed.yaml`로 검사할 수 있습니다. 파일명은 실제 실습 자료에 맞추세요. 적용 라벨과 클라이언트 응답, 감사가 켜진 경우 대응하는 감사 기록을 남기세요. 서버 드라이런에는 저장된 Pod가 없으므로 컨트롤러의 조정이나 노드 실행은 별도 확인이 필요합니다. 명령과 동작은 공식 문서로 검토했으며 실제 클러스터에서 실행하지 않았습니다.

## 5. 오프라인에서 가상 관측 여덟 건 분류하기

<a href="{{ '/assets/labs/kubernetes-pod-security-admission-evidence.py' | relative_url }}" download="kubernetes-pod-security-admission-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/kubernetes-pod-security-admission-evidence-cases.json' | relative_url }}" download="kubernetes-pod-security-admission-evidence-cases.json">가상 JSON 자료</a>를 같은 폴더에 저장하고 승인된 작업 공간에서 Python 3으로 실행하세요. 사례는 가상의 감사·클라이언트 기록을 정규화한 것입니다. `storedPodUid`와 `denialSource`는 별도 관측으로 얻은 보강 정보입니다. 실습은 로컬 파일만 읽고 Pod 매니페스트를 평가하지 않습니다.

```bash
python3 kubernetes-pod-security-admission-evidence.py kubernetes-pod-security-admission-evidence-cases.json
```

```text
template_warning: template_accepted_check_pod
pod_denied: psa_denied
audit_only: pod_stored_audit_violation
other_403: rejection_source_unconfirmed
exemption: exempt_request
server_dry_run: dry_run_no_persistence
pod_stored: pod_stored_check_runtime
partial_event: outcome_unobserved
```

파일을 열 수 없으면 파일 이름과 현재 폴더를 확인하세요. 분류가 예상과 다르면 Deployment인지 Pod인지, 완료 단계가 있는지, PSA를 거부 출처로 확인할 근거가 있는지부터 살펴보세요. Python은 이 가상 자료로 실행 검증했습니다.

## 6. 확인 문제와 완료 기준

- **Deployment가 201과 Restricted 경고를 반환했습니다. Pod가 수락됐나요?** 컨트롤러 상태와 별도 Pod 요청을 확인하세요.
- **Pod 요청에 enforce-policy 주석이 있고 403이 나왔습니다. PSA가 차단했나요?** 거부 원문이나 이를 뒷받침하는 자료를 찾으세요. 주석은 평가할 때 적용한 정책을 알려 줍니다.
- **Pod 하나가 만들어졌습니다. 컨테이너가 실행됐나요?** 스케줄링, 컨테이너 상태나 런타임 기록을 확인하세요.

여덟 결과가 일치하고 `template_warning`, `other_403`, `pod_stored`에 어떤 증거가 더 필요한지 말할 수 있으면 완료입니다.

## 공식 참고자료

2026-11-22 검토. PSA는 Kubernetes v1.25부터 안정 기능입니다. v1.36 문서를 포함한 공식 자료로 동작을 검토했습니다. 실제 환경의 서버와 모드 정책 버전, 공급자 로그 가용성을 확인하세요.

- 모드, 워크로드 범위와 예외. [Kubernetes v1.36 · Pod Security Admission](https://v1-36.docs.kubernetes.io/docs/concepts/security/pod-security-admission/)
- 정책 수준, 운영체제와 버전에 따른 제한. [Kubernetes · Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- 네임스페이스 라벨 변경과 서버 드라이런. [Kubernetes · 네임스페이스 라벨로 Pod 보안 표준 적용](https://kubernetes.io/docs/tasks/configure-pod-container/enforce-standards-namespace-labels/)
- 감사 정책과 단계, PSA 주석 이름. [Kubernetes · 감사](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/) · [감사 주석](https://kubernetes.io/docs/reference/labels-annotations-taints/audit-annotations/)
- 워크로드 이벤트 명령과 옵션. [Kubernetes · kubectl events](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_events/)

[이전 학습 · Kubernetes 감사 증거]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }}) · [다음 학습 · Kubernetes NetworkPolicy 증거]({{ '/ko/wiki/kubernetes-network-policy-evidence/' | relative_url }})
