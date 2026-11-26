---
title: "Kubernetes 리소스 할당량 · 승인 거부와 스케줄링 실패 추적하기"
description: "네임스페이스 할당량, 컨테이너별 제약, 노드 배치 실패를 API·컨트롤러·Pod 증거로 구분합니다."
category: cloud
tags: [Kubernetes, ResourceQuota, LimitRange, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/kubernetes-quota-evidence/
---

Deployment가 있고 이전 복제본도 계속 트래픽을 받는데, 새 Pod가 한 개도 나타나지 않는다고 가정해 봅시다. Deployment 요청과 컨트롤러가 보내는 Pod 생성 요청은 별도의 API 작업입니다. 어느 단계에서 처음 실패했는지 알면 네임스페이스 정책, 스케줄러의 배치 조건, 이후 단계 중 어디를 살펴봐야 할지 좁힐 수 있습니다. 이 장은 관련 어드미션 컨트롤러가 활성화된 클러스터의 일반적인 Deployment 관리 Pod를 다룹니다.

## 1. 정책, 배치, 실행에서 무엇을 확인하나요?

**네임스페이스**는 객체와 정책의 적용 범위를 나눕니다. 컨테이너의 CPU **요청량(request)**은 스케줄러가 Pod를 노드에 배치할 수 있는지 계산할 때 사용합니다. **제한량(limit)**은 지원되는 리소스에 적용하는 실행 중 상한입니다. CPU는 밀리코어로 표현할 수 있습니다. `250m`은 CPU 0.25개에 해당하고 `1000m`은 CPU 1개입니다. ResourceQuota는 요청량과 제한량을 각각 집계할 수 있습니다. 모니터링에서 측정한 현재 사용량과도 구분하세요.

| 기능 | 적용 범위와 판단 | 확인할 증거 |
| --- | --- | --- |
| ResourceQuota | 네임스페이스 안의 합계를 제한하며 필요하면 일부 객체에만 적용. 리소스 요청량, 제한량, 종료되지 않은 Pod 개수 등을 제한할 수 있음 | 거부 응답의 할당량 이름과 리소스. 당시 `status.used` 및 `status.hard`와 요청으로 늘어나는 양을 비교 |
| LimitRange | Container, Pod 같은 대상 유형별 기본값과 객체별 제약. 최솟값, 최댓값, 제한량과 요청량의 비율을 지정할 수 있음 | 제출한 리소스, 승인 단계에서 적용된 기본값, 구체적인 제약 |
| 스케줄러 | 생성된 Pod의 요청과 배치 조건을 만족하는 노드를 찾음 | Pod UID, 스케줄링 조건, 스케줄러 이벤트 메시지. 할당량이 남아도 맞는 노드가 없을 수 있음 |
| 실행 단계 | 노드가 정해진 뒤 kubelet과 런타임이 Pod를 실행·관리 | `OOMKilled` 또는 준비 상태 검사 실패 등 컨테이너 상태와 이벤트. 노드와 런타임 기록을 함께 확인 |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-quota-evidence-ko.svg' | relative_url }}" alt="Deployment가 생성되면 컨트롤러가 별도 Pod 생성을 요청합니다. 승인 거부는 API 응답이나 컨트롤러 이벤트에서 확인하고, Pod가 저장됐다면 스케줄링과 실행 단계를 각각 조사합니다." style="max-width: 100%; height: auto;">
  <figcaption>그림 1. Deployment 요청이 성공해도 하위 Pod 생성 요청은 따로 확인해야 합니다.</figcaption>
</figure>

## 2. 정상적인 배포를 따라간 뒤 수치를 바꿔 보세요

가상의 네임스페이스에서 `requests.cpu` 한도가 `2000m`이고 현재 집계량은 `1500m`입니다. Pod 템플릿에는 컨테이너 한 개만 있고 초기화 컨테이너나 별도 오버헤드는 없습니다. CPU 요청량은 `250m`, 제한량은 `500m`입니다. 적용되는 LimitRange와 다른 조건도 만족한다고 가정합니다. Deployment의 ReplicaSet이 Pod 한 개의 생성을 요청합니다. `1500m + 250m = 1750m`이므로 할당량 검사에서 허용될 수 있습니다. API는 별도의 UID가 있는 Pod를 생성합니다. 요청을 수용할 노드가 있어야 스케줄러가 배치할 수 있으며, 이후 kubelet이 컨테이너를 시작하고 준비 상태를 보고합니다.

이제 CPU 요청량을 `750m`, 제한량을 `1000m`으로 바꿉니다. 가상 LimitRange는 여전히 만족합니다. 기존 집계량이 `1500m`이라면 예상 합계는 `2250m`입니다. 할당량 검사에서 이 Pod 요청을 거부하고, ReplicaSet에 `FailedCreate` 이벤트가 생길 수 있습니다. 이전 Deployment는 그대로 저장되어 있고 기존 복제본도 동작할 수 있습니다. 롤링 업데이트 중 필요한 양을 계산할 때는 기존 복제본과 일시적으로 더 생성할 복제본을 함께 고려하세요. 다른 Pod의 생성이나 종료로 현재 값은 바뀔 수 있으므로 가능한 경우 최초 거부 응답에 포함된 값을 확보하세요.

## 3. 증거로 확인할 수 있는 첫 실패를 찾으세요

- **어떤 객체를 누가 요청했는지 봅니다.** 배포 서비스나 운영자의 Deployment 생성과 컨트롤러의 Pod 생성은 감사 ID가 다릅니다. 네임스페이스, 워크로드, 컨트롤러의 소유자 참조, 확인 가능한 Pod 이름이나 UID, 시각을 연결하세요. 생성이 거부된 Pod에는 UID가 없을 수 있습니다. ReplicaSet과 거부된 요청부터 추적하세요.
- **자세한 실패 사유를 읽습니다.** 할당량 초과와 LimitRange 위반은 모두 HTTP `403`일 수 있습니다. 인가 정책이나 Pod Security, 웹훅도 요청을 거부할 수 있습니다. 할당량 이름과 `requested`, `used`, `limited`가 담긴 응답은 초과 여부를 설명합니다. 필수 리소스 요청량이 누락됐다는 응답은 사양과 기본값 적용을 확인해야 하는 경우입니다. `FailedCreate`는 컨트롤러가 생성에 실패한 사실을 보여 주며 원인은 상세 메시지에서 확인합니다.
- **해당 시도의 Pod가 존재하는지 확인합니다.** 저장된 Pod의 UID와 `PodScheduled=False` 조건 및 대응되는 스케줄러 이벤트가 있다면 배치 단계에 도달한 것입니다. `Pending`만으로 원인을 좁히기는 어렵습니다. `FailedScheduling`의 상세 메시지에서도 CPU 부족, 배치 조건 불충족, 여러 제약의 조합을 구분하세요.
- **서버 측 사전 검증의 범위를 확인합니다.** 서버 측 dry-run은 객체를 저장하지 않고 관련 승인 검사를 거칠 수 있습니다. 성공해도 Pod를 생성하거나 후속 컨트롤러를 실행하지 않으며, 다음 요청을 위해 할당량을 예약하지 않습니다.

승인 없이 할당량을 늘리거나 공유 네임스페이스의 예산을 과도하게 차지하는 것이 오용의 예입니다. 부정확한 요청량 설정, 정상적인 트래픽 증가나 롤링 업데이트도 가용성에 같은 영향을 줄 수 있습니다. 오류 이벤트만으로 의도를 판단하기 어렵습니다. 할당량을 변경할 수 있는 주체를 제한하고 변경의 출처를 확인하세요. 할당량을 줄여도 기존 Pod가 자동으로 제거되지는 않습니다. 실행 중인 Pod가 남은 채 다음 생성 요청만 거부될 수 있습니다.

## 4. 블루팀 수집·탐지·대응

승인된 클러스터에서 Deployment와 ReplicaSet의 상태, 소유 관계, 세대 번호와 UTC 시각을 확보하세요. 이벤트는 보존 기간과 집계 방식이 환경마다 다르므로 초기에 확보합니다. 기존 Pod와 이름을 재사용한 새 Pod는 UID로 구분할 수 있습니다. 다음 명령은 읽기 전용이며 `kubectl`, kubeconfig, 대상 네임스페이스의 적절한 `get`·`list` 권한이 필요합니다. 이름은 승인 범위의 실제 객체로 바꿔 사용하세요.

```bash
kubectl -n team-a get resourcequota,limitrange -o yaml
kubectl -n team-a describe rs reports-6cf7c79c4b
kubectl -n team-a get events --sort-by=.metadata.creationTimestamp
kubectl -n team-a describe pod reports-6cf7c79c4b-abcde
```

마지막 명령은 Pod가 존재할 때 사용합니다. 컨트롤 플레인에서는 완료된 Pod 요청의 시각, 요청자, 동작, 리소스, 네임스페이스, 감사 ID, 응답 코드와 내보낸 실패 사유를 수집합니다. 해당 요청과 단계를 포함하는 감사 정책 및 수집이 필요합니다. 본문 가시성은 감사 수준과 공급자 내보내기 설정에 따릅니다. 필요한 필드와 보존 범위를 선택해 불필요한 민감 정보 수집을 줄이세요. ResourceQuota와 LimitRange 변경이 성공한 기록도 확인합니다.

네임스페이스와 컨트롤러별로 거부된 고유 생성 요청을 세고 배포 진행률과 비교하세요. 감사 ID는 한 API 요청의 여러 단계를 연결합니다. 같은 배포의 모든 재시도를 하나로 묶는 값은 아닙니다. 이벤트 집계의 횟수와 감사 요청 수는 단위가 다릅니다. 하드 한도를 바꾸기 전에 요청량이 과하게 늘었는지, 롤링 업데이트가 겹쳤는지 확인하세요. 할당량이나 템플릿이 예상 밖으로 바뀌었다면 전후 설정과 변경 주체를 보존합니다. 필요한 경우 승인된 배포 절차로 되돌리고, 의도한 Pod의 생성·배치·준비를 확인해 복구를 검증하세요. 감사 기록이 없다면 수집 공백도 고려합니다.

## 5. 승인된 오프라인 실습

<a href="{{ '/assets/labs/kubernetes-quota-evidence.py' | relative_url }}" download>Python 판정 도구</a>와 <a href="{{ '/assets/labs/kubernetes-quota-evidence-cases.json' | relative_url }}" download>가상 관측 10건</a>을 같은 디렉터리에 저장하세요. 소유하거나 사용을 승인받은 환경에서 Python 3으로 실행합니다. Kubernetes에는 접속하지 않습니다. JSON에는 조사에 필요한 정규화된 사실이 담겨 있습니다. 거부 유형은 원래 응답의 상세 정보를 보고 확인했다고 가정하며, 실제 로그를 직접 파싱하지 않습니다.

```bash
python3 kubernetes-quota-evidence.py
```

| 비교할 사례 | 기대 판정 |
| --- | --- |
| CPU 할당량과 Pod 개수 할당량 | 모두 원인이 확인된 할당량 거부. 계산 단위는 다름 |
| 요청량 누락과 컨테이너별 LimitRange 위반 | 둘 다 `403`이어도 서로 다른 승인 거부 이유 |
| 배치되지 않은 기존 Pod와 `OOMKilled`가 기록된 기존 Pod | 각각 스케줄링과 실행 단계 |
| 원인 불명의 `403`, dry-run 성공, Deployment 생성만 확인 | 각각 원인 미확정, 저장 없는 평가, 하위 결과 미확정 |
| 거부 메시지와 제시된 수치가 맞지 않는 사례 | 거부 기록은 보존하고 제시된 수치로는 초과를 설명할 수 없다고 표시 |

판정 도구는 밀리코어 또는 개수로 미리 단위를 맞춘 정수만 계산합니다. 기대 출력은 `10/10 evidence cases matched.`입니다. 필드나 JSON 오류가 난다면 두 파일이 같은 버전인지, 같은 디렉터리에 있는지 확인하세요. 편집 후 판정이 다르면 기대값을 바꾸기 전에 응답, 거부 사유, 기존 Pod와의 연결을 점검하세요. 대조 시험으로 A의 `requested`를 `750`에서 `500`으로 바꾸고 기대 판정은 그대로 두세요. 합계가 한도와 정확히 같으면 초과를 뒷받침하지 못하므로 모순이 보고돼야 합니다. API·스케줄러·로그 예시는 업스트림 문서로 검토했으며, 실행 검증은 가상 입력을 사용한 오프라인 도구에 해당합니다.

## 6. 확인 문제와 완료 기준

1. **Deployment는 있지만 컨트롤러의 Pod 생성이 `403`입니다. 무엇으로 이유를 확인하나요?** 완료된 응답의 상세 정보와 당시 적용된 정책을 봅니다. 별개 요청이 인가됐다는 기록만으로는 이유를 알 수 없습니다.
2. **Pod UID가 있고 `Insufficient cpu` 이벤트가 있습니다. 즉시 막은 원인이 네임스페이스 할당량인가요?** 이미 만들어진 Pod에 대한 배치 실패입니다. 후보 노드의 요청량과 배치 제약을 확인하세요.
3. **측정된 CPU 사용량은 낮은데 `requests.cpu` 할당량은 왜 꽉 찼나요?** 할당량은 적용 대상 객체에 선언된 요청량을 집계합니다. 측정 사용량이 낮아도 요청량은 그대로일 수 있습니다.

**완료 기준.** 열 가지 사례와 대조 시험을 재현하고, Pod 거부 한 건의 요청 주체와 단계, 아직 필요한 증거를 설명하세요. 요청 식별은 [Kubernetes API 감사 로그]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }})로, Pod가 시작된 뒤의 상태는 [Kubernetes 프로브]({{ '/ko/wiki/kubernetes-probe-evidence/' | relative_url }})로 이어집니다.

## 공식 참고자료

2026-11-26에 검토했습니다. 정책 정의는 Kubernetes v1.36 문서 스냅샷을 기준으로 하고, 나머지 업스트림 자료는 관련 API와 실행 개념을 다룹니다. 실제 클러스터의 버전과 활성화한 어드미션 플러그인을 확인하세요.

- [ResourceQuota v1.36](https://v1-36.docs.kubernetes.io/docs/concepts/policy/resource-quotas/)와 [LimitRange v1.36](https://v1-36.docs.kubernetes.io/docs/concepts/policy/limit-range/)
- [어드미션 컨트롤러](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)와 [API dry-run 및 인가](https://kubernetes.io/docs/reference/using-api/api-concepts/#dry-run)
- [컨테이너 리소스 관리](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)와 [실행 중인 Pod 디버깅](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [감사 단계와 정책](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
