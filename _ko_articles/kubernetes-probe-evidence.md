---
title: "Kubernetes 프로브 조사 · 시작, 준비 상태, 활성 상태"
description: "kubelet의 검사부터 Pod 상태와 Service 엔드포인트까지 따라가며 트래픽 제외와 컨테이너 재시작을 구분합니다."
category: cloud
tags: [Kubernetes, Cloud Security, Kubernetes Probes, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/kubernetes-probe-evidence/
---

**학습 목표.** Pod는 `Running`인데 사용자는 오류를 겪고, 운영자는 재시작 흔적을 발견했습니다. 어느 Pod와 컨테이너에서 일어난 일인지, Service 트래픽에 어떤 영향이 있었는지, 재시작을 프로브와 연결하려면 어떤 증거가 필요한지 알아봅니다.

## 1. 프로브 세 가지는 서로 다른 질문에 답합니다

**Pod**는 Kubernetes가 노드에 배치하는 단위입니다. 한 Pod 안에 여러 **컨테이너**가 있을 수 있고 각각 별도의 실행 수명 주기를 가집니다. 노드의 **kubelet**이 설정된 **프로브**를 실행해 컨테이너를 검사합니다. **Service**는 클라이언트에게 고정된 접속 주소를 제공합니다. 선택자가 있는 Service의 백엔드는 컨트롤러가 **EndpointSlice**에 기록합니다. 트래픽을 전달하는 구성 요소는 여기에 기록된 상태를 사용해 백엔드를 고를 수 있습니다. **UID**는 Kubernetes 객체가 생성돼 살아 있는 한 시기를, 컨테이너 런타임 ID는 그 기간 안에서 컨테이너가 실행된 한 시기를 식별합니다.

| 프로브 | 판단할 질문 | 연속 실패가 기준에 도달하면 |
| --- | --- | --- |
| 시작 상태(startup) | 이 컨테이너의 초기화가 끝났나요? | kubelet이 해당 컨테이너를 종료합니다. 이후 동작은 적용되는 재시작 정책을 따릅니다. 이 프로브를 설정하면 처음 성공할 때까지 준비 상태와 활성 상태 검사가 대기합니다. |
| 준비 상태(readiness) | 이 컨테이너가 지금 요청을 받을 수 있나요? | kubelet이 해당 컨테이너를 준비되지 않은 상태로 표시합니다. Pod도 준비되지 않은 상태로 바뀌면서 Service의 일반 트래픽 대상에서 빠질 수 있습니다. 준비 상태 검사는 계속됩니다. |
| 활성 상태(liveness) | 이 컨테이너가 작업을 계속 진행할 수 있나요? | kubelet이 해당 컨테이너를 종료합니다. 재시작 여부는 적용되는 재시작 정책에 따라 결정됩니다. |

프로브는 HTTP 요청, TCP 연결, gRPC 상태 확인, 컨테이너 내부 명령 중 하나를 사용할 수 있습니다. TCP 검사가 성공했다면 포트가 연결을 받아들인 것입니다. HTTP 검사 결과는 그 시점에 설정된 경로로 받은 응답을 설명합니다. 확인하려는 상태에 맞는 검사를 선택하세요. 활성 상태 검사는 재시작으로 해결할 수 있는 문제에 초점을 맞춥니다. 준비 상태 검사에 서비스 제공에 필요한 의존성을 포함할 때는 검사 비용과 제한 시간을 정해 사용자 요청에 필요한 자원을 확보하세요.

`periodSeconds`는 검사 주기, `timeoutSeconds`는 개별 검사 제한 시간, `failureThreshold`는 연속 실패 기준입니다. `initialDelaySeconds`는 검사 시작까지의 지연입니다. 추가로 준비 상태는 `successThreshold`로 몇 번 연속 성공해야 하는지 설정할 수 있습니다. 시작 상태와 활성 상태의 이 값은 1이어야 합니다. 배포 리비전마다 값이 다를 수 있으니 조사할 때는 실제 Pod에 적용된 설정을 확인하세요. 여유 시간은 부하가 걸린 환경에서 측정한 초기화 시간에 맞춥니다. 주기와 실패 기준은 예상 시간을 잡는 데 쓰고, 실제 경과 시간은 스케줄링과 검사·종료 타이밍에 따라 달라질 수 있습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/kubernetes-probe-evidence-ko.svg' | relative_url }}" alt="시작 상태 프로브가 성공하면 준비 상태와 활성 상태 검사가 시작됩니다. 준비 상태는 Pod와 엔드포인트 상태에 반영됩니다. 시작 상태 또는 활성 상태의 연속 실패가 기준에 도달하면 컨테이너가 종료되고 재시작 정책이 적용됩니다." width="480" height="496">
  <figcaption>kubelet이 컨테이너를 검사합니다. 엔드포인트의 상태와 클라이언트가 경험한 결과는 서로 다른 지점에서 관측합니다.</figcaption>
</figure>

## 2. 정상 동작을 시간 순서로 읽기

선택자가 있는 가상의 Service `checkout`에 복제본 두 개가 있다고 가정해 보세요. 롤아웃 중 새 Pod에 일반 앱 컨테이너 `api`가 뜹니다. 18초에 시작 상태, 21초에 준비 상태 검사가 성공합니다. 새 복제본이 준비되기까지는 기존 복제본이 요청을 처리합니다. 이후 새 Pod의 조건이 `Ready=True`가 되고 해당 EndpointSlice에서 그 엔드포인트가 `ready: true`로 표시됩니다. 이 변경이 요청 경로에 반영된 뒤 새 연결이 새 복제본에 도달할 수 있습니다.

70초에 서비스에 필요한 의존 시스템이 느려집니다. 새 복제본은 준비 상태 검사에서 실패 기준에 도달합니다. 컨테이너는 `ready: false`, Pod는 `Ready=False`가 됩니다. 변경이 전파되면 Service의 일반적인 새 트래픽은 이 엔드포인트를 선택하지 않습니다. 컨테이너 ID와 재시작 횟수는 그대로입니다. 의존 시스템이 회복되면 같은 컨테이너가 다시 준비 상태가 됩니다. 별개의 사례로 프로세스가 교착에 빠져 활성 상태 실패 기준에 도달하면 kubelet이 해당 컨테이너를 종료합니다. 재시작 정책이 `Always`라면 같은 Pod UID 안에 새 컨테이너 ID가 생기고 재시작 횟수가 증가할 수 있습니다.

Pod 단계 `Running`은 범위가 넓습니다. `status.containerStatuses[]`의 `name`, `started`, `ready`, `restartCount`, `containerID`, `lastState`를 Pod의 `ContainersReady`와 `Ready` 조건과 함께 보세요. 사용자 정의 준비 상태 게이트(`readinessGate`) 때문에 모든 컨테이너가 준비돼도 Pod가 준비되지 않을 수 있습니다. 실제 Service와 연결된 EndpointSlice도 열어 보세요. 예를 들어 `publishNotReadyAddresses: true`가 설정되면 Pod가 준비되지 않았어도 엔드포인트를 준비된 상태로 게시합니다. 일반적인 Service에서 종료 중인 엔드포인트의 `ready`는 보통 `false`입니다. `serving`은 계속 서비스할 수 있는지를, `terminating`은 종료 중인지를 보여 줍니다. 사용 가능한 엔드포인트가 모두 종료 중이면 Service 프록시가 그중 계속 서비스할 수 있는 대상을 선택할 수 있습니다. 컨트롤러와 프록시는 서로 다른 시점에 상태를 반영하므로 실제 영향이 중요할 때는 해당 경로의 클라이언트 관측과 대조하세요.

## 3. 장애와 오용의 원리

| 상황 | 영향 | 대조할 자료 |
| --- | --- | --- |
| 활성 상태 검사에 공용 의존성이 들어감 | 상위 서비스가 느려지면 회복할 수 있는 프로세스가 여러 곳에서 재시작돼 장애가 커질 수 있습니다. | 실제 프로브 정의, 의존성의 지연 시점, 여러 Pod의 이전 컨테이너 종료 정보 |
| 단순한 준비 상태 검사가 계속 통과함 | 포트가 열려 있거나 단순한 경로가 성공해도 실제 요청은 실패할 수 있습니다. | 같은 목적지 워크로드와 리비전에 대한 준비 상태 및 새 요청의 오류 |
| 예상 밖의 배포 변경 이후 상태 검사 결과가 달라짐 | 프로브, 이미지, Service 설정의 변경은 트래픽 제외나 재시작으로 이어질 수 있습니다. 예정된 롤아웃이나 구성 실수도 같은 양상을 보입니다. | 변경 전후 설정, 승인된 배포 주체, API 감사 결과, 새로 관측한 Pod UID |
| 재시작과 검사 실패가 가까운 시점에 관측됨 | 메모리 부족 종료나 프로세스 자체 종료도 검사 실패와 겹칠 수 있습니다. 이벤트 사유 한 줄이나 높은 재시작 횟수만으로 원인을 정할 수 없습니다. | 이전 런타임 ID, 종료 사유와 시각, 그 실행 인스턴스에 해당하는 kubelet 기록 |

## 4. 블루팀의 수집, 탐지, 대응

1. **시간 범위와 대상을 고정합니다.** UTC 기준으로 클러스터, 네임스페이스, Pod UID, 노드, 리비전, 컨테이너 이름과 런타임 ID를 기록합니다. 현재 상태와 이전 종료 정보를 일찍 보존하세요. 같은 이름의 Pod가 교체됐을 수 있습니다. 여러 복제본의 컨테이너 이름이 같다면 클러스터, 네임스페이스, Pod UID, 컨테이너, 실행 인스턴스의 시간 범위를 묶어 비교합니다.
2. **계층마다 무슨 일이 있었는지 확인합니다.** Pod 설정과 상태, Service 설정, 레이블로 연결된 EndpointSlice 전체를 확인합니다. 컨트롤러가 관리하는 Pod 엔드포인트에 `targetRef.uid`가 있으면 대상 Pod와 비교하세요. 수집 시각과 각 시스템 시계 오차를 고려해 사건 순서를 정합니다. 사용자가 겪은 영향은 클라이언트 오류와 게이트웨이 또는 백엔드 기록으로 확인합니다.
3. **종료에 가까운 증거를 찾습니다.** kubelet 이벤트 원본과 확보할 수 있는 워크로드·노드·런타임 기록을 보존합니다. 조치 시점과 종료 시점을 이전 인스턴스에 맞춰 대조하세요. Kubernetes 이벤트는 기록이 보장되지 않고 보존 기간이 짧으며 여러 번의 관측이 하나로 집계될 수 있습니다. 이벤트가 없으면 증거 공백으로 남기세요. `Unhealthy` 사유가 있으면 수집된 세부 내용을 읽습니다. 정책과 보존 설정이 갖춰진 API 감사 로그는 누가 객체 변경을 요청했는지 조사하는 데 쓰고, 실제 실행 중 어떤 일이 일어났는지는 런타임 기록으로 확인합니다.
4. **탐지를 검증하고 대응합니다.** 재시작 탐지는 같은 Pod UID와 컨테이너에서 횟수 증가와 런타임 ID 변경을 비교한 뒤 종료 사유와 프로브 기록을 덧붙입니다. 트래픽 탐지는 준비되지 않은 선택 대상 엔드포인트와 사용자 오류를 함께 보며, 정상 롤아웃의 초기화 시간을 고려해 탐지 구간을 잡습니다. 정상 시작, 준비 상태만 실패한 경우, 활성 상태 실패, 메모리 부족 종료로 각각 확인하세요. 장애 대응 중 가능하면 Pod를 교체하기 전에 증거를 보존합니다. 확인된 의존성, 롤아웃, 자원 문제는 담당자에게 전달하고 예상 밖의 변경은 승인된 설정과 감사 기록을 대조한 뒤 의도를 판단합니다.

아래 조회 명령은 승인된 네임스페이스에서 사용하세요. 호환되는 `kubectl`과 Pod·Service 조회, EndpointSlice·이벤트 목록 조회, Pod 로그 하위 리소스 읽기 권한이 필요합니다. 예시 이름을 실제 승인된 대상에 맞게 바꾸고 먼저 접속 컨텍스트를 확인하세요.

```sh
kubectl config current-context
kubectl -n training get pod checkout-0 -o json
kubectl -n training get svc checkout -o json
kubectl -n training get endpointslices \
  -l kubernetes.io/service-name=checkout -o json
kubectl -n training events --for pod/checkout-0 -o json
kubectl -n training logs checkout-0 -c api --previous --timestamps
```

각 출력과 함께 수집 시각을 남기세요. 이름으로 필터링하면 이전 UID를 가리키는 이벤트도 포함될 수 있습니다. 이벤트 형식에 따라 `involvedObject.uid` 또는 `regarding.uid`를 확인하고, 있으면 컨테이너 필드도 비교하세요. `--previous`는 지정한 컨테이너에서 직전에 끝난 실행의 로그를 요청하며 해당 로그가 남아 있어야 합니다. 그보다 오래된 실행이나 교체된 Pod의 자료는 별도로 보존된 중앙 로그에서 확인합니다. `Forbidden`, 로그 누락, 수집 공백은 관측한 그대로 표시하고 민감한 로그는 승인된 사고 대응 저장소에 보관합니다.

## 5. 승인된 오프라인 검증 실습

<a href="{{ '/assets/labs/kubernetes-probe-evidence.py' | relative_url }}" download>Python 3 판정 도구</a>와 <a href="{{ '/assets/labs/kubernetes-probe-evidence-cases.json' | relative_url }}" download>가상 사례 JSON</a>을 소유한 디렉터리 한 곳에 내려받으세요. 도구는 로컬 파일만 읽으며 별도 패키지, 네트워크, 클러스터 자격 증명 없이 실행됩니다. 사례마다 하나의 시계와 Service를 가정하고 관측값을 공통 형식으로 정리했습니다. `kubelet-probe-stop`은 노드의 종료 조치를 실행 인스턴스와 시점까지 확인했다는 뜻으로 사용하는 실습용 필드입니다. 실제 조사에서는 이를 확인하기 위해 서로 다른 이벤트 형식과 노드 로그를 대조할 수 있습니다.

각 사례에서 실행 인스턴스가 어떻게 바뀌었는지, 재시작 근거는 무엇인지, 엔드포인트에 어떤 상태가 기록됐는지 먼저 예상해 보세요.

```sh
python3 kubernetes-probe-evidence.py
```

| 사례 | 설명해야 할 증거 |
| --- | --- |
| A | 초기화 중이던 컨테이너가 같은 인스턴스에서 준비 상태가 됩니다. |
| B | 준비 상태 검사 실패로 엔드포인트는 준비되지 않은 상태가 되고 컨테이너 ID는 그대로입니다. |
| C | 활성 상태 검사로 인한 종료 조치가 이전 인스턴스와 일치합니다. 새 인스턴스는 이미 준비됐습니다. |
| D | 시작 상태 검사 실패 후 첫 인스턴스가 종료됩니다. 새 인스턴스는 아직 준비 중입니다. |
| E | 이전 인스턴스에 `OOMKilled`가 기록되고 별도로 준비 상태 검사도 실패했습니다. |
| F | 컨테이너는 준비됐지만 사용자 정의 게이트 때문에 Pod와 엔드포인트는 준비되지 않았습니다. |
| G | 이 Service에서는 Pod가 준비되지 않았어도 엔드포인트가 준비된 상태로 표시됩니다. |
| H | 같은 Pod 이름이 재사용됐습니다. 보존된 종료 관측과 엔드포인트 모두 이전 UID를 가리킵니다. |
| I | 엔드포인트는 아직 서비스 가능하며 종료 중입니다. 트래픽을 해석할 때 두 조건을 함께 기록하세요. |
| J | 재시작은 보입니다. 한 종료 기록은 인스턴스 ID가 다르고 다른 하나는 종료 시각보다 늦습니다. |

원본은 `10/10 probe evidence cases matched.`를 출력합니다. 음성 대조로 JSON을 복사해 C 사례 종료 관측의 `instance_id`를 `runtime://other`로 바꿔 보세요. 복사한 파일의 이름을 명령 인수로 주면 C는 `restart-cause-open`으로 바뀌고 9건이 일치하며 종료 코드는 1이 됩니다. 원본이 열리지 않으면 파일명 두 개, Python 3, JSON 형식을 확인하세요. 복사본까지 통과하면 C 사례의 이벤트 필드를 수정했고 복사본 이름을 명령에 전달했는지 확인하세요.

가상 사례 원본과 음성 대조는 클라우드 Python 환경에서 실행했습니다. Kubernetes 동작과 수집 명령은 공식 문서를 검토했습니다. 실습은 비교 방법과 증거 공백을 보여 주며 실제 클러스터와 트래픽 경로에서의 실행은 검증 범위에 포함되지 않습니다.

## 6. 확인 문제와 해설

1. **Pod가 Running이고 컨테이너가 두 개입니다. API 컨테이너가 준비되지 않았을 때도 트래픽이 올 수 있나요?** Pod Ready, Service 설정, 엔드포인트 조건부터 확인하세요. 일반적인 선택에서는 준비되지 않은 대상을 제외할 수 있습니다. 준비되지 않은 주소의 게시 설정, 상태 반영 지연, 기존 연결에 따라 클라이언트 관측은 달라질 수 있습니다.
2. **재시작 횟수가 증가했고 예전 kubelet 이벤트에 활성 상태 실패가 보입니다. 무엇이 원인을 뒷받침하나요?** 클러스터, Pod UID, 컨테이너 이름을 맞춘 뒤 종료 조치를 종료된 런타임 인스턴스와 종료 시간대에 연결하세요. 프로세스 자체 종료나 메모리 부족 종료 기록도 함께 확인합니다.
3. **준비 상태 게이트의 영향과 프로브 실패를 어떻게 구분하나요?** 컨테이너 준비 상태를 Pod Ready와 비교하고 `spec.readinessGates`와 해당 조건을 확인합니다. 조건이 없거나 거짓이면 모든 컨테이너가 준비됐어도 Pod는 준비되지 않은 상태입니다.
4. **엔드포인트가 준비됐으면 거래가 성공했다는 뜻인가요?** 관측 시점에 엔드포인트가 선택 가능한 상태로 게시됐다는 뜻입니다. 거래 결과는 클라이언트 기록이나 요청 추적으로 확인하세요.

**완료 기준.** 세 프로브가 각각 어떤 판단에 쓰이는지 설명해 보세요. B·C·E·H·J의 결정적 필드와 추가로 확인할 사항을 하나씩 짚고, 원본과 수정본의 실습 결과를 재현하면 됩니다.

## 공식 참고자료

2026-11-26 기준, 업스트림 Kubernetes v1.37 문서를 검토했습니다. 관리형 서비스의 수집 기능이나 기능 게이트, 트래픽 구현 차이는 실제 배포 버전의 문서에서 확인하세요.

- 프로브 종류와 동작, 검사 기준. [Kubernetes Probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/) 및 [프로브 설정 가이드](https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/)
- Pod 단계와 조건, 준비 상태 게이트와 재시작 정책. [Kubernetes Pod Lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/)
- Service 엔드포인트 조건과 종료 시 동작. [Kubernetes EndpointSlices](https://kubernetes.io/docs/concepts/services-networking/endpoint-slices/)
- 이벤트 보존과 자료 수집 명령. [Kubernetes Event API](https://kubernetes.io/docs/reference/kubernetes-api/core/event-v1/), [kubectl events](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_events/) 및 [kubectl logs](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_logs/)

[이전 · Kubernetes NetworkPolicy 조사]({{ '/ko/wiki/kubernetes-network-policy-evidence/' | relative_url }}) · [다음 · Linux cgroup 메모리 조사]({{ '/ko/wiki/linux-cgroup-memory-evidence/' | relative_url }}) · [관련 · Kubernetes API 감사 로그]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }})

## 할당량과 배치 증거 확인하기

배포가 멈췄다면 [Kubernetes 리소스 할당량]({{ '/ko/wiki/kubernetes-quota-evidence/' | relative_url }})에서 정책에 따른 생성 거부와 노드 배치 실패를 구분해 보세요.
