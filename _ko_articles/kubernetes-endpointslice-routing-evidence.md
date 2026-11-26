---
title: "Kubernetes EndpointSlice 증거 · Service 백엔드와 포트 확인하기"
description: "Service 포트가 모든 EndpointSlice의 주소·포트에 어떻게 연결되는지 확인하고, 백엔드 신원과 노드별 차이를 가상 사례 여섯 가지로 검증합니다."
category: cloud
tags: [Kubernetes, EndpointSlice, Cloud Security, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/kubernetes-endpointslice-routing-evidence/
---

**학습 순서** · [Pod 준비 상태와 프로브]({{ '/ko/wiki/kubernetes-probe-evidence/' | relative_url }}) → Service 백엔드 증거 → [NetworkPolicy와 패킷 전달]({{ '/ko/wiki/kubernetes-network-policy-evidence/' | relative_url }}).

## 1. 고정된 Service 주소와 바뀌는 백엔드

**Service**는 Pod가 시작되거나 다른 노드로 옮겨지거나 종료되어도 애플리케이션에 일정한 주소로 접근할 수 있게 합니다. **EndpointSlice**는 그 Service의 백엔드 중 일부를 기록합니다. 백엔드는 요청이 향할 실제 주소와 포트입니다. **컨트롤 플레인**은 Kubernetes API로 이 객체들을 공개합니다. kube-proxy 같은 **Service 프록시**는 객체를 관찰해 실제 트래픽이 흐르는 **데이터 플레인**에 전달 규칙을 반영합니다. 클라이언트가 백엔드에 도달하려면 전달 규칙, 네트워크 접근, 애플리케이션의 포트 수신 상태가 모두 맞아야 합니다.

이 장은 일반적인 ClusterIP 전달을 따라갑니다. 헤드리스 Service(`clusterIP: None`)와 ExternalName Service는 DNS를 서로 다르게 사용하므로 DNS부터 조사합니다. 외부 로드 밸런서가 있다면 대상 등록과 상태 점검 기록도 함께 수집하세요.

## 2. 주소·포트·객체 신원을 잇는 순서

1. 클러스터, 네임스페이스, 이름으로 Service를 찾습니다. 객체의 한 수명 주기를 식별하는 **UID**, 선택자, 클라이언트가 접속하는 포트, 프로토콜, targetPort, 트래픽 정책을 보존합니다. **Service 포트 이름**은 Service 안에서 해당 포트를 가리킵니다. 문자열 **targetPort**는 대상 Pod에서 찾아야 할 포트 이름입니다. 두 이름은 달라도 됩니다.
2. 같은 네임스페이스에서 `kubernetes.io/service-name`이 Service 이름과 일치하는 EndpointSlice를 **모두** 찾습니다. `endpointslice.kubernetes.io/managed-by`와 소유자 참조를 확인합니다. Service 소유자 참조가 있다면 그 UID를 조사 대상 Service UID와 대조하세요. Pod를 백엔드로 쓰는 항목에는 `targetRef.uid`가 있을 수 있습니다. UID를 대조하고 주소도 Pod 상태와 비교하세요. 참조가 없으면 다른 근거가 필요합니다. 선택자가 없는 Service는 별도 관리자가 합법적으로 Slice를 관리하며 Pod 네트워크 바깥의 대상을 사용할 수도 있습니다.
3. 각 Slice에서 Service 포트의 **이름과 프로토콜**이 일치하는 항목을 찾아 숫자 포트를 읽습니다. 하나의 Slice 안에서는 모든 엔드포인트가 같은 포트 목록을 사용합니다. 주소 계열, 상태 조건, 노드도 보존하세요. 같은 Service 포트와 주소 계열에서 주소·포트·프로토콜 조합이 중복되면 집계할 때 한 번만 셉니다. 값이 충돌하면 양쪽 원본과 출처를 모두 보존하세요.
4. 클라이언트와 실제 전달 구현을 식별합니다. 요청의 주소 계열과 정책을 적용한 뒤 후보를 판단합니다. `internalTrafficPolicy: Local`인 kube-proxy 환경에서는 다른 노드의 백엔드가 정상이어도 클라이언트 노드에 대상이 없어서 실패할 수 있습니다. 해당 요청의 결과를 보려면 백엔드 접근 로그나 승인된 연결 관측을 요청 ID와 시간 범위로 연결하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/kubernetes-endpointslice-routing-evidence-ko.svg' | relative_url }}" alt="Service 포트와 프로토콜을 연결된 모든 EndpointSlice와 대조합니다. 주소와 대상 UID, 숫자 포트로 API 후보를 찾고, 클라이언트 노드 및 백엔드 기록으로 실제 전달을 확인합니다." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>Service 설정부터 실제 전달까지 세 번의 대조가 필요합니다. 각 단계의 API 상태와 트래픽 관측 시각을 함께 기록하세요.</figcaption>
</figure>

## 3. 정상 구성과 예상 밖의 결과 읽기

**가상 롤아웃.** `checkout` Service의 포트 이름은 `https`이고 TCP 443을 받습니다. `targetPort`는 Pod 포트 이름인 `app-tls`입니다. 이전 버전은 `app-tls`를 8443, 새 버전은 9443으로 선언했고 두 세대의 Pod가 모두 선택자와 일치합니다. 컨트롤러는 이름이 `https`이고 숫자 포트가 서로 다른 Slice를 만들 수 있습니다. 따라서 Service의 443으로 새로 요청하면 두 숫자 포트 중 하나에 도달할 수 있습니다. 클라이언트와 동일한 요청 ID가 새 버전의 9443 백엔드에 기록됐다면 **그 요청이** 해당 백엔드에 도달했다는 근거가 됩니다.

| 관측 | 뒷받침하는 판단 | 더 수집할 증거 |
|---|---|---|
| Slice 간 포트 이름은 같고 숫자 포트가 다름 | 롤아웃 중 두 세대에서 다른 포트가 해석되는 정상 상황일 수 있음 | Pod 명세, 배포 이력, 애플리케이션 수신 포트 |
| Slice의 Service 소유자 UID가 현재 Service와 다름 | Service 재생성 등으로 연결 관계를 확인할 필요가 있음 | 이전 Service와 Slice 버전, 컨트롤러 로그, 수락된 API 쓰기 요청 |
| 선택자가 없는 Service에 별도 관리자가 있음 | 수동 또는 별도 자동화로 등록한 백엔드일 수 있음 | 승인된 목적지 목록, 작성 자동화, 네트워크 기록 |
| `ready=false`, `serving=true`, `terminating=true` | 종료 중이며 아직 요청을 처리할 수 있다고 표시됨 | 프록시 버전과 정책. 적용 후보 집합에 대안이 없으면 종료 중인 serving 백엔드가 사용될 수 있음 |
| 다른 노드의 Slice는 정상이고 로컬 후보가 없음 | Local 정책 때문에 노드마다 결과가 다를 수 있음 | 클라이언트 노드, 엔드포인트의 `nodeName`, 같은 시각 해당 노드에서의 관측 |

Pod를 가리키는 엔드포인트에서 `serving`은 보통 Pod 준비 상태를 따르고, `terminating`은 삭제 진행을 나타냅니다. `publishNotReadyAddresses: true`이면 Pod 준비 상태와 관계없이 ready로 공개될 수 있습니다. v1 API는 생략된 `ready`와 `serving`을 true, `terminating`을 false로 해석합니다. 원본에는 생략과 명시를 구분해 남기세요. API 기본 해석만으로 애플리케이션 상태를 입증할 수는 없습니다.

예상 밖으로 바뀐 선택자나 Slice 때문에 요청이 엉뚱한 목적지로 전달될 수 있습니다. 단일 스냅샷에서는 배포 실수, 오래된 객체, 승인되지 않은 변경이 비슷하게 보입니다. 수락된 API 변경을 승인된 담당자와 배포 기록에 대조하세요. 예상 밖의 목적지에 도달했다면 요청 단위 증거로 영향을 좁힙니다. 객체에 쓰인 관리자 레이블은 기록된 선언입니다. 실제 작성자를 확인하려면 감사 이벤트와 요청 신원을 살펴보세요.

## 4. 블루팀 수집·탐지·대응

아래는 읽기 전용 조회입니다. 승인된 컨텍스트에서 호환되는 `kubectl`을 사용하세요. 해당 네임스페이스의 Service 조회, EndpointSlice 목록 조회, 대상 Pod 조회 권한이 필요합니다. 이름은 승인된 대상으로 바꾸세요. `targetRef.name`으로 Pod를 조회한 뒤 실제 UID를 대조합니다. 전체 JSON 출력은 각각 수집 시각과 함께 보존하세요.

~~~sh
kubectl config current-context
kubectl -n checkout get service checkout -o json
kubectl -n checkout get endpointslices.discovery.k8s.io \
  -l kubernetes.io/service-name=checkout -o json
kubectl -n checkout get pod checkout-green -o json
~~~

1. **수집.** UTC 시각, 클러스터, 네임스페이스, 클라이언트 주소와 노드, Service UID, 각 Slice UID와 resourceVersion, 백엔드 주소와 포트를 기록합니다. resourceVersion은 API의 변경 추적에 쓰이는 버전입니다. 사건 순서는 수집·감사 시각을 바탕으로 판단하세요. 각 명령은 별도의 스냅샷을 제공합니다.
2. **탐지.** 연속 수집한 API 스냅샷을 승인된 배포와 비교합니다. 목적지를 알 수 없는 백엔드, 변경 예정 시간 밖의 포트 변화, 새로운 클라이언트 실패와 동시에 나타난 로컬 엔드포인트 부재를 우선 살펴보세요. 감사 정책이 해당 리소스와 시점을 기록했다면 [Kubernetes API 감사 증거]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }})를 활용하세요. 요청 본문 포함 여부는 감사 수준에 따라 달라집니다.
3. **대응.** 변경하기 전에 먼저 증거를 보존합니다. 후보 목록이 정상인데 한 노드에서만 실패하면 그 노드의 Service 프록시 상태와 동기화 상태, 워크로드 측 연결 허용·차단 기록을 확인하세요. 새 연결이나 고유 요청 ID를 사용하세요. 기존 연결은 이전 백엔드를 계속 사용할 수 있습니다. Service 담당자와 승인된 선택자, 포트 또는 관리 대상 설정을 복구한 뒤 API와 클라이언트 양쪽에서 정상 동작을 확인합니다.

## 5. 오프라인 실습 · 가상 API 스냅샷 여섯 가지

Python 3이 있는 승인된 작업 공간에서 두 파일을 같은 디렉터리에 저장하세요. JSON은 API 형식에서 일부 필드를 발췌한 가상 기록과 정답입니다. 검사기는 이 자료만 대조하며 트래픽을 전송하지 않습니다. IPv4의 TCP Service 포트 하나가 실습 범위입니다. ready 상태인 비종료 후보를 표시하고 종료 중인 엔드포인트는 따로 기록합니다. kube-proxy의 전달 동작이나 도달 여부는 이 실습으로 확인하지 않습니다.

- <a href="{{ '/assets/downloads/kubernetes-endpointslice-routing-evidence/inspect_slices.py' | relative_url }}" download>Python 점검 스크립트 다운로드</a>
- <a href="{{ '/assets/downloads/kubernetes-endpointslice-routing-evidence/slice_cases.json' | relative_url }}" download>가상 스냅샷 여섯 가지 다운로드</a>

~~~sh
python3 inspect_slices.py slice_cases.json
~~~

| 사례 | 기대 결과 |
|---|---|
| 두 세대의 포트 | Service 포트 이름이 같아도 서로 다른 주소·포트 조합 두 개가 나옵니다. |
| 중복 엔트리 | 주소·포트 조합은 한 번만 집계되고 중복이 표시됩니다. |
| Service 재생성 | 준비 상태인 주소가 있어도 소유자 UID 불일치를 찾습니다. |
| Local 정책 | 다른 노드에 적합한 백엔드가 있지만 주어진 클라이언트 노드의 후보는 없습니다. |
| 종료 중인 엔드포인트 | serving과 terminating이 함께 표시된 항목을 일반 준비 후보와 구분합니다. |
| 선택자 없는 Service | 별도 관리되는 백엔드가 있어 승인된 목적지 목록과 대조가 필요합니다. |

여섯 사례가 모두 정답과 일치해야 합니다. JSON을 복사하고 첫 사례에서 첫 Slice의 숫자 포트만 `7443`으로 바꾸세요. 정답을 그대로 두고 실행하면 해당 사례 하나가 실패하고 종료 코드는 1이 됩니다. 비교를 시작하기 전에 멈추면 작업 디렉터리, JSON 문법, 스크립트와 자료의 버전을 확인하세요.

## 6. 확인 문제와 완료 기준

- **Service의 `name: https`가 `targetPort: app-tls`를 가리킨다면 Slice에서 무엇을 맞춰야 하나요?** `https`와 프로토콜을 Slice 포트에서 찾으세요. `app-tls`는 Pod에 선언된 숫자 포트로 해석됩니다.
- **EndpointSlice에 목적지가 보이면 특정 요청이 그곳에 도착한 건가요?** 해당 요청을 연결할 수 있는 클라이언트와 백엔드 관측이 필요합니다. API 스냅샷은 후보를 보여줍니다.
- **UID가 다르면 누가 바꿨고 악의적인 변경이었는지 알 수 있나요?** 수락된 API 쓰기 요청과 행위자, 승인된 변경 기록을 확인하세요. 불일치 자체에는 행위자와 의도가 담겨 있지 않습니다.

포트를 바꿔 예상대로 실패하게 하고, Local 정책이 노드별로 다른 결과를 내는 이유를 설명하고, 실제 전달을 입증할 추가 증거를 제시하면 실습을 완료한 것입니다.

## 공식 참고자료

**2026-11-27** Kubernetes v1.36 문서를 기준으로 검토했습니다. 실제 클러스터의 버전과 전달 구현에 맞는 문서를 확인하세요. EndpointSlice는 v1.21부터 안정 기능입니다. 이전 Endpoints API는 v1.33부터 사용 중단 권고 대상이며 백엔드가 많은 Service에서 주소 일부를 누락할 수 있습니다.

- [Kubernetes v1.36 EndpointSlices · 그룹 구성, 대상 신원, 상태 조건](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/endpoint-slices/)
- [Kubernetes EndpointSlice v1 API · 필드와 생략된 상태 값](https://v1-36.docs.kubernetes.io/docs/reference/kubernetes-api/discovery/endpoint-slice-v1/)
- [Kubernetes v1.36 Services · 포트, 선택자 없는 Service와 헤드리스 Service](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/service/)
- [Kubernetes v1.36 Service 프록시 · 동기화, Local 정책 및 종료 중인 엔드포인트](https://v1-36.docs.kubernetes.io/docs/reference/networking/virtual-ips/)
