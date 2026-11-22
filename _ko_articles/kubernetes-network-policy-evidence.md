---
title: "Kubernetes NetworkPolicy 증거 · Pod 연결의 양쪽 읽기"
description: "Pod 선택자와 수신·송신 규칙을 읽고 정책 설정, 실제 적용, 애플리케이션 결과를 구분합니다."
category: cloud
tags: [Kubernetes, Cloud Security, Network Security, NetworkPolicy, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/kubernetes-network-policy-evidence/
---

**학습 목표.** Kubernetes API 감사 로그에 정책 변경이 기록됐고, 호출자는 요청 시간이 초과됐다고 합니다. 정책상 허용돼야 하는 통신, 실제 네트워크에서 일어난 일, 애플리케이션이 받은 요청을 각각 어떻게 확인할지 익힙니다.

## 1. NetworkPolicy는 무엇을 제어하나요?

**Pod**는 하나 이상의 컨테이너를 실행하도록 Kubernetes가 배치하는 단위입니다. **네임스페이스**는 그 범위에 속하는 리소스를 묶습니다. **레이블**은 리소스에 붙는 키와 값입니다. **선택자**는 `app=api`처럼 어떤 조건을 만족하는 리소스를 찾습니다. **Service**는 애플리케이션에 고정된 주소나 이름을 제공합니다. 선택자가 있는 Service가 찾아낸 백엔드는 **EndpointSlice**에 기록됩니다. Service 이름이 그대로여도 그 뒤의 Pod는 바뀔 수 있습니다.

**NetworkPolicy**는 선택된 Pod에 허용할 IP·전송 계층 트래픽을 정의합니다. **Ingress**는 목적지 Pod로 들어오는 트래픽이고, **Egress**는 출발지 Pod에서 나가는 트래픽입니다. 클러스터가 정책을 저장할 수 있어도 네트워크 구현이 정책을 지원하지 않으면 적용되지 않습니다. 지원 여부와 설정은 네트워크 담당자에게 확인하세요. **CNI**는 여러 Kubernetes 네트워크 플러그인이 Pod 네트워크를 구성할 때 사용하는 인터페이스입니다. 실제로 어떤 정책을 적용하고 무엇을 관측할 수 있는지는 플러그인과 데이터 경로에 달려 있습니다. 표준 NetworkPolicy의 범위는 HTTP 사용자의 신원이나 경로, 메서드까지 포함하지 않습니다.

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/kubernetes-network-policy-evidence-ko.svg' | relative_url }}" alt="새 Pod 연결은 출발지 송신 규칙과 목적지 수신 규칙을 모두 통과해야 합니다. 한쪽이라도 허용하지 않으면 모델에서 차단되고, 양쪽이 허용하면 애플리케이션 상태를 이어서 확인합니다.">
<figcaption>새 Pod 간 연결은 양쪽 방향의 정책을 읽습니다. 정책상 허용돼도 Service 라우팅, 수신 포트 상태 또는 애플리케이션 인가에서 실패할 수 있습니다.</figcaption>
</figure>

## 2. 선택자와 양방향 정책을 읽는 순서

출발지와 목적지 Pod, 각 네임스페이스를 먼저 파악합니다. 그런 다음 각 Pod를 해당 방향으로 격리하는 정책을 모두 찾습니다. 표준 NetworkPolicy가 그 방향의 Pod를 하나도 선택하지 않으면 해당 방향은 정책으로 격리되지 않습니다. 하나 이상 선택하면 그 방향의 허용 규칙을 모두 합쳐 판단합니다. 일반 Pod 사이에서 새 연결을 시작하려면 출발지 송신과 목적지 수신이 모두 허용돼야 합니다. 허용된 연결의 응답 트래픽은 암묵적으로 허용됩니다. 이 장의 모델은 네트워크 구현별 차이와 문서에 명시된 노드 트래픽 예외를 제외합니다.

| 정책 요소 | 선택하는 대상 | 확인할 점 |
| --- | --- | --- |
| 최상위 `spec.podSelector` | 정책과 같은 네임스페이스의 Pod | 빈 선택자는 해당 네임스페이스의 모든 Pod에 적용. 통신 상대가 아닌 보호 대상 |
| `podSelector`만 있는 `from` 또는 `to` 항목 | 정책과 같은 네임스페이스의 상대 Pod | 다른 네임스페이스의 Pod는 레이블이 같아도 선택되지 않음 |
| 한 항목에 `namespaceSelector`와 `podSelector`를 함께 지정 | 일치하는 네임스페이스 안에서 Pod 레이블도 일치하는 상대 | 같은 항목 안에서는 두 조건이 모두 필요(AND). 서로 다른 목록 항목은 각각 평가(OR) |
| `policyTypes`로 방향을 지정하고 해당 규칙 목록을 비움 | 선택된 Pod를 그 방향으로 격리하며 해당 정책은 아무 트래픽도 허용하지 않음 | 함께 적용되는 다른 정책에서 허용할 수 있음. 정책 평가 순서로 결과를 판단하지 않음 |

가상의 `shop/web` Pod가 `orders` Service의 TCP 80에 연결한다고 가정해 봅시다. Service는 요청을 `shop/api`의 TCP 8080으로 보냅니다. DNS가 이미 Service 이름을 해석했고 백엔드는 준비 완료이며 8080에서 대기한다고 가정합니다. 먼저 실제 백엔드 주소와 포트를 확인하세요. Service 주소 변환 시점과 IP 기반 규칙의 적용에는 구현 차이가 있으므로, 관측한 주소와 포트를 해석할 때 플러그인을 확인합니다.

아래 학습용 정책은 `shop`의 `app=api` Pod를 선택하고, 같은 네임스페이스의 `app=web`에서 들어오는 TCP 8080을 허용합니다. 정상 예시에는 별도 정책이 `web`의 `api:8080` 송신도 허용한다고 가정합니다. 아래 수신 정책만으로 상대 Pod의 송신 허용을 결정할 수 없습니다.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: orders-api-ingress
  namespace: shop
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: web
      ports:
        - protocol: TCP
          port: 8080
```

## 3. 오용, 설정 실수, 다른 장애 구분하기

| 관측 | 가능한 원인 | 구분에 도움이 되는 증거 |
| --- | --- | --- |
| 정책 저장 뒤에도 트래픽이 그대로 보임 | 플러그인이 정책을 지원하지 않음, Pod가 선택되지 않음, 다른 정책이 넓게 허용함, 이미 열려 있던 연결 | 플러그인 기능, 당시 레이블, 적용되는 정책 전체, 새 연결, 데이터 경로 관측 |
| 호출자가 시간 초과를 보고함 | 정책 차단, DNS 실패, 백엔드 부재·비정상, 다른 네트워크 문제 | DNS 결과, EndpointSlice, 백엔드 포트, 흐름 판정과 서비스 상태 |
| HTTP 403을 받음 | 응답한 애플리케이션이나 중계 지점까지 연결된 뒤 요청이 거부됨 | 실제 응답 주체, 요청 또는 추적 ID, 애플리케이션 정책과 로그 |
| 예상 밖 호출자가 API에 연결됨 | 과도하게 넓은 네임스페이스 선택, 추가 허용, 레이블이나 배포 변경 | 변경 전후 정책과 레이블, API 감사 로그, 관측된 출발지와 백엔드, 승인 작업 기록 |

편집 권한이 있는 주체가 정책을 넓히거나 레이블을 바꾸면 의도하지 않은 접근이 가능해질 수 있습니다. 연결 허용은 네트워크 도달성을 판단하는 증거입니다. 실제 사용자와 HTTP 인가 결과, 애플리케이션에 미친 영향은 각각 확인하세요. 시간 초과에는 여러 원인이 있습니다. CNI의 차단 기록이 있더라도 어느 Pod·방향·시각을 설명하는지 확인한 뒤 해당 장애와 연결합니다.

## 4. 세 층의 증거를 수집하고 대응하기

1. **API 설정과 변경 이력.** 클러스터 ID와 UTC, 정책 UID 및 resourceVersion, 영향받은 네임스페이스와 Pod UID·레이블, Service 포트와 EndpointSlice를 보존합니다. 현재 설정은 사고 당시와 다를 수 있습니다. 과거 매니페스트나 변경 이벤트를 확보하세요. API 감사 정책이 변경을 수집했다면 사용자, 동작, 객체, 응답, 시각을 확인합니다. 감사 수준과 보존 설정에 따라 요청 본문이나 변경 전 상태가 없을 수 있습니다. [Kubernetes API 감사 증거]({{ '/ko/wiki/kubernetes-audit-evidence/' | relative_url }})에서 증거의 범위를 확인하세요.
2. **실제 경로와 적용 여부.** 영향받은 워크로드에서 Service 이름의 DNS 결과를 확인하거나 보존된 리졸버 기록을 찾습니다. 백엔드 주소, 준비 상태, 대상 포트를 확인하세요. 네트워크 플러그인의 정책 지원과 관측 범위를 점검합니다. Cilium과 Hubble이 활성화된 환경에서는 흐름 기록으로 관련 워크로드, 방향, 판정을 대조할 수 있습니다. 관측 지점, UTC 시각, 프로토콜, 출발지·목적지 식별 정보와 포트, 제공되는 경우 차단 사유를 남깁니다. 수집 범위와 보존 기간은 환경마다 다릅니다. 일반 API 감사 이벤트에는 패킷 판정이 없습니다.
3. **애플리케이션 결과.** 호출자 결과를 대상 로그의 요청 ID나 추적 ID 및 시각과 맞춥니다. 프록시나 다른 백엔드가 응답했을 수 있으므로 실제 응답 주체를 먼저 확인하세요. 시간대와 리소스 식별 정보를 포함해 각 증거를 보존합니다. 접근 범위가 넓어졌다면 승인된 설정 변경 절차로 되돌리고, 영향받은 서비스까지 실제 요청이 도달했는지 확인합니다.

아래는 읽기 전용 조회 예시입니다. 승인된 Kubernetes 컨텍스트에서 실행하고, 지정한 네임스페이스의 Pod, Service, EndpointSlice, NetworkPolicy에 필요한 조회·목록 권한을 확인하세요. 이름은 승인된 대상으로 변경합니다. 네임스페이스가 다르면 양쪽 자료를 확보하세요. 이 명령의 결과는 현재 상태입니다.

```bash
kubectl config current-context
kubectl -n shop get pods --show-labels -o wide
kubectl -n shop get networkpolicies -o yaml
kubectl -n shop get service orders -o yaml
kubectl -n shop get endpointslices -l kubernetes.io/service-name=orders -o yaml
```

실제 방어 검증은 승인된 전용 테스트 네임스페이스에서 진행합니다. 알려진 허용 출발지와 차단 출발지를 하나씩 준비하고, 네트워크 정책이 적용된 뒤 각각 새 연결을 열어 자체 테스트 서비스에 무해한 요청을 보냅니다. 각 실험의 출발지·백엔드, 애플리케이션 결과, 수집 가능한 정책 판정을 기록하세요. 설계에는 필요한 DNS와 상태 확인 트래픽도 포함합니다. 운영 장애를 확인하려고 즉석에서 운영 정책을 변경하지 마세요. 정책을 변경해도 기존 연결을 끊을지는 구현에 따라 달라집니다.

## 5. 오프라인 실습 · 여덟 가지 결과 예측하기

<a href="{{ '/assets/labs/kubernetes-network-policy-lab.py' | relative_url }}" download>Python 정책 판정표</a>를 내려받아 `python3 kubernetes-network-policy-lab.py`로 실행하세요. 실행 전에 표의 결과를 직접 예측해 보세요. 실습은 Pod를 네임스페이스와 앱 레이블로, 규칙을 명시적 TCP 상대·포트 허용으로 단순화합니다. G를 제외하면 Service가 이미 백엔드를 선택했다고 가정합니다. 방향별 허용 규칙의 합집합을 평가하는 모델이며, 실제 Kubernetes YAML이나 클러스터를 읽지 않습니다. 네트워크와 관리자 권한 없이 실행할 수 있습니다.

| 사례 | 정상 예시와 달라진 점 | 기대하는 해석 |
| --- | --- | --- |
| A | web → api의 TCP 8080이 양쪽 규칙에 일치 | 모델에서 허용 |
| B | 같은 네임스페이스의 `worker`. 송신은 격리되지 않음 | 목적지 수신에서 차단 |
| C | `dev` 네임스페이스의 `app=web`. 송신은 격리되지 않음 | 네임스페이스가 달라 목적지 수신에서 차단 |
| D | web이 송신 격리됐지만 허용 규칙이 없음 | 수신은 허용되더라도 출발지 송신에서 차단 |
| E | web이 TCP 9090 사용 | 양쪽 모두 차단 |
| F | 운영 점검 Pod에 API 수신 허용을 추가 | 적용되는 허용 규칙을 합치므로 허용 |
| G | 실습에서 Service가 선택한 백엔드가 없음 | 목적지 Pod가 없어 정책 판정 대상이 없음 |
| H | api 수신을 격리했고 모든 적용 정책에 허용 규칙이 없음 | 목적지 수신에서 차단 |

마지막에 `8/8 policy matrix controls matched.`가 표시됩니다. 실행이 안 되면 Python 3과 파일 이름을 확인하세요. B 또는 C가 허용된다고 생각했다면 상대 Pod 레이블과 네임스페이스를 따로 대조합니다. D가 허용된다고 생각했다면 출발지의 송신 규칙을 다시 읽으세요. 가상 사례는 클라우드에서 실행했습니다. Kubernetes 조회 명령과 Service·CNI 동작은 공식 문서를 바탕으로 검토했으며 실제 클러스터에서 실행하지 않았습니다.

## 6. 확인 문제와 완료 기준

1. **API가 NetworkPolicy를 저장했습니다. 패킷이 차단됐다고 볼 수 있나요?** 플러그인의 정책 지원 여부를 확인하고 실제 데이터 경로에서 새 연결을 관측해야 합니다.
2. **어떤 정책은 수신 허용 규칙이 없고 다른 정책은 web의 TCP 8080을 허용합니다. 어떻게 판정하나요?** 빈 목록은 허용을 추가하지 않습니다. 다른 정책이 수신을 허용할 수 있으며, 출발지 송신도 확인해야 합니다.
3. **정책 차단과 준비된 Service 백엔드 부재를 어떻게 구분하나요?** Service와 EndpointSlice부터 확인하세요. 이후 관련 노드나 워크로드에서 새 연결과 흐름 판정을 대조합니다.
4. **네트워크가 연결을 허용하면 HTTP 사용자가 정당하다고 볼 수 있나요?** 실제로 답한 주체를 확인하고 애플리케이션의 인증·인가 자료를 확보합니다.

**완료 기준.** 정책의 보호 대상 Pod와 상대 선택자를 찾아내고 양방향을 봐야 하는 이유를 설명하세요. 여덟 사례를 분류하고 실제 적용을 입증할 추가 자료 한 가지를 제시하면 됩니다.

## 공식 참고자료

검토일 2026-11-21. 정책과 EndpointSlice는 Kubernetes v1.36 문서를 기준으로 검토했습니다. 실제 배포 버전과 네트워크 구현에 맞는 문서를 확인하세요.

- Kubernetes v1.36 [Network Policies](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/network-policies/)와 [EndpointSlices](https://v1-36.docs.kubernetes.io/docs/concepts/services-networking/endpoint-slices/).
- Kubernetes 공식 [Service 디버깅](https://kubernetes.io/docs/tasks/debug/debug-application/debug-service/)과 조회 명령 [kubectl get](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_get/).
- Cilium 1.20의 구현별 관측 예시인 [Hubble 네트워크 관측성](https://docs.cilium.io/en/stable/observability/hubble/index.html).

## 워크로드 신원과 토큰 수명 확인

[Kubernetes 서비스 계정 토큰 증거]({{ '/ko/wiki/kubernetes-service-account-evidence/' | relative_url }})에서 Pod의 자격 증명 발급과 API 인증·인가를 따라갑니다.

## Pod 생성 단계의 보안 정책 조사

[Kubernetes Pod Security Admission 조사]({{ '/ko/wiki/kubernetes-pod-security-admission-evidence/' | relative_url }})에서 워크로드 템플릿의 수락, 컨트롤러의 Pod 생성 요청, 실제 실행 상태를 구분하는 방법을 익힙니다.
