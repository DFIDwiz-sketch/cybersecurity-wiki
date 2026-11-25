---
title: "DNS HTTPS 레코드 조사 · 광고한 접속 후보와 실제 사용 경로"
description: "HTTPS 서비스 바인딩을 읽고 후보를 평가한 뒤, 실제 연결과 요청을 별도 증거로 확인합니다."
category: network
tags: [DNS, HTTPS RR, SVCB, HTTP, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/dns-https-record-evidence/
---

**학습 목표.** 서비스 이름과 DNS 응답, 클라이언트 기록을 받아 DNS가 어떤 접속 지점을 안내했는지 설명합니다. 해당 클라이언트가 쓸 수 있는 후보를 찾고, 실제 연결이나 HTTP 요청을 확인할 자료를 고릅니다.

## 1. 접속에는 주소 외에도 정보가 필요합니다

**리소스 레코드(RR)**는 DNS에 저장되는 자료입니다. **RRset**은 소유자 이름, 클래스, 자료형이 같은 레코드의 모음입니다. A와 AAAA는 각각 IPv4와 IPv6 주소를 제공합니다. **서비스 바인딩**은 클라이언트가 연결하기 전에 어디로, 어떤 조건으로 접속할 수 있는지 알려 줍니다. RFC 9460은 범용 SVCB(유형 64)와 웹의 HTTP·HTTPS용 HTTPS 레코드(유형 65)를 정의합니다. 두 자료형의 구조는 같지만 이 표준을 따르는 웹 클라이언트는 웹 오리진에 대해 HTTPS를 조회합니다. **DoH(DNS over HTTPS)**는 DNS 질의를 나르는 전송 방식입니다. HTTPS 레코드는 일반 DNS나 암호화 DNS에서 모두 조회할 수 있습니다.

| 응답에서 보는 항목 | 읽는 법 | 추가로 볼 증거 |
| --- | --- | --- |
| AliasMode, 우선순위 `0` | 다른 이름에서 같은 유형의 조회를 계속합니다. 이 모드의 매개변수는 무시합니다. | 대상 이름의 다음 HTTPS 응답과 전체 이름 경로 |
| ServiceMode, 양수 우선순위 | 접속 지점 하나와 설정을 알립니다. 호환 후보 가운데 숫자가 작을수록 먼저 고려합니다. | 호환 조건과 실제 적용할 대상. 대상이 `.`이면 이 레코드의 소유자 이름입니다. |
| `alpn`, `no-default-alpn` | 안내한 프로토콜과 표준의 기본 프로토콜 포함 여부입니다. | 클라이언트가 지원하는 프로토콜, 실제 협상 결과 |
| `mandatory` | 클라이언트가 이해하고 사용할 수 있어야 하는 키입니다. | 해당 키가 같이 있는지 확인합니다. 필수 키를 지원하지 않으면 후보에서 빠질 수 있습니다. |
| `port`, 주소 힌트, `ech` | 대체 접속 포트, 사용 가능한 주소 단서, 있는 경우 ECH 설정입니다. | 대상의 주소 조회 결과, 소켓과 TLS 결과, HTTP 요청 |

**오리진**은 스킴, 호스트, 포트의 조합입니다. **TargetName**은 실제 접속 지점에 도달하기 위해 사용하는 이름입니다. DNS에서 대상 이름과 접속 포트를 정해도 오리진의 신원은 바뀌지 않습니다. HTTPS 바인딩을 쓰는 클라이언트는 TLS의 SNI에 오리진 이름을 표시합니다. ECH를 쓰면 보호된 안쪽 ClientHello에 들어갈 수 있습니다. TLS 정책에 따라 오리진을 인증하며 HTTP 요청의 authority에도 오리진을 나타냅니다. 접속 대상은 여러 오리진이 공유하는 엣지 서버일 수 있습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/dns-https-record-ko.svg' | relative_url }}" alt="클라이언트가 오리진의 HTTPS 레코드를 조회하고 별칭이 있으면 따라갑니다. 호환되는 접속 후보를 평가한 뒤, 연결과 TLS 기록에서 실제 시도를 확인합니다. HTTP 요청 증거로 사용한 서비스를 판단합니다.">
  <figcaption>DNS가 제공한 정보, 실제 연결, HTTP 요청 결과를 각 단계의 증거로 확인합니다.</figcaption>
</figure>

## 2. 정상적인 접속 따라가기

`https://reports.example/`에 접속하는 가상의 클라이언트를 예로 듭니다.

```text
reports.example.      120 IN HTTPS 0 routes.example.
routes.example.       120 IN HTTPS 1 edge-a.example. alpn=h3,h2
routes.example.       120 IN HTTPS 2 edge-b.example. alpn=h2
edge-a.example.       120 IN A     192.0.2.20
edge-b.example.       120 IN A     192.0.2.21
```

1. 첫 응답은 HTTPS **조회**를 `routes.example.`에서 계속하도록 안내합니다. 이 단계에서 HTTP 리다이렉트가 일어나거나 오리진 이름이 바뀌지는 않습니다. 같은 RRset에 두 모드가 함께 있다면 별칭을 따르고 그 집합의 ServiceMode 레코드는 무시합니다. AliasMode의 대상이 `.`이면 서비스가 제공되지 않는다는 참고 신호입니다. ServiceMode의 점은 앞서 설명한 소유자 이름을 뜻합니다.
2. 두 번째 응답은 접속 후보 두 곳을 안내합니다. h3와 h2를 지원하는 클라이언트는 `edge-a.example.`을 우선 고려할 수 있습니다. HTTPS 매핑의 기본 ALPN은 HTTP/1.1입니다. `alpn`과 함께 `no-default-alpn`을 지정하면 이 기본값이 빠집니다. DNS에 h3가 있다는 사실만으로 h3 전용 서비스나 QUIC 연결 성공을 확정할 수 없습니다. 호환 ALPN은 전송 방식의 선택에 쓰입니다. 어떤 프로토콜이 실제로 선택됐는지는 해당 전송 방식의 ClientHello와 서버 조건에 따른 TLS 협상 결과에서 확인합니다.
3. 클라이언트는 실제로 고려한 대상의 주소를 확인합니다. 사용할 수 있는 A/AAAA가 이미 있다면 RFC 9460은 주소 힌트를 무시하도록 권고합니다. 아직 결과가 없다면 A/AAAA를 조회하면서 힌트를 이용할 수 있습니다. URI 자체의 포트가 기본값과 다르면 조회 이름도 달라집니다. 예를 들어 `https://reports.example:8443/`은 `_8443._https.reports.example.`에서 HTTPS 조회를 시작합니다. ServiceMode의 `port`는 해당 접속 지점에 연결할 때의 포트를 지정하며, URI에 적힌 오리진 포트는 바뀌지 않습니다.
4. 클라이언트 기록이 `192.0.2.20:443`의 성공한 QUIC 연결과 h3 협상, 오리진 인증, `reports.example`에 보낸 HTTP 요청을 연결한다고 가정합니다. 이 기록을 함께 보면 그 요청에 h3가 쓰였음을 확인할 수 있습니다. DNS 응답이나 UDP 패킷 한 건만으로는 부족합니다. h3가 시간 초과된 뒤 h2가 성공했다면 동일 요청의 기록을 연결해 재시도나 전환을 확인하세요. 시각만 가까우면 다른 동시 접속 시도와 섞일 수 있습니다.

## 3. 예상 밖의 접속 지점이나 연결 실패 조사하기

승인되지 않은 DNS 변경으로 접속 지점이 달라지거나, 개인정보 보호나 성능 관련 설정이 빠지거나, 연결 자체가 실패할 수 있습니다. 올바른 이름에 대한 인증서를 제시하지 못하면 일반적인 TLS 인증은 실패합니다. CDN 설정 변경, 리졸버 캐시, 지역별 응답, 제품 호환 차이도 처음에는 비슷하게 보입니다. 예를 들어 Cloudflare는 특정 설정의 프록시 이름에 HTTPS 레코드를 자동으로 생성한다고 설명합니다. 응답과 관리 화면이 다를 때는 승인받은 관리 설정과 제공자 동작을 먼저 대조합니다.

1. **조회 관점을 기록합니다.** UTC 시각, 클라이언트와 리졸버, 전송 방식, 조회 이름과 종류, 응답 코드, TTL, 전체 응답 집합과 별칭 경로, A/AAAA 결과를 보존합니다. NOERROR인데 해당 유형이 없는 경우는 NXDOMAIN이나 SERVFAIL과 다릅니다. 권한 서버의 현재 응답과 재귀 리졸버의 캐시는 정상적으로 다를 수 있습니다. 암호화 DNS로 경유지 패킷에서 응답을 읽을 수 없다면 승인된 단말이나 리졸버 기록을 사용하세요.
2. **쓸 수 있는 후보를 가립니다.** 필수 매개변수, 클라이언트 프로토콜 지원과 대상 주소를 확인합니다. DNS 조회가 성공해도 모든 후보가 호환되지는 않습니다. 바인딩 없이 연결 가능한 클라이언트는 조건에 따라 원래 방식으로 접속할 수 있습니다. 보호된 DNS 조회가 실패한 경우의 RFC 9460 전환 조건과 해당 ECH 정책을 함께 확인합니다. TLS 인증은 여전히 필요합니다.
3. **같은 연결의 자료를 맞춥니다.** 단말 DNS와 전송 기록, 소켓 목적지와 포트, TLS 인증과 ALPN 결과, 오리진의 authority가 기록된 HTTP 트랜잭션을 비교합니다. 가능한 경우 연결이나 요청 ID를 사용합니다. 프록시 양쪽 구간은 따로 기록하세요. 주소 힌트의 IP나 여러 서비스가 공유하는 CDN 주소로 도메인이나 주체를 확정할 수 없습니다.
4. **대응하고 재검증합니다.** 반환된 HTTPS RRset과 대상의 레코드를 승인된 DNS 변경 및 제공자 이력과 대조합니다. 설정을 복구하기 전에 이상했던 응답을 보존하세요. 같은 클라이언트와 리졸버에서 다시 확인하고 정상 대조 결과도 확보합니다. TTL 전후의 응답을 남기고 연결 오류, 실제 프로토콜, 오리진 인증이 기대대로 돌아왔는지 검증합니다. DNSSEC는 신뢰 체인이 적용되는 DNS 자료를 검증합니다. DoH는 리졸버까지의 연결을 보호할 수 있습니다. 오리진 인증은 별도 단계입니다.

### 읽기 전용 DNS 조회

본인이 관리하거나 조사 승인을 받은 존과 리졸버에서 사용합니다. 문서용 리졸버 주소와 가상 이름을 실제 승인된 값으로 바꾸세요. HTTPS 유형을 지원하는 BIND `dig`에서는 이름으로 조회할 수 있습니다. 오래된 버전은 `TYPE65`를 일반 형식으로 표시할 수 있습니다. 짧은 결과만 저장하지 말고 헤더와 응답을 보존합니다. 아래 명령에서 `HTTPS`는 레코드 유형이며 DoH를 켜는 옵션은 아닙니다.

```bash
dig @192.0.2.53 reports.example. HTTPS +noall +comments +answer +additional
dig @192.0.2.53 routes.example. HTTPS +noall +comments +answer
dig @192.0.2.53 edge-a.example. A +noall +comments +answer
dig @192.0.2.53 edge-a.example. AAAA +noall +comments +answer
```

`dig`는 그 리졸버에 새로 질의합니다. 이전에 브라우저가 받은 응답을 되살리는 명령은 아닙니다. 앱이 본 리졸버를 확인하고 캐시, 프록시, 다른 DNS 전송 방식이 소켓 접속에 관여했는지 살펴봅니다.

## 4. 가상 자료로 오프라인 실습하기

승인된 작업 공간에서 <a href="{{ '/assets/labs/dns-https-evidence.py' | relative_url }}" download="dns-https-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/dns-https-evidence-cases.json' | relative_url }}" download="dns-https-evidence-cases.json">사례 파일</a>을 같은 폴더에 저장합니다. Python 3.9 이상을 사용하세요. 스크립트는 가상 자료를 정리한 파일만 읽으며 네트워크에 연결하지 않습니다. 후보 평가 규칙 일부를 확인하고 사례 파일에 이미 연결 근거가 있는 접속 기록을 별도로 읽습니다. DNS 전송 형식이나 제품별 TLS·재시도 정책 전체를 구현하는 도구는 아닙니다.

```bash
python3 dns-https-evidence.py dns-https-evidence-cases.json
```

| 사례 | 기대 결과 |
| --- | --- |
| `alias_offer_only` | 별칭이 호환 후보로 이어집니다. 사용 증거는 없습니다. |
| `priority_and_dot` | 두 후보를 순서대로 읽고, ServiceMode의 점을 소유자 이름으로 해석합니다. |
| `unknown_mandatory` | 우선순위가 높은 후보에 지원하지 않는 필수 키가 있어 다른 후보만 남습니다. |
| `missing_mandatory_value` | 필수 키 값이 없는 응답은 일관되지 않아 후보에서 제외합니다. |
| `hint_and_port` | 포트와 힌트가 함께 안내되지만, 사례의 실제 요청은 A/AAAA에서 확인한 주소로 갑니다. |
| `default_alpn` | 한 후보는 기본 프로토콜로 호환됩니다. 기본값을 끈 다른 후보는 해당 클라이언트와 호환되지 않습니다. |
| `no_https_answer` | NOERROR에 HTTPS 레코드가 없으며 기존 방식의 HTTP/2 연결과 요청이 기록됩니다. |
| `attempt_without_request` | 연결 시도는 확인되지만 요청이 완료됐다는 증거는 없습니다. |

여덟 사례 모두 PASS가 나와야 합니다. 복사본에서 `priority_and_dot`의 첫 레코드 우선순위를 1에서 9로 바꿔 실행하면 순서가 달라져 원래 기대값에 대해 FAIL이 나와야 합니다. 파일을 읽지 못하면 두 파일의 경로를 확인하세요. 후보가 보이지 않으면 별칭 경로와 필수 키부터 확인한 뒤 연결 기록을 대조합니다. Python 실습은 실행 검증했습니다. DNS 조회 명령과 제공자 동작은 공식 문서로 검토했습니다. 실제 존, 브라우저별 지원, Cloudflare 설정을 대상으로 실행한 실습은 아닙니다.

## 5. 판단 확인하기

- **HTTPS 응답에 h3가 있습니다. HTTP/3 요청이 있었다고 보고할 수 있나요?** 응답은 후보를 알립니다. 실제 협상한 프로토콜과 해당 연결의 HTTP 요청을 확인하세요.
- **연결이 CDN 대상 이름으로 향했다면 어느 이름을 인증해야 하나요?** 접속하려던 오리진입니다. DNS 대상과 IP는 접속 지점에 이르는 정보입니다.
- **우선순위 숫자가 가장 작은 후보에 모르는 필수 키가 있다면 왜 다른 접속 지점이 쓰일 수 있나요?** 호환 여부를 먼저 판단합니다. 사용 불가 후보를 빼고 남은 후보에서 클라이언트 정책에 따라 선택합니다.

모든 사례가 통과하면 DNS 광고, 후보 선택, 연결, 요청 증거를 구분해 타임라인 하나를 작성해 보세요.

## 공식 참고자료

2026년 11월 26일 검토. SVCB·HTTPS 기본 표준은 2023년 11월, ECH와 DNS 매핑 표준은 2026년 3월에 발행됐습니다. 제공자 동작은 문서에 적힌 서비스와 설정 범위에 적용합니다.

- 우선순위, 별칭, 호환성, HTTPS 매핑. [RFC 9460 §§2–3, 7–9](https://www.rfc-editor.org/rfc/rfc9460.html)
- DNS를 통한 ECH 설정 전달과 핸드셰이크. [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html) · [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)
- DNS 진단 명령. [BIND 9 dig 매뉴얼](https://bind9.readthedocs.io/en/stable/manpages.html#dig-dns-lookup-utility)
- 조건을 만족한 프록시 이름의 HTTPS 레코드 자동 생성. [Cloudflare DNS 레코드 유형](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/#svcb-and-https)

[이전 글 · DNS 기초와 보안 조사]({{ '/ko/wiki/dns-investigation/' | relative_url }}) · [다음 글 · QUIC과 HTTP/3]({{ '/ko/wiki/quic-http3-evidence/' | relative_url }}) · [관련 글 · TLS Encrypted Client Hello]({{ '/ko/wiki/tls-ech-evidence/' | relative_url }})
