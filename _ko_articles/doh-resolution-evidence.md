---
title: "DNS over HTTPS 조사 · TLS, HTTP, DNS 응답 구분하기"
description: "가상 관측 10건으로 DoH 리졸버 선택, HTTP 상태, DNS 응답 코드, 캐시와 대체 경로를 확인합니다."
category: network
tags: [DNS, DoH, Network Security, TLS, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/doh-resolution-evidence/
---

**이 애플리케이션은 이 이름을 어느 리졸버에 물었고, 어떤 답을 받았을까요?** 암호화된 연결, HTTP 응답, DNS 결과는 각각 이 질문의 다른 부분을 설명합니다. 이름과 레코드, 재귀 리졸버가 처음이라면 [DNS 기초]({{ '/ko/wiki/dns-investigation/' | relative_url }})부터 읽어 보세요.

## 1. DNS를 HTTPS로 전송하는 이유

**DNS over HTTPS(DoH)**는 클라이언트와 HTTPS 리졸버 서비스 사이에서 DNS 질의와 응답을 HTTPS로 운반합니다. TLS 연결을 인증하면, 일반적으로 로컬 네트워크에서 보호된 HTTP 교환 속 DNS 질의나 응답을 읽을 수 없습니다. 리졸버는 여전히 질의를 보고 처리합니다. 리졸버의 캐시, 상위 서버와의 통신, 개인정보 처리 정책은 각각 따로 확인해야 합니다. DNSSEC는 검증이 적용되는 서명된 DNS 데이터의 진위를 확인합니다. DoH는 HTTPS 서비스까지의 전송을 보호합니다.

클라이언트는 URI 템플릿을 사용해 접속 지점을 설정할 수 있습니다. RFC 8484는 GET과 POST를 정의합니다. GET은 DNS 메시지를 base64url로 인코딩해 질의 파라미터에 싣고, POST는 DNS 바이트를 본문에 넣습니다. 표준 DNS 바이트 응답은 `application/dns-message`를 사용합니다. HTTP 경로, URL 질의 파라미터, 본문이 클라이언트나 승인된 TLS 종료 지점에 노출될 수 있으므로 기록과 보존 범위를 제한하세요. base64url은 바이트 표현 방식이라 다시 디코딩할 수 있습니다.

RFC 9462는 지원 클라이언트가 지정된 암호화 리졸버를 찾는 방법을 정의합니다. RFC 9463은 DHCP와 라우터 광고를 통한 네트워크 제공 탐색 옵션을 다룹니다. 어느 쪽이든 클라이언트 지원과 설정이 필요합니다. 탐색 결과만으로 특정 조회에 그 리졸버가 쓰였다고 판단할 수 없습니다. 앱이 운영체제와 별개로 리졸버, 정책과 캐시를 관리하기도 합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/doh-resolution-evidence-ko.svg' | relative_url }}" alt="애플리케이션의 이름 조회가 TLS로 보호된 HTTP 질의를 통해 DoH 서비스로 전달됩니다. 리졸버는 캐시를 쓰거나 상위 조회를 하고, HTTP 상태와 DNS 메시지를 돌려줍니다.">
  <figcaption>각 단계가 보이는 위치에서 증거를 확보합니다. 캐시를 쓰면 상위 서버에 새로 질의하지 않고 답할 수 있습니다.</figcaption>
</figure>

## 2. 세 계층의 증거 읽기

| 관측한 사실 | 뒷받침하는 판단 | 다음 확인 |
| --- | --- | --- |
| 승인된 리졸버 접속점과 TLS 연결 | 해당 접속점과의 전송 계층 활동 | 수집 가능한 경우 앱과 HTTP 트랜잭션 |
| HTTP 200과 디코딩된 DNS NXDOMAIN | DNS 응답이 이름 오류를 보고함 | 질의, 리졸버가 보는 영역, 부정 캐시와 정책 가능성 |
| HTTP 200과 디코딩된 DNS SERVFAIL | HTTP 교환은 성공했고 DNS 응답에는 실패가 기록됨 | 리졸버 진단, 상위 조회, DNSSEC 검증 |
| HTTP 200과 다른 미디어 유형 또는 읽을 수 없는 본문 | 웹 응답이 관측됨 | 프록시나 오류 페이지, 미디어 유형, 메시지 완전성 |
| DNS 응답 없는 HTTP 502 | HTTP 계층의 오류를 관측함 | 게이트웨이·상위 서비스 로그와 별도의 재시도 |
| NOERROR와 빈 응답 섹션 | 오류 코드가 없고 해당 섹션에 레코드가 없음 | NODATA로 해석하기 전 질의 유형, 권한 섹션, 별칭과 정책 |

본문을 DNS 응답으로 해석하기 전에 HTTP 상태를 읽으세요. RFC 8484에서는 유효한 DNS 메시지라면 DNS 코드가 오류를 나타내도 HTTP 성공으로 운반합니다. HTTP 캐시는 저장된 응답을 다시 검증할 수도 있습니다. 예를 들어 304를 관측했다면 저장된 응답과 함께 의미를 해석하세요. 새 DNS 메시지를 받았다고 단정할 수 없습니다. 하나의 HTTPS 연결에서 여러 질의를 처리하거나 연결을 재사용할 수 있습니다. 목적지 IP나 TLS 메타데이터만으로 질의 이름이나 응답 내용을 알 수 없습니다.

## 3. 정상 조회와 대체 경로를 따라가기

가상의 관리형 브라우저가 `app.example.test`의 IN A 레코드를 조회합니다. 클라이언트 진단으로 이 조회와 `application/dns-message`를 담은 HTTP 200을 연결합니다. DNS를 디코딩하면 `NOERROR`와 응답 하나인 `192.0.2.10`이 나옵니다. 실습은 레코드 TTL을 120초, HTTP `Age`를 35초로 설정해 남은 시간이 85초가 되는 예를 보여 줍니다. RFC 8484는 DNS TTL을 계산할 때 Age를 반영하도록 합니다. 이 시간대 상위 질의가 없으면 캐시 사용 가능성이 있습니다. 원인을 정하려면 캐시 또는 응답 증거를 확인하세요. 이름 오류도 남아 있는 이유는 [DNS 부정 캐시]({{ '/ko/wiki/dns-negative-cache-evidence/' | relative_url }})에서 이어서 봅니다.

다른 가상 사례에서는 승인된 DoH 연결이 실패합니다. 클라이언트 기록을 보면 같은 이름 조회가 시스템 리졸버로 다시 시도됐습니다. 같은 조회 ID나 신뢰할 수 있는 클라이언트 진단을 확보하고, 가능한 경우 예상된 대체 리졸버의 기록과 대조하세요. 시간상 가까운 평문 DNS 패킷은 다른 프로세스, 재시도 또는 내부 이름에 해당할 수 있습니다. Firefox의 기업용 `DNSOverHTTPS` 정책은 `ProviderURL`, `ExcludedDomains`, `Fallback`과 버전 조건을 설명합니다. 실제 적용 정책과 버전을 확인하고 해당 조회를 관측합니다. 제외된 내부 이름이 처음부터 시스템 리졸버를 쓰는 경우와 DoH 실패 뒤 대체 경로로 가는 경우를 구분하세요.

## 4. 블루팀의 수집·탐지·대응

1. **클라이언트 기준선을 잡습니다.** 호스트, 애플리케이션, 프로세스, 시각, 설정한 정책과 실제 적용 정책, 내부·외부 이름에 예상한 경로를 기록하세요. 브라우저, OS, VPN 조건도 확인합니다. 승인된 실습에서는 소유한 시험 이름을 쓰고 어떤 캐시를 비웠거나 보존했는지 남기세요.
2. **판단과 결과가 보이는 지점을 찾습니다.** 승인된 클라이언트 진단과 리졸버 로그를 사용합니다. 승인된 HTTP 종료 지점에서 수집할 수 있다면 요청 또는 트랜잭션 ID, 상태, 미디어 유형, 캐시 정보를 보존하세요. 질의 이름과 유형, RCODE, 응답 또는 권한 섹션 요약은 승인 범위에서만 수집합니다. 수동 캡처에서 IP와 시각은 관측할 수 있어도 일반적으로 보호된 HTTP 메시지는 읽을 수 없습니다. 기록이 없으면 센서 범위, 캡처 손실과 로그 보존 상태를 확인하세요.
3. **정책과 다른 경로를 조사합니다.** 승인되지 않은 리졸버를 사용하면 조직이 평소 쓰는 로그와 정책에서 질의가 빠질 수 있습니다. 정상 배포, 리졸버 장애, 내부 이름의 별도 처리나 캐시도 같은 수치 변화를 만들 수 있습니다. 프로세스, 적용 정책, 리졸버 경로와 독립적으로 관측한 요청을 대조하세요. 정책 이탈이 확인되면 담당자와 조치한 뒤 알려진 정상 이름과 예상하는 부정 응답으로 복구 경로를 검증합니다. 리졸버 IP나 User-Agent 하나만으로 공격자를 특정할 수 없습니다.

## 5. 오프라인 실습 · 가상 관측 열 건

두 파일을 한 폴더에 내려받고 Python 3.10 이상으로 그 폴더에서 실행하세요. JSONL에는 가상 관측과 DNS 형식의 바이트가 들어 있습니다. 스크립트는 DNS 헤더만 읽어 응답 및 잘림 비트, 하위 4비트 응답 코드와 응답 레코드 수를 확인합니다. 메시지 전체나 EDNS 확장 응답 코드를 검증하지 않습니다. TTL 차감은 자료에 제공된 필드를 사용합니다. 네트워크에는 접속하지 않습니다.

<a href="{{ '/assets/labs/doh-resolution-evidence.py' | relative_url }}" download="doh-resolution-evidence.py">doh-resolution-evidence.py</a> · <a href="{{ '/assets/labs/doh-resolution-evidence-cases.jsonl' | relative_url }}" download="doh-resolution-evidence-cases.jsonl">doh-resolution-evidence-cases.jsonl</a>

```bash
python3 doh-resolution-evidence.py doh-resolution-evidence-cases.jsonl
```

```text
answer: NOERROR answers=1 example_remaining_ttl=85
name_error: NXDOMAIN answers=0
resolution_failure: SERVFAIL answers=0
empty_answer: NOERROR answers=0
upstream_gateway_error: non_success_http_502
html_success: unexpected_media
short_dns_body: invalid_header
dns_query_body: not_a_dns_response
passive_tls_only: no_http_observation
correlated_retry: linked_system_retry
```

명령이 실패하면 작업 폴더와 파일명을 확인하세요. `short_dns_body`는 HTTP가 200이어도 DNS 헤더를 읽을 수 없습니다. `passive_tls_only`는 제한된 관측이라 리졸버나 이름 해석의 성공 여부를 확정할 수 없습니다. 대체 경로 사례에는 이미 상관관계가 확인된 클라이언트 관측을 제공합니다. 시간 순서만으로 재시도를 추론하지 않습니다. 가상 자료는 Python 3.12에서 실행했고, 브라우저·리졸버·프록시 동작은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **HTTP 200인데 NXDOMAIN이 나오는 이유는 무엇인가요?** HTTP 계층은 유효한 DNS 메시지를 운반했습니다. DNS 계층은 해당 리졸버가 보는 범위의 이름 오류를 보고합니다.
- **응답 레코드가 0개면 이름이 없다는 뜻인가요?** 한 섹션의 개수입니다. 코드, 질의 유형, 권한 섹션을 함께 읽어야 합니다.
- **일반 평문 질의와 대체 경로를 어떻게 구분하나요?** 두 시도를 같은 조회로 연결하는 클라이언트 기록을 확인하고, 가능하면 예상된 대체 리졸버 로그를 대조합니다.

열 줄의 결과를 재현하고 120초에서 35초를 뺀 값을 구하세요. `passive_tls_only`에서 결과를 확인하려면 어떤 출처가 더 필요한지 설명하면 실습을 마친 것입니다.

## 공식 참고자료

검토일은 2026-11-22입니다. RFC는 상호 운용에 필요한 동작을 정의합니다. 공급자의 정책과 기본값은 조사 대상 클라이언트의 버전에서 확인하세요.

- 2018년 10월. HTTP 캡슐화, 상태 코드, 캐시와 프라이버시. [RFC 8484 · DNS Queries over HTTPS](https://www.rfc-editor.org/rfc/rfc8484.html)
- 2023년 11월. 지정된 암호화 리졸버의 탐색. [RFC 9462 · Discovery of Designated Resolvers](https://www.rfc-editor.org/rfc/rfc9462.html)
- 2023년 11월. DHCP와 라우터 광고를 이용한 탐색 옵션. [RFC 9463 · Network-designated resolvers](https://www.rfc-editor.org/rfc/rfc9463.html)
- Firefox 기업용 리졸버, 제외 도메인, 대체 경로와 버전 호환성. [Mozilla · DNSOverHTTPS](https://firefox-admin-docs.mozilla.org/reference/policies/dnsoverhttps/)
- Firefox 사용자 설정 모드와 대체 경로 동작. [Mozilla · DoH protection levels](https://support.mozilla.org/en-US/kb/dns-over-https)

[이전 · DNS 기초]({{ '/ko/wiki/dns-investigation/' | relative_url }}) · [관련 · TLS 핸드셰이크]({{ '/ko/wiki/tls-handshake-evidence/' | relative_url }}) · [관련 · DNS 부정 캐시]({{ '/ko/wiki/dns-negative-cache-evidence/' | relative_url }})

## Encrypted Client Hello 조사 이어가기

[TLS Encrypted Client Hello 조사]({{ '/ko/wiki/tls-ech-evidence/' | relative_url }})에서 패킷에 보이는 이름, ECH 수락 여부와 실제 애플리케이션 요청을 구분합니다.

전송 암호화와 위임 과정의 이름 노출 최소화를 구분하려면 [DNS QNAME 최소화]({{ '/ko/wiki/dns-qname-minimisation-evidence/' | relative_url }})에서 확인하세요.
