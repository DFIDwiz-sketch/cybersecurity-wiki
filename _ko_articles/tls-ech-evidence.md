---
title: "TLS Encrypted Client Hello 조사 · 바깥 이름에서 HTTP까지"
description: "가상 사례 여덟 건으로 ECH 설정 광고, GREASE, 수락과 재시도, HTTP 요청 증거를 구분합니다."
category: network
tags: [TLS, ECH, DNS, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /wiki/tls-ech-evidence/
---

**학습 목표.** 패킷에 나타난 TLS 이름과 DNS 응답, 연이어 일어난 두 번의 연결을 보고 ECH 수락 여부와 실제 HTTP 요청을 각각 어떤 증거로 확인할지 판단합니다. [TLS 핸드셰이크 증거]({{ '/ko/wiki/tls-handshake-evidence/' | relative_url }})를 먼저 읽어도 좋습니다.

## 1. ClientHello를 왜 보호하나요?

TLS 연결은 클라이언트가 지원 버전 등의 조건을 제안하는 **ClientHello**로 시작합니다. **SNI(Server Name Indication)**는 클라이언트가 접속하려는 서버 이름을 전달하는 TLS 확장입니다. 하나의 IP 주소에서 여러 서비스를 호스팅할 때 서버는 이 이름을 보고 적절한 설정을 고를 수 있습니다. 일반적인 TLS에서는 이후 HTTP 데이터가 암호화되어도 처음 보낸 ClientHello에 서버 이름이 드러날 수 있습니다.

**ECH(Encrypted Client Hello)**는 실제 서비스 이름이 들어 있는 **안쪽 ClientHello(ClientHelloInner)**를 보호합니다. 클라이언트는 이를 암호화해 관측 가능한 **바깥 ClientHello(ClientHelloOuter)**에 넣습니다. 바깥쪽 SNI에는 보통 ECH 설정의 **공개 이름(public name)**이 들어갑니다. 여러 서비스가 같은 공개 이름을 공유할 수 있습니다. **ECHConfig**는 **HPKE(하이브리드 공개키 암호화)**에 사용할 공개키와 설정을 담습니다. 암호화된 안쪽 메시지는 대응하는 개인키를 갖는 서비스에서 처리합니다. 이후 TLS 핸드셰이크는 접속하려는 서비스를 인증하고 트래픽을 보호할 키를 별도로 마련합니다.

| 용어 | 조사에서의 의미 |
| --- | --- |
| 오리진 이름 | 애플리케이션이 접속하려는 서비스 이름입니다. 예를 들어 `reports.example`입니다. |
| 공개 이름 | 클라이언트가 처음 접속하는 서비스를 가리키는 ECH 설정 속 이름입니다. 예를 들어 여러 서비스가 `edge.example`을 공유할 수 있습니다. |
| HTTPS DNS 레코드 | `ech` 등의 서비스 설정을 광고할 수 있는 DNS 레코드 유형입니다. HTTP 요청 및 암호화된 DNS 전송과는 용도가 각기 다릅니다. |
| GREASE | 사용 가능한 ECH 설정이 없어도 실제처럼 보이는 확장을 보내, 구현이 모르는 확장에도 정상적으로 동작하도록 돕는 기능입니다. |

ECH는 해당 TLS 구간에서 이름 노출을 줄입니다. 센서는 목적지 주소와 패킷 크기, 전송 시각을 여전히 볼 수 있습니다. 평문 DNS 질의에는 원래 질의한 이름이 드러날 수 있습니다. DNS over HTTPS는 클라이언트와 리졸버 사이의 질의를 보호하며 리졸버는 질의 내용을 볼 수 있습니다. 공유 IP나 공개 이름만으로 어느 오리진에 요청했는지 판단하기는 어렵습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/tls-ech-evidence-ko.svg' | relative_url }}" alt="DNS가 ECH 설정을 제공할 수 있습니다. 바깥 ClientHello에는 공개 이름과 암호화된 안쪽 ClientHello가 들어갑니다. 안쪽에는 오리진 이름이 있습니다. 클라이언트나 TLS 종단에서 ECH 수락을 확인하고, 연결된 애플리케이션 기록에서 HTTP 요청을 확인합니다.">
  <figcaption>설정 발견, 패킷 관측, TLS에서의 수락, 애플리케이션 결과를 각각 확인합니다.</figcaption>
</figure>

## 2. 정상 연결과 재시도를 따라가기

가상의 서비스 `reports.example`이 공개 이름 `edge.example`을 사용하는 TLS 종단 뒤에 있다고 가정합니다.

1. 클라이언트는 HTTPS DNS 레코드 등에서 사용 가능한 ECH 설정을 얻습니다. 조사자가 나중에 DNS를 다시 조회하면 캐시, 리졸버 정책, 배포 시점 차이 때문에 클라이언트가 받은 레코드와 다른 결과를 볼 수 있습니다.
2. 클라이언트는 종단에서 열 수 있게 안쪽 메시지를 암호화하여 바깥 메시지로 보냅니다. 이를 캡처하고 해석한 센서는 `edge.example`과 ECH 확장을 기록할 수 있습니다. 다른 연결에서 같은 확장을 찾아도 패킷의 확장만으로 실제 ECH 제안과 GREASE를 구분할 수 없습니다.
3. 서비스가 ECH를 수락하면 클라이언트는 암호학적으로 수락 신호를 확인하고 안쪽 메시지로 핸드셰이크를 이어갑니다. 원래 접속하려는 오리진은 통상의 방식으로 인증합니다. 이 연결과 일치하는 클라이언트 또는 승인된 TLS 종단의 진단 결과로 ECH 수락을 확인할 수 있습니다. HTTP 요청 여부는 해당 연결과 대응하는 애플리케이션 기록에서 확인합니다.
4. 클라이언트에 예전 설정이 캐시됐거나 일부 엣지에 키 배포가 늦으면 실제 ECH 제안이 거부될 수 있습니다. 복구용 핸드셰이크에서는 **공개 이름**의 인증서와 핸드셰이크를 검증한 뒤, 서버가 제공한 인증된 새 설정을 클라이언트가 지원하면 새 연결로 재시도할 수 있습니다. 거부된 연결에는 클라이언트의 애플리케이션 데이터를 보내지 않습니다. 재시도는 별도 연결로 추적하고 결과도 따로 확인합니다. 공개 이름 인증에 실패한 연결에서 받은 대체 설정은 신뢰할 수 없습니다.

이 장은 2026년 3월에 발행된 ECH와 DNS 설정 전달 표준을 기준으로 합니다. 초안 시절 패킷을 해석할 때는 해당 구현이 따랐던 초안을 확인하세요. Cloudflare의 2026년 4월 제품 문서는 공유 바깥 이름으로 `cloudflare-ech.com`을 제시합니다. 이는 해당 공급자의 예시이므로 조사 대상의 실제 설정을 확인합니다.

## 3. 관측값으로 어디까지 말할 수 있나요?

| 관측값 | 확인할 수 있는 것 | 다음 증거 |
| --- | --- | --- |
| DNS의 HTTPS 응답에 `ech`가 있음 | 관측된 리졸버가 ECH 설정을 광고했습니다. | 앱이 그 리졸버와 응답을 사용했는지, ECH를 시도했는지 확인합니다. |
| 바깥 SNI와 ECH 확장이 보임 | 디코더가 해당 구간에서 필드를 읽었습니다. GREASE도 비슷하게 보입니다. | 캡처가 온전한지 확인하고 구간 양 끝 중 한 곳의 진단 기록을 찾습니다. |
| 클라이언트가 ECH 수락을 기록함 | 기록과 연결 매칭이 신뢰할 만하면 해당 연결에서 수락된 것입니다. | 오리진 인증 결과와 별도의 HTTP 증거를 확인합니다. |
| 공개 이름 핸드셰이크 후 재시도함 | 클라이언트 기록이 뒷받침되면 ECH 복구 흐름과 일치합니다. | 공개 이름 인증, 신뢰 가능한 대체 설정, 새 연결 결과를 확인합니다. |
| 승인된 HTTP 종단에 요청 호스트와 상태 코드가 있음 | 해당 구간에서 종단이 그 호스트로 들어온 HTTP 요청을 처리했습니다. | 연결 ID나 추적 ID로 특정 TLS 이벤트에 대응하는지 확인합니다. |
| ECH 확장이 파싱되지 않음 | 해당 센서에서 ECH 확장이 관측되지 않았습니다. | 수집 위치, 누락, 파서 버전과 클라이언트 정책을 확인합니다. |

ECH 확장 하나, 공유 엣지 IP 하나, 재시도처럼 보이는 연결 한 쌍은 각각 약한 단서입니다. 설정 발견 경로에 영향을 주는 주체가 클라이언트의 설정 수신을 방해할 수 있지만, 단계적 배포, 캐시, 미지원 클라이언트, 캡처 누락도 비슷한 결과를 만듭니다. 인증에 실패한 교환은 ECH를 해제해도 된다는 신호로 사용할 수 없습니다. 가설을 좁힐 증거가 생길 때까지 여러 원인을 함께 검토하세요.

## 4. 수집·탐지·대응에 활용하기

1. **구간을 정합니다.** UTC 시각, 클라이언트 버전, 연결 또는 추적 ID, 캡처 위치, 기대한 서비스를 기록합니다. 브라우저에서 엣지까지와 엣지에서 오리진까지를 구분합니다. TCP는 주소와 포트를 남깁니다. QUIC은 가능하면 종단의 연결 ID를 확보하고 패킷과 어떻게 연결했는지 적습니다.
2. **필요한 증거만 수집합니다.** 권한이 있다면 앱이 실제 사용한 리졸버 기록이나 진단 자료를 확보합니다. 레코드 유형, 응답, TTL, 리졸버, 수집 시각을 남기고 바깥 SNI와 파싱 상태를 확인합니다. 승인된 클라이언트나 TLS 종단에서 연결별 ECH 결과와 이름 검증 결과를 얻을 수 있다면 HTTP 요청 ID, 요청 호스트, 상태를 연결합니다. 진단 필드는 제품마다 다릅니다. 개인키·세션 비밀·관련 없는 방문 기록은 사고 자료에 넣지 않습니다.
3. **비교 가능한 기준선을 만듭니다.** 클라이언트 버전, 리졸버 경로, 엣지 리전별로 전체 시도 수와 ECH 거부 또는 핸드셰이크 오류 비율을 비교합니다. 예정된 키 교체 직후 오류가 늘면 영향을 받은 클라이언트의 레코드, TTL, 공개 이름 인증서 유효성, 엣지 키 배포를 확인합니다. 자료가 서로 다르면 시각과 원본을 보존하고 매칭이 모호한 건은 판단을 보류합니다.
4. **수정 결과를 확인합니다.** 서비스 담당자와 광고된 설정과 엣지 키를 맞추거나 승인된 DNS 경로를 복구합니다. 같은 조건으로 다시 검증해 ECH 수락, 오리진 인증, HTTP 결과를 각각 확인합니다. 평문 SNI를 쓰던 탐지의 관측 범위를 다시 측정하고 승인된 종단·리졸버·서비스 자료로 보완합니다.

## 5. 오프라인에서 증거 해석 실습하기

<a href="{{ '/assets/labs/tls-ech-evidence.py' | relative_url }}" download="tls-ech-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/tls-ech-evidence-cases.json' | relative_url }}" download="tls-ech-evidence-cases.json">가상 JSON 자료</a>를 승인된 작업 공간의 같은 폴더에 저장하고 Python 3으로 실행하세요. 자료에 쓰인 필드는 이미 연결 단위로 대조했다고 가정한 간소화된 진단 값입니다. HTTP 증거는 해당 연결과 일치하는지 별도로 표시합니다. 스크립트는 로컬 JSON만 읽으며 패킷을 수집하거나 TLS·DNS 요청을 보내지 않습니다.

```bash
python3 tls-ech-evidence.py tls-ech-evidence-cases.json
```

```text
dns_only: configuration_advertised
wire_only: offer_or_grease
lab_grease: grease_confirmed
accepted_tls: accepted_check_http
accepted_http: accepted_http_observed
rotation_retry: rejected_retry_available
untrusted_outer: rejected_no_trusted_retry
capture_gap: insufficient_evidence
```

파일을 열지 못하면 현재 폴더와 두 파일 이름을 확인하세요. HTTP 결과까지 확인한 것으로 분류되지 않으면 ECH 수락, 오리진 인증, 같은 연결의 HTTP 기록이 모두 있는지 살펴봅니다. `rotation_retry`에서는 인증된 대체 설정이 있어도 새 연결의 결과는 아직 모릅니다. 가상 사례 여덟 건은 Python으로 실행했습니다. 표준과 공급자 동작은 공식 문서로 검토했으며 실제 ECH 종단에서는 실행하지 않았습니다.

## 6. 확인 문제와 완료 기준

- **패킷에서 공개 이름 `edge.example`을 봤습니다. `reports.example`에 연결했다고 볼 수 있나요?** 이 예에서 공개 이름은 앞단 서비스를 가리킵니다. 실제 오리진은 연결이 일치하는 종단 또는 애플리케이션 기록을 확인해야 알 수 있습니다.
- **패킷 디코더에 ECH 확장이 보입니다. ECH가 수락됐나요?** 실제 제안과 GREASE가 모두 이처럼 보일 수 있습니다. 해당 연결의 클라이언트나 서비스 진단 결과를 찾습니다.
- **복구용 핸드셰이크에서 `edge.example` 인증에 성공했습니다. `reports.example`도 인증됐나요?** 오리진 핸드셰이크는 별도로 확인합니다. 복구용 연결은 신뢰할 수 있는 설정이나 표준이 정의한 신호를 확인하는 데 쓰이며 클라이언트 HTTP 요청을 보내지 않습니다.
- **ECH 수락 기록으로 GET 요청까지 확인할 수 있나요?** 같은 연결의 HTTP 기록을 확보합니다. 어느 연결과 일치하는지 모르면 요청 여부도 보류합니다.

여덟 개 출력이 모두 일치하고, 각 사례에서 설정 발견·확장 관측·ECH 수락·오리진 인증·HTTP 결과의 확인 여부를 설명할 수 있으면 실습을 마친 것입니다.

## 공식 참고자료

2026년 11월 23일 검토했습니다.

- ECH 수락·거부·GREASE의 2026년 3월 표준. [IETF RFC 9849 §§6.1.4–6.2](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4)
- 2026년 3월 ECH 설정 전달과 2023년 10월 서비스 바인딩 레코드 형식. [IETF RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html) · [IETF RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html)
- 2022년 2월 HPKE 명세. [IETF RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)
- 공급자의 바깥 이름 예시와 적용 범위. 2026년 4월 17일 갱신. [Cloudflare · ECH Protocol](https://developers.cloudflare.com/ssl/edge-certificates/ech/)

[이전 · TLS 핸드셰이크 증거]({{ '/ko/wiki/tls-handshake-evidence/' | relative_url }}) · [다음 · DNS over HTTPS 조사]({{ '/ko/wiki/doh-resolution-evidence/' | relative_url }}) · [관련 · QUIC과 HTTP/3]({{ '/ko/wiki/quic-http3-evidence/' | relative_url }})

[관련 글 · DNS HTTPS 레코드와 실제 접속 경로]({{ '/ko/wiki/dns-https-record-evidence/' | relative_url }})
