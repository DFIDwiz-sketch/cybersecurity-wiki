---
title: "QUIC과 HTTP/3 · UDP 트래픽에서 요청 증거까지"
description: "패킷 캡처의 한계, 클라이언트 로그와 오프라인 실습으로 HTTP/3 발견, QUIC 시도, 실제 요청 프로토콜과 프록시 구간을 구분합니다."
category: network
tags: [QUIC, HTTP, TLS, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/quic-http3-evidence/
---

**학습 목표.** UDP 트래픽, 브라우저 요청, 역방향 프록시 로그를 보고 어느 연결에서 QUIC을 사용했는지, 특정 요청에는 어떤 HTTP 버전이 쓰였는지 설명합니다. HTTP/2 등으로 전환됐다고 판단하려면 어떤 증거가 필요한지도 살펴봅니다. TLS의 역할이 처음이라면 [TLS 핸드셰이크 증거]({{ '/ko/wiki/tls-handshake-evidence/' | relative_url }})를 먼저 읽어 보세요.

## 1. UDP와 HTTP 요청 사이에서 무슨 일이 일어나나요?

**UDP**는 데이터그램을 전달합니다. **QUIC**은 UDP 위에서 동작하는 보안 전송 프로토콜입니다. TLS 1.3 핸드셰이크를 사용해 키를 마련하고, 설정된 TLS 정책에 따라 상대를 인증합니다. 안정적인 스트림, 손실 복구, 혼잡 제어는 QUIC이 담당합니다. **HTTP/3**는 HTTP 메시지를 QUIC 스트림에 실어 보냅니다. **ALPN**은 핸드셰이크 중 애플리케이션 프로토콜을 협상하는 기능이며, HTTP/3의 식별자는 보통 `h3`입니다. 브라우저는 한 연결에서 여러 요청을 처리할 수 있으므로 연결 기록으로 특정 요청을 식별하려면 추가 근거가 필요합니다.

클라이언트는 `Alt-Svc: h3=":443"` 같은 **Alt-Svc** 헤더나, 클라이언트가 지원한다면 DNS HTTPS 레코드 등으로 HTTP/3 접속 지점을 알 수 있습니다. 이런 정보는 사용할 수 있는 대안이 있다는 뜻입니다. 실제 사용 여부는 협상 결과와 요청 기록에서 확인합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/quic-http3-ko.svg' | relative_url }}" alt="HTTP/3 발견 단서가 QUIC 시도로 이어질 수 있습니다. 요청 기록에는 QUIC에서의 h3 또는 TCP에서의 h2가 나타날 수 있습니다. 프록시에서 원본 서버로 가는 구간에는 별도의 HTTP 버전이 쓰일 수 있습니다.">
  <figcaption>발견 단서, 연결 결과, 실제 요청 프로토콜을 각각 기록하세요. 엣지가 TLS를 종료한다면 엣지에서 원본 서버까지는 별도의 구간입니다.</figcaption>
</figure>

## 2. 정상 브라우저 요청을 따라가 봅시다

가상 사례에서 브라우저는 먼저 `https://catalog.example.test/`를 HTTP/2로 가져오고 HTTP/3를 광고하는 `Alt-Svc` 헤더를 받습니다. 이후 `/items` 요청은 QUIC을 사용합니다. 브라우저는 완료된 요청의 프로토콜을 `h3`로 표시하고, 엣지 로그에는 클라이언트 쪽 구간이 HTTP/3로 기록됩니다. 엣지는 상위 서버에 HTTP/2로 요청해 응답을 받습니다. 브라우저에서는 HTTP/3로, 원본 서버에서는 HTTP/2로 기록돼도 두 기록이 같은 애플리케이션 요청을 나타낼 수 있습니다.

다른 예에서 승인된 테스트 클라이언트는 QUIC 연결 실패와 그에 이어진 동일 요청의 재시도를 연결해 기록합니다. 재시도는 HTTP/2로 완료됩니다. 이렇게 실패한 시도와 완료된 요청이 연결되면 폴백을 뒷받침합니다. 클라이언트는 TCP와 QUIC을 가까운 시각에 시작해 먼저 준비되는 쪽을 쓰거나 기존 연결을 재사용할 수도 있습니다. 가까운 시각에 UDP 패킷과 성공한 TCP 요청이 보이면 가능한 시간 순서로 기록하세요. 전환을 판단하려면 요청 간 연결과 클라이언트 결과를 확인해야 합니다. 폴백을 확인해도 처음 실패한 원인은 별도 조사 대상입니다.

| 관측 | 뒷받침하는 판단 | 다음 확인 |
| --- | --- | --- |
| Alt-Svc에서 `h3` 광고 | 원본 서비스가 대체 접속 지점을 광고함 | 완료된 요청에는 어떤 프로토콜이 표시됐나요? |
| 목적지 포트 443의 UDP | 해당 경로의 UDP 활동 | 지원하는 디코더나 종단 기록으로 QUIC을 식별할 수 있나요? |
| 디코딩된 클라이언트 QUIC Initial | 관측 경로에서 QUIC 시작 패킷을 보냄 | 상대 응답이 보이나요? 클라이언트에 연결 결과가 남았나요? |
| 완료된 클라이언트 요청에서 `h3` | 관측한 클라이언트 구간에서 HTTP/3 사용 | 어느 엣지가 처리했고 상위 연결에서는 무슨 일이 있었나요? |
| 클라이언트의 `h2` 요청에 QUIC 실패가 연결됨 | 해당 요청의 폴백을 뒷받침 | 순서, 클라이언트 오류, 캡처 범위와 정책을 대조해 원인 조사 |

## 3. 수동 캡처로 어디까지 확인할 수 있나요?

캡처 위치에 따라 보이는 내용이 다릅니다. 적절한 위치에서는 UDP 헤더와 시각, QUIC 긴 헤더의 버전과 연결 ID 같은 정보를 볼 수 있습니다. 호환 디코더는 필요한 Initial 트래픽을 확보했다면 지원하는 QUIC 버전의 공개 입력값으로 Initial 보호 키를 유도할 수 있습니다. 이 경우 바깥쪽 TLS ClientHello와 그 안에 있는 메타데이터를 읽을 수 있습니다. 핸드셰이크가 여러 패킷으로 나뉘었다면 재조립할 수 있을 만큼 캡처가 있어야 합니다. **Encrypted Client Hello(ECH)**를 사용하면 안쪽 ClientHello는 별도로 보호됩니다. 바깥쪽에서 이름을 읽었다면 그 메시지에서 관측한 이름으로 기록하세요. 협상된 애플리케이션 프로토콜과 HTTP 본문을 확인하려면 보통 권한 있는 종단이나 TLS 종료 지점의 증거가 필요합니다. 클라이언트의 ALPN 제안은 후보 목록입니다.

5튜플은 출발지와 목적지의 IP·포트, 그리고 전송 프로토콜로 구성됩니다. QUIC 연결은 연결 마이그레이션이나 NAT 매핑 변경으로 주소나 포트가 달라져도 이어질 수 있습니다. 연결 ID도 바뀔 수 있고, 관측 방향과 위치에 따라 해석 범위가 달라집니다. 튜플이 바뀐 시점과 캡처 구간을 보존하고, 동일 연결인지는 종단 기록으로 대조하세요. 캡처 도구나 클라이언트가 부여한 ID는 그 도구나 세션의 범위에서 해석합니다. QUIC 연결 ID로 HTTP 요청 ID를 대신할 수는 없습니다.

## 4. 경보와 수집 공백 조사하기

네트워크 센서가 TCP 웹 세션을 분석하고 UDP는 흐름만 남긴다면 정책을 검증하기 어려운 구간이 생깁니다. QUIC 연결은 일반 웹 트래픽일 수도 있고 예상한 정책 범위를 벗어난 애플리케이션 트래픽일 수도 있습니다. 프로토콜이나 포트만으로 요청, 신원, 의도를 판단하기 어렵습니다. 특정 프로토콜을 허용하거나 제한하는 정책을 검증할 때는 해당 경로의 규칙과 실제 집행 결과를 확인하세요. 승인된 종단 테스트에서 가시성과 집행 결과를 함께 확인할 수 있습니다.

| 자료 | 수집 요건 | 검토 방법 |
| --- | --- | --- |
| 방화벽 또는 흐름 기록 | 센서 위치, 방향, 시각, 튜플, 동작 필드 | 일치하는 UDP 차단 기록은 그 장비의 정책 결정을 보여 줌. 폴백 원인으로 판단하기 전에 시각과 관련 요청 대조. |
| 패킷 캡처 | 관련 인터페이스, 가능하면 양방향, 캡처 손실 정보와 호환 디코더 | 관측 프로토콜과 방향 확인. 단방향 UDP나 Initial 재전송에는 손실, 경로 문제, 캡처 공백이 영향을 줄 수 있음. |
| 브라우저 또는 클라이언트 | 완료된 요청의 프로토콜과 시각, 시도 사이 관계를 보여 주는 전송 진단 자료 | Chrome DevTools의 Network 요청 표에서 **Protocol**을 표시하고 필요하면 **Remote address**를 추가. 요청 행에는 실패한 모든 연결 시도가 보이지 않음. |
| 엣지와 원본 서버 로그 | 구간을 명시한 프로토콜, 시각, 접속 지점과 신뢰할 수 있는 연계 ID | 프로토콜이 어느 구간에 해당하는지 확인. 공유 요청 ID의 서비스와 시간 범위를 좁히고 누가 설정했는지 확인. |

영향받은 장치, URL, 시간대를 정리한 뒤 클라이언트 결과와 엣지 로그, 방화벽 동작과 캡처 범위를 대조하세요. 특정 엣지, 경로, 정책 변경 또는 클라이언트 집단에만 발생하는지 살펴봅니다. 비슷한 설정에서 동작이 확인된 승인 요청과 비교하세요. 목적지가 QUIC 요청을 받을 수 있는지 확인하고, 패킷 크기나 경로 문제가 의심되면 [경로 MTU 증거]({{ '/ko/wiki/pmtu-icmp-evidence/' | relative_url }})를 참고하세요. 초기 증거를 보존한 뒤 네트워크나 애플리케이션 담당자에게 전달합니다. 로그와 내보낸 자료에 민감한 URL이나 세션 식별자가 있을 수 있으므로 조사에 필요한 범위를 보존하세요.

## 5. 가상 관측 자료로 실습하기

[quic-http3-review.py]({{ '/assets/labs/quic-http3-review.py' | relative_url }}){: download="quic-http3-review.py" }와 [quic-http3-cases.json]({{ '/assets/labs/quic-http3-cases.json' | relative_url }}){: download="quic-http3-cases.json" }을 본인 작업 공간의 같은 디렉터리에 저장합니다. Python 3.8 이상에서 `python3 quic-http3-review.py`를 실행하세요. JSON에는 패킷 대신 가상 사례 8건을 요약했습니다. 프로그램은 표준 라이브러리만 사용하며 네트워크에 접속하지 않습니다.

| 사례 | 기대 해석 |
| --- | --- |
| `client-used-h3` | 클라이언트 요청이 h3 사용 |
| `fallback-supported` | 요청이 h2를 사용했고, 그 요청에 실패한 QUIC 시도가 연결됨 |
| `parallel-traffic-unlinked` | 요청은 h2를 사용함. 가까운 시각의 QUIC Initial과 관계는 미확인. |
| `advertisement-only`, `udp-port-only`, `quic-initial-only` | 광고, UDP 활동, QUIC 시작 단서는 서로 다름. 각각으로 요청 프로토콜을 확정할 수 없음. |
| `edge-terminates-h3` | 클라이언트 h3와 상위 서버 h2는 서로 다른 구간의 관측 |
| `conflicting-client-records` | 두 프로토콜 기록이 모두 같은 클라이언트 요청을 가리킴. 요청 ID, 리디렉션과 중간 구간을 재확인. |

JSON 파일을 찾지 못하면 디렉터리와 두 파일명을 확인하세요. 출력된 사례 이름과 결과를 표와 대조합니다. 실습 자료에는 알고 있는 시도 관계가 이미 표시돼 있습니다. 프로그램은 가까운 시각만으로 시도 관계를 추정하지 않습니다. Python 3.12.14에서 가상 사례 8건을 모두 실행했습니다.

### 승인된 종단에서 직접 비교하기

본인이 소유하거나 명시적으로 테스트를 승인받은 신뢰할 수 있는 HTTPS 종단을 사용하세요. `H3_LAB_URL`에 해당 URL을 설정하고 클라이언트 빌드, 프록시 설정과 네트워크 경로를 기록합니다. POSIX 셸과 HTTP3 기능을 지원하는 curl 빌드가 필요합니다. 크기가 작은 공개 테스트 응답을 제공하는 승인된 URL을 사용하세요. curl 7.88.0 이상에서 `--http3-only`는 QUIC 연결을 맺지 못하면 실패합니다. 폴백을 허용하는 `--http3`는 이전 HTTP 버전을 사용할 수 있습니다. 인증서 검증은 켜 둡니다.

```sh
curl --version
curl --http3-only --max-time 15 --silent --show-error --output /dev/null \
  --write-out 'http=%{http_version} status=%{response_code} peer=%{remote_ip}\n' "$H3_LAB_URL"
curl --http3 --max-time 15 --silent --show-error --output /dev/null \
  --write-out 'http=%{http_version} status=%{response_code} peer=%{remote_ip}\n' "$H3_LAB_URL"
```

각 실행의 종료 코드, 응답에 쓰인 HTTP 버전과 curl이 보고한 상대 주소를 기록하세요. HTTP 상태는 애플리케이션의 응답을 나타냅니다. HTTP/3로 응답을 받으면 `http=3`이 표시됩니다. 시간 초과만으로 UDP 차단을 확정하기는 어렵습니다. 폴백을 허용한 명령에서 HTTP/2가 나오면, 시도가 실패했는지 또는 정책이 영향을 줬는지 판단하기 전에 클라이언트 전송 진단 자료를 확인하세요. curl과 Chrome 예제는 공식 문서로 검토했으며 실제 종단을 사용한 비교 실행은 검증 범위에 포함되지 않습니다.

## 6. 확인 문제와 해설

1. **HTTP/2 응답에서 `Alt-Svc` 헤더만 확보했습니다. 그 응답에는 어느 프로토콜이 쓰였나요?** HTTP/2입니다. 헤더는 이후에 사용할 수 있는 대안을 알립니다.
2. **캡처에 QUIC Initial이 있고 완료된 요청 행에는 h2라고 나옵니다. 폴백이 발생했나요?** 요청에 h2를 썼고 관측한 흐름에서 QUIC이 시작됐음을 알 수 있습니다. 해당 요청에 연결된 시도와 결과를 보여 주는 클라이언트 자료가 더 필요합니다.
3. **검증한 요청 ID가 같은데 엣지는 h3, 원본 서버는 h2라고 기록했습니다. 어느 쪽이 틀렸나요?** 둘 다 맞을 수 있습니다. 역방향 프록시는 클라이언트 연결을 종료하고 상위 서버에 독립된 연결을 열 수 있습니다.

**완료 기준.** 사례 8건을 재현하세요. 사례마다 관측 구간과 근거가 뒷받침하는 가장 강한 결론, 다음에 확인해야 할 항목 하나를 적어 보세요.

## 공식 참고자료

2026년 11월 22일 검토. RFC는 각각의 발행일을 표시했습니다. curl과 Chrome 자료는 검토 시점에 문서화된 인터페이스를 설명합니다. 캡처와 클라이언트 지원은 버전과 설정에 따라 다릅니다.

- IETF [RFC 9000 · QUIC 전송, 2021년 5월](https://www.rfc-editor.org/rfc/rfc9000.html) · [RFC 9001 · QUIC에서 TLS 사용, 2021년 5월](https://www.rfc-editor.org/rfc/rfc9001.html)
- IETF [RFC 9114 · HTTP/3와 대체 지점 발견, 2022년 6월](https://www.rfc-editor.org/rfc/rfc9114.html) · [RFC 9460 · DNS SVCB·HTTPS 레코드, 2023년 11월](https://www.rfc-editor.org/rfc/rfc9460.html)
- IETF [RFC 9312 · QUIC 관측, 2022년 9월](https://www.rfc-editor.org/rfc/rfc9312.html) · [RFC 9849 · TLS ECH, 2026년 3월](https://www.rfc-editor.org/rfc/rfc9849.html)
- [curl 매뉴얼 · HTTP/3 옵션](https://curl.se/docs/manpage.html#--http3) · [Chrome DevTools · Network 참고자료](https://developer.chrome.com/docs/devtools/network/reference#columns)

[이전 · TLS 핸드셰이크 증거]({{ '/ko/wiki/tls-handshake-evidence/' | relative_url }}) · [다음 · HTTP 프록시 응답 증거]({{ '/ko/wiki/http-proxy-response-evidence/' | relative_url }})

## Encrypted Client Hello 조사 이어가기

[TLS Encrypted Client Hello 조사]({{ '/ko/wiki/tls-ech-evidence/' | relative_url }})에서 패킷에 보이는 이름, ECH 수락 여부와 실제 애플리케이션 요청을 구분합니다.

## UDP 데이터그램의 송신과 수신 확인하기

[UDP 데이터그램 조사]({{ '/ko/wiki/udp-datagram-evidence/' | relative_url }})에서 패킷 캡처와 실제 수신을 구분하고, 작은 버퍼에서 데이터그램이 잘리는 과정을 루프백으로 확인하세요.
