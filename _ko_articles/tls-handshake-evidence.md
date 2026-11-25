---
title: "TLS 핸드셰이크와 관측 증거 · 연결부터 HTTP까지"
description: "TLS 1.3의 단계와 센서 가시성을 비교하고 오프라인 검증 네 가지를 실행합니다."
category: network
tags: [TLS, Network Security, Zeek, Blue Team, DFIR, OpenSSL]
level: Beginner
updated: "2026-11-20"
translation_url: /wiki/tls-handshake-evidence/
---

**학습 목표.** TCP 연결, TLS 핸드셰이크, HTTP 요청을 다른 단계로 읽습니다. 센서에서 보이는 메타데이터로 조사 범위를 좁히고, 인증 실패나 앱 오류는 어떤 기록으로 확인해야 하는지 익힙니다.

## 1. HTTPS 접속을 세 단계로 나누기

브라우저가 HTTPS로 상태 조회 페이지를 열 때도 전달, 보안 채널, 앱 요청은 따로 일어납니다. TCP 기반 HTTPS에서 먼저 양쪽이 연결을 설정합니다. TLS가 암호화 방식과 세션 키를 확립하고 서버 신원을 확인합니다. 그다음 앱은 HTTP 요청과 응답을 교환합니다. 아래 흐름은 인증서 기반의 전체 TLS 1.3 핸드셰이크를 단순화한 것입니다. 재개·PSK·0-RTT, 클라이언트 인증은 별도 경우입니다.

![TCP 연결 · 실제 전송 경로 → ClientHello / ServerHello · 협상 → TLS 1.3 암호화 구간 · 서버 증명 → HTTP 요청·응답 · 앱 결과]({{ '/assets/diagrams/tls-handshake-ko.svg' | relative_url }})

| 단계 | 확인할 질문 | 대표 증거 |
| --- | --- | --- |
| TCP | 서버와 전송 연결이 성립했나? | SYN·SYN-ACK·ACK, 네트워크 상태 |
| TLS | 암호화 채널과 상대 신원을 검증했나? | 협상 기록, 클라이언트 검증 결과 |
| HTTP | 어떤 요청을 보내 어떤 응답을 받았나? | TLS 종단의 요청 ID·라우트·상태 코드 |
| 사용자 로그인 | 앱이 어떤 계정에 세션을 부여했나? | 앱·ID 공급자의 인증 및 세션 기록 |

HTTP/3는 QUIC 위에서 동작합니다. QUIC은 TLS를 통합하지만 TCP의 3단계 연결을 사용하지 않습니다. UDP 443만으로 HTTP/3나 TLS 상태를 확정하지 마세요.

## 2. ClientHello에서 HTTP까지 따라가기

1. **ClientHello.** 클라이언트가 지원 버전, 키 합의에 필요한 값, 암호 설정과 확장을 제안합니다. SNI(Server Name Indication)는 서버가 가상 호스트 설정을 고르는 데 쓰는 요청 이름입니다. ALPN(Application-Layer Protocol Negotiation)으로는 HTTP/2의 h2처럼 상위 프로토콜 후보를 제안할 수 있습니다.
2. **ServerHello.** 서버가 버전과 암호 스위트 등 협상값을 선택합니다. 일반적인 TLS 1.3 전체 핸드셰이크에서는 이 이후의 EncryptedExtensions, 증명용 인증서 메시지, Finished 등이 핸드셰이크 키로 보호됩니다. 클라이언트는 정책과 이름에 따라 인증서와 서명 등을 검증합니다.
3. **앱 데이터.** 검증과 핸드셰이크 이후 HTTP 데이터를 암호화해 주고받습니다. 같은 TLS 연결이 여러 HTTP 요청을 운반할 수 있습니다. TLS 종단이 프록시라면 클라이언트–프록시 연결과 프록시–앱 연결을 각각 추적해야 합니다.

SNI는 클라이언트가 제안한 이름, 인증서 SAN은 인증서가 담는 이름, HTTP Host 또는 :authority는 앱이 요청한 대상입니다. 세 값을 따로 기록하세요. 예를 들어 SNI가 보인다는 사실만으로 서버가 그 이름에 맞는 인증서를 줬거나 앱이 해당 요청을 받았다고 결론 내리지 않습니다.

## 3. 센서가 볼 수 있는 범위

| 정보 | 일반적인 수동 캡처의 한계 | 확인할 곳 |
| --- | --- | --- |
| 주소·포트·시각·방향 | NAT·프록시·손실·미러 위치의 영향 | 방화벽과 연결 로그 |
| 제안한 TLS 버전 및 SNI | 초기 메시지를 놓칠 수 있음. ECH의 내부 이름은 보호될 수 있음 | 센서, 클라이언트와 승인된 종단 |
| 협상된 TLS 버전·암호 스위트 | ServerHello가 관측·분석된 경우 | TLS 센서 또는 종단 로그 |
| TLS 1.3 서버 인증서·선택된 ALPN | 인증서 기반 전체 핸드셰이크에서 해당 메시지는 암호화됨 | 클라이언트·서버의 검증 또는 종단 로그 |
| URL 경로, 요청 헤더, 쿠키 | 정상 암호화 구간에서는 평문을 관측하지 못함 | 승인된 프록시·애플리케이션 로그 |

예전 TLS 1.2 전체 핸드셰이크 자료에는 평문 인증서 메시지가 보일 수 있습니다. 그 캡처 예를 TLS 1.3에 그대로 적용하면 안 됩니다. 2026년 7월 RFC 9846은 기존 TLS 1.3 명세 RFC 8446을 대체합니다. 2026년 3월 RFC 9849의 ECH는 내부 ClientHello를 암호화합니다. 외부 ClientHello가 남으므로 관측되는 외부 이름이 실제 요청 이름과 일치하는지 단정하지 않습니다. ECH 확장이 보이거나 SNI 필드가 비어도 그것만으로 ECH 수락이나 공격을 입증할 수 없습니다.

Zeek의 **ssl.log**는 TLS 메타데이터 이름입니다. 버전, server_name, established 등은 분석기 설정과 관측된 메시지에 따라 다릅니다. established 값은 센서의 관측 결과로 읽으세요. 클라이언트의 이름·루트 검증 정책이나 앱의 로그인 성공을 증명하려면 다른 자료가 필요합니다. 설치 버전과 현재 공식 필드 정의를 대조합니다.

## 4. 정상 장애와 보안 가설을 함께 확인하기

| 관측 | 정상 원인 후보 | 추가 증거 |
| --- | --- | --- |
| TCP 연결 후 TLS 검증 실패 | 잘못된 서비스 이름, 사설 CA 누락, 만료 | 클라이언트 오류, 대상 이름, 인증서 경로, 변경 기록 |
| TLS 성립 후 HTTP 404 | 경로 오타, 라우팅, 앱 정책 | 종단·앱의 요청 ID, 라우트 및 생성한 계층 |
| 새 인증서 또는 신뢰 경로 | 정상 갱신, 승인 프록시, 배포 변경 | 인증서와 발급자, 대상, 변경 승인 비교 |
| SNI 없음 또는 다른 이름 관측 | 캡처 손실, ECH, 프록시, 다른 클라이언트 동작 | 관측 위치, 핸드셰이크 메시지, 종단 로그 |

의심스러운 재지정이나 신뢰 설정 변경이 있다면 승인된 프록시·관리 변경과 먼저 대조하세요. 확인되지 않은 징후 하나로 중간자 공격이나 감염을 단정하지 않습니다. 조사 기록에는 UTC·센서 위치·주소와 포트·클라이언트 오류·요청 ID·프록시 양쪽 연결을 남깁니다. 허가된 정상 요청을 한 건 발생시켜 어느 지점에서 어떤 필드가 생기는지 확인하세요. 인증서 검증 장애는 원인을 고쳐 재시험합니다.

## 5. 오프라인 TLS 실습

[tls-handshake-evidence.py]({{ '/assets/labs/tls-handshake-evidence.py' | relative_url }})

Python 3, TLS 1.3과 ALPN을 지원하는 Python SSL, OpenSSL 3.x 실행 파일이 필요합니다. 실습은 임시 인증서와 키를 만들고 명시적으로 신뢰하는 시험용 클라이언트를 준비합니다. Python MemoryBIO가 실제 TLS 레코드를 **메모리 안에서** 주고받으며 HTTP 메시지를 대조합니다. TCP 소켓, 외부 호스트, 운영 저장소와 통신하지 않습니다. 만든 키는 임시 폴더에 두며 정상 종료 후 제거합니다.

~~~bash
python3 tls-handshake-evidence.py
~~~

| 시험 | 기대 결과 | 해석 |
| --- | --- | --- |
| 올바른 이름·신뢰·/health | TLSv1.3, http/1.1, 200 OK | TLS 성공 뒤 앱 응답 |
| 같은 설정에서 /missing | TLSv1.3, http/1.1, 404 Not Found | TLS 성공 뒤 앱의 다른 결과 |
| 다른 이름 | Hostname mismatch | 클라이언트의 이름 검증 실패 |
| 신뢰 저장소에 시험 인증서 없음 | self-signed certificate | 클라이언트의 신뢰 확인 실패 |

마지막에 `PASS: two authenticated HTTP exchanges and two TLS verification failures`가 표시됩니다. OpenSSL 실행 파일이 없다면 설치와 PATH부터 확인합니다. 버전 오류는 Python이 연결한 SSL과 CLI를 각각 확인하세요. 이 실습은 실제 TLS 처리와 확인 결과를 실행 검증했습니다. 응답 상태는 교육용으로 작성한 값입니다. Zeek, TCP, QUIC과 ECH 캡처 검증은 별도입니다.

## 6. 확인 문제와 완료 기준

- **정상 TCP 연결 뒤 인증서 오류가 났다면 HTTP 응답을 받았나요?** 전송 연결과 TLS 오류는 각각 기록합니다. HTTP 증거는 종단·앱에서 확인하세요.
- **TLS가 성공했는데 404가 나올 수 있나요?** 가능합니다. 404는 보안 채널 이후 반환될 수 있는 앱 계층 결과입니다.
- **센서의 SNI가 보이면 TLS 인증도 성공했나요?** 요청 측 제안이 관측된 것입니다. 인증서와 클라이언트 검증 결과를 확인하세요.

네 시험 결과에서 어떤 단계까지 입증됐는지와 운영 로그에서 더 확인할 자료를 한 줄씩 적으면 완료입니다.

[이전 · 인증서 검증]({{ '/ko/wiki/certificate-validation/' | relative_url }}) · [다음 · HTTP 로그 조사]({{ '/ko/wiki/http-evidence/' | relative_url }})

## 공식 자료

2026년 11월 20일 검토. 표준 발행일과 실제 설치 제품의 기능·수집 범위를 구분하세요.

- [IETF RFC 9846 · TLS 1.3, July 2026](https://datatracker.ietf.org/doc/html/rfc9846)
- [IETF RFC 9849 · Encrypted Client Hello, March 2026](https://datatracker.ietf.org/doc/html/rfc9849)
- [IETF RFC 9001 · TLS with QUIC, May 2021](https://www.rfc-editor.org/rfc/rfc9001.html)
- [Zeek · ssl.log](https://docs.zeek.org/en/current/reference/logs/ssl.html)
- [Python 3.12 · SSL and Memory BIO](https://docs.python.org/3.12/library/ssl.html)
- [OpenSSL 3.5 · openssl req](https://docs.openssl.org/3.5/man1/openssl-req/)

## TLS 관측을 인증서 투명성과 연결하기

[서비스에서 본 인증서를 별도로 확보한 발급 증거와 대조합니다.]({{ '/ko/wiki/certificate-transparency-evidence/' | relative_url }})

## 이어서 읽기

[상호 TLS(mTLS) 입문]({{ '/ko/wiki/mtls-client-identity-evidence/' | relative_url }}) · TLS 종료 지점에서 클라이언트를 인증하는 과정과 애플리케이션 권한 판단을 로컬 연결 여섯 가지로 비교하세요.

## QUIC과 HTTP/3 조사 이어서 읽기

[QUIC과 HTTP/3 요청 증거]({{ '/ko/wiki/quic-http3-evidence/' | relative_url }}) · 발견 단서와 연결 시도, 프록시 구간별 요청 프로토콜을 대조합니다.

## HTTPS로 보호된 DNS 질의 조사하기

[DNS over HTTPS 조사]({{ '/ko/wiki/doh-resolution-evidence/' | relative_url }})에서 연결, HTTP 상태, DNS 응답과 실제 리졸버 선택을 구분합니다.

## 메일 서버 간 TLS 정책 확인하기

[MTA-STS와 TLS-RPT 조사]({{ '/ko/wiki/smtp-mta-sts-evidence/' | relative_url }})에서 SMTP의 MX 선택, 인증서 검사와 TLS 실패 보고를 연결해 보세요.

## Encrypted Client Hello 조사 이어가기

[TLS Encrypted Client Hello 조사]({{ '/ko/wiki/tls-ech-evidence/' | relative_url }})에서 패킷에 보이는 이름, ECH 수락 여부와 실제 애플리케이션 요청을 구분합니다.

## HSTS 전환과 서버 리디렉션 확인

[HSTS 전환 조사]({{ '/ko/wiki/http-hsts-evidence/' | relative_url }})에서 브라우저가 전송 전에 HTTPS로 바꾼 요청과 서버가 응답한 리디렉션을 구분합니다.

## TLS 세션 재개와 조기 데이터 이어서 읽기

[TLS 1.3 세션 재개와 0-RTT 조사]({{ '/ko/wiki/tls-resumption-evidence/' | relative_url }})에서 PSK 제안, 재개 수락과 앱 요청 처리에 필요한 증거를 구분합니다.
