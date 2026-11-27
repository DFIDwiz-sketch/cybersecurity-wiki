---
title: "TLS 1.3 하이브리드 키 합의 · 실제 선택된 그룹 확인하기"
description: "ClientHello의 제안, 실제 합의 그룹, 인증서 검증, HTTP 결과를 구분하고 OpenSSL 루프백 실습 네 가지로 확인합니다."
category: network
tags: [TLS, TLS 1.3, Post-Quantum Cryptography, ML-KEM, OpenSSL, Blue Team]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/tls-hybrid-key-agreement-evidence/
---

패킷의 ClientHello에 `X25519MLKEM768`이 보입니다. 이 연결에 양자내성 하이브리드 키 합의가 적용됐다고 보고해도 될까요? 클라이언트 제안에 이어 최종 ServerHello, 핸드셰이크 성공 여부, 관측한 연결 구간을 차례로 확인해야 합니다.

## 1. 키 합의, 상대 인증, 트래픽 보호의 역할

**이름이 지정된 그룹(named group)**은 TLS 양쪽이 어떤 방식으로 키 재료를 교환하는지 지정합니다. **X25519**는 임시 타원곡선 디피–헬먼(ECDHE) 연산으로 양쪽에 같은 공유 비밀값을 만듭니다. **ML-KEM**은 NIST FIPS 203에 정의된 키 캡슐화 방식입니다. 한쪽이 공개 캡슐화 키로 공유 비밀값과 암호문을 만들면, 해당하는 개인 역캡슐화 키를 가진 쪽이 그 암호문에서 같은 비밀값을 얻습니다.

**X25519MLKEM768**은 X25519와 ML-KEM-768을 하나의 TLS 그룹으로 묶습니다. 클라이언트는 임시 X25519 공개 키 재료와 ML-KEM 공개 캡슐화 키를 보냅니다. 서버는 자기 쪽 X25519 공개 키 재료와 ML-KEM 암호문을 돌려줍니다. 양쪽은 각 방식의 공유 비밀값을 얻습니다. RFC 10024의 이 그룹에서는 ML-KEM 비밀값 뒤에 X25519 비밀값을 붙여 TLS 키 파생 과정에 넣습니다. TLS는 핸드셰이크로부터 트래픽 키를 파생하고 대칭 인증 암호(AEAD)로 애플리케이션 레코드를 보호합니다. 두 구성 요소가 하나의 키 합의를 이루며, 성공 여부는 핸드셰이크 완료로 판단합니다.

도입 배경에는 **지금 수집해 나중에 복호화하는 위협**이 있습니다. 누군가 오늘 암호화된 트래픽을 저장하고, 미래의 계산 기술로 당시의 키 재료를 복구할 수 있기를 기대하는 상황입니다. 하이브리드 방식은 기존 방식에 양자내성 요소를 함께 사용합니다. 배포 시에는 상대의 신원, 구현의 안전성, 단말과 서버의 보호 상태도 각각 확인합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/tls-hybrid-key-agreement-evidence-ko.svg' | relative_url }}" width="360" height="440" alt="클라이언트가 그룹과 키 재료를 제안합니다. 서버는 새 키 재료를 요청하거나 최종 ServerHello에서 그룹을 선택합니다. 하이브리드 그룹은 두 비밀값을 TLS 키 파생에 쓰며, 인증서 검증은 별도로 진행됩니다." />
  <figcaption>최종 ServerHello에서 선택된 그룹을 확인한 뒤, 핸드셰이크 완료 여부와 상대 인증 결과를 확인합니다.</figcaption>
</figure>

| 관측 필드 | 이 필드로 알 수 있는 것 | 함께 확인할 증거 |
| --- | --- | --- |
| ClientHello `supported_groups` | 이번 연결에서 클라이언트가 알린 지원 그룹 | 실제로 보낸 그룹별 키 재료와 서버의 최종 선택 |
| ClientHello `key_share` | 이번 ClientHello에 실은 그룹별 키 재료 | 지원 목록에만 있는 그룹도 있습니다. 재요청이 있으면 두 번째 ClientHello까지 확인합니다. |
| HelloRetryRequest `key_share.selected_group` | 이 확장이 있을 때 서버가 새 키 재료를 요구한 그룹 | 재요청은 ServerHello와 같은 형식을 사용합니다. 두 번째 ClientHello와 최종 ServerHello를 확인합니다. |
| 최종 ServerHello `key_share` | 해당 연결에서 선택된 그룹. IANA에서 `X25519MLKEM768`은 **4588**(`0x11ec`)입니다. | 최종 ServerHello 뒤에도 실패할 수 있습니다. 단말이나 서버 기록으로 핸드셰이크 완료를 확인합니다. |
| TLS 1.3 암호 스위트, 인증서, 서명 | 암호 스위트는 대칭 인증 암호와 키 파생에 쓰는 해시를 지정합니다. 인증서와 핸드셰이크 서명은 검증을 거쳐 상대 인증의 근거가 됩니다. | 합의 그룹, 인증서·서명 검증, 앱 요청 결과를 따로 봅니다. 사전 공유 키(PSK)만 쓰는 핸드셰이크에서는 키 재료 교환이 생략될 수 있습니다. |

## 2. 정상 연결과 키 재료 재요청 읽기

승인된 클라이언트가 게이트웨이에 접속하는 예를 보겠습니다. ClientHello의 지원 목록에는 X25519와 X25519MLKEM768이 있고, 처음부터 하이브리드 그룹의 키 재료도 담겨 있습니다. 최종 ServerHello는 4588을 선택합니다. 클라이언트에서 신뢰하는 ECDSA 인증서로 인증을 마치고, TLS 1.3 AES-GCM 스위트와 하이브리드 그룹으로 핸드셰이크를 완료합니다. 게이트웨이가 TLS를 종료한 뒤 원본 서버에 새 TLS 연결을 맺는다면 원본 방향의 그룹과 인증 결과는 별개입니다. 두 구간의 로그나 캡처를 모두 확인해야 전체 경로를 설명할 수 있습니다.

다른 예에서는 클라이언트가 두 그룹을 모두 알리지만 첫 ClientHello에 X25519 키 재료만 보냅니다. 하이브리드 그룹을 요구하는 서버는 4588을 지정해 **HelloRetryRequest**를 보낼 수 있습니다. 클라이언트가 두 번째 ClientHello에 요청받은 하이브리드 키 재료를 싣고 서버가 선택을 확정합니다. 정상 재요청도 왕복 한 번을 추가합니다. 재요청 메시지의 특수 Random 값, 두 번째 ClientHello, 최종 ServerHello의 순서를 확인하면 재요청과 최종 선택을 구별할 수 있습니다. PSK를 사용하지 않는 연결에서 공통 그룹이 없으면 아래 실습처럼 핸드셰이크가 실패할 수 있습니다.

**표준과 제품 동작의 시점.** 2026년 7월 RFC 9846이 TLS 1.3의 초기 표준인 2018년 8월 RFC 8446을 대체했습니다. 2026년 8월 RFC 10024는 하이브리드 그룹 세 가지를 정의합니다. OpenSSL 3.5 문서는 하이브리드 그룹을 지원하며, 3.5부터 기본 그룹 목록의 첫 항목이 X25519MLKEM768이라고 설명합니다. 실제 목록은 빌드, 프로바이더, 앱 설정에 따라 달라질 수 있습니다. 예전 캡처나 분석 도구의 표기와 대조할 때 IANA의 숫자 식별자도 확인합니다.

## 3. 블루팀 수집, 변경 검증, 대응

1. **연결 구간을 특정합니다.** UTC 시각, 양쪽 주소와 포트, 게이트웨이 리스너, TLS 구현 버전과 정책, 원본 서버 연결 정보를 기록합니다. 연결 식별자나 앱 요청 식별자로 관측 자료를 이어 봅니다. 세션 재개, TLS 검사 장비, 앱이 재시도할 때 생성한 별도 연결도 확인합니다.
2. **메시지를 순서대로 읽습니다.** 해당 구간에서 패킷을 수집할 수 있어야 하며 TLS 메시지를 재조립할 만큼 데이터가 필요합니다. Wireshark의 `tls.handshake.extensions_key_share_group`은 클라이언트와 서버 메시지 모두에 나타날 수 있으므로 방향과 메시지 종류를 확인합니다. HelloRetryRequest에서 요청한 그룹은 `tls.handshake.extensions_key_share_selected_group`으로 찾을 수 있습니다. ECH가 적용된 경우 바깥쪽 ClientHello에서 보인 제안은 그 바깥 메시지에 대한 증거입니다. 관련 필드가 가려졌거나 연결 일부만 수집됐다면 해당 단말이나 게이트웨이의 기록으로 보완합니다.
3. **계층별로 결과를 확인합니다.** 가능하면 통제하는 단말이나 신뢰할 수 있는 게이트웨이 로그에서 최종 그룹, TLS 버전, 핸드셰이크 완료, 인증서 검증 결과를 수집합니다. HTTP나 앱 응답은 별도 기록과 대조합니다. 하이브리드 키 재료는 크기가 커서 여러 세그먼트로 나뉠 수 있습니다. ClientHello 해석이 불완전할 때는 캡처 길이 제한, 누락 패킷, 재조립 설정을 먼저 점검합니다. 일상적인 그룹 모니터링에는 개인키나 세션 비밀값을 수집할 필요가 없습니다.
4. **정책과 실제 결과가 다르면 경로부터 확인합니다.** 구형 클라이언트, 다른 정책의 프록시, 프로바이더 제약, 잘못 지정된 리스너로 인해 정책보다 보호 수준이 낮을 수 있습니다. 승인되지 않은 TLS 종료나 그룹 설정 변경도 영향을 줍니다. 의도를 판단하기 전에 실제 경로와 설정을 확인합니다. 변경을 단계적으로 적용하면서 승인된 클라이언트로 시험하고, 구간별 선택 그룹과 실패율, 재요청 비율을 기록합니다.

## 4. 루프백에서 네 가지 경우 확인하기

본인이 소유하거나 명시적으로 승인받은 Linux 환경에서 Python 3과 대상 그룹 및 `-trace`를 지원하는 OpenSSL CLI를 사용합니다. `openssl version`과 `openssl list -tls-groups -tls1_3`으로 확인하세요. 이 예제는 **OpenSSL 3.5.9**에서 실행했습니다. <a href="{{ '/assets/labs/tls-hybrid-key-agreement-evidence/tls-group-cases.csv' | relative_url }}" download="tls-group-cases.csv">tls-group-cases.csv</a>를 내려받고, 같은 폴더에 아래 코드를 `review_groups.py`로 저장한 뒤 `python3 review_groups.py`를 실행합니다.

스크립트는 사례마다 `127.0.0.1`의 새 포트에만 서버를 엽니다. 임시 디렉터리에 짧은 수명의 시험용 인증서와 개인키를 만들고, 시험 클라이언트에서만 그 인증서를 신뢰해 `localhost` 이름을 검증합니다. 운영체제의 신뢰 저장소는 그대로 유지됩니다. 추적 결과에서 표준 HelloRetryRequest의 Random 값을 찾고 ClientHello 개수를 셉니다. 검증 범위는 TLS 핸드셰이크까지입니다. 재요청 행의 OpenSSL `*` 표기는 처음부터 키 재료를 보낼 그룹을 지정하며, 지원 목록에는 두 그룹이 모두 올라갑니다.

```python
import csv
import os
from pathlib import Path
import re
import select
import subprocess
import tempfile
import time

def listening_address(server):
    deadline = time.monotonic() + 5
    output = b""
    while time.monotonic() < deadline:
        wait = max(0, deadline - time.monotonic())
        if not select.select([server.stdout], [], [], wait)[0]:
            break
        chunk = os.read(server.stdout.fileno(), 4096)
        if not chunk:
            break
        output += chunk
        match = re.search(rb"^ACCEPT (127\.0\.0\.1:[0-9]+)\r?$", output, re.M)
        if match:
            return match[1].decode("ascii")
    raise RuntimeError("The loopback TLS server did not report a listening port")

def check(row, cert, key):
    server_args = [
        "openssl", "s_server", "-accept", "127.0.0.1:0", "-tls1_3",
        "-groups", row["server_groups"], "-cert", str(cert), "-key", str(key), "-www",
    ]
    with subprocess.Popen(server_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as server:
        try:
            address = listening_address(server)
            result = subprocess.run([
                "openssl", "s_client", "-connect", address, "-tls1_3",
                "-groups", row["client_groups"], "-CAfile", str(cert),
                "-verify_hostname", "localhost", "-verify_return_error", "-brief", "-trace",
            ], input="", capture_output=True, text=True, timeout=8)
        finally:
            server.terminate()

    count = len(re.findall(r"^\s+ClientHello, Length=", result.stdout, re.M))
    retry = bool(re.search(
        r"gmt_unix_time=0xCF21AD74\s+random_bytes \(len=28\): "
        r"E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C",
        result.stdout,
    ))
    assert count == (2 if retry else 1), f"{row['case']}: trace incomplete or unexpected"
    if row["expected_group"] == "none":
        assert result.returncode != 0 and "alert handshake failure" in result.stderr, result.stderr
        assert "CONNECTION ESTABLISHED" not in result.stderr
        group = "none"
    else:
        assert result.returncode == 0 and "Verification: OK" in result.stderr, result.stderr
        match = re.search(r"^(?:Negotiated TLS1\.3 group|Peer Temp Key): ([^,\s]+)", result.stderr, re.M)
        assert match, result.stderr
        group = match[1]
    assert group == row["expected_group"], f"{row['case']}: got group {group}"
    assert retry == (row["hello_retry"] == "yes"), f"{row['case']}: unexpected ClientHello count"
    print(f"{row['case']}: group={group}, retry={retry}")

with tempfile.TemporaryDirectory() as tmp:
    cert = Path(tmp) / "cert.pem"
    key = Path(tmp) / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-noenc", "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost", "-days", "1",
    ], check=True, capture_output=True)
    with open("tls-group-cases.csv", encoding="utf-8", newline="") as stream:
        cases = list(csv.DictReader(stream))
    assert len(cases) == 4
    for case in cases:
        check(case, cert, key)
```

| 시험 | 기대 결과 |
| --- | --- |
| 하이브리드 | TLS 완료, 인증서 검증 성공, X25519MLKEM768, ClientHello 1회 |
| 기존 방식 | TLS 완료, 인증서 검증 성공, X25519, ClientHello 1회 |
| 재요청 | HelloRetryRequest와 ClientHello 2회에 이어 X25519MLKEM768로 TLS 완료 |
| 공통 그룹 없음 | 핸드셰이크 오류로 연결 완료에 이르지 못함 |

**실패 점검.** 그룹이 거부되면 OpenSSL 버전, 지원 그룹 목록, 빌드와 프로바이더를 확인합니다. 추적 검사가 실패하면 콘솔의 추적 항목 이름과 메시지 형식을 대조합니다. 추적이 누락됐다면 관측 불충분으로 기록합니다. 검사기가 실제 차이를 잡는지 보려면 CSV 사본에서 첫 번째 사례의 기대 그룹을 X25519로 바꿔 같은 이름으로 별도 폴더에 저장하고, 스크립트 사본을 그 폴더에서 실행합니다. 검사기가 실제로 관측한 하이브리드 그룹을 알려주면서 실패해야 합니다. 실행으로 확인한 범위는 루프백의 OpenSSL CLI이며, Wireshark 필드의 의미는 공식 문서로 대조했습니다.

## 5. 확인 문제와 완료 기준

1. **클라이언트가 4588을 제안하고 최종 ServerHello가 29를 골랐습니다. 선택된 그룹은 무엇일까요?** X25519입니다. 실제 선택은 최종 ServerHello에서 확인합니다.
2. **하이브리드 연결에서 ECDSA 인증서를 사용했습니다. 4588은 무엇을 설명할까요?** 키 합의 방식을 설명합니다. 상대 인증을 판단하려면 서명과 인증서 검증 결과를 확인합니다.
3. **브라우저와 게이트웨이 사이가 하이브리드라면 원본 구간도 보호될까요?** 원본 방향의 TLS 연결에서 선택 그룹과 완료 여부를 따로 찾아야 판단할 수 있습니다.

제안, 재요청, 최종 선택을 구별하고, 선택 그룹을 핸드셰이크 완료 기록에 연결하고, 결과가 적용되는 구간을 설명할 수 있다면 학습을 마쳤습니다.

## 공식 참고자료

검토일은 **2026-11-27**입니다. 표준은 ML-KEM(2024년 8월), TLS 1.3(2026년 7월), 하이브리드 TLS 그룹(2026년 8월)을 기준으로 삼았습니다. 제품은 OpenSSL 3.5와 Wireshark의 TLS 필드 레퍼런스를 확인했습니다.

- [IETF · RFC 9846 TLS 1.3](https://www.rfc-editor.org/rfc/rfc9846.html)
- [IETF · RFC 10024 하이브리드 키 합의 그룹](https://www.rfc-editor.org/rfc/rfc10024.html)
- [IANA · TLS 지원 그룹 등록부](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8)
- [NIST · FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [OpenSSL 3.5 · 지원 그룹 설정](https://docs.openssl.org/3.5/man3/SSL_CONF_cmd/)
- [OpenSSL 3.5 · 초기 키 재료와 그룹 설정](https://docs.openssl.org/3.5/man3/SSL_CTX_set1_curves/)
- [OpenSSL 3.5 · s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/)
- [Wireshark · TLS 필드](https://www.wireshark.org/docs/dfref/t/tls.html)

[이전 · 공개키, 개인키와 전자서명]({{ '/ko/wiki/public-key-cryptography/' | relative_url }}) · [다음 · TLS 핸드셰이크 증거 읽기]({{ '/ko/wiki/tls-handshake-evidence/' | relative_url }}) · [연결 구간별 ALPN 비교]({{ '/ko/wiki/tls-alpn-evidence/' | relative_url }})
