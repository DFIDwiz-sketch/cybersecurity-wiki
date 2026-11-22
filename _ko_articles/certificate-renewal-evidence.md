---
title: "TLS 인증서 갱신 · 발급 요청부터 실제 제시 인증서까지"
description: "CSR 서명, 승인된 발급, 배포 준비 파일을 대조하고 실제 TLS 연결에서 어떤 인증서가 제시되는지 확인합니다."
category: network
tags: [TLS, PKI, Certificates, Cryptography, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/certificate-renewal-evidence/
---

**학습 목표.** 승인된 갱신 건에서 인증서와 키가 짝을 이루는지, 발급된 인증서가 서비스 이름을 포함하는지, 각 TLS 종료 지점이 예상한 최종 인증서를 제시하는지 확인합니다. 신뢰 체인과 서비스 신원 확인이 처음이라면 [인증서 검증]({{ '/ko/wiki/certificate-validation/' | relative_url }})부터 읽어 보세요.

## 1. 키에서 클라이언트가 보는 인증서까지

**개인키**는 서명에 사용하며 운영자가 통제합니다. 짝이 되는 **공개키**는 공유할 수 있습니다. **인증서 서명 요청(CSR)**은 공개키와 주체 정보, 선택 속성을 담아 서명한 요청입니다. PKCS #10에서는 요청 내용에 서명하며, 요청에 있는 공개키로 그 서명을 검증할 수 있습니다. 서명이 유효하면 서명 시점에 누군가 해당 개인키를 사용할 수 있었다는 근거가 됩니다. DNS 이름 사용 권한과 발급 요청 권한은 따로 확인해야 합니다.

**인증 기관(CA)**은 신원 확인 절차와 발급 정책을 적용한 뒤 X.509 인증서에 서명합니다. **최종 인증서(leaf certificate)**는 서비스를 직접 식별하는 인증서입니다. **주체 대체 이름(SAN)**의 `dNSName` 항목은 표준을 따르는 TLS 클라이언트가 DNS 이름과 대조하는 값입니다. **SubjectPublicKeyInfo(SPKI)**는 공개키와 알고리즘을 함께 인코딩한 값입니다. DER로 인코딩한 SPKI의 SHA-256 해시는 그 키를 식별하며, 인증서 지문은 전체 DER 인증서의 SHA-256 해시입니다. 같은 키를 써서 갱신하면 SPKI가 유지되어도 인증서 지문은 바뀝니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/certificate-renewal-ko.svg' | relative_url }}" alt="서명한 CSR이 CA의 검증과 발급, 배포 준비를 거쳐 적용됩니다. 준비 단계에서는 공개키와 이름, 신뢰 체인과 날짜를 확인합니다. 새 TLS 연결에서 이름을 검증하고 제시된 최종 인증서를 배포 기록과 비교합니다.">
  <figcaption>서명 근거, CA의 발급 승인, 배포할 묶음, 실제로 제시된 인증서를 각각 기록하세요.</figcaption>
</figure>

## 2. 정상적인 키 교체 절차 따라가기

가상의 `inventory.example.test` 서비스에서 담당자가 같은 DNS 이름에 새 키를 사용하도록 갱신을 승인합니다. 09:00 UTC에 서명 시스템이 CSR을 만들고, 09:10에 CA가 승인된 SAN으로 최종 인증서를 발급합니다. 09:15 배포 준비 단계에서 새 키와 SPKI가 일치하고 신뢰 체인과 이름 검사를 통과했다는 기록과 승인된 지문이 남습니다. 09:25에 엣지 배포가 시작됩니다. 09:30에는 서쪽 엣지가 새 인증서를 제시하지만 동쪽 엣지는 여전히 같은 이름에 유효한 이전 인증서를 제시합니다. 최종 배포 후 동쪽 엣지에서 새 핸드셰이크로 예상 지문을 확인합니다. 09:30의 관측은 일부에만 배포가 적용됐다는 근거입니다. 당시 배포 단계와 인증서 만료 시각을 함께 봐야 의미를 판단할 수 있습니다.

| 확인 시점 | 확보할 증거 | 남은 확인 |
| --- | --- | --- |
| 요청 | CSR 서명, SPKI 해시, 요청한 이름과 변경 승인 | CA의 승인 및 실제 발급 |
| 발급 | CA 주문 또는 요청 ID, 발급자와 일련번호, 최종 SAN·공개키·유효 기간 | 배포할 키의 일치와 클라이언트 신뢰 |
| 배포 준비 | 예상 지문, 키 일치, 신뢰 체인과 서비스 이름 검사 결과 | 어느 리스너가 묶음을 읽었는지 |
| 클라이언트 관측 | 시각, 접속한 리스너, SNI, 의도한 서비스 이름, 검증된 상대 인증서, 관측 지점 | 다른 엣지·경로·클라이언트의 적용 범위 |

ACME에서 **주문(order)**에는 발급을 요청한 식별자가 들어갑니다. CA는 검증 절차로 해당 식별자에 대한 발급을 승인합니다. 발급을 완료할 때 제출하는 CSR은 주문과 같은 식별자 집합을 요청해야 합니다. 발급된 인증서와 각 리스너가 읽은 인증서는 이후에 각각 확인합니다. 관리형 서비스에서는 원본 CSR이나 내보낼 수 있는 키 대신 인증서 리소스 ID와 배포 상태만 제공할 수 있습니다. 권한 있는 공급자 기록을 확보하고 클라이언트가 접속하는 리스너에서 확인하세요.

## 3. 구성 오류와 승인되지 않은 변경 조사하기

새 인증서에 이전 키를 연결하거나, 잘못된 이름으로 발급하거나, 중간 인증서를 빠뜨리거나, 올바른 인증서를 다른 리스너에 적용하는 실수가 생길 수 있습니다. 서명 서비스에 접근할 수 있는 공격자는 개인키를 내보내지 않고도 유효한 CSR 서명을 요청할 수 있습니다. 발급 신청 계정이나 검증 절차에 대한 미승인 접근은 발급에도 영향을 줄 수 있습니다. 판단하기 전에 CA 감사 로그, 서명 서비스 기록, 승인된 인벤토리를 대조하세요. 공개 발급 경보는 [인증서 투명성 증거]({{ '/ko/wiki/certificate-transparency-evidence/' | relative_url }})를 참고하세요. CT 항목은 발급 관측의 근거이며, 어느 리스너가 실제 제시했는지는 별도 조사 대상입니다.

| 증상 | 확인과 대응 |
| --- | --- |
| CSR 서명은 유효하지만 발급된 SAN이 다름 | 승인받은 이름과 최종 SAN을 비교하고 CA 주문과 발급 정책 확인. 올바른 이름으로 재발급할 때까지 배포 보류. |
| 최종 인증서와 키가 맞지 않음 | 배포할 인증서의 SPKI와 선택한 키에서 권한 있게 얻은 공개키를 대조. 개인키 내보내기나 기록 없이 묶음 연결을 수정. |
| 일부 클라이언트만 신뢰 체인 검증에 실패 | 서버가 보낸 중간 인증서와 영향받은 클라이언트의 신뢰 정책, 이름, 시간, 검증 오류를 비교하고 다른 정책이 있다면 기록. |
| 한 엣지만 이전 인증서를 제시 | 엣지·SNI 테넌트·배포 단계에 맞는 예상 지문과 대조. 다시 읽기 결과를 확인하고 같은 경로에서 새 연결로 시험. |
| 예상 밖 발급자, 이름 또는 키 | 인증서, 시각, 발급 신청 기록, 배포 이력을 보존하고 CA와 서비스 담당자에게 전달. 침해를 확인했다면 대응 계획에 따라 키 교체와 해지를 조율. |

**2026년 11월 공개 TLS 유효 기간.** CA/Browser Forum 기본 요구사항 v2.3.1은 2026년 3월 15일부터 2027년 3월 15일 전까지 발급된 공개 신뢰 구독자 인증서의 최대 유효 기간을 200일로 정합니다. 2027년 3월 15일부터 발급되는 인증서는 100일, 2029년 3월 15일부터는 47일이 상한입니다. 이 일정은 공개 신뢰 TLS 발급에 적용됩니다. 사설 신뢰 영역의 정책은 다를 수 있습니다. 모든 종료 지점에서 만료까지 남은 시간을 확인하고, 일부에만 적용되는 문제를 찾을 여유를 두고 갱신하세요.

## 4. 개인키 복사 없이 증거 모으기

배포 전에는 준비 파일에 접근 권한이 있는 실행 환경을 사용합니다. 승인된 이름, 키 식별자, 주문 ID, 발급자와 일련번호, 유효 기간, 예상 인증서 지문을 기록하세요. SPKI 해시가 같으면 두 자료에 연결된 인코딩 공개키가 같음을 확인할 수 있습니다. DNS 사용 권한, 신뢰 경로와 이름은 따로 확인해야 합니다. HSM에서 관리하는 키는 개인키를 내보내지 말고 공급자가 권한 있는 조회에 제공하는 공개키 결과를 비교하세요.

다음 OpenSSL 3.5 읽기 전용 명령은 접근을 승인받은 PEM CSR과 최종 인증서를 확인합니다. 신뢰 체인 검사에서 `SERVICE_NAME`은 의도한 DNS 이름, `roots.pem`은 신뢰 앵커 묶음, `intermediates.pem`은 필요한 중간 인증서 묶음입니다. 최종 인증서에 신뢰 앵커가 직접 서명했다면 `-untrusted intermediates.pem`은 생략합니다. 정확한 SAN이 있는지 명시적으로 확인하세요. OpenSSL 이름 검사는 일부 조건에서 Common Name을 사용할 수 있고, RFC 9525는 서비스 신원 확인에 DNS SAN을 사용합니다.

```sh
openssl req -in service.csr -noout -verify
openssl x509 -in leaf.pem -noout -issuer -serial -dates -ext subjectAltName
openssl x509 -in leaf.pem -noout -sha256 -fingerprint
openssl verify -CAfile roots.pem -no-CApath -no-CAstore \
  -untrusted intermediates.pem -purpose sslserver -verify_hostname "$SERVICE_NAME" leaf.pem
```

서명된 요청과 최종 인증서의 공개키 인코딩을 비교하려면 다음을 Bash에서 실행하세요. 파이프라인에 오류가 발생하면 해당 검사는 실패로 기록합니다.

```bash
set -o pipefail
openssl req -in service.csr -pubkey -noout |
  openssl pkey -pubin -outform DER | openssl dgst -sha256
openssl x509 -in leaf.pem -pubkey -noout |
  openssl pkey -pubin -outform DER | openssl dgst -sha256
```

배포 후에는 올바른 **서버 이름 표시(SNI)**와 서비스 이름 검증을 사용해 승인된 새 TLS 연결을 확인하세요. 범위에 여러 엣지 주소나 리전이 있다면 리스너별로 확인합니다. OpenSSL 진단 도구의 관련 옵션은 `-servername`, `-verify_hostname`, `-verify_return_error`이며, 의도한 CA 신뢰 설정도 필요합니다. `-showcerts`를 사용하면 서버가 실제 보낸 인증서 목록을 볼 수 있습니다. 공개 최종 인증서의 지문과 검증 결과를 남기고 세션 비밀이나 원본 진단 출력은 저장하지 마세요. 관측 결과를 해당 리스너의 배포 명세와 대조합니다. 엣지나 신뢰 저장소 하나에서 확인한 결과가 모든 클라이언트에 적용되지는 않습니다.

## 5. 일부에만 적용된 갱신을 오프라인에서 재현하기

[certificate-renewal-lab.py]({{ '/assets/labs/certificate-renewal-lab.py' | relative_url }}){: download="certificate-renewal-lab.py" }를 내려받아 본인 작업 공간에서 Python 3.12와 OpenSSL 3.5 CLI로 실행하세요. 스크립트는 임시 디렉터리에 짧은 수명의 실습 키와 사설 테스트 CA를 만들고 시스템 신뢰 저장소는 건드리지 않습니다. 실제 TLS 핸드셰이크 두 번을 Python 메모리 버퍼에서 수행하며 네트워크 소켓은 열지 않습니다.

```sh
python3 certificate-renewal-lab.py
```

`PASS` 줄이 8개 나와야 합니다. CSR 서명 검증이 성공하고, 갱신 CSR·키·인증서의 SPKI가 일치하며 이전 키는 다릅니다. 이름을 일부러 틀리게 발급한 인증서는 CA 체인과 키가 일치해도 의도한 이름으로 검증하면 거절됩니다. 유효 기간이 14일인 인증서는 15일 이내에 만료되지만 하루 남았다는 경보에는 해당하지 않습니다. 가상 리스너 두 곳 모두 TLS 인증을 통과하고, 한 곳은 이전 지문을, 다른 곳은 배포할 지문을 제시합니다.

생성에 실패하면 PATH의 OpenSSL CLI와 Python SSL 라이브러리가 출력한 버전을 확인하세요. 시간 검사에 실패하면 시스템 시각을 확인하고 스크립트를 다시 실행하세요. 스크립트는 실행할 때마다 새 임시 디렉터리를 만듭니다. 핸드셰이크 오류가 나면 설정을 바꾸기 전에 신뢰, 이름, 키와 인증서 연결을 점검하세요. Python 3.12.14, OpenSSL CLI 3.5.7, Python이 연결한 OpenSSL 3.5.8에서 8개 검사를 통과했습니다. 실제 운영 CA·리스너·ACME 서비스에는 접속하지 않았습니다.

## 6. 확인 문제와 해설

1. **운영 서비스 이름을 요청한 CSR의 서명이 유효합니다. 발급을 승인해도 되나요?** 서명은 해당 개인키를 사용했다는 근거입니다. 해당 절차에 따라 서비스 이름의 사용 권한과 발급 승인을 따로 확인하세요.
2. **최종 인증서는 배포할 키와 맞고 신뢰 체인 검사도 성공했습니다. 바로 써도 되나요?** SAN, 용도, 유효 기간과 클라이언트 정책도 확인하세요. 실습에서는 이름을 틀리게 발급한 인증서가 그 필요성을 보여 줍니다.
3. **배포는 성공으로 표시됐지만 검증된 연결 하나에 이전 지문이 나왔습니다. 무엇부터 보나요?** 리스너, SNI, 경로, 시각, 승인된 배포 단계를 확인합니다. 다시 읽은 뒤 새 연결에서 그 엣지가 예상 지문을 제시하는지 기록하세요.

**완료 기준.** 8개 결과를 재현하세요. 승인된 서비스 이름과 예상 지문, 가상 리스너별로 관측한 지문과 판단을 짧은 증거 기록으로 남기면 완료입니다.

## 공식 참고자료

2026년 11월 22일 검토. RFC는 발행일을 표시했고, OpenSSL 자료는 3.5 계열의 동작을 설명합니다. 공개 TLS 유효 기간 변경은 명시된 발급일 기준입니다.

- IETF [RFC 2986 · PKCS #10, 2000년 11월](https://www.rfc-editor.org/rfc/rfc2986.html) · [RFC 8555 · ACME, 2019년 3월](https://www.rfc-editor.org/rfc/rfc8555.html) · [RFC 9525 · TLS 서비스 신원, 2023년 11월](https://www.rfc-editor.org/rfc/rfc9525.html)
- [CA/Browser Forum · TLS 기본 요구사항 v2.3.1, 2026년 10월, §6.3.2](https://cabforum.org/working-groups/server/baseline-requirements/requirements/#632-certificate-operational-periods-and-key-pair-usage-periods)
- OpenSSL 3.5 [req](https://docs.openssl.org/3.5/man1/openssl-req/) · [x509](https://docs.openssl.org/3.5/man1/openssl-x509/) · [검증 옵션](https://docs.openssl.org/3.5/man1/openssl-verification-options/) · [s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/)
- [Python 3.12 · TLS Memory BIO](https://docs.python.org/3.12/library/ssl.html#memory-bio-support)

[이전 · 인증서 검증]({{ '/ko/wiki/certificate-validation/' | relative_url }}) · [다음 · 인증서 투명성 증거]({{ '/ko/wiki/certificate-transparency-evidence/' | relative_url }})

## DNS CAA 발급 정책 확인하기

[DNS CAA 발급 조사]({{ '/ko/wiki/dns-caa-issuance-evidence/' | relative_url }})에서 인증기관이 어느 DNS 레코드 집합을 발급 정책으로 보는지 확인합니다.
