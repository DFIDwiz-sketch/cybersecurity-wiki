---
title: "이메일 발신자 인증과 피싱 조사"
description: "SMTP 봉투와 헤더부터 SPF·DKIM·DMARC 정렬까지 단계별로 배우고, 가상 원본 헤더를 직접 읽어 봅니다."
category: network
tags: [Email Security, DNS, Blue Team, DFIR, SPF, DKIM, DMARC]
level: Beginner
updated: "2026-11-19"
translation_url: /wiki/mail-auth-evidence/
---

**학습 목표:** 메일에 표시된 발신자, 실제로 검사한 도메인, 수신 서버의 처분을 각각 설명할 수 있게 됩니다. 1–5절에서 원리를 익히고, 6절에서 헤더를 한 줄씩 읽은 뒤, 7–9절에서 조사와 실습으로 연결하세요. DNS나 암호 서명은 필요한 만큼 본문에서 설명합니다.

## 1. 주문 확인 메일은 어떻게 받은편지함까지 오나요?

온라인 상점 **Example Orders**가 주문 확인 메일을 발송 업체에 맡겼다고 합시다. 업체의 발송 서버는 수신 도메인의 DNS에서 MX 레코드로 메일 서버를 찾습니다. SMTP로 접속해 발신·수신 주소와 메시지를 넘깁니다. 수신 게이트웨이는 인증과 정책을 평가하고, 사서함으로 전달하거나 격리·거절할 수 있습니다. 메일 앱은 도착한 메시지의 From을 보여 줍니다.

![발송 서버에서 수신 게이트웨이의 SPF·DKIM 검사와 DMARC 정렬을 거쳐 배달 또는 격리·거절로 이어지는 흐름]({{ '/assets/diagrams/mail-auth-ko.svg' | relative_url }})

SMTP의 **봉투**는 서버 사이의 배달 정보이고, **헤더**는 메시지와 함께 이동하는 항목입니다. 발송 업체가 반송을 처리하고 상점이 고객에게 표시되는 경우 두 주소가 정상적으로 다릅니다. SMTP 서버의 수락, 받은편지함 배달, 사용자의 열람·클릭은 각각 별도로 확인해야 합니다. SMTP 구간의 TLS는 전송 중 통신을 보호하며, SPF·DKIM·DMARC는 아래의 발신 도메인 관련 질문을 다룹니다.

| 볼 위치 | 예시 | 쓰임 |
| --- | --- | --- |
| SMTP MAIL FROM | bounces@relay.mailer.invalid | 배달 실패 통지를 위한 봉투 발신 주소 |
| SMTP RCPT TO | analyst@receiver.test | 이 SMTP 교환에서 요청한 수신자. 화면의 To와 다를 수 있음 |
| From | Example Orders &lt;receipts@orders.example.test&gt; | 표시 이름과 작성자 주소. DMARC는 주소의 도메인을 비교 |
| Reply-To | support@orders.example.test | 답장 목적지. 별도 주소가 있으면 승인된 발송 구성을 대조 |
| Return-Path | bounces@relay.mailer.invalid | 최종 배달 과정에서 기록하는 봉투 반환 경로의 단서 |
| Received | from relay.mailer.invalid … by mx.receiver.test | 수신 서버가 추가한 전송 홉. 신뢰할 수 있는 서버가 쓴 줄부터 확인 |

MAIL FROM은 원래 SMTP 거래의 값입니다. 전달 과정에서 바뀔 수 있으므로 Return-Path가 어느 홉을 반영하는지 살펴보세요. 표시 이름만 보이면 주소 전체를 펼쳐서 확인합니다.

## 2. SPF는 어느 IP가 전송했는지 확인합니다

**SPF(Sender Policy Framework)**는 수신 서버가 실제로 접속받은 IP와 SMTP 발신 신원을 사용해 DNS 정책을 검사합니다. 예시에서 수신 서버가 192.0.2.25에서 접속을 받았고 봉투 주소가 bounces@relay.mailer.invalid라면, SPF의 질문은 **그 IP가 relay.mailer.invalid를 사용해 전송할 권한이 있는가**입니다. 일반 메일에서는 MAIL FROM 도메인을 보고, 반송 메일처럼 봉투 발신자가 비어 있으면 SPF에서 HELO 신원을 사용한 처리 문맥을 확인합니다.

가상의 SPF 정책 `v=spf1 ip4:192.0.2.25 -all`은 예시 IP를 허용하고, 앞의 조건에 맞지 않는 나머지 IP에 실패를 표시합니다. 이 문서의 IP와 도메인은 교육용입니다. 운영 설정에서는 승인된 모든 발송 경로와 적용 전에 확인할 영향을 목록으로 관리하세요.

| SPF 결과 | 읽는 방법 |
| --- | --- |
| pass | 검사한 IP가 **해당 SMTP 신원**으로 발송하도록 허용됨 |
| fail / softfail | 정책이 발송을 허용하지 않음 / 약한 부정 결과. 수신 처분은 정책에서 확인 |
| none / neutral | 적용할 SPF 결과 없음 / 정책이 해당 IP에 대한 판단을 유보 |
| temperror / permerror | 일시 평가 오류 / 정책·평가의 지속적인 오류. 실패 원인과 재시도를 따로 확인 |

전달 서버가 그대로 넘겨도 다음 수신기는 **전달 서버의 IP**를 보므로 SPF가 실패할 수 있습니다. 따라서 fail을 봤을 때는 전달 경로와 원래 정책을 함께 보세요. pass가 나왔다면 어떤 도메인에 대해 통과했는지 적습니다.

## 3. DKIM은 어느 도메인이 어떤 내용을 서명했는지 확인합니다

**DKIM(DomainKeys Identified Mail)**에서 발송 서비스는 개인키로 헤더 일부와 본문 해시를 포함한 서명을 붙입니다. 수신 서버는 DNS에서 공개키를 찾고 서명을 검증합니다. **공개키**는 검증에 쓰이고 **개인키**는 서명 서비스가 보관합니다. [공개키·개인키와 전자서명]({{ '/ko/wiki/public-key-cryptography/' | relative_url }})에서 원리를 이어서 볼 수 있습니다.

| 서명 태그 | 초보자가 읽을 값 |
| --- | --- |
| d= | 서명 도메인. DMARC 정렬에 쓰이는 DKIM 신원 |
| s= | 선택자. 해당 도메인의 공개키 중 어느 것을 조회할지 결정 |
| h= | 서명에 포함된 헤더 목록 |
| bh= | 검증에 사용하는 본문 해시 |
| b= | 디지털 서명 값 |

예를 들어 `d=orders.example.test`와 `s=notice`가 있으면 공개키 조회 이름은 `notice._domainkey.orders.example.test`입니다. 한 메일에 업체와 고객의 서명이 함께 올 수 있습니다. 성공한 서명마다 d=를 확인하세요. 메일링 리스트가 서명한 제목에 태그를 붙이거나 본문에 푸터를 추가하면 검증 결과가 바뀔 수 있습니다. 변경이 검증에 영향을 주는지는 서명 범위와 공백·줄바꿈 등을 처리하는 정규화 규칙에 따릅니다.

## 4. DMARC는 성공한 신원과 화면에 보이는 From을 연결합니다

**DMARC(Domain-based Message Authentication, Reporting, and Conformance)** 수신 평가에서는 From 도메인을 기준으로 SPF와 DKIM을 각각 읽습니다.

1. 표시 이름 오른쪽의 실제 From 주소에서 도메인을 적습니다.
2. SPF가 pass이면 해당 인증 도메인과 From이 **정렬**되는지 확인합니다.
3. DKIM이 pass인 서명마다 d=와 From이 정렬되는지 확인합니다.
4. 정렬된 pass가 하나 이상이면 DMARC 인증을 통과할 수 있습니다. 둘 다 없으면 실패 가능성을 평가하고, 일시 오류나 정책 조회 결과도 확인합니다.
5. 수신기가 어떤 정책을 찾았는지, 실제로 배달·격리·거절했는지 추적 로그에서 확인합니다.

**엄격 정렬**은 도메인이 정확히 같아야 합니다. **완화 정렬**은 표준에 따라 확인한 조직 도메인을 비교합니다. 예를 들어 두 이름의 조직 도메인이 모두 example.test로 확인된 경우 `orders.example.test`와 `notify.example.test`는 완화 정렬이 가능합니다. 엄격 정렬은 실패합니다. 단순히 맨 끝 두 부분이 같다는 이유로 완화 정렬을 확정하지 마세요.

| SPF | DKIM | 적용 가능한 DMARC 정책 아래의 판단 예 |
| --- | --- | --- |
| pass, 정렬됨 | 실패 | SPF로 통과 가능 |
| pass, 정렬 안 됨 | pass, 정렬됨 | DKIM으로 통과 가능 |
| pass, 정렬 안 됨 | pass, 정렬 안 됨 | 두 결과가 성공이어도 정렬된 통과 없음 |
| 일시 오류 | 사용할 성공 서명 없음 | 평가 결과와 실제 처분을 수신 로그에서 확인 |

RFC 9989(2026년 5월)는 RFC 7489와 9091을 대체하며 정책 및 조직 도메인 확인에 **DNS Tree Walk**를 정의합니다. 예전 공개 접미사 목록 기반 설명과 운영 수신기의 구현을 구분하세요. 정책은 보통 `_dmarc.<From 도메인>` TXT 조회에서 찾기 시작합니다. `p=none`, `quarantine`, `reject`는 도메인 소유자의 처리 선호입니다. 수신 시스템이 실제로 취한 조치와 분리해 기록하세요. 집계 보고서는 도메인 발송 경로와 인증 결과의 경향을 파악하는 데 쓰입니다. 개별 수신자의 클릭 여부는 다른 증거가 필요합니다.

## 5. 인증 결과는 어느 서버가 썼나요?

원본 메일이나 인터넷 헤더를 열면 `Received`, `Authentication-Results`, `From` 등이 보입니다. Gmail 웹에서는 메일을 열고 답장 옆 메뉴에서 **원본 보기(Show original)**를 선택합니다. 조직 메일은 승인된 관리자 추적이나 해당 클라이언트의 헤더 보기 기능을 사용하세요. 원본에는 개인 정보와 내부 주소가 포함될 수 있으므로 공개 도구에 붙여넣기 전에 조직 절차를 확인합니다.

`Authentication-Results`에서 세미콜론 앞의 **인증 서비스 식별자(authserv-id)**를 먼저 읽습니다. 조직이 승인한 수신 시스템과 메시지 추적 기록을 대조합니다. 겉보기에 식별자가 같아도 조직 수신 경계의 헤더 제거·보존 설정과 실제 추적 기록으로 출처를 확인해야 합니다. 보이는 헤더 맨 위 또는 `pass` 한 줄만으로 신뢰 여부를 정하지 않습니다. 줄이 공백으로 시작하면 보통 바로 위 헤더의 이어지는 줄입니다.

`Received`는 각 수신 홉이 새 줄을 앞에 추가하므로 일반적으로 위에 최근 홉이 옵니다. 그중 조직이 통제하는 첫 수신 지점의 연결 IP, UTC, 큐 ID가 조사 출발점입니다. 이전 홉의 주장은 수신 경계를 벗어날수록 별도 증거가 필요합니다.

## 6. 가상 원본 헤더 세 건 읽기

아래 파일은 텍스트로 열 수 있습니다. **가상 결과를 미리 기록한 발췌본**이며, 실제 DKIM 서명이나 발송은 포함하지 않습니다. 실습에서는 `mx.receiver.test`가 조직에서 승인한 수신 서비스이고, 추적 기록으로 그 출처를 확인했다고 가정합니다.

### A. 정상 위탁 발송

[가상 헤더 A 다운로드]({{ '/assets/labs/mail-headers-outsourced.txt' | relative_url }})

~~~text
Authentication-Results: mx.receiver.test;
 spf=pass smtp.mailfrom=relay.mailer.invalid;
 dkim=pass header.d=orders.example.test header.s=notice;
 dmarc=pass header.from=orders.example.test
~~~

1. From 도메인은 **orders.example.test**입니다.
2. SPF는 업체의 **relay.mailer.invalid**에 통과했습니다. 엄격 정렬은 실패합니다.
3. DKIM의 **orders.example.test**는 From과 정확히 같고 검증도 성공했습니다. 수신기의 DMARC pass를 DKIM으로 설명할 수 있습니다.
4. 위탁 관계가 승인됐는지는 공급자 목록이나 발송 이력에서 확인합니다.

### B. 신뢰할 수 없는 인증 결과

[가상 헤더 B 다운로드]({{ '/assets/labs/mail-headers-untrusted-result.txt' | relative_url }})

수신기의 `mx.receiver.test`에는 SPF pass, DKIM none, DMARC fail이 기록돼 있습니다. SPF pass는 `relay.alerts.invalid`에 대한 결과입니다. 같은 파일에서 `supplied.relay.invalid`도 DMARC pass를 주장합니다. 이 실습에서 그 시스템은 신뢰 경계 밖에 있습니다. 두 결과를 섞지 말고 수신기 결과와 추적 ID **LAB-2042**를 같이 기록하세요. Reply-To도 표시 From과 다릅니다. 정상 서비스인지 확인하려면 승인된 발송·답장 경로와 실제 처분 기록이 필요합니다.

### C. 인증을 통과한 유사 도메인

[가상 헤더 C 다운로드]({{ '/assets/labs/mail-headers-lookalike.txt' | relative_url }})

표시 이름은 Example Orders이지만 실제 From은 **0rders.example.invalid**입니다. 첫 글자가 알파벳 O 대신 숫자 0입니다. SPF·DKIM 모두 그 도메인으로 통과하고 정렬됩니다. DMARC pass는 수신기가 **그 주소의 도메인**을 인증했다는 뜻입니다. 기존 상점의 승인이나 결제 요청의 진위는 기존 연락처와 거래 기록으로 확인하세요.

## 7. 블루팀 조사 순서와 흔한 오판

| 관측 | 다른 설명과 다음 확인 |
| --- | --- |
| 전달 후 SPF 실패 | 전달 서버의 IP를 봤을 수 있음. 수신 홉과 전달 경로 확인 |
| 메일링 리스트 이후 DKIM 실패 | 제목·푸터 변경 가능. 서명 범위와 중계 기록 대조 |
| 자사 From에서 DMARC 실패 증가 | 사칭 가설과 새 위탁 서비스·DNS 변경을 함께 점검 |
| 정상 도메인의 DMARC pass와 위험한 요청 | 정상 계정이나 승인 서비스가 악용될 수 있음. 사용자·계정·발송 감사 확인 |
| Reply-To가 다른 도메인 | 고객지원 서비스 또는 답장 유도 가능. 승인 구성과 실제 대상 확인 |

1. 승인된 사서함이나 게이트웨이에서 원본과 헤더를 보존합니다. UTC, 수신자, 내부 추적 ID와 Message-ID를 기록하세요. Message-ID만으로 같은 메일을 단정하기보다 시간·수신자·내부 ID로 보강합니다.
2. 신뢰할 수 있는 처리 지점에서 SPF 검사 도메인, DKIM d=, From, 정렬 및 최종 처분을 비교합니다. 공급자별 필드와 수집 범위를 정상 시험 메일로 확인합니다.
3. 유사 주소, 답장 목적지, 표시 링크와 실제 목적지, 첨부 유형을 따로 기록합니다. 사용자가 클릭했거나 로그인 정보를 입력했다는 근거가 있을 때는 승인된 프록시·엔드포인트·계정 로그를 대조하세요.
4. 근거가 뒷받침되면 조직 절차에 따라 관련 사서함을 추적하고 격리합니다. 인증 실패율이 늘었다면 총 평가 건수와 승인된 발송 경로 변경도 함께 확인합니다.

보고 예시: **“LAB-2042의 신뢰 수신기에서 DMARC fail을 기록했습니다. From과 정렬되는 성공 신원이 관측되지 않았고 Reply-To가 승인 목록과 일치하는지 확인 중입니다. 배달·클릭 여부는 추가 추적이 필요합니다.”** 관측 사실과 해석, 남은 확인을 나누어 기록하세요.

## 8. 두 번째 실습 · 표에서 엄격 정렬 계산

[mail-auth.csv]({{ '/assets/labs/mail-auth.csv' | relative_url }}) · [mail-auth.py]({{ '/assets/labs/mail-auth.py' | relative_url }})

두 파일을 같은 폴더에 저장하고 Python 3으로 실행하세요. 이 실습은 원본 헤더 세 건과 별도의 **가상 정규화 자료**입니다. 이미 제공된 SPF·DKIM 결과에 정확한 도메인 비교를 적용합니다. 실제 DNS 질의, DMARC 정책 탐색, 서명 검증은 별도 기능입니다.

~~~bash
python3 mail-auth.py
~~~

| CSV 사례 | 기대 결과 |
| --- | --- |
| A | SPF로 엄격 정렬 통과 |
| B | 두 인증이 pass, 엄격 정렬은 실패 |
| C | SPF 실패, DKIM으로 엄격 정렬 통과 |
| D | 유사 이름을 가진 별도 도메인이 자체 신원으로 통과 |
| E | 일시 오류로 워크시트에서 판단 보류 |

마지막에 `PASS: five synthetic cases`가 나오면 됩니다. 파일 오류는 두 파일 이름과 위치를, 결과 오류는 CSV 값과 헤더를 확인하세요. B의 완화 정렬에는 조직 도메인 확인이 필요하고, E의 실제 처리에는 수신기 재시도·처분 로그가 필요합니다. 게시 과정에서는 헤더 파일 파싱과 CSV 분석을 확인했습니다. 실제 메일 발송 및 공급자 로그는 자체 환경에서 별도로 검증하세요.

## 9. 확인 문제와 완료 기준

1. **SPF pass인데 From 도메인이 다르면 오류인가요?** 발송 업체가 반송을 처리하는 정상 발송일 수 있습니다. DKIM과 From 정렬, 승인 경로를 확인합니다.
2. **DKIM이 두 개면 무엇을 비교하나요?** 각각의 성공 여부와 d=를 봅니다. 성공한 서명 중 From과 정렬되는 것이 있는지 확인합니다.
3. **수신 결과가 둘이면요?** 가장 좋은 결과를 고르는 대신 승인된 수신 경계와 추적 기록이 뒷받침하는 결과를 사용합니다.
4. **DMARC pass가 피싱 조사를 끝내 주나요?** 통과한 정확한 도메인을 확인하고, 유사 이름·계정 오용·요청의 진위는 별도 근거로 판단합니다.

세 헤더에서 **From / SPF 도메인 / DKIM 도메인 / 신뢰 수신기 / DMARC / 남은 증거**를 한 줄씩 작성하면 완료입니다. 소유하거나 승인받은 환경에서는 정상 시험 메일 한 건의 인증 결과와 사서함 추적을 연결해 보세요.

관련 학습: [DNS 레코드와 응답]({{ '/ko/wiki/dns-investigation/' | relative_url }}) · [HTTP 로그로 후속 접속 확인]({{ '/ko/wiki/http-evidence/' | relative_url }})

## 공식 자료

2026년 11월 19일 검토. 아래 표준으로 프로토콜을 확인하고 제품 문서와 실제 수신기에서 헤더 표시·수집 동작을 대조합니다.

- [SMTP · RFC 5321 (2008)](https://www.rfc-editor.org/info/rfc5321/) · [메시지 형식 · RFC 5322 (2008)](https://www.rfc-editor.org/info/rfc5322/)
- [SPF · RFC 7208 (2014)](https://www.rfc-editor.org/info/rfc7208/) · [DKIM · RFC 6376 (2011)](https://www.rfc-editor.org/info/rfc6376/)
- [DMARC · RFC 9989 (2026)](https://www.rfc-editor.org/rfc/rfc9989.html) · [DMARC 집계 보고 · RFC 9990 (2026)](https://www.rfc-editor.org/rfc/rfc9990.html)
- [Authentication-Results · RFC 8601 (2019)](https://www.rfc-editor.org/rfc/rfc8601.html)
- [Gmail 원본 보기](https://support.google.com/mail/answer/29436) · [Microsoft 365 메시지 헤더](https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo)

## 인증에서 SMTP 전달 추적으로 이어가기

[수신자 한 명의 SMTP 응답부터 후속 처리 기록까지 따라갑니다.]({{ '/ko/wiki/smtp-delivery-evidence/' | relative_url }})

## ARC와 전달 메일 이어서 조사하기

[ARC 체인과 배달 증거 확인하기]({{ '/ko/wiki/arc-forwarding-evidence/' | relative_url }}) · 직접 인증과 수신 정책, 실제 배달을 구분합니다.

[DMARC 집계 보고서에서 정렬, 발송량, 정책 예외 읽기]({{ '/ko/wiki/dmarc-aggregate-report-evidence/' | relative_url }})
