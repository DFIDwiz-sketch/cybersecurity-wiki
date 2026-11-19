---
title: "이메일 발신자 인증과 피싱 조사"
description: "SPF·DKIM·DMARC와 도메인 정렬을 가상 수신 기록 다섯 건으로 분석합니다."
category: network
tags: [Email Security, DNS, Blue Team, DFIR, SPF, DKIM, DMARC]
level: Beginner
updated: "2026-11-19"
translation_url: /wiki/mail-auth-evidence/
---

## 한 메시지에 들어 있는 여러 발신 신원

SMTP 봉투의 MAIL FROM은 반송 처리에 쓰이고 RCPT TO에는 실제 전송을 요청한 수신자가 들어갑니다. 메일 앱에서 보는 From은 메시지 헤더입니다. Reply-To는 답장을 보낼 주소입니다. 주문 알림을 위탁한 회사는 업체의 반송 도메인과 자사 표시 From을 함께 사용할 수 있습니다. 수신 서버의 SMTP 수락, 사서함 배달, 사용자의 링크 클릭은 서로 다른 사건입니다.

![SMTP 봉투와 메시지 → 수신기 · SPF / DKIM → DMARC · From 정렬 → 수신기 · 배달 / 격리 / 거절]({{ '/assets/diagrams/mail-auth-ko.svg' | relative_url }})

## SPF·DKIM·DMARC를 읽는 순서

| 검사 | 확인하는 내용 | 기록할 신원 |
| --- | --- | --- |
| SPF | 연결 IP가 SMTP 발신 도메인 정책에 허용되는지 | MAIL FROM의 도메인. 빈 봉투 발신자는 HELO 신원 |
| DKIM | 서명에 포함된 헤더와 본문 범위가 검증되는지 | 서명 도메인 d=, DNS 키 선택자 s= |
| DMARC | 성공한 SPF나 DKIM 중 표시 From에 정렬되는 신원이 있는지 | From 도메인, 성공 방법과 정렬된 도메인 |

**정렬**은 인증에 성공한 도메인과 표시 From 도메인의 관계를 확인하는 단계입니다. 엄격 정렬에는 정확히 같은 도메인이 필요합니다. 완화 정렬은 표준에 따라 찾은 조직 도메인을 비교합니다. SPF와 DKIM이 각각 통과해도 둘 다 정렬되지 않으면 통과의 근거가 없습니다. 반대로 SPF가 실패했더라도 정렬된 DKIM이 통과하면 DMARC 통과가 가능합니다.

정상 위탁 발송에서 From이 orders.example.test이고 SPF가 mailer.example.test로 통과했다고 가정하세요. 엄격 SPF 정렬은 실패합니다. orders.example.test로 서명한 DKIM이 통과하면 그 서명이 정렬됩니다. DNS TXT 레코드에서 정책을 조회할 수 있지만 사건 이후 조회값은 현재 설정입니다. 사고 시점은 수신기 평가와 구성 이력으로 확인하세요.

**현행 표준:** RFC 9989(2026년 5월)는 RFC 7489와 9091을 대체하며 정책·조직 도메인 발견에 DNS Tree Walk를 정의합니다. 기존 공개 접미사 목록 기반 설명을 실제 수신기에 그대로 가정하지 마세요. p=none·quarantine·reject는 도메인 소유자의 처리 선호입니다. 최종 배달·격리·거절은 수신기 기록에서 별도로 확인합니다.

## 공격 가설과 정상 대안

| 관측 | 가능한 원인 | 확인할 증거 |
| --- | --- | --- |
| 전달 후 SPF 실패 | 전달 서버의 IP가 원래 정책에 없음 | 신뢰하는 Received 홉과 전달 경로 |
| 메일링 리스트 후 DKIM 실패 | 커버된 제목·본문이 수정됨 | 중계 기록과 서명 범위 |
| DMARC 실패 | 사칭 시도 또는 정상 발송 서비스 설정 오류 | 승인된 업체 목록과 정렬 결과 |
| DMARC 통과, 비슷한 철자의 From | 다른 도메인이 자기 이름으로 정상 인증 | 표시 이름과 정확한 도메인, 계정·발송 승인 |
| 정상 도메인에서 위험한 링크 | 실제 계정 또는 발송 서비스 오용 가능 | 로그인 및 메일 감사, URL·클릭 기록 |

예를 들어 0rders.example.test는 orders.example.test와 비슷하지만 별도 도메인입니다. 자신의 이름으로 SPF·DKIM·DMARC를 통과할 수 있습니다. 결제나 계좌 변경은 기존 연락 경로로 확인하고, 표시된 링크와 실제 목적지를 구분해 보존하세요.

## 블루팀 조사 절차

1. 승인된 사서함이나 게이트웨이에서 원본과 헤더를 확보합니다. UTC, 내부 추적 ID, Message-ID, 수신자 및 처리 결과를 기록합니다. Message-ID는 시간·수신자·내부 추적 ID로 보강합니다.
2. 수신 경계가 추가한 Authentication-Results를 찾습니다. 승인된 인증 서비스 식별자와 헤더 처리 설정을 확인하세요. 외부에서 넣은 같은 이름의 헤더와 내부 결과를 구분합니다. Received도 신뢰할 수 있는 수신 지점부터 읽습니다.
3. 실제 필드 이름은 공급자 문서를 확인하고 알려진 정상 메일로 생성·수집을 검증합니다. 자사 보호 도메인의 정렬 실패 증가를 기준선과 비교하고, 정상 전달이나 발송 서비스 변경으로 설명되는지 확인합니다.
4. 피싱이 뒷받침되면 추적 기록으로 영향 사서함을 찾아 조직 절차에 따라 격리합니다. 클릭·자격 증명 입력 가능성이 있으면 프록시·호스트·계정 세션을 함께 조사합니다. 원본에 포함된 개인정보와 토큰은 승인된 저장소에 보관하세요.

## 자체 실습과 해설

[mail-auth.csv]({{ '/assets/labs/mail-auth.csv' | relative_url }}) · [mail-auth.py]({{ '/assets/labs/mail-auth.py' | relative_url }})

Python 3으로 두 파일을 같은 폴더에서 실행합니다. 가상 기록에 준비된 검사 결과를 사용해 엄격 정렬을 비교합니다.

```bash
python3 mail-auth.py
```

| 사례 | 기대 결과 |
| --- | --- |
| A | 정렬된 SPF 통과 |
| B | 두 인증이 통과했지만 엄격 정렬은 실패 |
| C | SPF 실패에도 정렬된 DKIM 통과 |
| D | 유사 철자의 별도 도메인이 SPF·DKIM 모두 정렬 통과 |
| E | 일시 오류로 워크시트에서 판단 보류 |

PASS와 각 수신 처분의 출력이 기대 결과입니다. 파일 오류가 나면 이름과 폴더를 확인하세요. B의 완화 정렬은 조직 도메인 판정을 추가로 확인해야 합니다. E의 실제 처리는 수신 로그의 재시도·처분을 확인하세요. 이 실행은 오프라인 CSV 분석을 검증했습니다. 실제 DNS 조회, 서명 검증과 공급자 로그는 자체 환경에서 별도로 확인합니다.

**완료 기준:** 봉투·헤더·서명 도메인을 적고, B의 실패와 D의 통과를 설명하세요. D가 위험한 이유를 도메인 정렬 결과와 나눠 기록하세요. 승인된 환경에서는 정상 시험 메일 한 건을 수신해 신뢰 가능한 인증 헤더와 사서함 추적을 연결해 보세요.

[DNS]({{ '/ko/wiki/dns-investigation/' | relative_url }}) · [이전 장 · HTTP 로그]({{ '/ko/wiki/http-evidence/' | relative_url }})

## 공식 자료

2026년 11월 19일 검토. 실제 수신기 동작은 배포 환경에서 확인하세요.

- [SMTP · RFC 5321, 2008](https://www.rfc-editor.org/rfc/rfc5321.html)
- [SPF · RFC 7208, 2014](https://www.rfc-editor.org/rfc/rfc7208.html)
- [DKIM · RFC 6376, 2011](https://www.rfc-editor.org/rfc/rfc6376.html)
- [DMARC · RFC 9989, 2026](https://www.rfc-editor.org/rfc/rfc9989.html)
- [Authentication-Results · RFC 8601, 2019](https://www.rfc-editor.org/rfc/rfc8601.html)
