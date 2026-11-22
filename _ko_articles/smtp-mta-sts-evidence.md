---
title: "MTA-STS와 TLS-RPT 조사 · SMTP 전송 정책과 실패 증거"
description: "SMTP 구간에서 MX 정책, STARTTLS, 인증서 검사, 정책 캐시와 집계 보고를 구분합니다."
category: network
tags: [SMTP, MTA-STS, TLS-RPT, TLS, Email Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/smtp-mta-sts-evidence/
---

메일 전송이 지연될 때는 수신 SMTP 서버가 메시지를 받아 보기 전부터 문제가 생겼을 수 있습니다. MTA-STS를 적용하는 발신 서버는 특정 MX로 배달하지 않거나 TLS 연결을 중단하고 메일을 재시도 대기열에 둘 수 있습니다. TLS 보고서는 어느 구간에서 문제가 났는지 찾는 데 도움이 됩니다. 이 장은 메일 서버 사이의 직접 전송을 SMTP 한 구간씩 따라갑니다.

## 1. 각 기능은 무엇을 제어하나요?

**MTA**는 메일을 전달하는 서버 또는 프로그램입니다. 발신 MTA는 수신 도메인의 **MX** 레코드에서 전송 대상 후보를 찾습니다. **STARTTLS**는 평문으로 시작한 SMTP 연결에서 서버가 기능을 알린 뒤 TLS로 전환할 수 있게 합니다. 기회적 TLS에서는 전환할 수 없을 때 발신 측 설정에 따라 다음 동작이 달라집니다. 평문이 허용된 경로에서 STARTTLS 안내가 사라지거나 바뀌면 암호화 없이 전송될 수 있습니다.

**MTA-STS**는 수신 도메인이 어떤 MX를 허용하고 검증된 TLS를 요구할지 지원하는 발신 서버에 알리는 정책입니다. `_mta-sts.<domain>`의 DNS TXT에는 `STSv1`과 `id`가 들어 있습니다. 실제 정책은 `https://mta-sts.<domain>/.well-known/mta-sts.txt`에서 HTTPS로 가져오며 `version`, `mode`, MX 패턴과 `max_age`를 담습니다. TXT의 ID는 변경을 알립니다. 정책 본문과 HTTPS 인증서 검증은 별도로 필요합니다. HTTPS 정책 서버와 실제 SMTP MX는 서로 다른 엔드포인트이며 각각 인증서를 검증합니다.

**TLS-RPT**는 보고 기능입니다. 수신 도메인은 `_smtp._tls.<domain>` TXT에 `v=TLSRPTv1`과 보고서 수신 위치인 `rua`를 게시합니다. 참여하는 발신 MTA가 관측 결과를 집계해 보냅니다. 보고서로 TLS 문제를 찾을 수 있지만 특정 메일의 최종 결과를 알아내려면 메시지 추적이 필요합니다. SPF, DKIM, DMARC는 발신자나 메시지의 신원을 다루며 종단 간 메시지 암호화는 한 전송 구간을 넘어 본문을 보호합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/smtp-mta-sts-evidence-ko.svg' | relative_url }}" alt="발신 서버가 수신 MX와 적용 정책을 확인한 뒤 STARTTLS와 인증서를 검증합니다. 검사를 통과하면 SMTP 전송을 시도할 수 있습니다. enforce에서는 검사에 실패한 MX로 배달하지 않습니다. 참여 발신 서버는 집계된 TLS 결과를 따로 보고합니다.">
  <figcaption>정책 검사는 SMTP 전송 경로를 제어합니다. 보고는 관찰된 TLS 결과를 별도 경로로 집계합니다.</figcaption>
</figure>

## 2. 정상 전송 한 구간을 따라가세요

가상의 `mail-lab.example` 도메인이 `mx1.mail-lab.example`과 `mx2.mail-lab.example`을 게시한다고 가정합니다. HTTPS 정책에는 `mode: enforce`, 두 호스트에 맞는 `mx`, `max_age: 86400`이 있습니다. 발신 서버는 정책을 가져올 때 HTTPS 엔드포인트를 검증합니다. 허용된 MX를 선택하고 `STARTTLS` 안내를 받아 TLS를 협상한 뒤, MX 인증서의 신뢰 체인과 유효 기간, 인증서의 SAN(Subject Alternative Name)에 선택한 MX와 일치하는 DNS 이름이 있는지 확인합니다. TLS 연결 안에서 새 `EHLO`로 SMTP 서버가 지원하는 기능을 다시 확인합니다. `*.mail-lab.example`은 왼쪽 한 레이블만 일치시키므로 `mx1.mail-lab.example`에 적용됩니다. 루트 이름과 `mx1.edge.mail-lab.example`은 범위를 벗어납니다. 이후 SMTP 전송 절차를 진행할 수 있습니다. 메시지 데이터가 끝난 다음 받는 `250`은 해당 구간에서 수락했음을 뒷받침합니다. 이후 처리는 다음 게이트웨이 기록이나 메시지 추적으로 확인하세요.

| 적용 정책 | 선택한 MX가 정책 검사에 실패했을 때 |
| --- | --- |
| 유효한 `enforce` | 해당 MX로 배달하지 않습니다. 다른 적격 MX는 통과할 수 있습니다. 해결되지 않는 실패는 일시 오류로 다루는 것이 권고되며, 영구 실패 처리 전에는 정책 갱신 여부를 확인합니다. |
| 유효한 `testing` | MTA-STS 자체로는 시도를 막지 않습니다. 참여 발신 서버는 실패를 보고할 수 있고, 별도 전송 보안 정책은 적용됩니다. |
| 유효한 `none` | 활성 MTA-STS 요구 사항이 없습니다. 다른 제어가 TLS를 요구할 수 있습니다. |
| 발견하거나 캐시한 유효 정책 없음 | MTA-STS 강제 적용 없이 진행합니다. 정책 검색·가져오기 오류와 다른 정책 출처를 살펴보세요. |

발신 서버가 어제 받은 정책이 아직 유효하면 오늘 DNS나 HTTPS가 잠시 중단돼도 계속 적용될 수 있습니다. 지금 내 컴퓨터에서 확인한 정책으로 과거에 특정 발신 서버가 적용한 정책을 확정하기 어렵습니다. 가능한 경우 발신 시점의 모드와 내려받은 시각, 캐시 만료 시각을 확보하세요. 처음 정책 검색에 실패하고 유효한 캐시가 없으면 MTA-STS 보호에 공백이 생깁니다. DANE은 DNSSEC으로 검증된 TLSA 정보를 사용하며 정책 발견과 인증 조건이 다릅니다.

## 3. TLS 협상, 정책 검사, 대기열 결과를 구분하세요

`starttls-not-supported`가 급증했다면 서버가 안내를 중단했거나 경유 게이트웨이 또는 특정 경로에서 문제가 발생했을 수 있습니다. 독립된 발신자 여러 곳에서 같은 MX와 시간대에 실패하는지 확인하세요. `certificate-host-mismatch`는 메일 공급자 이전이나 일부 리스너의 설정 불일치 뒤에도 발생합니다. 영향을 받은 각 MX가 실제로 제공한 인증서를 예상 DNS 이름과 변경 이력에 대조하세요. HTTPS 정책을 가져오는 데 성공했다는 기록만으로 SMTP 인증서를 판단할 수 없습니다.

| 증거 | 확인할 수 있는 범위 |
| --- | --- |
| DNS·HTTPS 정책 이력과 발신 서버 캐시 | 출처에 따라 무엇을 게시했고 가져왔으며 적용했는지 확인합니다. 시각과 세 출처를 구분해 보존합니다. |
| 발신 서버 SMTP·대기열 로그 | 제품이 기록하는 경우 해당 수신자의 MX 선택, 재시도 또는 최종 상태를 확인합니다. |
| 수신 서버·후속 게이트웨이 추적 | 수락, 거절, 후속 전달 여부를 파악합니다. |
| TLS-RPT JSON | 보고자·정책 도메인·시간 구간별 TLS 관측 집계입니다. 집계 단위는 세션입니다. |

집계 수를 보기 전에 보고자, `report-id`, UTC `date-range`, 정책 항목을 확인하세요. `policy-type: sts`는 MTA-STS 정책 항목입니다. `no-policy-found`는 해당 항목에서 보고자가 적용 가능한 DANE 또는 MTA-STS 정책을 찾지 못했다는 뜻입니다. 보고서는 보통 UTC 하루를 다루고 나중에 도착할 수 있습니다. 정책의 실패 요약에는 `total-failure-session-count`를 사용하세요. 한 시도가 여러 실패 세부 항목에 잡힐 수 있으므로 세부 합계는 중복 집계될 수 있습니다. 보고서가 없으면 발신 서버 미참여, 보고서 미생성, 보고 수신 경로 장애도 확인해야 합니다.

## 4. 수집하고 탐지한 뒤 대응하세요

1. 영향받은 도메인, UTC 구간, 방향, 알려진 대기열·추적 식별자로 시작하세요. 발신 측에서 선택한 MX와 IP, 적용 정책, TLS 결과, 재시도·수락 필드를 가능한 범위에서 수집합니다. 수신자별로 전송 구간을 나누고 메시지 식별자와 수신자 정보의 접근을 제한하세요.
2. 승인된 DNS·정책 변경 기록을 발신 서버 캐시 및 MX 인증서와 대조하세요. 실제로 쓰이는 주·예비 MX와 경유 게이트웨이를 모두 확인합니다. 정책 모드와 관련 DNS TTL, 정책 캐시 수명을 기록하세요.
3. 보고자·도메인별 평상시 수치를 파악하고 정책 오류가 계속 늘거나 꾸준하던 보고가 끊기면 조사하세요. 보고자의 출처를 확인하고 같은 보고자와 보고 ID의 재전송은 중복 제거합니다. 보고서는 외부 입력으로 다루고 분석 결과가 자동 격리로 바로 이어지지 않도록 구성하세요.
4. 전송이 지연되면 대기열과 정책·로그를 보존하고 DNS·PKI·메일 운영자와 복구를 조율합니다. 복구 뒤 적격 MX로 전송한 시험 메일의 결과와 재시도 정상화를 확인하세요. 집계 보고는 늦게 반영될 수 있습니다.

Microsoft 문서에 따르면 Exchange Online은 보호 대상 도메인에 아웃바운드 MTA-STS를 적용하며 Exchange 관리 센터에 아웃바운드 전송 보안 집계를 제공합니다. 조회 전 보고서 범위와 역할 권한을 확인하세요. 수신자 단위 판단에는 별도의 메시지 추적이나 발신 서버 정책 기록이 필요합니다.

## 5. 가상 관측으로 오프라인 실습하기

<a href="{{ '/assets/labs/smtp-mta-sts-evidence.py' | relative_url }}" download="smtp-mta-sts-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/smtp-mta-sts-evidence-cases.json' | relative_url }}" download="smtp-mta-sts-evidence-cases.json">가상 JSON 자료</a>를 같은 폴더에 저장하고 소유하거나 승인받은 작업 공간에서 Python 3으로 실행하세요. 각 사례에는 후보 MX 한 곳의 정책 가져오기·캐시 상태와 검증 결과가 들어 있습니다. MTA-STS의 판정만 해석하며 실제 메일을 보내거나 인증서를 검증하지 않습니다. 마지막 줄은 가상의 TLS-RPT 정책 항목 하나를 집계합니다.

```bash
python3 smtp-mta-sts-evidence.py smtp-mta-sts-evidence-cases.json
```

```text
normal: live:eligible_for_smtp
backup_outside_policy: live:blocked_candidate
no_starttls: live:blocked_candidate
testing_bad_certificate: live:testing_failure
cache_outage: cache:blocked_candidate
expired_cache: no_policy:no_sts_enforcement
retired_policy: live:no_sts_enforcement
handshake_failed: cache:blocked_candidate
tls_report: failures=3 detail_sum=4
```

마지막 보고서의 두 실패 유형은 일부 세션을 공통으로 셉니다. 보고된 실패 세션 수는 3입니다. 파일 오류가 나면 두 파일 이름과 현재 폴더를 확인하세요. 예상 밖 판정은 유효한 캐시가 있었는지, 어느 검사가 실패했는지부터 확인하세요. Python 분석기는 가상 자료로 실행했습니다. 메일 서버, HTTPS 정책 가져오기, Exchange Online은 문서로 검토했으며 제품 환경 검증은 별도입니다.

## 6. 확인 문제와 완료 기준

- **enforce 실패가 공격을 입증하나요?** 대상 MX, 인증서, 정책 캐시와 변경 이력을 대조해 정상 정비, 설정 차이, 경로 간섭을 구분합니다.
- **DNS 레코드가 없어졌는데 발신 서버가 계속 강제할 수 있나요?** 유효한 캐시가 있으면 적용할 수 있습니다. 그 발신 서버의 상태를 확인하세요.
- **보고서에 실패 세션 3개가 있습니다. 메일 세 통이 유실됐나요?** 집계 단위는 세션입니다. 최종 전달 결과는 메시지 추적과 대기열 로그에서 확인하세요.

`cache_outage`와 `expired_cache`가 다른 이유를 설명하고, 결과 아홉 줄을 모두 맞추고, 메시지 수락을 확인할 기록을 지정할 수 있으면 완료입니다.

## 공식 참고자료

2026-11-22 검토. RFC 3207은 SMTP 확장을, 2018년 표준은 MTA-STS와 TLS 보고를 정의합니다. 공급자 문서는 설명된 Exchange Online 범위에 적용됩니다.

- SMTP 업그레이드와 보안 고려사항. [IETF RFC 3207 (2002)](https://www.rfc-editor.org/info/rfc3207/)
- 정책 검색·캐시·모드, MX 검증과 다운그레이드 한계. 3–5절, 10절. [IETF RFC 8461 (2018)](https://www.rfc-editor.org/info/rfc8461/)
- 보고 기간, 집계, 실패 유형. 4절. [IETF RFC 8460 (2018)](https://www.rfc-editor.org/info/rfc8460/)
- SMTP의 DNSSEC·TLSA 활용. [IETF RFC 7672 (2015)](https://www.rfc-editor.org/info/rfc7672/)
- 인바운드·아웃바운드 동작과 포털 보고. [Microsoft Learn · MTA-STS](https://learn.microsoft.com/en-us/exchange/security-and-compliance/enhance-mail-flow-using-strict-transport-security) · [아웃바운드 전송 보안](https://learn.microsoft.com/en-us/exchange/monitoring/mail-flow-reports/outbound-messages-in-transit-security-report)

[이전 학습 · SMTP 전송 증거]({{ '/ko/wiki/smtp-delivery-evidence/' | relative_url }}) · [다음 학습 · TLS 핸드셰이크 증거]({{ '/ko/wiki/tls-handshake-evidence/' | relative_url }})
