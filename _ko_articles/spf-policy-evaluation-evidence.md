---
title: "SPF 정책 조사 · 봉투 발신 도메인과 DNS 평가 경로 확인하기"
description: "수신 서버가 검사한 SMTP 구간과 DNS 평가 경로를 찾고, 오프라인 사례 열한 가지로 판정을 검증합니다."
category: network
tags: [SPF, DNS, SMTP, Email Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/spf-policy-evaluation-evidence/
---

메일 발송 업체를 바꾼 뒤 수신 게이트웨이에 `spf=permerror`가 찍혔습니다. 어느 도메인을 검사했고, 정책의 어느 부분에서 오류가 났을까요? 먼저 해당 SMTP 연결을 찾고, 수신 서버가 검사한 정책을 평가 순서대로 따라가 봅니다.

## 1. 검사한 IP와 도메인 찾기

**SPF(Sender Policy Framework)**는 도메인 관리자가 SMTP에서 해당 도메인을 사용할 수 있는 발송 서버를 DNS로 알리는 방식입니다. 수신 서버는 해당 구간에서 자기에게 접속한 상대의 IP 주소와 검사할 도메인으로 정책을 평가합니다. 게이트웨이는 HELO/EHLO와 MAIL FROM을 각각 검사할 수 있으므로 결과와 함께 어느 식별자를 사용했는지 기록하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/spf-policy-evaluation-evidence-ko.svg' | relative_url }}" width="360" height="395" alt="SMTP 봉투에서 검사할 도메인을 찾고, 접속 IP와 DNS TXT 정책을 대조한 다음 판정과 도메인을 기록합니다. DMARC는 표시 From과의 정렬을 별도로 확인합니다." />
  <figcaption>수신 구간 하나씩 조사하고, SPF 결과와 검사한 도메인을 함께 기록합니다.</figcaption>
</figure>

| 증거 | 어디서 보나요? | 어떻게 해석하나요? |
| --- | --- | --- |
| 접속 IP | 수신 SMTP 세션이나 신뢰할 수 있는 게이트웨이 추적 기록 | 직접 접속한 상대가 전달 서버나 내부 릴레이일 수 있습니다. 해당 구간에 한정해 해석합니다. |
| HELO 또는 EHLO | 상대 서버가 보낸 SMTP 인사말 | 이 도메인을 별도로 검사할 수 있습니다. 빈 반송 경로에서는 HELO 도메인의 `postmaster` 주소를 MAIL FROM 식별자로 구성합니다. |
| MAIL FROM | SMTP 봉투의 발신 주소. 반송 경로라고도 합니다. | 비어 있지 않으면 이 주소의 정확한 도메인에서 시작합니다. 상위 도메인의 SPF 정책은 자동으로 상속되지 않습니다. |
| 화면에 표시되는 From | 메시지 헤더 | DMARC는 이 도메인과 SPF로 검증한 MAIL FROM 도메인 또는 DKIM 서명 도메인의 정렬을 확인합니다. 개별 HELO 통과는 MAIL FROM 평가와 구분합니다. |
| Return-Path | 보통 최종 배달 서버가 추가한 헤더 | 확보한 메시지의 보조 증거입니다. 중간에 봉투가 바뀔 수 있으므로 각 구간의 원래 값은 로그에서 찾습니다. |

## 2. DNS 정책이 평가되는 순서

1. 검사 대상 도메인 **그 이름에 있는** TXT 레코드 집합을 확인합니다. 적용되는 SPF 버전 1 레코드가 둘 이상이면 `permerror`입니다. TXT 레코드 하나가 문자열 여러 조각으로 나뉘어 있다면 중간에 공백을 더하지 않고 붙여서 읽습니다. 같은 이름에 SPF와 무관한 TXT 레코드도 함께 존재할 수 있습니다.
2. 조건을 왼쪽부터 읽고 일치하거나 오류가 나면 평가를 멈춥니다. 일치한 조건 앞에 기본값 `+`가 적용되면 `pass`, `-`면 `fail`, `~`면 `softfail`, `?`면 `neutral`입니다. `all`에 도달하면 언제나 일치하므로 앞의 기호가 결과를 결정합니다.
3. `include`는 참조 도메인의 정책을 같은 접속 IP로 평가합니다. 자식 평가가 `pass`면 부모의 `include` 조건이 일치하고, 최종 결과는 부모 조건의 기호가 결정합니다. 자식이 `fail`, `softfail`, `neutral`이면 부모의 다음 조건으로 넘어갑니다. 자식의 `none`은 부모에서 `permerror`가 되며, 자식의 일시적·영구적 오류는 부모에게도 전달됩니다. `redirect`는 메커니즘에 일치한 것이 없을 때 표준이 정한 조건에 따라 평가할 대체 정책을 지정합니다. 정책에 `all`이 있으면 `redirect`는 적용되지 않습니다.
4. 재귀 평가 전체에서 DNS 조회를 유발하는 항목을 셉니다. RFC의 한도는 `include`, `a`, `mx`, `ptr`, `exists`, `redirect`를 합해 **10개**입니다. 열한 번째 항목을 평가하려 하면 `permerror`가 납니다. 이 숫자는 DNS 패킷 수, 캐시 미스 수, TXT 레코드 수와 다를 수 있습니다. `ip4`, `ip6`, `all`은 이 한도를 소모하지 않습니다. 이름이 없다는 NXDOMAIN 응답이나 답변이 0건인 정상 응답 등 이른바 **빈 조회**는 별도로 두 번까지 제한하도록 권고합니다.

| 결과 | 수신 서버에서의 의미 |
| --- | --- |
| `pass` | 이 도메인의 정책이 해당 IP에 발송을 허용했습니다. |
| `fail` / `softfail` | 각각 허용하지 않는다는 선언과 그보다 약한 부정적 판단입니다. 배달 여부는 수신 정책을 따로 확인합니다. |
| `none` / `neutral` | 예시에선 각각 적용할 SPF 정책이 없음, 정책이 긍정·부정 판단을 유보함을 뜻합니다. |
| `temperror` | DNS 시간 초과나 서버 장애 같은 일시적 오류입니다. |
| `permerror` | 현재 정책 구성이나 평가 한도 때문에 처리를 끝낼 수 없습니다. 중복 레코드, 잘못된 참조, 실제 평가 경로를 살펴봅니다. |

## 3. 정상 발송, 전달, 의미가 제한적인 통과 비교

가상의 직접 발송에서는 수신 서버가 `192.0.2.25`와 MAIL FROM `notify@orders.example.test`를 봅니다. 최초 정책은 `v=spf1 include:relay.provider.test -all`이고, 업체 도메인의 정책이 그 IP를 허용합니다. SPF는 **orders.example.test**에 대해 `pass`입니다. 참조한 업체 도메인은 그 결론에 사용한 정책의 출처입니다. 표시 From도 정확히 `orders.example.test`라면 SPF로 인증된 도메인과 엄격 정렬됩니다.

전달 서버 `198.51.100.7`이 원래 봉투 주소를 유지하고 전달할 수도 있습니다. 다음 수신 서버는 전달 서버 IP를 검사하고, 부모 정책의 `-all`에 도달할 수 있습니다. 전달 서버가 자기가 관리하는 허용된 봉투 도메인으로 바꾸면 그 도메인의 SPF는 통과할 수 있습니다. 표시 From, DKIM, 수신 정책을 추가로 확인해 DMARC와 배달 결과를 해석합니다. 서명이 보호한 내용이 유지된 전달에서는 DKIM이 통과할 수 있고, ARC에는 이전 처리 시점의 인증 평가가 남을 수 있습니다.

사칭 메일에 쓰인 별개의 도메인도 자기 발송 서버 IP를 정식으로 허용할 수 있습니다. SPF 통과는 검사한 도메인과 IP에 관한 근거입니다. 표시된 발신자와 실제 처리 결과는 해당 증거를 추가로 확인합니다. 인증 결과 헤더를 위조해 통과한 것처럼 보이는 경우도 있으므로 게이트웨이 세션과 조직의 인증 경계에서 근거를 찾습니다. 외부 서비스에 과도하게 권한을 부여하면 통과 가능한 발송 서버가 늘어납니다. 정책을 바꾸기 전에 발송 책임자와 서비스의 테넌트 단위 통제 범위를 확인합니다.

## 4. 블루팀 수집, 탐지, 대응

1. UTC 시각, 수신 게이트웨이와 커넥터, 상대 IP, HELO, 봉투 발신 주소, 표시 From, 수신자 처리 결과, 추적 또는 큐 식별자를 기록합니다. 승인된 출처에서 원본 헤더를 확보합니다. 게이트웨이가 여러 대라면 SPF를 실제로 검사한 장비의 로그를 찾아 `authserv-id`가 조직의 신뢰 경계와 일치하는지 대조하세요. 익숙한 이름이 외부 헤더에 들어 있을 수 있습니다. SMTP 단계에서 거절했다면 받은편지함에 헤더가 남지 않을 수 있으므로 게이트웨이 기록부터 봅니다.
2. 평가 대상 DNS 이름, 선택한 TXT 레코드, 중첩 참조, DNS 응답 코드, 확인 가능한 TTL, 관측 시각을 보존합니다. 승인된 도메인은 통제하는 리졸버나 게이트웨이 진단 기능으로 확인합니다. 현재 DNS와 사건 당시 수신 서버가 관측한 DNS가 다를 수 있으므로, 가능할 때 그 시점의 로그나 DNS 변경 이력을 함께 확보합니다.
3. 게이트웨이, 검사 도메인, 결과, 시각으로 묶어 비교합니다. 정책 변경 직후 `permerror`가 늘면 발송 IP별로 실제 `include` 경로를 확인합니다. 서로 무관한 발신자에 `temperror`가 급증하면 리졸버 장애 여부를 점검합니다. 전달 기록과 함께 `fail`이 나타나면 경로와 정렬부터 확인합니다. 공격 여부나 받은편지함 배달 여부를 판단하려면 SPF 외의 증거가 필요합니다.
4. 승인된 발송원과 최근 DNS 변경을 대조합니다. 더 이상 쓰지 않는 위임을 변경 관리 절차를 통해 제거하고, 앞에서 일치하는 경로와 더 깊이 평가하는 경로를 각각 시험합니다. 수신 결과를 확인한 후 조사를 마무리합니다. 메시지 추적, DNS 근거, 최종 처리는 사고 기록에 각각 남깁니다.

## 5. 오프라인 실습 · 열한 가지 결과 재현하기

본인 소유 또는 사용 승인을 받은 폴더에서 Python 3을 사용합니다. <a href="{{ '/assets/labs/spf-policy-evaluation-evidence/spf-cases.json' | relative_url }}" download="spf-cases.json">spf-cases.json</a>를 내려받으세요. 아래 코드를 같은 폴더의 `review_spf.py`로 저장한 뒤 `python3 review_spf.py`를 실행하세요. 가상의 SMTP 정보와 문서용 IP, 이미 선별한 TXT 정책을 입력으로 사용합니다. 네트워크나 실제 메일 발송은 필요 없습니다. 구현은 `ip4`, `ip6`, `include`, `all`의 평가에 한정합니다. JSON의 `null`은 일시적 DNS 오류를 나타냅니다. 실제 DNS 응답에서 레코드를 선별하는 과정, DMARC 정책 탐색, SMTP 배달은 이 실습의 검증 범위 밖입니다.

```python
import ipaddress
import json
from pathlib import Path
import sys

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
LIMIT = 10


def evaluate(domain, address, txt, trace):
    records = txt.get(domain, [])
    if records is None:
        return "temperror"
    if not records:
        return "none"
    if len(records) > 1:
        return "permerror"

    version, *terms = records[0].split()
    if version != "v=spf1":
        raise ValueError(f"Fixture needs a selected SPF record for {domain}")

    for term in terms:
        qualifier = term[0] if term[0] in QUALIFIERS else "+"
        if term[0] in QUALIFIERS:
            term = term[1:]
        mechanism, _, value = term.partition(":")

        if mechanism == "all" and not value:
            return QUALIFIERS[qualifier]
        if mechanism in {"ip4", "ip6"}:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != int(mechanism[-1]):
                raise ValueError(f"Address family mismatch in {term}")
            if address in network:
                return QUALIFIERS[qualifier]
        elif mechanism == "include" and value:
            trace.append(f"{domain} -> {value}")
            if len(trace) > LIMIT:
                return "permerror"
            child = evaluate(value, address, txt, trace)
            if child == "pass":
                return QUALIFIERS[qualifier]
            if child in {"temperror", "permerror"}:
                return child
            if child == "none":
                return "permerror"
        else:
            raise ValueError(f"Unsupported fixture mechanism: {term}")
    return "neutral"


def main(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    failures = 0
    for case in data["cases"]:
        sender = case["mail_from"]
        domain = case["helo"] if sender == "<>" else sender.rsplit("@", 1)[1]
        trace = []
        result = evaluate(domain, ipaddress.ip_address(case["ip"]), data["txt"], trace)
        observed = {"domain": domain, "result": result, "include_terms": len(trace)}
        expected = case["expected"]
        label = "OK" if observed == expected else "MISMATCH"
        print(f"{label} {case['case_id']}: {domain} {result} includes={len(trace)}")
        if observed != expected:
            failures += 1
            print(f"  expected: {expected}")
        if case["case_id"] == "over-limit":
            for count, step in enumerate(trace, 1):
                extra = " (limit exceeded before lookup)" if count > LIMIT else ""
                print(f"  {count:2} {step}{extra}")
    return int(failures != 0)


if __name__ == "__main__":
    fixture = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("spf-cases.json")
    raise SystemExit(main(fixture))
```

| 사례 | 기대 결과 |
| --- | --- |
| `direct`, `direct-ipv6`, `forwarded` | 같은 도메인과 한 번의 `include`. 허용된 IPv4와 IPv6는 통과하고 전달 서버 IP는 실패합니다. |
| `null-sender`, `missing-root` | 반송 메시지에서는 HELO에서 도출한 도메인이 통과합니다. 최초 정책이 없는 도메인은 `none`입니다. |
| `missing-include`, `duplicate-txt`, `transient-dns` | 참조 대상 정책 누락과 최초 정책 중복은 `permerror`, 가상 DNS 장애는 `temperror`입니다. |
| `early-match`, `at-limit`, `over-limit` | 앞에서 일치하면 1개만 씁니다. 정확히 10개여도 통과할 수 있습니다. 열한 번째 항목에 닿으면 대상을 조회하기 전에 멈춥니다. |

`OK`가 열한 줄 나오고 `over-limit` 평가 경로가 번호와 함께 출력됩니다. 파일을 못 찾으면 내려받은 폴더에서 실행하거나 JSON 경로를 인수로 넘기세요. 검사기가 틀린 기대값을 잡는지 시험하려면 JSON을 복사한 뒤 `over-limit` 사례의 기대 결과를 `pass`로 바꿉니다. `python3 review_spf.py altered.json`을 실행하면 불일치와 종료 코드 1이 나와야 합니다. 이 재현은 Python에서 실행했습니다. SPF·DMARC 표준과 Microsoft 365 동작은 공식 문서를 대조했습니다.

## 6. 확인 문제와 완료 기준

1. **HELO는 통과하고 비어 있지 않은 MAIL FROM은 실패했습니다. DMARC에서 SPF 통과로 보나요?** MAIL FROM의 평가 결과를 사용하므로 SPF 통과가 아닙니다. 빈 반송 경로에서는 HELO로부터 MAIL FROM 식별자를 도출해 평가한 결과를 확인합니다.
2. **같은 정책이 한 발송 IP에는 통과, 다른 IP에는 한도 초과를 반환할 수 있나요?** 가능합니다. 앞에서 일치한 IP의 평가는 먼저 끝납니다. 다른 IP는 더 긴 참조 경로까지 평가할 수 있습니다.
3. **지금 조회한 TXT와 사건 당시 게이트웨이 기록이 다릅니다. 무엇을 근거로 삼나요?** 현재 조회는 지금 리졸버가 반환한 내용의 근거입니다. 당시 수신 서버가 검사한 내용을 설명하려면 시각이 기록된 당시 자료를 찾습니다.

검사 구간과 도메인을 설명하고, `fail`, `permerror`, `temperror`를 구별하세요. 같은 실습에서 왜 10개는 통과하고 11개는 오류가 나는지 설명하고, DMARC와 배달 결과에 필요한 추가 증거를 댈 수 있으면 학습을 마쳤습니다.

## 공식 참고자료

검토일은 **2026-11-27**입니다. SPF의 RFC 7208(2014년 4월 및 이후 갱신)은 RFC 4408을 대체했습니다. RFC 8601(2019년 5월)은 인증 결과 헤더의 신뢰 경계를 다룹니다. DMARC는 기존 RFC 7489를 대체한 RFC 9989(2026년 5월)를 확인했습니다. Microsoft Learn은 Microsoft 365 구성 범위이며, 정확한 항목 수 계산은 IETF 표준을 기준으로 합니다.

- [IETF · RFC 7208, SPF](https://www.rfc-editor.org/rfc/rfc7208.html)
- [RFC Editor · RFC 7208 갱신·정오표](https://www.rfc-editor.org/info/rfc7208/)
- [IETF · RFC 8601, Authentication-Results](https://www.rfc-editor.org/rfc/rfc8601.html)
- [IETF · RFC 9989, DMARC](https://www.rfc-editor.org/rfc/rfc9989.html)
- [Microsoft Learn · Microsoft 365용 SPF](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure)

[이전 · SPF·DKIM·DMARC 기초]({{ '/ko/wiki/mail-auth-evidence/' | relative_url }}) · [다음 · SMTP 배달 조사]({{ '/ko/wiki/smtp-delivery-evidence/' | relative_url }}) · [DMARC 집계 보고서]({{ '/ko/wiki/dmarc-aggregate-report-evidence/' | relative_url }}) · [ARC와 전달 메일]({{ '/ko/wiki/arc-forwarding-evidence/' | relative_url }})
