---
title: "DNS QNAME 최소화 · 서버마다 보이는 이름이 다른 이유"
description: "클라이언트 질의와 반복 질의를 대조하고, 이름 최소화·캐시·전달·호환성 재시도를 오프라인 사례 8건으로 구분합니다."
category: network
tags: [DNS, QNAME Minimisation, DNS Privacy, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/dns-qname-minimisation-evidence/
---

워크스테이션이 `mail.lab.test.`의 메일 레코드를 찾습니다. 조직의 리졸버에는 전체 이름이 남았는데, 상위 서버 쪽 센서에는 `test.`와 `lab.test.`만 보입니다. 두 관측 모두 맞을 수 있습니다. 먼저 리졸버의 어느 쪽을 보고 있는지 확인합니다.

## 1. DNS 이름을 계층별로 따라가기

**QNAME**은 DNS 질문에 들어 있는 도메인 이름입니다. **QTYPE**은 요청하는 레코드 유형으로, A는 IPv4 주소를, MX는 수신 메일 서버 정보를 묻습니다. 클라이언트의 스텁 리졸버는 보통 재귀 리졸버에 전체 질문을 보냅니다. 재귀 리졸버가 캐시로 답할 수 없다면 서버들을 차례로 조회하는 반복 질의를 만들 수 있습니다. 상위 서버는 하위 **영역**(zone)의 권한 서버를 알려 주는 **위임 응답**(referral)을 돌려줄 수 있습니다. **영역 경계**(zone cut)는 이렇게 위임이 일어나는 지점입니다. 리졸버는 응답을 보고 다음 서버에 새 질문을 보냅니다.

**QNAME 최소화**는 올바른 권한 서버를 찾는 과정에서 원래 질문이 필요 이상으로 드러나는 것을 줄입니다. 위임을 알아보기 위해 일반적으로 이미 권한을 확인한 접미 이름에 라벨을 하나 더 붙여 원래 이름 쪽으로 나아갑니다. 이 과정의 QTYPE은 원래 질문과 다를 수 있습니다. 요청한 레코드를 관할하는 서버에 이르면 필요한 경우 원래 질문을 보냅니다. 접미사는 라벨 경계로 비교해야 합니다. `mail.lab.test.`에 `lab.test.`는 포함되지만 `ab.test.`는 접미 이름이 아닙니다.

<figure>
  <img src="{{ '/assets/diagrams/dns-qname-minimisation-evidence-ko.svg' | relative_url }}" width="560" height="358" alt="클라이언트가 전체 MX 질문을 리졸버에 보냅니다. 리졸버는 상위 서버들에 각각 test와 lab.test만 묻고, lab.test 영역의 권한 서버에는 전체 MX 질문을 보냅니다." />
  <figcaption>캐시에 위임 정보가 없는 예시입니다. 리졸버가 서로 다른 서버에 각각 질문합니다.</figcaption>
</figure>

## 2. 관측 위치별로 정상 흐름 읽기

예약된 `.test` 아래에 **가상의 DNS 계층**을 구성했다고 가정합니다. 루트는 `test.`를, `test.` 상위 서버는 `lab.test.`를 위임합니다. 메일 이름에는 별도 위임이 없습니다. 아래 표는 주요 관측을 요약하며, 중간 확인 질의와 전송 재시도는 생략했습니다.

| 관측 위치 | 질문 또는 증거 예시 | 해석 |
| --- | --- | --- |
| 클라이언트 → 재귀 리졸버 | `MX mail.lab.test.` | 애플리케이션의 원래 질문입니다. 리졸버가 캐시에서 바로 답할 수 있습니다. |
| 리졸버 → 루트 | `A test.`, 이어서 위임 응답 | 다음 권한 서버를 찾는 중입니다. 여기서는 개별 메일 호스트 이름을 알 수 없습니다. |
| 리졸버 → `test.` 상위 서버 | `A lab.test.`, 이어서 위임 응답 | 위임 확인에도 A를 쓸 수 있습니다. 응답의 권한(Authority) 섹션에서 위임 정보를 확인합니다. |
| 리졸버 → `lab.test.` 권한 서버 | `MX mail.lab.test.` | 실제 레코드를 묻는 최종 질의입니다. 이 서버가 전체 이름을 받는 것은 정상입니다. |
| 리졸버 → 설정된 포워더 | 원래 질문이 보일 수 있음 | 어느 리졸버가 재귀 해석을 맡는지 확인합니다. 포워더가 전체 이름을 받았다고 해서 상위 서버에도 그대로 보냈다는 뜻은 아닙니다. |

IETF의 2021년 11월 [RFC 9156](https://www.rfc-editor.org/rfc/rfc9156.html)은 실험적 RFC 7816을 대체했습니다. 위임 확인 질의에는 NS를 사용할 수 있고, 표준의 선택 조건을 만족하는 A·AAAA도 사용할 수 있습니다. 확인 질의의 유형은 원래 질문의 QTYPE에 의존하지 않게 고릅니다. 실제 순서는 캐시에 있는 위임과 이미 알려진 영역에 따라 달라집니다. DS처럼 부모 영역에 권한이 있는 레코드는 최종 질문도 상위 서버에 갈 수 있습니다. 별칭을 따라가며 다른 이름에 대한 조회가 시작될 수도 있습니다.

| 제품 문서 | 문서에 명시된 기본 동작 | 확인할 증거 |
| --- | --- | --- |
| ISC BIND 9.20.31 | 기본은 `qname-minimization relaxed`입니다. 이 모드에서 NS로 계층을 따라가며, 예상 밖의 응답 뒤에는 전체 이름으로 재시도할 수 있습니다. | 뷰에 실제 적용된 설정, 처음 질문과 응답, 같은 상대에 이어진 질의를 대조합니다. |
| NLnet Labs Unbound | 기본은 `qname-minimisation: yes`와 `qname-minimisation-strict: no`입니다. 가능하면 A를 사용합니다. 매뉴얼은 오류 응답 뒤 대체 동작을 설명하며 DNSSEC 서명 영역의 NXDOMAIN을 예외로 둡니다. | 설치 버전과 적용 설정, 상위 응답 코드와 전체 이름 질의가 이어졌는지 확인합니다. 실제 영역에서 관측한 결과를 기준으로 판단합니다. |

위임이 캐시에 있으면 루트와 상위 서버에 묻지 않고 최종 질문부터 할 수 있습니다. 답 자체가 캐시돼 있으면 외부 질의가 사라질 수 있습니다. 엄격 모드와 호환 모드는 정보 노출과 이름 해석의 호환성에서 차이가 납니다. 정책이 달라졌다고 판단하기 전에 같은 버전·뷰·캐시 조건의 관측을 비교하세요.

## 3. 블루팀 수집과 대응

1. **리졸버의 양쪽을 확인합니다.** 자산과 센서, UTC 시각, 리졸버 버전, 뷰와 전달 정책을 기록합니다. 승인된 범위에서 클라이언트 유입과 반복 질의 송신을 관측하세요. 목적지가 루트·상위·최종 권한 서버인지 포워더인지 승인된 설정과 위임 기록으로 확인합니다. 목적지 IP만으로 역할을 확정하기 어렵습니다.
2. **질문과 응답을 구간별로 연결합니다.** 출발지·목적지 주소, 포트, 전송 방식, DNS 트랜잭션 ID, QNAME, QTYPE, RCODE, 위임에 사용된 레코드를 보존합니다. 트랜잭션 ID는 재사용될 수 있으며 클라이언트 질의와 리졸버의 외부 질의에서 같을 필요가 없습니다. Zeek의 `dns.log`에서는 `uid`, 통신 양단, 시각, `trans_id`를 함께 확인해 한 구간의 자료를 해석하세요. 위임 세부 내용이나 구간 간 연결 근거가 없으면 원본 PCAP이나 승인된 리졸버 로그를 대조합니다. Zeek에 DNS 트래픽이 보이고 분석기가 동작하며 필요한 구간이 수집돼 있어야 합니다. 암호화된 구간에는 신뢰할 수 있는 단말 또는 리졸버 로그가 필요할 수 있습니다.
3. **이름이 없거나 예상과 다른 이유를 확인합니다.** 답이나 위임이 캐시에 있었는지, 포워더를 썼는지, 상위 오류 뒤 호환성 재시도가 있었는지, 수집에 공백이 있었는지 살펴봅니다. 가능하면 리졸버의 요청 연결 기록을 사용하세요. 짧은 이름 하나만으로 생략된 앞부분이나 개별 클라이언트를 복원하거나 설정을 확정할 수 없습니다.
4. **예상 밖 노출을 검증하고 대응합니다.** 상위 서버에 내부용으로 보이는 전체 이름이 전송됐다면, 운영 서비스 라벨이 해당 서버나 평문 DNS를 볼 수 있는 관측자에게 드러날 수 있습니다. 승인되지 않은 포워더나 잘못 적용된 뷰는 노출 범위를 넓힐 수 있습니다. 올바른 권한 서버의 정상 응답 과정이나 호환성 재시도에서도 전체 이름은 나타납니다. 질문과 응답, 적용 설정을 보존하고 같은 경로의 정상 자료와 비교합니다. 원인이 확인되면 DNS 운영팀과 수정하고 재검증하세요. 전체 클라이언트 이름을 수집할 때는 접근 권한과 보존 기간을 제한합니다.

QNAME 최소화는 위임 과정에서 공개하는 정보를 줄입니다. HTTPS나 TLS 기반 DNS는 암호화된 구간의 수동 관측을 제한하지만, 선택된 리졸버에는 질문이 도달합니다. DNSSEC는 데이터의 출처와 무결성을 검증하는 별도 통제입니다. 각 통제는 해당 계층의 증거로 확인합니다.

## 4. 오프라인으로 방어 판단 검증하기

자기 소유 또는 명시적으로 승인된 작업 폴더와 Python 3를 사용합니다. <a href="{{ '/assets/labs/dns-qname-minimisation-evidence/qname-cases.csv' | relative_url }}" download="qname-cases.csv">qname-cases.csv</a>를 내려받고 같은 폴더에 아래 코드를 `review_qname.py`로 저장한 뒤 `python3 review_qname.py`를 실행합니다. 가상 기록만 읽으며 DNS 트래픽은 보내지 않습니다.

CSV는 이미 연결된 관측을 조회 한 건씩 시간순으로 묶었습니다. `point`와 `target`은 실습에서 주어진 네트워크 구조에 따릅니다. `outcome`은 연결된 응답이나 확인된 캐시 상태를 요약한 값입니다. 실제 조사에서는 원본 패킷과 리졸버 로그, 네트워크 정보로 이 분류의 근거를 확인합니다. 코드는 이 가상 ASCII 이름과 관측 패턴을 분류하는 데 사용합니다.

```python
import csv
from collections import defaultdict

expected = {
    "cold": "minimisation-shape",
    "warm-delegation": "authority-only",
    "answer-cache": "cache-evidence",
    "forwarding": "forwarder-path",
    "compatible-retry": "possible-compatibility-retry",
    "early-full": "full-name-at-parent",
    "point-unverified": "insufficient-context",
    "upstream-only": "insufficient-context",
}

def labels(name):
    return tuple(name.rstrip(".").lower().split("."))

def is_proper_suffix(short, full):
    return bool(short) and len(short) < len(full) and full[-len(short):] == short

def classify(records):
    client = next((r for r in records if r["point"] == "client"), None)
    if client is None:
        return "insufficient-context"
    full = labels(client["qname"])
    probes = set()
    refused = set()
    complete = False
    for row in records:
        if (row["point"], row["target"], row["outcome"]) == ("resolver", "cache", "hit"):
            return "cache-evidence"
        if row["point"] == "forwarder":
            return "forwarder-path"
        if row["point"] != "iterative":
            continue
        target = row["target"]
        queried = labels(row["qname"])
        if target in {"root", "parent"}:
            if queried == full:
                if target in refused and row["qtype"] == client["qtype"]:
                    return "possible-compatibility-retry"
                return "full-name-at-parent"
            if is_proper_suffix(queried, full):
                probes.add(target)
                if row["outcome"] == "REFUSED":
                    refused.add(target)
        elif target == "authority" and queried == full and row["qtype"] == client["qtype"]:
            complete = True

    if complete:
        return "minimisation-shape" if probes else "authority-only"
    return "insufficient-context"

with open("qname-cases.csv", encoding="utf-8", newline="") as stream:
    cases = defaultdict(list)
    for row in csv.DictReader(stream):
        cases[row["case"]].append(row)

actual = {name: classify(records) for name, records in cases.items()}
assert actual == expected, f"Expected {expected!r}, got {actual!r}"
for name, result in actual.items():
    print(f"{name}: {result}")
```

**기대 결과.** 사례 8건이 통과합니다. 빈 캐시 사례에는 짧은 질문들과 최종 질문이 있습니다. 최종 권한 서버만 관측한 경우, 캐시가 확인된 경우, 포워더가 보인 경우는 따로 분류합니다. 같은 상위 서버에 짧은 질문을 보냈다가 REFUSED를 받고 원래 질문을 보내면 호환성 재시도 가능성이 있습니다. 앞선 맥락 없이 전체 이름만 보이면 이유는 미확정입니다. 목적지 역할이 불명확하거나 상위 관측만 있다면 판단 근거가 부족합니다.

**실패 점검.** 복사한 CSV에서 `cold` 사례의 상위 서버 질의 이름을 `lab.test.`에서 `mail.lab.test.`로 바꾸세요. 기대한 최소화 흐름이 `full-name-at-parent`로 판정되면서 검증에 실패해야 합니다. 파일을 열 수 없으면 작업 폴더와 CSV 헤더를 확인하세요. 가상 사례와 대조 사례는 클라우드에서 실행했습니다. BIND·Unbound·Zeek 동작은 각 제품 문서와 대조했습니다.

## 5. 확인 문제와 완료 기준

1. **루트 서버에는 `test.`만 보였습니다. 클라이언트가 접속하려던 호스트는 무엇인가요?** 이 관측에는 접미 이름만 있습니다. 승인된 클라이언트 쪽 리졸버 자료를 확인합니다.
2. **최종 권한 서버에 전체 이름을 보낸 기록만 있습니다. 최소화가 꺼진 건가요?** 위임이 캐시에 있어도 같은 모습이 나옵니다. 목적지 역할과 캐시 상태, 앞선 트래픽을 확인합니다.
3. **상위 서버에서 전체 이름을 봤다면 무엇을 결론 내릴 수 있나요?** 그 이름이 서버에 전달됐습니다. 상위 서버가 관할하는 질의인지, 정상 재시도인지, 예상과 다른 경로나 설정인지 대조합니다.

관측 구간을 식별하고, 전체 이름과 짧은 이름이 나타난 근거를 각각 설명하고, 로그 누락 때문에 남는 질문을 제시할 수 있으면 학습을 마친 것입니다.

## 공식 참고자료

**검토일 2026-11-27.** RFC 9156은 2021년 11월 표준 트랙 문서입니다. 제품 동작은 ISC BIND 9.20.31 레퍼런스, 검토 당시 NLnet Labs Unbound 매뉴얼과 Zeek 9.0.1 필드 문서를 기준으로 했습니다.

- [RFC 9156 · DNS 질의 이름 최소화](https://www.rfc-editor.org/rfc/rfc9156.html)
- [RFC 9076 · DNS 개인정보 보호 고려 사항](https://www.rfc-editor.org/rfc/rfc9076.html)
- [RFC 2606 · 시험 및 문서용 예약 DNS 이름](https://www.rfc-editor.org/rfc/rfc2606.html)
- [ISC BIND 9 · qname-minimization 설정](https://bind9.readthedocs.io/en/stable/reference.html#qname-minimization)
- [NLnet Labs · Unbound 설정 레퍼런스](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [Zeek · DNS 로그 필드](https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html)

[이전 · DNS 기초와 보안 조사]({{ '/ko/wiki/dns-investigation/' | relative_url }}) · [다음 · DNS over HTTPS 조사]({{ '/ko/wiki/doh-resolution-evidence/' | relative_url }}) · [확장 DNS 오류와 대조]({{ '/ko/wiki/dns-extended-error-evidence/' | relative_url }})
