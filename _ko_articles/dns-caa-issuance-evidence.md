---
title: "DNS CAA 발급 조사 · 조회에서 인증서까지"
description: "가상 사례 여덟 건으로 CAA 상위 이름과 별칭 조회, 발급자·와일드카드 제한, 갱신 실패를 살펴봅니다."
category: network
tags: [DNS, CAA, PKI, Certificates, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /wiki/dns-caa-issuance-evidence/
---

**학습 목표.** 인증서에 넣으려는 이름마다 어떤 DNS CAA 레코드 집합이 적용되는지 확인합니다. 발급자 제한과 DNS 조회 실패, 인증서 배포 문제를 서로 다른 증거로 판단합니다.

## 1. CAA는 무엇을 제어하나요?

**CAA(Certification Authority Authorization)**는 공개 TLS 인증기관(CA)이 발급 전에 확인하는 DNS 레코드 유형입니다. **RRset**은 한 DNS 소유자 이름에 있는 같은 유형의 레코드 집합입니다. **발급자 식별자**는 CA가 CAA 값에 쓰도록 안내하는 DNS 형태의 이름입니다. 인증서에 표시되는 발급자 이름과 다를 수 있습니다. **SAN(Subject Alternative Name)**은 인증서가 포함하는 DNS 이름 등을 담는 확장입니다.

CA는 보통 요청된 각 DNS 이름을 따로 검사합니다. 와일드카드 이름도 각각 확인합니다. CAA는 발급할 수 있는 CA의 범위를 줄입니다. 신청자는 도메인 제어권을 증명해야 하며 다른 발급 조건도 충족해야 합니다. 브라우저가 배포된 인증서를 검증하는 일은 별도입니다. CAA를 바꿔도 기존 인증서는 폐기되지 않으며 로드밸런서가 제공하는 인증서도 저절로 바뀌지 않습니다.

| 레코드 | 역할 |
| --- | --- |
| `0 issue "ca-a.example"` | 일반 이름에 대해 해당 발급자를 허용합니다. `issuewild`가 없으면 와일드카드에도 적용될 수 있습니다. |
| `0 issuewild ";"` | 이 항목은 와일드카드에 대해 어떤 발급자도 허용하지 않습니다. 다른 적용 가능한 `issuewild` 항목이 발급자를 허용할 수 있습니다. |
| `0 iodef "mailto:security@example"` | 보고를 받을 곳을 알립니다. 발급 권한을 부여하지 않으며 보고 전달도 보장하지 않습니다. |
| 플래그 `128`이 설정된 미지원 속성 | CA가 해당 속성을 처리할 수 없으면 이 이름의 발급을 중단해야 합니다. |

적용되는 `issue ";"`만 있으면 어떤 CA도 허용되지 않습니다. 같은 집합에 유효한 허용 항목이 있다면 빈 항목이 그 허용을 취소하지 않습니다. 선택된 집합에 적용되는 발급자 태그도, 처리하지 못한 필수 속성도 없으면 CAA에 따른 발급자 제한이 없습니다. 보고 속성만 들어 있어도 비어 있지 않은 첫 집합이라면 상위 이름 검색은 거기서 끝납니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/dns-caa-issuance-evidence-ko.svg' | relative_url }}" alt="요청한 이름마다 별칭을 따라 CAA를 조회합니다. 비어 있지 않은 결과를 찾으면 검색을 끝냅니다. 사용할 수 있는 빈 응답이면 원래 이름의 상위 이름으로 이동합니다. 실패는 따로 조사합니다. 선택한 집합에서 발급자 태그를 평가합니다.">
  <figcaption>DNS 조회 결과와 반환된 발급 정책을 따로 판단합니다.</figcaption>
</figure>

## 2. 정상적인 갱신을 따라가기

팀이 가상의 `ca-a.example`에 `api.example`과 `*.apps.example`의 발급을 요청합니다. `api.example`에 CAA가 없고 상위 `example`에 `issue "ca-a.example"`가 있다고 가정합니다. 와일드카드는 앞의 `*.`를 뺀 `apps.example`부터 조회합니다. 이 집합에 `issue "ca-a.example"`과 `issuewild ";"`가 함께 있으면 일반 이름은 CAA상 허용되지만 와일드카드는 해당 정책에 막힙니다. 팀은 묶어서 제출한 요청을 다시 시도하기 전에 두 이름을 각각 점검합니다.

CA가 각 단계의 이름에 CAA를 질의할 때 CNAME이나 DNAME이 적용되면 별칭을 따라갑니다. 별칭을 따라간 뒤에도 CAA가 없으면, 다음 상위 이름은 **원래 질의한 이름**에서 왼쪽 라벨 하나를 뗀 이름입니다. 별칭 대상 자체에서 반환된 CAA는 적용될 수 있지만, 대상 쪽 상위 이름의 정책을 자동으로 적용하지 않습니다. 조사 자료에는 질의 이름, 별칭과 실제 반환된 소유자 이름을 남깁니다.

## 3. 실패하거나 예상 밖으로 발급됐을 때

| 관측 | 이어서 모을 증거 |
| --- | --- |
| 정상적인 부정 응답에서 CAA가 없음 | 헤더와 권한 섹션을 보존합니다. NOERROR인데 해당 유형만 없는 경우와 NXDOMAIN을 구분한 뒤 별칭·상위 이름을 확인합니다. |
| SERVFAIL, 시간 초과 또는 DNSSEC 검증 오류 | 검증 리졸버와 권한 서버의 관측을 대조합니다. 오류와 DNSSEC 맥락을 남기고 빈 집합으로 처리하지 않습니다. |
| 로컬 리졸버에서는 허용되지만 CA는 거부함 | CA가 보고한 이름과 발급자 식별자, 와일드카드 태그, 적용되는 매개변수, DNS 변경 이력, TTL과 관측 지점을 비교합니다. |
| 새 인증서가 발급됐지만 클라이언트는 이전 인증서를 봄 | 클라이언트가 연결하는 TLS 종단에서 실제 제공하는 최종 인증서를 확인합니다. 발급과 배포의 증거는 따로 확인합니다. |

DNS 변경으로 의도하지 않은 발급자를 허용하거나 정상 갱신을 막을 수 있습니다. 계획된 전환, 남아 있는 캐시, 깨진 위임도 비슷한 증상을 만듭니다. 변경 승인, DNS 관리 시스템의 감사 기록, 주문 또는 요청 ID, SAN 목록, DNS 응답 집합, TTL, 조회 위치와 UTC 시각을 보존합니다. 나중에 로컬에서 본 정책만으로 발급 시점에 CA가 같은 결과를 봤다고 단정할 수 없습니다. 현행 공개 TLS 기본 요구사항은 CA의 주 관측 지점에서 CAA 조회 시 DNSSEC 검증을 요구하며, 그 범위에서 발생한 검증 오류를 발급 허용으로 처리하지 못하게 합니다. 예외와 관측 지점의 적용 범위는 문서를 확인하세요. 아래 실습은 조회 오류에서 판단을 보류합니다.

발급자와 이름을 승인된 CA 및 인증서 목록과 대조합니다. 실제 제공되는 인증서를 확인하고, 적용되는 경우 인증서 투명성(CT) 로그에서 대응하는 항목을 찾습니다. CT 항목은 발급 타임라인을 뒷받침하지만 서버가 언제부터 그 인증서를 제공했는지는 알려 주지 않습니다. 승인되지 않은 변경이라면 증거를 보존하고 DNS 담당자와 구성을 수정한 뒤 지정된 관측 지점에서 확인하고 갱신을 다시 시도합니다. 무단 발급이 의심되면 사고 절차에 따라 CA에 문의합니다. 개인키는 사고 자료에 복사하지 않습니다.

## 4. 오프라인 증거 실습

<a href="{{ '/assets/labs/dns-caa-issuance-evidence.py' | relative_url }}" download="dns-caa-issuance-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/dns-caa-issuance-evidence-cases.json' | relative_url }}" download="dns-caa-issuance-evidence-cases.json">가상 조회 사례</a>를 승인된 작업 공간의 한 폴더에 둡니다. 자료는 별칭 처리 결과를 포함한 각 조회 단계를 제공합니다. 스크립트는 첫 번째 비어 있지 않은 집합을 평가하거나 조회 오류·증거 누락으로 표시합니다. DNS를 직접 조회하거나 CA별 매개변수를 구현하거나 인증서를 발급하지 않습니다.

```bash
python3 dns-caa-issuance-evidence.py dns-caa-issuance-evidence-cases.json
```

```text
parent: authorized_by_caa
wildcard: issuer_not_authorized
alias_target: issuer_not_authorized
empty_and_allowed: authorized_by_caa
critical: unsupported_critical_property
report_only: unrestricted_by_caa
lookup_error: lookup_unresolved
missing_parent: incomplete_evidence
```

Python 3으로 실행합니다. 입력 파일을 열 수 없으면 폴더와 파일 이름을 확인하세요. 판단이 예상과 다르면 어떤 집합이 선택됐는지, 대상이 와일드카드인지 확인합니다. 실습 자료에서 `complete`는 결과가 비어 있어도 필요한 조회 단계가 모두 제공됐다는 뜻입니다. 여덟 사례는 오프라인에서 실행했습니다.

실시간 관측을 따로 비교하려면 BIND의 `dig`와 승인된 리졸버를 사용해 관리 권한이 있는 이름에 `dig @RESOLVER_IP YOUR_APPROVED_NAME CAA`을 실행하세요. 리졸버, 응답 코드, 별칭, TTL과 권한 섹션을 기록합니다. 사용할 수 있는 부정 응답이라면 상위 이름에서도 반복합니다. 와일드카드 인증서는 `*.`를 뺀 이름부터 시작합니다. `+short` 결과만으로 판단하지 마세요. 로컬 조회는 CA의 관측 환경과 다를 수 있습니다. 명령과 CA 절차는 공식 문서로 검토했으며 실제 CA 또는 DNS 존에서는 실행하지 않았습니다.

## 5. 확인 문제와 완료 기준

- **해당 이름에는 `iodef`만 있고 상위 이름에 `issue` 제한이 있습니다. 제한을 적용하나요?** 해당 이름의 집합이 비어 있지 않아 검색이 끝납니다. 보고 속성은 발급자를 제한하지 않습니다.
- **SERVFAIL이면 “CAA 없음”으로 기록해도 되나요?** 오류를 보존하고 리졸버와 DNSSEC 기록을 확인합니다. 성공한 빈 응답이 아닙니다.
- **CAA가 올바른 CA를 허용합니다. 사용자가 새 인증서를 받는다고 볼 수 있나요?** 클라이언트가 이용하는 TLS 종단의 인증서를 확인하고 발급·배포 증거와 대조합니다.

여덟 사례의 출력이 모두 일치하고, 선택한 집합과 적용 태그, 배포를 확인할 독립 증거를 설명하면 실습을 마친 것입니다.

## 공식 참고자료

2026년 11월 23일에 검토했습니다. RFC 8659(2019년)는 초기 RFC 6844를 대체합니다. 공개 TLS 기본 요구사항은 CA/Browser Forum 2.3.1(2026년 10월 4일)을 확인했습니다. 과거 사건에는 당시 유효한 요구사항을 적용합니다.

- 이름 검색, 속성과 와일드카드 판정. [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html)
- 발급자 검사, DNSSEC와 여러 관측 지점. [CA/Browser Forum TLS 기본 요구사항](https://cabforum.org/working-groups/server/baseline-requirements/requirements/)
- 발급자 식별자와 공급자별 예시. 2026년 10월 4일 갱신. [Let's Encrypt CAA 문서](https://letsencrypt.org/docs/caa/)
- 조회 문법과 진단. [BIND 9 dig 설명서](https://bind9.readthedocs.io/en/latest/manpages.html#dig-dns-lookup-utility)

[이전 · DNS 조사]({{ '/ko/wiki/dns-investigation/' | relative_url }}) · [다음 · 인증서 갱신 증거]({{ '/ko/wiki/certificate-renewal-evidence/' | relative_url }}) · [관련 · 인증서 투명성]({{ '/ko/wiki/certificate-transparency-evidence/' | relative_url }})
