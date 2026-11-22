---
title: "SAML SSO 조사 · 신원 제공자 인증에서 앱 접근까지"
description: "가상 사례 열 건으로 SAML 발급자 신뢰, 어설션 검사, 세션 발급과 앱 인가를 구분합니다."
category: cloud
tags: [SAML, SSO, IAM, Microsoft Entra, Cloud Security, Blue Team]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/saml-sso-evidence/
---

IdP에서 로그인에 성공했는데도 애플리케이션이 SAML 응답을 거부하거나 세션을 만들지 않거나, 이후 작업을 거부할 수 있습니다. 인증 시스템과 앱의 기록을 함께 보고 어느 단계에서 실패했거나 확인이 끊겼는지 찾아보세요. 이 장의 범위는 SP가 요청을 시작하고 브라우저가 응답을 HTTP POST로 전달하는 SAML 2.0 웹 브라우저 SSO입니다.

## 1. 누가 누구를 신뢰하나요?

**SAML(Security Assertion Markup Language)**은 XML 기반의 페더레이션 표준입니다. 페더레이션은 앱이 사전에 합의한 인증 시스템을 신뢰할 수 있게 합니다. 사용자는 **IdP(Identity Provider, 신원 제공자)**에서 인증합니다. **SP(Service Provider, 서비스 제공자)**는 그 결과를 받아 자체 세션을 시작할지 결정하는 앱입니다. **어설션(assertion)**은 인증 사실이나 속성처럼 특정 주체에 관한 진술을 담습니다. **응답(response)**은 처리 상태를 전하는 메시지로, 이 장에서 다루는 정상 흐름에서는 어설션도 담습니다.

SP와 IdP는 로그인 전에 신뢰 관계를 설정합니다. SP의 **엔터티 ID(entity ID)**는 서비스의 논리적 식별자이고, **ACS(Assertion Consumer Service)**는 응답을 받는 엔드포인트입니다. 페더레이션 메타데이터에는 식별자, 엔드포인트, 서명 검증에 쓰는 공개키 등이 들어갈 수 있습니다. 합의된 인증 채널에서 받아 올바른 테넌트와 앱에 적용하세요. 브라우저가 HTTPS 연결에 사용하는 인증서와 SP가 SAML 서명을 검증하는 키는 역할이 다릅니다.

## 2. 정상 로그인 한 건을 따라가세요

교육용 경비 포털의 엔터티 ID를 `urn:example:expenses`, ACS를 `https://expenses.example.test/sso/acs`라고 가정합니다. 둘 다 가상 값입니다. 포털은 요청 `req-17`을 저장하고 브라우저를 통해 `AuthnRequest`를 보냅니다. IdP는 사용자를 인증하거나 기존 세션과 정책을 적용한 후 응답을 발급합니다. 브라우저가 응답을 ACS에 전달하면, SP는 대기 중인 요청과 대조하고 설정된 신뢰 관계와 정책에 따라 어설션을 검사합니다. 이후 어설션의 주체를 앱 내부 계정에 연결합니다. 성공하면 포털이 세션을 만들 수 있으며, 경비 보고서를 열 수 있는지는 포털이 별도로 판단합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/saml-sso-evidence-ko.svg' | relative_url }}" alt="SP가 요청을 보내면 IdP가 응답을 발급하고 SP의 ACS가 검사합니다. 승인된 응답은 계정 연결과 세션 생성을 거쳐 작업 인가로 이어집니다. 거부된 응답은 세션 생성 전에 중단됩니다.">
  <figcaption>단계마다 다른 기록이 남을 수 있습니다. 브라우저 POST 방식에서는 브라우저가 IdP 응답을 SP로 전달합니다.</figcaption>
</figure>

| 검사 항목 | 답할 수 있는 질문 |
| --- | --- |
| 발급자와 서명 | SP가 사용하는 서명 대상이 이 발급자와 연동에 대해 신뢰한 키로 검증되나요? |
| Audience | 이 SP의 논리적 식별자가 허용된 대상에 들어 있나요? |
| Recipient와 Destination | 소지 기반 확인 정보가 실제 응답 수신 ACS를 가리키나요? 응답 목적지가 제공됐거나 필수라면 수신 위치와 일치하나요? |
| InResponseTo | 이 SP가 보낸 대기 중 요청에 대한 응답인가요? 프로파일과 바인딩에 따라 응답과 소지 기반 확인 데이터를 대조합니다. |
| Conditions와 소지 기반 만료 | 수신 시점이 설정된 허용 오차까지 고려했을 때 유효한가요? 어설션 조건의 기간과 소지 기반 확인의 만료 시각은 각각 확인합니다. |
| 재사용 방지 | 같은 어설션이 해당 검사 범위에서 이미 수락된 적이 있나요? |
| 앱 계정 연결과 인가 | 어떤 앱 계정과 역할이 선택됐고, 세션이 발급됐으며, 작업이 허용됐나요? |

요청 ID는 최초 요청, 응답 ID는 응답 메시지, 어설션 ID는 진술 묶음을 가리킵니다. 앱의 세션 참조는 별도로 생성되고 기록됩니다. IdP가 먼저 시작하는 프로파일에는 원래 SP 요청이 없으므로, 어떤 흐름을 허용하는지와 어떤 기록을 기대할지 별도의 기준선을 두어야 합니다.

## 3. 실패와 오용을 구분하세요

시험 환경 설정을 운영 환경에 복사하면 Audience가 틀릴 수 있습니다. 호스트나 경로가 바뀐 뒤에는 ACS 불일치가 생길 수 있습니다. 시간 경계에서는 SP 수신 시각, 시계 동기화 상태, 설정된 허용 오차를 어설션 조건 및 소지 기반 확인의 만료와 비교하세요. 허용 오차 적용 전에는 `NotOnOrAfter` 값에 도달하는 순간 유효 기간이 끝납니다. 이 만료 시각은 어설션 수락 여부에 적용됩니다. 이미 만들어진 앱 세션에는 자체 수명과 제어가 있습니다.

소지 기반(bearer) 어설션은 누가 갖고 있는지가 중요하므로 민감합니다. 재사용(replay)은 같은 어설션을 다시 쓰려는 시도입니다. 중복 거부는 정상적인 브라우저 재제출이나 앱 재시도에서도 나타날 수 있습니다. 먼저 수락된 기록을 찾고 두 요청을 처리한 노드 모두에서 재사용 방지 기록이 수집되는지 확인하세요. 서명 키가 유출되면 맞는 서명도 신뢰하기 어려워집니다. 계획된 키 교체 직후 불일치는 SP가 오래된 메타데이터나 이전 키만 사용하는 경우에도 생깁니다. 서명 검증은 앱이 실제로 읽는 데이터까지 포함해야 합니다. 유지보수되는 SAML 라이브러리와 해당 연동에서 합의한 서명 설정을 사용하세요.

## 4. 기록을 수집하고 대응하세요

| 기록 출처 | 확보할 항목 |
| --- | --- |
| IdP 로그인 및 변경 감사 | UTC, 테넌트, 앱, 사용자 참조, 결과, 정책·인증 문맥, 수집되는 경우 연동·인증서 변경 |
| SP 페더레이션 또는 ACS 진단 | UTC, 테넌트·연동, 앱과 노드, 안전한 요청·어설션 참조, 판정 사유, 키 참조, 메타데이터 버전과 엔드포인트 |
| 앱 세션 및 업무 감사 | UTC, 범위가 지정된 트랜잭션·세션 참조, 연결된 계정, 역할, 작업, 리소스, 판정 |

기록이 없다고 해석하기 전에 진단 설정과 접근 권한, 시각 동기화, 보존 기간, 수신 노드 전체의 수집 여부를 확인하세요. 이 장의 필드와 판정 이름은 개념을 설명하기 위한 것입니다. Entra 로그인 로그는 IdP 쪽 증거이므로 앱 쪽 감사 기록도 별도로 확보합니다. Entra 상관관계 ID가 SAML 요청 ID와 같거나 SP에 있다고 가정하지 마세요. 문서화된 공통 참조가 있으면 활용하고, 앱·시각·계정만 맞으면 후보 연결이라고 기록하고 불확실성을 적으세요. 티켓에 원본 어설션, 세션 쿠키, 불필요한 신원 속성을 넣지 마세요. 원본은 접근을 제한하고 공유 자료에는 승인된 방식으로 일관되게 가명화한 참조를 사용합니다.

연동과 배포 단위로 수락·거부 사유의 평상시 분포를 파악하세요. 변경 직후 한 앱에서 알 수 없는 서명 키 오류가 늘면 키 참조, 적용 메타데이터, 변경 기록을 대조합니다. 여러 노드에서 같은 참조의 수락이 반복되면 재사용 방지 작동 여부와 로그 중복, 재시도, 실제 별도 세션을 구분하세요. 어설션 수락 뒤 예상 밖 권한이 부여됐다면 앱 내부 계정·역할 연결과 업무 감사 기록을 봅니다. 설정 버전과 시간순 기록을 보존하고 IdP·앱 운영자와 대응하세요. 키 노출이 의심되면 그 키를 신뢰하는 SP의 범위를 파악하고 교체와 앱 세션 무효화 방법을 조율합니다. 조치 후 예상한 접근만 가능한지 재확인하세요.

## 5. 오프라인 실습으로 가상 기록 분석하기

<a href="{{ '/assets/labs/saml-sso-evidence.py' | relative_url }}" download="saml-sso-evidence.py">Python 분석 스크립트</a>와 <a href="{{ '/assets/labs/saml-sso-evidence-cases.json' | relative_url }}" download="saml-sso-evidence-cases.json">가상 JSON 사례</a>를 같은 폴더에 저장하세요. 본인이 소유하거나 승인받은 작업 공간에서 Python 3으로 실행합니다. 로컬 JSON에서 가상 상관관계 참조를 읽고 기록이 뒷받침하는 마지막 단계를 출력합니다. ACS 판정은 예제에 미리 들어 있으며, 실습은 실제 SAML 메시지를 처리하거나 서비스에 접속하지 않습니다.

```bash
python3 saml-sso-evidence.py saml-sso-evidence-cases.json
```

정상 조회, ACS 기록 없음, 대상 불일치, 세션 기록 없음, 재사용 거부, 세션 생성 뒤 작업 거부, 다른 연동의 기록, 세션보다 앞선 작업, 역할 연결 실패, 요청이 다른 ACS 기록이 차례로 나옵니다. 결과를 보기 전에 각 사례에서 무엇까지 확인할 수 있는지 예상해 보세요.

```text
normal: action_allowed
idp_only: acs_unobserved
wrong_audience: acs_rejected:audience
session_missing: session_unobserved
duplicate: acs_rejected:replay
action_denied: action_denied
other_connection: session_unobserved
early_action: action_unobserved
mapping_denied: session_denied
wrong_request: acs_unobserved
```

파일을 열 수 없으면 두 파일의 이름과 현재 폴더를 확인하세요. 사건이 연결되지 않으면 테넌트, 연동, 참조, 이벤트 순서를 살펴보세요. 승인된 테스트 테넌트에서 추가로 검증하려면 격리된 시험 계정과 보호된 읽기 작업을 하나 정해 양쪽에서 수집한 기록과 대조하세요. 게시 검증에서는 가상 데이터 분석기를 실행했습니다. SAML 메시지 검증, Entra 로그인과 SP 세션 제어는 문서로 검토했으며 실제 제품 검증은 별도입니다.

## 6. 확인 문제와 완료 기준

- **IdP가 성공을 기록했지만 ACS가 Audience를 거부했습니다. 앱에 로그인했나요?** 해당 응답은 ACS에서 거부됐습니다. 전체 접근을 판단하려면 다른 트랜잭션이나 기존 세션이 있었는지 확인하세요.
- **어설션 서명이 맞았습니다. 더 볼 것이 있나요?** 프로파일에 따라 발급자 신뢰, 대상, 요청 연결, 시각, 재사용 여부를 확인합니다. 앱 내부 계정 연결과 세션 발급, 작업 인가도 별도로 확인하세요.
- **같은 참조가 있는 작업이 세션보다 1초 빠릅니다. 무엇을 보고할 수 있나요?** 이 실습에서는 연결하지 않습니다. 운영 환경에서는 이벤트 시각의 정의와 시계 차이, 연동 범위를 확인한 뒤 연결을 판단하세요.

열 줄이 모두 예상 결과와 일치하고 `idp_only`, `session_missing`, `early_action`에서 다음으로 볼 기록을 말할 수 있으면 완료입니다.

## 공식 참고자료

2026-11-22 검토. OASIS 표준과 정오표는 프로토콜을, NIST 2025년 개정판은 페더레이션 보증 수준을 다룹니다. Microsoft 자료는 문서에 기술된 Entra 흐름과 설정을 설명합니다.

- 어설션, 조건과 메시지 의미. [OASIS SAML 2.0 Core (2005)](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- 웹 브라우저 SSO와 POST 처리, 4.1.4·4.1.5절. [OASIS SAML 2.0 Profiles (2005)](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf) · [승인된 정오표 05 (2012)](https://docs.oasis-open.org/security/saml/v2.0/sstc-saml-approved-errata-2.0.html)
- 신뢰 관계와 재사용 방지, 검증 요구 사항. [NIST SP 800-63C-4 (2025)](https://pages.nist.gov/800-63-4/sp800-63c.html)
- Microsoft Entra의 요청과 응답 처리. [Microsoft Learn · SAML SSO 프로토콜](https://learn.microsoft.com/en-us/entra/identity-platform/single-sign-on-saml-protocol)
- 서명 인증서 교체와 메타데이터. [Microsoft Learn · 페더레이션 인증서 관리](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tutorial-manage-certificates-for-federated-single-sign-on)
- Entra 로그인 기록의 범위. [Microsoft Learn · 로그인 로그](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)

[관련 글 · OAuth와 OpenID Connect]({{ '/ko/wiki/oauth-oidc-evidence/' | relative_url }}) · [다음 학습 · Microsoft Entra 로그인 조사]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }})
