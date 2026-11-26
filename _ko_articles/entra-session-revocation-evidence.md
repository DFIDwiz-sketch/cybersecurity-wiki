---
title: "Microsoft Entra 세션 취소 · 리소스에서 접근 차단 확인하기"
description: "디렉터리의 취소 작업, 토큰 갱신 실패, 클레임 챌린지, 기존 세션에 대한 실제 차단을 구분합니다."
category: cloud
tags: [Microsoft Entra, IAM, OAuth 2.0, Incident Response, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/entra-session-revocation-evidence/
---

기기를 잃어버린 뒤 관리자가 사용자의 로그인 세션을 취소했습니다. 디렉터리 감사 로그에는 성공으로 남았습니다. 사고 대응 담당자는 기존 클라이언트가 여전히 무엇을 할 수 있는지 확인해야 합니다. 문제의 세션을 토큰 서비스와 각 리소스까지 따라가면 어느 경로가 차단됐는지 설명할 수 있습니다.

## 1. 어떤 자격 증명이며 어디에서 판정하나요?

**액세스 토큰**은 리소스 API에 제시합니다. **새로 고침 토큰**은 발급자에게 새 토큰을 요청할 때 사용합니다. 브라우저의 **Entra 로그인 쿠키**는 ID 공급자의 로그인 상태를 이어 줍니다. 로그인 후 서비스가 자체 **애플리케이션 세션 쿠키**를 발급할 수도 있습니다. 이 세션은 수명이 별도이며 앱에서 종료해야 할 수 있습니다. OAuth 앱 전용 접근은 서비스 주체나 관리 ID에 속합니다. 사용자 세션을 취소할 때와 적용 대상이 다릅니다.

| 관측 자료 | 무엇을 뒷받침하나요? | 추가로 확인할 근거 |
| --- | --- | --- |
| 디렉터리 감사 로그의 취소 성공 | 기록된 테넌트와 대상에 관리 작업이 성공함 | 세션 기준 시각과 하위 경로 관측 |
| 토큰 서비스가 갱신을 취소 사유로 거부 | 해당 시도는 더 이상 토큰을 얻을 수 없음 | 기존 액세스 토큰과 앱 세션은 따로 확인 |
| 리소스의 클레임 챌린지 | 요청이 현재 리소스의 요구 조건을 충족하지 못함 | 원래 요청, 재인증과 최종 리소스 응답 |
| 기존 세션의 인증된 요청에 리소스가 성공 응답 | 시험한 경로에서 요청을 여전히 처리함 | 자격 증명과 세션의 연결, 정확한 동작과 앱 결과 |
| 앱 세션의 종료 또는 거부 | 관측한 서비스와 세션에 대한 적용 결과 | 해당되는 다른 앱과 사용자 또는 워크로드 ID |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/entra-session-revocation-evidence-ko.svg' | relative_url }}" alt="디렉터리에서 세션을 취소한 뒤 토큰 서비스의 갱신과 리소스의 기존 접근을 따로 확인합니다. 앱이 관리하는 세션은 앱에서 확인합니다. 각 관측은 해당 경로의 근거입니다." style="max-width: 100%; height: auto;">
  <figcaption>그림 1. 관리 작업과 각 리소스에서의 차단은 서로 다른 질문입니다.</figcaption>
</figure>

## 2. 정상 세션에서 취소 이후까지 따라가기

가상 테넌트의 사용자가 UTC 09:00에 로그인하고 테스트 문서를 읽습니다. 클라이언트는 액세스 토큰으로 리소스를 호출하고 Entra에서 토큰을 갱신할 수 있습니다. 다른 브라우저 앱은 로그인 후 자체 세션을 만듭니다. 09:10에 관리자가 Entra 세션을 취소합니다. Microsoft Graph v1.0의 `revokeSignInSessions`는 `signInSessionsValidFromDateTime`을 현재 시각으로 옮겨 기존 새로 고침 토큰과 Entra 로그인 쿠키를 무효화합니다. 전파에 짧은 지연이 생길 수 있습니다.

09:12에 토큰 서비스가 취소와 관련된 사유로 기존 토큰의 갱신을 거부합니다. 09:13에 연속 액세스 평가(CAE)를 사용하지 않는 리소스는 이미 발급된 액세스 토큰의 요청을 받아들입니다. 토큰이 만료될 때까지 리소스별 처리가 중요합니다. 09:14에는 독립적인 앱 세션도 요청을 처리하므로 앱의 자체 종료 절차가 필요합니다. 갱신 실패와 기존 액세스 토큰 사용, 앱 세션 지속이 동시에 관측될 수 있습니다. 여기의 시각과 결과는 모두 가상입니다.

**연속 액세스 평가(CAE)**를 지원하는 리소스는 일반적인 토큰 만료 전에 특정 이벤트와 정책을 평가할 수 있습니다. Microsoft는 문서에 나온 중요 이벤트 경로에서 전파가 최대 15분까지 지연될 수 있다고 설명합니다. 적용하려면 리소스, 클라이언트 기능, 시나리오가 CAE를 지원해야 합니다. 이 시간을 모든 앱의 차단 완료 기준으로 쓰지는 않습니다. 지원 API의 클레임 챌린지는 401과 Bearer `WWW-Authenticate` 응답 헤더로 오며 `insufficient_claims`와 클레임 지시가 포함됩니다. 이는 해당 요청에 새로운 클레임이 필요했다는 증거입니다. 정책이 허용하면 이후 재인증과 새 요청은 성공할 수 있습니다.

## 3. 확인된 근거와 남은 가설

침해된 클라이언트가 관리 작업 이후에도 캐시된 액세스 토큰이나 별도 앱 세션을 사용할 수 있습니다. 정상 클라이언트도 잠시 캐시를 쓰거나 재인증한 뒤 나중에 열린 세션으로 전환할 수 있습니다. 기존 세션 또는 공격자에게 행위를 귀속하기 전에 리소스가 어느 계정, 발급 테넌트, 세션을 평가했는지 확인하세요. 이후의 HTTP 200이나 로그인 실패, IP 주소, User-Agent 한 가지로는 판단할 수 없습니다.

Microsoft Graph는 외부 사용자에 대한 적용 범위도 명시합니다. 리소스 테넌트에서 이 API를 호출해도 게스트의 홈 테넌트 로그인 세션은 취소되지 않습니다. 필요하면 홈 테넌트와 협조하고 리소스 테넌트의 접근 제어 및 앱 세션도 확인합니다. 앱 전용 활동은 워크로드 ID의 권한이나 자격 증명을 조사합니다. 비밀번호 변경, 계정 사용 중지, 세션 취소는 대응 타임라인의 별도 작업입니다. 각각의 기록을 남기고 적용 범위에서 효과를 검증하세요.

## 4. 블루팀 수집·탐지·대응

1. **관리 타임라인을 확보합니다.** 권한이 있는 Entra 테넌트의 감사 로그에서 UTC 시각, 활동, 결과, 대상 객체 ID, 실행 주체와 테넌트를 보존합니다. Graph의 `directoryAudit`에는 `activityDateTime`, `initiatedBy`, `targetResources`, `result`, `correlationId` 같은 필드가 있습니다. 승인을 받은 Microsoft Graph 읽기 권한이 있고 대상 사용자를 확정했다면 `$select`에 세션 기준 시각 속성을 명시해 조회합니다. 현재 값은 사고 이후 다시 바뀌었을 수 있는 스냅샷입니다. 작업 티켓이나 공유 로그에 토큰과 쿠키 원문을 수집하지 않습니다.
2. **발급자와 리소스를 따로 따라갑니다.** 영향받은 사용자, 토큰 발급 테넌트, 클라이언트 앱, 리소스, 작업과 원본 시각을 기록합니다. 관련 Entra 로그인 로그 범주와 리소스 감사 기록을 확인합니다. 로그가 없다고 해석하기 전에 보존과 내보내기 범위를 확인합니다. 기발급 토큰은 새로운 로그인 이벤트 없이 다시 사용될 수 있습니다. 신뢰할 수 있는 요청 ID는 연계 용도로 설계된 범위에서 사용합니다. 서비스가 서로 다르면 별도의 연결 근거 없이 ID가 같다고 가정하지 않습니다.
3. **승인된 조건에서 차단을 확인합니다.** 소유한 테스트 테넌트의 승인된 계정과 앱에서 무해한 읽기를 사용하세요. 기존 세션이 리소스에 도착했는지, 챌린지를 받았는지, 이후 작업이 새 세션을 썼는지 기록합니다. 앱 세션 경로는 각각 시험하고 소유자와 예상 범위를 확인하세요. 관계없는 접근 규칙에 막힌 요청은 취소 효과를 입증하지 못합니다.
4. **남아 있는 접근을 추적합니다.** 관리 작업 이후 성공한 해당 ID의 작업을 찾아 기존 세션, 새 로그인, 다른 주체로 나눕니다. 관측하지 못한 리소스나 불명확한 세션은 미확인으로 남깁니다. 필요하면 사고 대응 계획에 따라 앱의 세션 만료, 계정 또는 기기 조치를 담당자와 협의하고 리소스에서 효과를 확인합니다.

## 5. 승인된 오프라인 실습

<a href="{{ '/assets/labs/entra-session-revocation-evidence.py' | relative_url }}" download>Python 검사기</a>와 <a href="{{ '/assets/labs/entra-session-revocation-evidence.json' | relative_url }}" download>가상 타임라인</a>을 같은 폴더에 저장합니다. 본인이 소유했거나 사용 승인을 받은 환경에서 Python 3으로 실행하세요. 가상 행에는 `tenant`, `user`, 확인하는 경로인 `surface`, `session`이 미리 연결돼 있습니다. 이 값들은 실습용 표식이고 Entra 필드명이나 토큰 값과 다릅니다. 인증이나 네트워크 호출은 하지 않습니다.

~~~bash
python3 entra-session-revocation-evidence.py
~~~

| 사례 | 기대 관측 |
| --- | --- |
| A, B, C | 취소된 토큰의 갱신 거부, 기존 리소스 접근 허용, 앱 세션 허용 |
| D, E | 최종 판정이 없는 챌린지, 해당 리소스에서 취소로 귀속할 수 있는 거부 |
| F, G | 관리 작업 성공 후 하위 관측 없음, 적용 범위 밖의 홈 테넌트 세션 |
| H, I, J | 다른 세션, 원인이 확인되지 않은 거부, 관리 작업 실패 |

`10/10 cases matched.`가 나오는지 확인하세요. 사본에서 B의 `observation.session`만 `old-session`에서 `new-session`으로 바꾸고 기대값을 유지합니다. 사본 파일을 인자로 주면 B가 `different-session`으로 바뀌고 종료 코드 1이 나와야 합니다. 실행이 예상과 달리 실패하면 실습 파일의 경로와 UTC 형식을 확인합니다. 가상 실습만 직접 실행했습니다. Microsoft Graph, Entra와 앱 차단은 공식 문서로 검토했으며 실제 테넌트는 조작하지 않았습니다.

## 6. 확인 문제와 완료 기준

1. **취소 성공 감사 로그가 있으면 앱은 더 이상 데이터를 읽지 못하나요?** 관리 작업의 성공만 확인됩니다. 토큰 서비스와 영향받은 리소스 또는 애플리케이션 세션의 근거가 필요합니다.
2. **401과 `insufficient_claims`를 받으면 계속 접근할 수 없나요?** 그 요청의 챌린지를 확인한 것입니다. 승인된 후속 요청이 조건을 충족할 수 있었는지 확인합니다.
3. **취소 이후 새 세션이 문서를 읽었습니다. 기존 세션이 살아 있었나요?** 세션 연결 정보와 발급자를 대조하세요. 새 요청만으로 기존 세션을 판단할 수 없습니다.
4. **게스트와 워크로드는 왜 따로 조사하나요?** 게스트는 홈 테넌트가 로그인 세션을 관리하고 앱 전용 호출은 워크로드 주체에 속합니다. 각 경로의 권한과 리소스 제어를 확인합니다.

**완료 기준.** 열 건과 대조 실험을 재현합니다. 취소 작업 한 건에서 영향받은 ID와 자격 증명, 각 관측 지점에서 확인한 사실과 더 필요한 증거를 설명합니다. 이어서 [Entra 로그인 증거]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }})와 [OAuth 및 OpenID Connect 증거]({{ '/ko/wiki/oauth-oidc-evidence/' | relative_url }})를 읽어 보세요.

## 공식 참고자료

검토일 2026-11-27. Microsoft Graph v1.0과 현재 Microsoft Learn의 Entra 긴급 액세스 취소 및 CAE 지원 경로 문서를 확인했습니다. 애플리케이션 세션은 서비스별로 동작이 다릅니다. 사고를 조사할 때 적용되는 버전과 테넌트 설정을 함께 확인하세요.

- [Microsoft Graph v1.0 · revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0), [사용자 속성](https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0)
- [Microsoft Entra · 사용자 액세스 취소](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access), [연속 액세스 평가](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation)
- [Microsoft ID 플랫폼 · 클레임 챌린지](https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge)
- [Microsoft Graph v1.0 · directoryAudit](https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0), [Entra 로그인 로그 세부 정보](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details)
