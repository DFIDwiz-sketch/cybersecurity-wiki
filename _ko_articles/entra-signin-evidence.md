---
title: "Microsoft Entra 로그인 조사 · MFA와 조건부 액세스"
description: "Entra 인증·MFA·조건부 액세스·앱 감사의 차이를 가상 로그 8건으로 해석합니다."
category: cloud
tags: [Microsoft Entra, Cloud Security, IAM, MFA, Conditional Access, Blue Team, DFIR]
level: Beginner
updated: "2026-11-20"
translation_url: /wiki/entra-signin-evidence/
---

**학습 목표.** Entra ID가 기록한 로그인 결과, MFA 인증 단계, 조건부 액세스 정책 평가, 실제 앱 행위를 각각 읽습니다. 가상 사건에서 어느 것까지 확인했고 어떤 증거가 더 필요한지 한 문장으로 설명합니다.

## 1. 누가, 어떤 앱을 통해, 어디에 접근했나요?

**Microsoft Entra ID**는 클라우드 신원을 인증하고 앱 접근에 필요한 토큰을 발급하는 서비스입니다. **테넌트**는 조직의 신원 관리 경계입니다. 로그인에 표시되는 앱은 접근을 요청한 클라이언트일 수 있고, **리소스**는 토큰이 쓰이는 대상 서비스입니다. 예를 들어 메일 클라이언트가 메일 서비스의 토큰을 요청할 수 있습니다. **MFA**는 여러 인증 요소나 인증 요구를 뜻하고, **조건부 액세스(CA)**는 사용자·앱·위치·디바이스 등 정책에 적용되는 조건에 따라 접근에 필요한 통제를 평가합니다.

![사용자 또는 워크로드 → 인증 단계 · MFA 세부 정보 → 조건부 액세스 · 정책 평가 → 리소스 감사 · 실제 앱 활동]({{ '/assets/diagrams/entra-signin-flow-ko.svg' | relative_url }})

실제 로그인 경로는 서비스에 따라 달라집니다. 그림은 인증·정책 평가에서 앱 접근까지의 증거 관점을 단순화했습니다. Entra에서 성공한 로그인과 앱에서 발생한 파일 열람은 각자의 기록에서 확인합니다.

| 로그 종류 | 주체와 동작 | 흔히 보이는 정상 사례 |
| --- | --- | --- |
| 대화형 사용자 로그인 | 사용자가 인증 과정에 직접 참여 | 브라우저에서 앱으로 최초 접근 |
| 비대화형 사용자 로그인 | 클라이언트가 사용자를 대신해 인증·토큰 갱신 | 실행 중인 메일 앱의 배경 갱신 |
| 서비스 주체 로그인 | 앱 또는 워크로드 신원으로 접근 | 정기 보고 서비스 |
| 관리 ID 로그인 | Azure에서 관리하는 워크로드 신원 | 승인된 Azure 자원 간 접근 |

비대화형 로그는 같은 조건의 여러 이벤트가 요약될 수 있습니다. 포털의 그룹을 펼치고 시각과 실제 개수를 확인하세요. 워크로드 신원에는 사용자의 MFA 해석을 그대로 적용하지 않습니다.

## 2. 정상 업무의 로그를 한 단계씩 읽기

Ada가 브라우저에서 Portal에 접속합니다. Entra 로그에는 대화형 성공이 남고 인증 세부 정보에 MFA 수행이 기록됩니다. 적용한 CA 정책과 결과를 확인합니다. 이후 Portal의 감사 로그에서 시험 문서 읽기 이벤트가 확인되면 실제 앱 작업을 뒷받침할 수 있습니다. 몇 분 뒤 앱이 백그라운드에서 자격을 갱신하면 비대화형 성공이 보일 수 있습니다. 기존 토큰의 MFA 클레임으로 요구가 충족된 기록은 **이번 요청에 새로운 인증 응답이 있었는지**와 구분하세요.

| 항목 | 볼 값 | 이 값이 가리키는 범위 |
| --- | --- | --- |
| Sign-in status | 성공·실패·중단, 오류 이유 | 로그인 거래 결과. 파일 변경이나 메시지 전송은 따로 확인 |
| Authentication details | 단계별 방법·결과·클레임 | 해당 시도에서 MFA 수행 또는 이전 인증 사용 여부 |
| Conditional Access | 적용 정책 이름·정책별 결과 | 정책 평가 결과. 전체 로그인 결과와 따로 확인 |
| Report-only | 보고 전용 평가 결과 | 정책을 적용했을 때의 평가. 해당 정책이 실제 차단했는지는 별도 |
| App·resource·tenant | 클라이언트와 대상, 관리 경계 | 계정 또는 대상 조직을 혼동하지 않도록 범위를 명시 |
| Request ID·Correlation ID | 거래와 문제 추적의 단서 | 서비스 간 공통 조인 키라고 가정하지 않음 |

인증 세부 정보는 집계되기 전에 빠지거나 부정확할 수 있습니다. MFA 클레임과 기본 인증 행의 표시가 불확실하면 나중에 같은 기록을 다시 확인하고 요청 ID와 상관 ID를 보관하세요. CA 요약이 성공이어도 정책별 결과를 읽습니다. 적용된 정책의 내용과 실제 요구 조건을 확인해야 어떤 통제가 작동했는지 알 수 있습니다.

## 3. 수집과 의심 패턴 검증

1. 승인된 접근 권한으로 로그인 종류별 원본을 확인하고, UTC와 테넌트, 앱·리소스, 주체 ID, 오류·정책 세부 정보를 보존합니다. SIEM 전송에는 해당 진단 로그 범주를 포함하세요. 보존은 라이선스·로그 종류·외부 라우팅에 따라 달라집니다.
2. 시간 범위를 맞출 때 로그인 발생 시각과 수집 시각을 구분하세요. Log Analytics의 TimeGenerated와 CreatedDateTime은 일반적으로 수집과 로그인 발생의 차이를 나타냅니다. 원본 필드와 실제 테이블의 정의를 확인합니다.
3. 이상한 IP나 국가를 찾았다면 VPN·프록시·통신사·출장 여부를 비교하세요. 동일 계정의 이전 로그인, 디바이스, 세션과 앱 활동을 맞춰 봅니다. IP 지리 정보는 근사치입니다.
4. 사용자 동의·인증 방법·정책 변경이 의심되면 디렉터리 감사 로그에서 변경 주체와 작업을 찾습니다. 사서함, 파일 저장소 등 리소스 쪽 감사에서 실제 후속 행위를 확인합니다.

| 관측 | 가능한 정상 설명 | 우선 확인할 증거 |
| --- | --- | --- |
| 실패가 반복된 뒤 성공 | 사용자의 오타 또는 네트워크 변경 | 실패 이유, 사용자 확인, 세션·리소스 감사 |
| 이전 MFA 클레임으로 충족 | 정상 SSO 또는 갱신 | 토큰 발급 문맥, 원래 로그인과 디바이스, 서비스 세션 |
| 새 앱이나 서비스 주체 로그인 | 승인된 배포 | 앱 등록·권한·인증서 변경 감사, 서비스 소유자 |
| 보고 전용 실패와 로그인 성공 | 평가만 하는 정책 | 정책 모드와 실제 적용한 다른 CA 정책 |
| MFA 요구로 시도 중단 | 사용자가 과정을 완료하지 않음 | 해당 시도 결과와 뒤이은 시도, 인증 세부 정보 |

토큰이 오용되면 겉으로는 정상 로그인이나 앱 작업과 분리하기 어려울 수 있습니다. 의심이 뒷받침되면 해당 계정·워크로드와 영향을 받은 앱을 좁히고 조직 절차로 접근을 차단하거나 세션을 폐기합니다. 이미 발급된 액세스 토큰과 앱 자체 세션의 효과는 플랫폼·앱 구현에 따라 달라집니다. 폐기 요청을 보냈다는 기록에 더해 실제 대상에서 이후 접근이 중단됐는지 확인하세요.

## 4. 오프라인 실습 · 가상 기록 8건

[entra-signin-cases.json]({{ '/assets/labs/entra-signin-cases.json' | relative_url }}) · [entra-signin-evidence.py]({{ '/assets/labs/entra-signin-evidence.py' | relative_url }})

두 파일을 한 폴더에 두고 Python 3에서 실행하세요. 로그인 6건과 앱 감사 2건을 **가상 정규화 형식**으로 담았습니다. 연습용 link는 두 소스에 의도적으로 부여한 연결값입니다. Entra 포털의 필드와 같다고 가정하지 마세요. 조인은 테넌트, 앱, link 세 값이 맞을 때만 이뤄집니다.

~~~bash
python3 entra-signin-evidence.py
~~~

| 사례 | 기록을 읽는 법 |
| --- | --- |
| s-01 | 대화형 성공, MFA 수행. 같은 범위의 a-01이 시험 항목 읽기 증거 |
| s-02 | 비대화형 성공, 기존 MFA 클레임. a-02의 link가 같아도 테넌트가 달라 미연결 |
| s-03 | 로그인 실패와 CA 실패. 실제 접근을 뒷받침하는 앱 기록 없음 |
| s-04 | 실제 로그인 성공과 보고 전용 정책의 예상 실패가 함께 있음 |
| s-05 | 서비스 주체 성공. 사용자 MFA를 한 것으로 해석하지 않음 |
| s-06 | 진행 중단. 다른 성공 시도와 섞지 않음 |

마지막 줄은 `PASS: six sign-ins, one scoped resource match, five unlinked`입니다. 파일 오류는 이름·위치를, 조인 오류는 세 범위 값과 원본 이벤트 종류를 확인하세요. 미연결은 주어진 데이터의 한계입니다. 게시 과정에서 가상 분석기를 실행했습니다. 실제 Entra 인증과 CA 설정, Log Analytics 수집은 별도 시험이 필요합니다.

자가 소유하거나 명시적으로 승인된 테넌트에서는 기존 보안 정책 아래 테스트 사용자가 정상 로그인하고 시험 파일 하나를 읽는 방법으로 수집을 검증할 수 있습니다. 조직 정책이나 실제 사용자 세션을 바꾸지 않고 로그인과 앱 감사가 각각 기록되는지 확인합니다.

## 5. 확인 문제와 완료 기준

- **MFA 충족이면 방금 휴대전화에서 승인했나요?** 인증 세부 정보에서 새로 인증을 수행했는지, 기존 클레임을 썼는지 봅니다.
- **보고 전용 실패면 접근이 막혔나요?** 해당 정책은 평가 결과만 냅니다. 실제 로그인 결과와 적용 정책을 확인합니다.
- **성공한 로그인이면 파일을 읽었나요?** 앱 감사에서 별도 접근을 확인하고 연결 근거를 남깁니다.

s-01과 s-02의 MFA 문맥과 앱 증거 차이를 한 문장씩 적고, s-04에서 정책 평가와 실제 결과를 각각 설명하면 완료입니다.

[이전 · AD 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}) · [관련 · AWS IAM 역할과 CloudTrail]({{ '/ko/wiki/aws-iam-role-evidence/' | relative_url }})

## 다음 학습

[OAuth 2.0·OIDC 토큰과 API 작업 기록 조사]({{ '/ko/wiki/oauth-oidc-evidence/' | relative_url }})

## 공식 자료

2026년 11월 20일 검토한 Microsoft Learn 자료입니다. 현재 테넌트의 라이선스·수집 범위·앱 동작을 확인하세요.

- [Sign-in log types](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins)
- [Non-interactive logs and grouping](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins)
- [Sign-in activity details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details)
- [Conditional Access report-only](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only)
- [Audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs)
- [Retention](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention)
- [Revoke user access](https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access)

## 패스키와 WebAuthn 로그인 증거

[공개키 검증, 접근 정책과 앱 세션을 구분하는 실습]({{ '/ko/wiki/passkey-signin-evidence/' | relative_url }})

## Entra에서 앱 동의와 API 사용 대조하기

[Microsoft Entra 앱 동의 조사]({{ '/ko/wiki/entra-app-consent-evidence/' | relative_url }})에서 위임 동의, 앱 전용 권한과 실제 리소스 요청을 구분합니다.
