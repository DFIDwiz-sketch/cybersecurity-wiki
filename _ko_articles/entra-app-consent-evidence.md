---
title: "Microsoft Entra 앱 동의 조사 · 권한 부여에서 API 사용까지"
description: "가상 사례 12건으로 위임 동의, 앱 전용 권한, 토큰 사용과 API 응답을 구분합니다."
category: cloud
tags: [Microsoft Entra, OAuth 2.0, App Consent, Microsoft Graph, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/entra-app-consent-evidence/
---

낯선 앱이 동의 감사에 나타나면 **어떤 권한을 부여했는지**, **앱이 실제로 무엇을 했는지**를 각각 확인합니다. 동의는 디렉터리에 기록되는 인가 판단입니다. 이후 인증과 토큰 발급, 보호된 API의 작업은 별도의 증거를 남깁니다. 프로토콜의 역할은 [OAuth와 OpenID Connect]({{ '/ko/wiki/oauth-oidc-evidence/' | relative_url }})에서 확인할 수 있습니다.

## 1. 객체와 부여된 권한 식별하기

**앱 등록(application registration)**은 앱의 정의입니다. **서비스 주체(service principal)**는 특정 테넌트 안에서 앱을 나타내는 신원입니다. 다중 테넌트 앱은 애플리케이션 ID(`appId`, 클라이언트 ID라고도 함)가 같아도 각 테넌트의 서비스 주체 객체 ID가 다릅니다. 호출하는 클라이언트와 대상 리소스 API에도 각각 서비스 주체가 있습니다. 올바른 테넌트에서 객체 ID를 확인하세요. 표시 이름은 변경되거나 중복될 수 있습니다.

**위임 스코프**는 앱이 사용자 대신 리소스를 호출하도록 허용합니다. API는 해당 사용자의 권한과 추가 정책도 평가할 수 있습니다. `oAuth2PermissionGrant`의 `clientId`는 클라이언트 서비스 주체의 객체 ID, `resourceId`는 리소스 서비스 주체의 객체 ID입니다. `scope`는 공백으로 구분된 권한 값입니다. `Principal`은 `principalId`로 지정한 사용자에게 적용됩니다. `AllPrincipals`는 테넌트 사용자를 대신해 부여된 동의이며 `principalId`는 null입니다. 이 경우에도 위임 권한입니다.

**애플리케이션 권한**은 앱 전용 호출을 위해 클라이언트 서비스 주체에 부여한 앱 역할입니다. `appRoleAssignment`의 `principalId`, `principalType`, `resourceId`, `appRoleId`를 확인하고 리소스 서비스 주체에서 역할 ID를 해석하세요. 앱 역할은 사용자나 그룹에 할당될 수도 있으므로 앱 전용 권한으로 읽기 전에 주체 유형을 확인합니다. 앱 등록 화면의 권한 목록은 구성 정보입니다. 실제 부여 여부는 대응하는 권한 객체나 역할 할당으로 확인합니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/entra-app-consent-evidence-ko.svg' | relative_url }}" alt="테넌트와 서비스 주체를 확인한 뒤 디렉터리 권한 변경, 로그인과 토큰, 대상 리소스의 응답, 실제 영향을 순서대로 확인합니다.">
  <figcaption>타임라인에서 권한 부여 기록, 토큰과 로그인, 리소스의 결과를 구분합니다.</figcaption>
</figure>

| 확인한 증거 | 뒷받침하는 판단 | 다음 확인 |
| --- | --- | --- |
| 한 사용자의 위임 권한 | 해당 사용자와 API에 승인된 스코프 | 실제 사용자, 스코프, 리소스 응답 |
| AllPrincipals 위임 권한 | 테넌트 전반에 적용되는 위임 동의 | 각 요청의 사용자와 API 정책 |
| 서비스 주체에 할당된 앱 역할 | 대상 API에 대한 앱 전용 역할 할당 | 워크로드 상황, 역할 값, API 결과 |
| Graph 활동이나 리소스 감사 | 해당 관측 지점이 보고한 요청 또는 작업 | 요청의 의미, 실제 영향과 수집 범위 |

## 2. 정상 사례와 예상 밖의 동의

가상의 보고서 앱에서 사용자 U8이 테넌트 정책이 허용하는 범위에서 본인 계정에 대해 예시 Reports API의 `Reports.Read`에 동의합니다. 09:02 UTC에 디렉터리에 권한 부여 성공이 기록됩니다. 09:07에 리소스는 같은 테넌트, 클라이언트 서비스 주체, 리소스, 사용자 U8을 확인하고 조회를 처리합니다. 요청에는 예상 스코프가 기록되고 HTTP 200이 돌아옵니다. 앞의 기록은 권한 부여를, 뒤의 기록은 API 조회를 뒷받침합니다. 실제로 어떤 데이터가 반환됐는지는 그 범위를 보여 주는 리소스 로그를 확인하세요. 여기서 사용한 API와 스코프는 Microsoft Graph의 실제 권한이 아닙니다.

사용자가 앱의 용도나 요청 범위를 잘못 이해한 채 동의하면 비밀번호가 노출되지 않아도 실제 권한이 생길 수 있습니다. 정식 공급자 배포나 승인된 자동화도 같은 감사 활동을 남길 수 있습니다. 변경을 누가 시작했고 어떤 권한이 있었는지, 클라이언트·리소스·권한·범위가 승인과 일치하는지 대조하세요. 이후 실제 API 사용을 조사합니다. 권한을 부여한 변경 주체와 토큰의 사용자는 서로 다를 수 있습니다.

## 3. 기록을 수집하고 연결하기

1. **변경을 찾습니다.** Entra 디렉터리 감사의 ApplicationManagement 활동을 확인합니다. Microsoft가 문서화한 예로 `Consent to application`, `Add delegated permission grant`, `Add app role assignment to the service principal`이 있습니다. 결과, 시각, 시작 주체와 확인 가능한 대상·변경 속성을 읽으세요. 실패한 동의 이벤트는 시도를 뒷받침합니다. 실제 기록된 권한과 범위를 확인하고 현재 객체도 조회하세요. 과거에 생겼다가 제거된 권한은 현재 객체에 나타나지 않을 수 있습니다.
2. **인증 증거를 확인합니다.** 상황에 따라 사용자 또는 서비스 주체 로그인을 봅니다. 테넌트, 클라이언트와 리소스 ID, 시각을 기록하세요. 로그인이나 토큰 관련 이벤트 한 건으로 후속 작업을 확인할 수 없습니다. 일부 출처에는 대응하는 로그인 기록이 없을 수 있습니다. 토큰 관련 로그에서 위임 스코프는 보통 `Scopes`, 역할은 `Roles`에 나타납니다. 역할 클레임은 사용자에게도 있을 수 있으므로 `Roles` 값만 보고 앱 전용 사용을 단정하지 마세요. 주체와 토큰의 문맥을 확인합니다. 조사 기록에 원문 토큰을 넣지 않습니다.
3. **실제 응답을 찾습니다.** Microsoft Graph 활동 로그에서는 리소스 테넌트와 확인한 앱 객체 매핑을 기준으로 요청 ID, 메서드, 상태와 승인 범위의 경로 정보를 확보합니다. 이 테이블의 `AadTenantId`는 디렉터리 테넌트 ID이고, `TenantId`는 Log Analytics 작업 영역 ID입니다. 공급자 예제는 조건이 맞을 때 `SignInActivityId`와 로그인 기록의 `UniqueTokenIdentifier`를 연결합니다. 일치 항목이 없으면 수집 범위를 점검하고 해당 요청을 보존합니다. 실제 업무 영향은 대상 리소스 로그에서 확인하세요. 인증과 정책 맥락은 [Entra 로그인 조사]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }})에 이어집니다.

아래는 **승인된 읽기 전용 작업 영역**에서 알려진 클라이언트 서비스 주체의 최근 24시간 Graph 요청 후보를 살펴보는 예입니다. 해당 리소스 테넌트에서 Graph 활동 수집이 이미 켜져 있고 조회 중인 작업 영역으로 전달돼야 합니다. 지원되는 Entra P1 또는 P2 라이선스와 데이터 조회 권한이 필요합니다. ID를 바꾸고 조사에 맞는 UTC 범위로 제한하세요. 작업 영역에서 스키마와 수집 여부를 확인합니다. 지정한 ID가 없는 레코드는 이 필터에서 빠집니다. 검색식은 공급자 문서로 검토했습니다.

```kusto
let resourceTenant = "replace-with-resource-tenant-id";
let clientObject = "replace-with-client-service-principal-object-id";
MicrosoftGraphActivityLogs
| where TimeGenerated >= ago(24h)
| where AadTenantId == resourceTenant and ServicePrincipalId == clientObject
| project TimeGenerated, AppId, ServicePrincipalId, UserId, TokenIssuedAt,
          RequestId, RequestMethod, ResponseStatusCode, Scopes, Roles
| order by TimeGenerated asc
```

## 4. 판단하고 대응 효과를 확인하기

사용자 범위가 넓어졌거나 민감한 API에 앱 전용 권한이 생긴 예상 밖의 성공 변경을 우선 조사합니다. 동의 정책, 승인, 앱 담당자, 정상 백그라운드 작업과 대조하세요. 표시 이름, User-Agent, IP 또는 게시자 확인 표시 하나로 의도를 정할 수 없습니다. Graph 로그는 리소스 테넌트에서 관측한 Graph 요청을 보여 줍니다. 다중 테넌트 앱의 다른 테넌트 활동이나 모든 업무 결과까지 보여 주지는 않습니다. 403은 거부 기록입니다. 202는 접수 후 작업이 계속될 수 있으므로 완료 기록을 확인하세요. 일괄 요청은 조사 대상 하위 작업의 응답을 따로 확인합니다.

권한 객체와 역할 할당의 스냅샷, 접근 가능한 감사 로그를 보존합니다. 승인된 권한 제거 또는 앱의 일시 중지는 사고 대응 책임자와 앱 담당자와 조율하세요. 영향을 받는 사용자, 연계 워크로드, 이미 발급된 토큰과 세션의 노출 범위를 확인합니다. 기존 토큰의 동작은 만료, 서비스와 폐기 처리에 따라 달라집니다. 조치 후 디렉터리 상태를 확인하고 새 요청이나 재부여를 관찰하세요. 변경 기록 한 줄만으로 모든 접근이 차단됐다고 보고할 수 없습니다.

## 5. 오프라인 실습 · 가상 관측 열두 건

두 파일을 같은 폴더에 내려받고 Python 3.10 이상으로 실행합니다. 테넌트, 실제 동의나 액세스 토큰, 네트워크 연결이 필요 없습니다. JSONL의 각 행에는 정규화한 가상 권한 부여와 비교할 조회 한 건이 들어 있습니다. 비교 기준은 테넌트, 클라이언트와 리소스 서비스 주체의 객체 ID입니다. 실습에서는 API 리소스 신원과 토큰 유형을 이미 확인한 값으로 제공합니다. 시각은 상대 초이며 권한 구간은 관측 증거를 뜻합니다. 스크립트는 해당 증거와 요청이 일치하는지 보여 줍니다. 어떤 권한이 요청을 허용했는지, 권한 제거와 동시에 접근이 끝났는지는 판정하지 않습니다.

<a href="{{ '/assets/labs/entra-app-consent-evidence.py' | relative_url }}" download="entra-app-consent-evidence.py">entra-app-consent-evidence.py</a> · <a href="{{ '/assets/labs/entra-app-consent-evidence-cases.jsonl' | relative_url }}" download="entra-app-consent-evidence-cases.jsonl">entra-app-consent-evidence-cases.jsonl</a>

```bash
python3 entra-app-consent-evidence.py entra-app-consent-evidence-cases.jsonl
```

```text
normal_delegated: matching_success_response
tenant_wide_delegated: matching_success_response
app_only: matching_success_response
no_resource_observation: grant_only
same_name_other_tenant: different_identity_or_resource
wrong_user: different_delegated_user
outside_observed_grant: outside_grant_window
denied_read: matching_denied_response
wrong_resource: different_identity_or_resource
missing_mode: request_context_missing
other_token_permission: different_token_permission
accepted_async: inspect_response_semantics
```

실행이 안 되면 작업 폴더와 이름을 확인하세요. 결과가 예상과 다르면 테넌트와 객체 ID부터 확인하고 권한 유형, 사용자, 시각, 상태로 넘어갑니다. `outside_observed_grant`에서는 이전에 발급된 토큰, 다른 권한 또는 시각 오류를 확인해야 합니다. 현재 자료로 한 원인을 고를 수 없습니다. 가상 실습은 Python 3.12에서 실행했고, Entra, Microsoft Graph와 검색식은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **AllPrincipals는 앱 전용 권한인가요?** 테넌트 사용자 전반의 위임 동의입니다. 앱 전용 권한은 앱 역할 할당을 확인하세요.
- **권한 부여가 확인되면 데이터를 읽었다는 뜻인가요?** 대상 리소스에서 요청과 응답을 찾습니다. 실제 데이터 영향은 필요한 리소스 감사를 추가로 확인합니다.
- **다른 테넌트에도 이름이 같은 앱이 있으면요?** 테넌트와 객체 ID를 대조합니다. 다중 테넌트 앱은 애플리케이션 ID가 같아도 서비스 주체가 다를 수 있습니다.

열두 줄의 결과를 재현하세요. `no_resource_observation`, `outside_observed_grant`, `accepted_async`에 필요한 다음 증거를 각각 말할 수 있으면 실습을 마친 것입니다.

## 공식 참고자료

검토일은 2026-11-22입니다. 아래 권한 객체는 Microsoft Graph v1.0 기준입니다. 실제 클라우드 환경, 라이선스, 스키마, 설정된 로그 목적지를 확인한 뒤 수집 범위를 해석하세요.

- 2025년 4월 기준 Entra 감사 활동 이름. [Microsoft Learn · 앱 권한 감사 활동](https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/app-perms-audit-logs)
- 위임 권한 객체, 동의 범위와 ID. [Microsoft Learn · Microsoft Graph v1.0 · oAuth2PermissionGrant](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0)
- 앱 역할, 리소스, 주체 유형. [Microsoft Learn · Microsoft Graph v1.0 · appRoleAssignment](https://learn.microsoft.com/en-us/graph/api/resources/approleassignment?view=graph-rest-1.0)
- 수집 전제조건, 로그 연결, 리소스 테넌트 범위. [Microsoft Learn · Microsoft Graph 활동 로그 개요](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)
- 2026년 10월 MicrosoftGraphActivityLogs 스키마. [Microsoft Learn · Azure Monitor 테이블 참조](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs)
- 침해되거나 악성인 앱의 증거 수집, 격리와 복구. [Microsoft Learn · 애플리케이션 사고 대응 지침](https://learn.microsoft.com/en-us/security/zero-trust/security-operations-playbook-compromised-malicious-app)

[이전 · OAuth와 OpenID Connect]({{ '/ko/wiki/oauth-oidc-evidence/' | relative_url }}) · [관련 · Entra 로그인 조사]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }})
