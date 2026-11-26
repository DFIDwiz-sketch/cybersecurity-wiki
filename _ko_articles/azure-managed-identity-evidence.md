---
title: "Azure 관리 ID 조사 · 연결 설정에서 실제 리소스 접근까지"
description: "워크로드의 관리 ID 연결, Entra 로그인, 대상 리소스 요청을 식별자로 대조하고 가상 사례 여섯 가지로 판단을 검증합니다."
category: cloud
tags: [Azure, Microsoft Entra ID, Managed Identity, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/azure-managed-identity-evidence/
---

**학습 순서** · [Microsoft Entra 로그인 조사]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }}) → 관리 ID 조사 → [Azure Key Vault 비밀 조회]({{ '/ko/wiki/azure-key-vault-read-evidence/' | relative_url }}).

## 1. Azure가 관리하는 것은 무엇인가요?

**관리 ID**는 지원되는 Azure 워크로드가 Microsoft Entra 토큰을 받는 서비스에 인증할 수 있게 합니다. ID의 자격 증명은 Azure가 관리합니다. Entra 테넌트에서는 **서비스 주체**가 이 ID를 나타냅니다. 워크로드는 API용 **액세스 토큰**을 받아 API에 제시합니다. API는 토큰과 자체 인가 정책을 평가합니다. **Azure 역할 기반 액세스 제어(RBAC)**는 어떤 주체가 어떤 범위에서 무슨 작업을 할 수 있는지 정합니다. 허용 여부에는 대상 서비스의 설정이나 네트워크 규칙도 영향을 줄 수 있습니다.

**시스템 할당 관리 ID**는 하나의 Azure 리소스에 속하며 서비스 주체의 수명이 그 리소스에 묶입니다. **사용자 할당 관리 ID**는 별도의 Azure 리소스입니다. 여러 워크로드에 연결할 수 있고, 연결한 워크로드를 삭제해도 남습니다. 여러 곳에서 같은 ID를 쓰면 배포가 편할 수 있지만 서비스 주체만으로는 실행한 워크로드를 특정하기 어렵습니다. 리소스를 재생성하면서 같은 표시 이름을 쓰면 주체 ID가 바뀌었다는 사실을 놓칠 수도 있습니다.

| 식별자 | 활용 방법 | 혼동하기 쉬운 점 |
|---|---|---|
| 테넌트 ID와 ID의 주체 ID | 연결 설정의 `principalId`를 같은 테넌트의 Entra 호출자 `ServicePrincipalId`와 대조합니다. | 애플리케이션·클라이언트 ID, 표시 이름, IP 주소는 각각 다른 정보입니다. |
| 워크로드의 ARM 리소스 ID | 사건 시점에 ID가 붙어 있던 컴퓨팅·앱 리소스를 찾습니다. | 사용자 할당 ID 하나가 여러 워크로드에 연결될 수 있습니다. |
| 토큰 대상과 대상 서비스 주체 | 어느 API 서비스로 향했는지 확인합니다. Entra에는 `ResourceIdentity`, `ResourceServicePrincipalId` 같은 필드가 있습니다. | Key Vault 같은 API 서비스에는 개별 볼트가 여럿 있습니다. 실제 볼트와 작업은 대상 로그에서 확인하세요. |
| 대상 ARM 리소스 ID와 요청 ID | 대상 인스턴스를 식별하고 요청과 응답을 대조합니다. | Entra의 `CorrelationId`가 리소스 측 요청 ID와 같다고 가정하지 마세요. 문서에 명시된 매핑이나 별도 관측이 필요합니다. |

## 2. 정상 요청 한 건 따라가기

**가상 예시.** 09:00 UTC에 Azure 활동 로그에서 `report-vm-a`의 승인된 ID 연결 변경을 확인했다고 가정합니다. 인벤토리에는 주체 ID가 `0042`로 끝나는 사용자 할당 관리 ID가 이 VM에 연결된 것으로 나옵니다. 교육용 볼트에는 승인된 데이터 평면 역할이 부여돼 있습니다. 09:02 Entra에는 이 주체가 Key Vault 서비스에 로그인한 기록이 있고, 09:04 볼트에는 같은 테넌트와 주체가 읽기에 성공한 기록이 있습니다. 워크로드의 추적 기록에도 그 작업과 같은 볼트 요청 ID가 남아 있습니다.

이 증거로 ID 연결, 대상 API 인증, 리소스 요청 성공을 각각 확인할 수 있습니다. 요청 ID가 같은 워크로드 기록과 볼트 기록을 대조하면 해당 요청을 `report-vm-a`에 연결할 근거가 생깁니다. Entra 포털은 ID, 상태, 리소스가 같은 로그인 항목을 한 행으로 묶을 수 있습니다. 행을 펼쳐 각 로그인 시각을 확인하세요. 묶인 행의 수를 API 호출 횟수로 해석하면 안 됩니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/azure-managed-identity-evidence-ko.svg' | relative_url }}" alt="Azure 인벤토리와 활동 로그에서 ID 연결을 확인합니다. Entra에는 API 로그인, 대상 리소스에는 작업과 결과가 남습니다. 워크로드 기록을 대조해 실제 요청 주체를 좁힙니다." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>같은 UTC 범위를 기준으로 모으세요. 관리 ID의 식별자로 기록을 연결한 뒤, 서비스 요청 ID가 있으면 워크로드 추적 기록과도 대조합니다.</figcaption>
</figure>

## 3. 오용 가능성과 관측 공백 살피기

| 관측 | 어떤 판단이 가능한가요? | 다음 확인 |
|---|---|---|
| 관리 ID 로그인 성공, 대상 요청 기록 없음 | API 인증은 확인했습니다. 대상에서 어떤 작업이 있었는지는 아직 모릅니다. | 대상의 감사 범위와 해당 서비스 요청 기록을 확인합니다. |
| 대상 작업 성공, 같은 구간에 새 로그인 없음 | 대상이 작업을 허용했습니다. 토큰 재사용, 시간 범위 차이, 로그 공백이 모두 가능한 설명입니다. | Entra 내보내기·보존 기간과 더 넓은 시간 범위를 확인한 뒤 워크로드와 대상 기록을 대조합니다. |
| 하나의 주체가 워크로드 두 개에 연결됨 | 주체 ID만 보이는 리소스 로그로는 후보가 둘입니다. | 사건 당시의 인벤토리와 서비스 요청 ID, 워크로드 추적 또는 별도 네트워크 기록을 대조합니다. |
| 로그인 성공, 대상 요청 거부 | 인증을 받아도 대상 API가 요청을 거부할 수 있습니다. | 서비스가 남긴 거부 사유를 확인하고 역할 범위, 대상, 토큰 대상, 네트워크 규칙을 관련 범위에서 살핍니다. |
| 표시 이름은 같지만 주체 ID가 다름 | ID 교체나 조회 범위 착오가 가능해 보입니다. | 과거 연결 설정, 디렉터리 객체 ID, 승인된 변경 이력을 확인합니다. |

권한이 넓은 ID로 동작하는 워크로드는 대상 서비스가 허용한 작업을 수행할 수 있습니다. ID를 공유하거나 지나치게 넓은 역할을 부여하면 워크로드나 연결 설정에 예기치 않은 변경이 생겼을 때 영향 범위가 커집니다. 처음 나타난 주체와 대상 조합은 조사 단서로 삼으세요. 원인을 판단하려면 승인된 배포, 자동화, 평상시 관측과 비교해야 합니다.

Microsoft 문서에 따르면 인프라는 리소스 URI별로 관리 ID 토큰을 캐시합니다. 관리 ID의 그룹이나 역할 멤버십 변경이 토큰 클레임에 반영되기까지 수 시간이 걸릴 수 있습니다. 문서의 약 24시간 캐시 설명은 구현을 이해하는 데 쓰세요. 특정 시각에 접근이 반드시 끊긴다는 보장은 없습니다. 대상 리소스에 직접 부여한 역할을 수정하는 것과 토큰에 반영되는 멤버십을 바꾸는 것은 평가 경로가 다릅니다. 통제된 요청과 대상 서비스 응답으로 조치 결과를 확인하세요.

## 4. 블루팀 수집·탐지·대응

승인된 테넌트와 구독에서 읽기 전용 계정을 사용하세요. 다음 Azure CLI 명령은 VM의 ID 연결 정보와 사용자 할당 ID 리소스를 조회합니다. 승인된 대상 이름으로 바꾸고 두 리소스의 읽기 권한을 확인하세요. VM 이외의 서비스는 해당 서비스의 ID 인벤토리를 사용합니다. CLI 결과는 조회 당시 상태를 보여줍니다.

~~~sh
az account show --query '{tenant:tenantId,subscription:id}' -o json
az vm identity show --resource-group rg-training --name report-vm-a -o json
az identity show --resource-group rg-training --name report-worker \
  --query '{id:id,principalId:principalId,clientId:clientId,tenantId:tenantId}' -o json
~~~

Log Analytics에서 조회하려면 Entra 진단 설정에서 **ManagedIdentitySignInLogs**를 작업 영역으로 보내고, 분석자에게 `AADManagedIdentitySignInLogs` 테이블의 읽기 권한을 부여합니다. 예시는 가상 주체 ID와 최근 24시간을 사용합니다. 조사 대상의 식별자와 시간 범위로 바꾸세요. 0건이 나왔으면 작업 영역의 조회 범위, 내보내기 상태, 보존 기간부터 확인합니다. `CreatedDateTime`은 로그인 활동 시각입니다. `TimeGenerated`도 따로 보존하고 둘이 같다고 가정하지 마세요.

~~~kusto
let principal = "00000000-0000-4000-8000-000000000042";
AADManagedIdentitySignInLogs
| where CreatedDateTime >= ago(24h)
| where ServicePrincipalId =~ principal
| project CreatedDateTime, TimeGenerated, AADTenantId,
          ServicePrincipalId, AppId, ResourceDisplayName,
          ResourceIdentity, ResourceServicePrincipalId, ResultType,
          ResultDescription, CorrelationId, IPAddress
| order by CreatedDateTime asc
~~~

1. **수집.** 워크로드·ID 인벤토리, ID 연결 및 역할 범위의 Azure 활동 로그, Entra 로그인, 대상에서 별도로 설정한 데이터 평면 로그를 보존합니다. UTC, 테넌트, 구독, 식별자, 로그 수집 범위를 기록하고 원본은 제한된 저장소에 보관하세요. 이 대조 과정에는 토큰 문자열이나 비밀 값이 필요하지 않습니다.
2. **탐지.** 예상 밖의 ID 연결이나 넓은 역할 변경이 대상 활동과 겹칠 때 우선 확인합니다. 과거 인벤토리를 요청 당시 유효한 상태와 비교하세요. 새 주체·리소스 조합과 반복 실패를 결과·작업별로 살펴봅니다. 낯선 IP나 같은 표시 이름만으로는 실제 워크로드를 특정하기 어렵습니다.
3. **대응.** ID 담당자와 리소스 담당자가 함께 조사합니다. 증거를 보존하고 공유 ID에 연결된 워크로드를 모두 확인하세요. 승인된 사고 대응 절차에 따라 대상 접근 범위를 좁힙니다. 변경 후 대상 서비스의 허용·거부 결과를 확인하고, 기록 공백으로 검증하지 못한 부분을 남기세요.

## 5. 오프라인 실습 · 가상 사례 여섯 가지

Python 3이 있는 승인된 작업 공간에서 두 파일을 같은 디렉터리에 저장하세요. JSON은 분석 시간 범위에 맞춰 정리한 가상 증거와 정답입니다. Azure 원본 로그 형식과는 다릅니다. 스크립트는 네트워크를 사용하지 않습니다. 로그인은 테넌트·주체·API, 대상 작업은 테넌트·주체·대상·작업으로 대조합니다. ID 연결 수와 요청 추적 자료가 있는 경우 해당 요청도 확인합니다.

- <a href="{{ '/assets/downloads/azure-managed-identity-evidence/inspect_identity.py' | relative_url }}" download>Python 점검 스크립트 다운로드</a>
- <a href="{{ '/assets/downloads/azure-managed-identity-evidence/identity_cases.json' | relative_url }}" download>가상 사례 여섯 가지 다운로드</a>

~~~sh
python3 inspect_identity.py identity_cases.json
~~~

| 사례 | 기대 결과 |
|---|---|
| 증거가 이어진 성공 | 로그인, 대상 요청 성공, 워크로드 요청 추적이 모두 일치합니다. |
| 로그인만 확인 | 인증 기록은 일치하지만 대상 작업은 아직 확인되지 않았습니다. |
| 새 로그인 없이 대상 작업 성공 | 대상 작업 성공을 확인했으며, 관측 구간에 Entra 인증 기록은 없습니다. |
| 공유 ID | 호출자를 가리키는 추적 기록이 없어서 워크로드 후보가 둘입니다. |
| 대상 거부 | 로그인 결과와 별개로 대상 요청 거부가 한 건 확인됩니다. |
| 표시 이름 재사용 | 이름이 같아도 다른 주체의 로그인과 대상 작업을 제외합니다. |

JSON을 복사한 뒤 첫 사례의 대상 요청 ID만 바꾸세요. 워크로드 기록과 정답은 그대로 둡니다. 첫 사례가 실패하고 종료 코드는 1이어야 합니다. 비교를 시작하지 못하면 실행 디렉터리, 파일 이름, JSON 문법을 확인하세요. 공개 스크립트는 이 가상 사례로 실행했습니다. Azure CLI와 KQL은 공식 문서로 동작을 검토했습니다.

## 6. 확인 문제와 완료 기준

- **Key Vault 로그인 기록에서 정확한 볼트를 확인할 수 있나요?** 이 기록은 API 서비스를 가리킵니다. 개별 볼트와 작업 결과는 볼트의 로그에서 확인하세요.
- **두 호스트가 주체 하나를 공유할 수 있나요?** 사용자 할당 ID로 가능합니다. 사건 시점의 연결을 대조하고 요청 단위 증거로 실제 워크로드를 식별하세요.
- **대상 성공 시각에 로그인이 없으면 감사가 실패했나요?** 토큰 재사용, 서비스·테넌트 범위, 보존 기간, 내보내기 상태부터 확인해야 판단할 수 있습니다.

요청 한 건을 세 증거 출처에서 대조하고, 입력을 수정해 비교 실패를 재현하고, 여러 워크로드 중 실제 호출자를 확인하는 데 필요한 추가 증거를 설명하면 실습을 완료한 것입니다.

## 공식 참고자료

**2026-11-27** 검토. 제품 동작과 CLI 문법은 검토 시점의 Microsoft Learn 공개 문서를 기준으로 합니다. 관리 ID 로그인 보고서는 2026년 2월, 조회 테이블 스키마는 2026년 8월에 갱신됐습니다. 실제 테넌트의 내보내기, 보존 기간과 리소스별 설정을 확인하세요.

- [Microsoft Entra · Azure 관리 ID 유형과 수명 주기](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- [Microsoft Learn · 관리 ID 보안과 토큰 캐시](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations)
- [Microsoft Learn · 관리 ID 로그인과 이벤트 그룹](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-managed-identity-sign-ins)
- [Microsoft Learn · 관리 ID 로그인 테이블 스키마](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadmanagedidentitysigninlogs)
- [Microsoft Learn · Entra 진단 로그 라우팅](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings)
- [Azure Monitor · Azure 활동 로그](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log)
- Azure CLI · [VM ID 조회](https://learn.microsoft.com/en-us/cli/azure/vm/identity#az-vm-identity-show), [사용자 할당 ID 조회](https://learn.microsoft.com/en-us/cli/azure/identity#az-identity-show).
