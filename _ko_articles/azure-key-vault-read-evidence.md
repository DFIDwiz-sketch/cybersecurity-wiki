---
title: "Azure Key Vault 비밀 조회 조사 · SecretGet이 보여 주는 것"
description: "Key Vault 감사 기록에서 권한 부여, 비밀 메타데이터 조회, 값 응답, 이후 사용을 구분합니다."
category: cloud
tags: [Azure, Key Vault, Azure Monitor, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/azure-key-vault-read-evidence/
---

**학습 목표.** 워크로드 로그인, 볼트 역할 부여, `SecretGet` 호출이 차례로 기록됐습니다. 어떤 값 응답이 있었는지 찾고, 예상한 신원과 버전을 대조하며, 근거가 부족한 부분은 따로 남깁니다.

## 1. 네 단계를 구분하기

Azure Key Vault의 **비밀**(secret)은 애플리케이션 자격 증명 같은 값을 저장합니다. 비밀 **이름** 하나에 식별자가 다른 **버전**이 여럿 있을 수 있습니다. 워크로드는 **관리 ID**(managed identity)로 Microsoft Entra ID에 인증할 수 있습니다. Entra가 토큰을 발급하면 Key Vault는 제시된 신원이 해당 작업을 할 수 있는지 판단합니다. **Azure RBAC**를 사용하는 볼트는 역할 할당과 적용 범위가 중요합니다. **액세스 정책** 모델을 사용하는 볼트에는 별도의 데이터 권한 설정이 적용됩니다. 네트워크 규칙도 독립적으로 접근을 막을 수 있습니다.

**관리 평면**은 볼트 설정과 권한을 바꿉니다. **데이터 평면**은 비밀 값 요청 같은 호출을 처리합니다. SaaS와 호스팅 제품은 값을 캐시할 수 있습니다. 애플리케이션이 앞서 받아 둔 값을 쓰면 사용 시점에 볼트 조회가 새로 발생하지 않을 수 있습니다.

| 단계 또는 자료 | 확보할 수 있는 증거 | 별도로 확인할 것 |
| --- | --- | --- |
| Entra 로그인 또는 워크로드 신원 | 수집 범위에서 인증이나 토큰 획득 | 그 토큰을 사용한 볼트 요청 |
| Azure 활동 로그와 권한 설정 | 역할 할당 같은 관리 작업이나 잠재적 권한 | 데이터 평면 요청 발생 여부와 결과 |
| Key Vault `AuditEvent` | 특정 볼트에 대한 작업과 상태, 가능한 경우 토큰 신원 | 클라이언트가 값을 수신·보관·사용했는지 |
| 애플리케이션 또는 의존 서비스 감사 | 기록이 있는 경우 앱이 값을 받았거나 의존 서비스에서 사용한 사실 | 실제로 사용한 비밀 버전이나 자격 증명 |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/azure-key-vault-read-evidence-ko.svg' | relative_url }}" alt="워크로드가 Entra ID에 인증한 뒤 Key Vault에 비밀 값을 요청합니다. 볼트는 정책을 평가하고 응답을 기록합니다. 이후 앱의 사용은 별도로 확인합니다. 관리 이벤트는 다른 흐름에서 권한 변경을 기록합니다." width="480" height="384">
  <figcaption>역할 변경은 잠재적인 접근 권한을 보여 줍니다. 데이터 평면의 응답과 이후 사용은 각각 근거가 필요합니다.</figcaption>
</figure>

## 2. 정상 조회 한 건 따라가기

가상의 보고 서비스가 관리 ID `report-worker`로 `vault-training-a`에 접속합니다. 서비스 담당자는 필요한 범위에서 읽기 전용 데이터 역할을 승인했고, 요청은 예상한 네트워크 경로에서 들어옵니다. 서비스는 버전을 지정해 요청합니다. 볼트 리소스 감사에는 `SecretGet`과 HTTP 200이 기록됩니다. 문서화된 API에서 이 성공 응답에는 비밀 값이 포함됩니다. 따라서 서비스가 값을 포함한 응답을 만들었다고 볼 근거가 됩니다. 별도로 애플리케이션에는 수신이, 이후 의존 데이터베이스에는 연결이 기록됩니다. 수신 또는 사용 여부는 이 후속 자료와 대조해 판단합니다.

| 작업 또는 결과 | 해석 |
| --- | --- |
| `SecretGet`과 HTTP 200 | 값 응답에 성공한 작업입니다. 볼트, 비밀, 요청 버전과 신원을 대조하세요. |
| 버전 없는 `SecretGet`과 HTTP 200 | API는 요청 시점의 최신 버전을 고릅니다. 정확한 버전 식별자는 신뢰하는 응답·앱 또는 해당 서비스 메타데이터에서 확인합니다. 현재 최신 버전은 당시와 다를 수 있습니다. |
| `SecretList` 또는 `SecretListVersions`와 HTTP 200 | 메타데이터 목록입니다. 목록 기록만으로 값 조회를 판단할 수 없습니다. |
| `SecretGet`과 HTTP 401 또는 403 | 해당 시도의 인증 응답 또는 접근 거부입니다. 정상 인증 챌린지와 후속 재시도, 403의 세부 원인을 확인합니다. |
| `SecretGet`과 HTTP 404 또는 429 | 해당 시도의 리소스 조회 실패 또는 요청량 제한입니다. 클라이언트 재시도와 제한 시간을 확인하세요. |
| 역할 할당 또는 볼트 설정 쓰기 | 관리 작업의 증거입니다. 유효 권한과 데이터 평면 감사 기록을 대조합니다. |

실제 권한 모델을 확인하세요. Microsoft 문서에서 `Key Vault Contributor`는 관리 역할이며 `Key Vault Secrets User`는 RBAC 볼트에서 비밀 내용을 읽을 수 있는 역할입니다. 액세스 정책 모델에서는 Contributor가 액세스 정책을 바꿀 수 있다면 별도의 위험이 생깁니다. 무엇이 바뀌었고 호출자가 그 뒤 어떤 작업을 했는지 확인합니다.

## 3. 오용 가능성과 정상적인 대안 설명

공격자가 워크로드 신원이나 지나치게 넓은 권한을 확보하면 자격 증명 조회를 시도할 수 있습니다. 성공한 조회 한 건은 정상 서비스 시작, 예약 갱신 또는 비밀 교체 과정에서도 나옵니다. 호출이 몰리는 현상은 정상 확장이나 예상 밖의 열거에서도 생깁니다. 볼트 ID, 작업, 주체, 유효 범위, 예상 실행 환경과 시간대를 비교하세요.

| 관측 | 대응 범위를 키우기 전에 볼 자료 |
| --- | --- |
| 새로운 주체가 운영 비밀을 조회함 | 워크로드 인벤토리, 역할 변경 이력, 승인 기록, 네트워크 경로, 확보한 요청 세부 정보 |
| 권한 변경 직후 조회가 나옴 | 같은 범위와 신원인지 확인합니다. 시각이 가깝다는 사실만으로 두 작업을 연결할 수 없습니다. |
| 워크로드가 403을 받음 | 공급자의 상세 오류를 읽습니다. 방화벽 정책과 인가 정책 모두 403을 만들 수 있습니다. 사건 당시 유효 설정을 확인합니다. |
| 감사 행이 없음 | 진단 설정, 목적지, 볼트, 시간, 보존, 수집과 필터를 확인합니다. 캐시된 값을 사용했으면 새 호출이 없을 수 있습니다. |

토큰 신원은 가능할 때 API에 제시된 주체나 앱의 클레임을 알려 줍니다. 특정 사람, 호스트 프로세스나 장치를 식별하려면 다른 자료가 필요합니다. 여러 워크로드가 프록시나 공용 송신 IP를 공유할 수 있습니다. 목록 조회 뒤 값 조회가 이어졌다면 배포와 실행 기록을 대조해 그 맥락을 확인하세요.

## 4. 블루팀의 수집, 탐지, 대응

1. **로그가 도착하는 경로를 확인합니다.** 관련 볼트의 진단 설정에서 `AuditEvent`가 의도한 목적지로 전송되는지 확인하세요. Log Analytics에서는 실제 테이블과 스키마를 확인합니다. 아래 예제는 리소스별 테이블 `AZKVAuditLogs`를 사용합니다. 기존 `AzureDiagnostics` 목적지는 스키마가 달라 별도의 조회가 필요합니다. 적용 설정, 수집 지연, 보존 기간과 시각 범위를 남기고 필요하면 원본을 내보냅니다.
2. **서비스가 보고한 결과를 보존합니다.** UTC, 전체 볼트 리소스 ID, 작업, 상태와 확보 가능한 상세 결과를 기록하세요. `Identity`와 `CallerIpAddress`를 확인하고 범위를 제한한 `RequestUri`에서 비밀과 요청 버전을 식별합니다. URI에 버전이 없으면 정확한 반환 버전은 그 URI에서 확인할 수 없습니다. 경로와 신원 필드는 민감 자료로 취급합니다. 일반 조사 과정에서 비밀 값이나 원문 토큰을 수집하지 않습니다.
3. **신원과 변경 이력을 대조합니다.** 관련 리소스와 주체의 Entra 기록 및 관리 변경 내역을 비교합니다. Key Vault의 `CorrelationId`는 클라이언트가 제공할 수 있는 선택적 값이므로 비어 있을 수 있습니다. 적용 가능하면 시각, 리소스와 클라이언트 자료를 함께 쓰세요. Entra의 ID와 볼트의 상관관계 값이 같은 범위에 있다고 가정하지 않습니다. 집계에서 중복을 정리하기 전에 재시도와 중복 내보내기를 판단할 근거를 보존하세요.
4. **판정을 검증하고 노출에 대응합니다.** 승인된 범위의 값 응답, 거부된 요청, 메타데이터 목록을 하나씩 사용해 판정을 확인한 뒤 실제 건수와 공백을 비교하세요. 예상 밖 값 응답이 확인되면 증거를 보존하고 워크로드 담당자와 유효 권한을 확인합니다. 승인된 절차에 따라 접근을 제한하고 의존 서비스의 자격 증명을 교체합니다. Key Vault에 값을 새로 저장해도 의존 서비스가 이전 자격 증명을 계속 받아들이면 폐기 효과가 없습니다. 새 접근과 의존 서비스의 결과를 확인하세요.

리소스별 Key Vault 로그를 받는 작업 공간에서 읽기 권한이 있을 때, 승인된 볼트의 전체 ID를 넣어 조회합니다. 이 첫 조회는 요청 URI, 신원과 값을 출력하지 않습니다. 이후 필요한 자료만 좁혀 보세요.

```kusto
let vault = "/subscriptions/<id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<name>";
AZKVAuditLogs
| where TimeGenerated >= ago(1d)
| where _ResourceId =~ vault
| where OperationName in~ ("SecretGet", "SecretList", "SecretListVersions")
| project TimeGenerated, _ResourceId, OperationName,
          HttpStatusCode, ResultType, ResultSignature, CorrelationId
| order by TimeGenerated desc
```

탐지 기준선을 만들 때는 합의된 기간에 주체와 비밀 분류별로 처음 성공한 `SecretGet`을 확인하세요. 처음 보는 조합은 배포와 교체 일정에 대조합니다. 반복 거부는 별도로 모니터링하고, 거부 후 성공이 나타났다면 같은 볼트와 주체인지 확인해 조사합니다.

## 5. 오프라인 증거 실습

<a href="{{ '/assets/labs/azure-key-vault-read-evidence.py' | relative_url }}" download>Python 3 확인 도구</a>와 <a href="{{ '/assets/labs/azure-key-vault-read-evidence-cases.json' | relative_url }}" download>가상 감사 사례</a>를 같은 디렉터리에 내려받으세요. 연습용 공통 형식에는 가상 필드만 있습니다. 도구는 로컬 파일을 읽으며 클라우드에 요청하지 않습니다.

```sh
python3 azure-key-vault-read-evidence.py
```

| 사례 | 판단할 내용 |
| --- | --- |
| A, B, L | 값 응답이 성공해도 정확한 버전과 토큰 신원을 확인할 수 있는 범위는 다릅니다. |
| C, F, G, H | 접근 거부, 인증 응답, 리소스 없음, 요청량 제한은 각각 그 요청의 결과입니다. |
| D, E, N | 비밀·버전 메타데이터 목록, 볼트 속성 조회와 값 응답을 구분합니다. |
| I, J | 상태 필드가 없는 행과 행 자체가 없는 경우에는 서로 다른 자료가 필요합니다. |
| K, M | 관리 작업과 다른 볼트의 성공은 조사 범위 안 볼트의 값 응답 근거가 되지 않습니다. |

`14/14 Key Vault evidence cases matched.`를 확인하세요. 음성 대조로 JSON을 복사하고 A의 `http_status`를 200에서 403으로 바꿔 그 파일 이름을 명령 인수로 넘깁니다. A는 `access-denied-response`로 바뀌고 13건이 일치하며 종료 코드는 1입니다. 입력이 열리지 않으면 파일명, Python 3과 JSON 문법을 확인하세요. A가 계속 일치하면 실제 기록의 상태가 바뀌었는지, 기대 결과는 원본 그대로인지 확인합니다.

원본과 수정본은 클라우드 Python에서 실행했습니다. Azure 로깅, 조회 열과 REST 결과는 공식 문서로 검토했습니다. 실제 작업 공간 조회와 비밀 값 요청은 실행 범위에 포함되지 않습니다.

## 6. 확인 문제와 해설

1. **역할 할당이 성공했고 신원도 로그인했습니다. 값이 조회됐나요?** 정확한 볼트의 데이터 평면 작업과 결과를 확인하세요. 관리와 인증 기록은 각각 앞 단계를 설명합니다.
2. **목록 조회 성공과 Get 성공은 어떻게 다른가요?** 목록은 식별자와 메타데이터를 돌려줍니다. Get이 성공하면 요청한 값이 응답에 들어갑니다.
3. **버전을 생략한 요청은 어느 버전을 받았나요?** 당시 최신 버전을 요청한 것입니다. 정확한 식별자는 신뢰할 수 있는 응답, 앱 또는 서비스 메타데이터를 확인하세요.
4. **허용된 워크로드가 자격 증명을 사용했는데 새 Key Vault 이벤트가 없습니다. 왜 그럴까요?** 앞서 조회했거나 캐시한 값을 썼을 수 있습니다. 진단 범위, 앱과 의존 서비스의 타임라인을 확인하세요.

**완료 기준.** 원본과 수정본을 재현하고 A·B·D·J·K의 자료 출처와 판단 범위, 추가 증거를 설명하세요. 값 응답과 자격 증명 사용을 각각 어떤 자료로 확인할지 제시합니다.

## 공식 참고자료

2026-11-26 기준으로 검토했습니다. REST 동작은 Microsoft Key Vault Secrets API **2025-07-01** 버전에 해당합니다. Azure Monitor와 Key Vault 인가 동작은 Microsoft의 현재 문서를 기준으로 설명합니다. 실제 볼트에 배포된 권한과 내보내기 모드를 확인하세요.

- 작업과 결과 정의. [Get Secret](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01) · [List Secrets](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secrets/get-secrets?view=rest-keyvault-secrets-2025-07-01) · [List Secret Versions](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret-versions/get-secret-versions?view=rest-keyvault-secrets-2025-07-01) · [Key Vault 오류 코드](https://learn.microsoft.com/en-us/azure/key-vault/general/rest-error-codes)
- 감사 필드와 내보내기. [Key Vault 로깅](https://learn.microsoft.com/en-us/azure/key-vault/general/logging) · [AZKVAuditLogs 스키마](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azkvauditlogs) · [진단 설정](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/diagnostic-settings)
- 권한과 관리 이력. [Key Vault RBAC 지침](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide) · [Azure 활동 로그](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log) · [관리 ID](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)

[이전 · Entra 로그인 조사]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }}) · [다음 · AWS KMS 조사]({{ '/ko/wiki/aws-kms-evidence/' | relative_url }})
