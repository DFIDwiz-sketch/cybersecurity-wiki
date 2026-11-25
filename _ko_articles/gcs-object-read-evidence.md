---
title: "Google Cloud Storage 객체 읽기 조사 · 권한부터 수신까지"
description: "가상 사례 아홉 건으로 객체 목록·메타데이터·본문 읽기와 데이터 액세스 로그 공백을 구분합니다."
category: cloud
tags: [Google Cloud, Cloud Storage, Audit Logs, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /wiki/gcs-object-read-evidence/
---

**학습 목표.** Cloud Storage 감사 이벤트와 같은 요청의 클라이언트 또는 서비스 기록을 대조합니다. 객체 목록 조회, 메타데이터 조회, 본문 읽기, 결과를 알 수 없는 요청을 구분하고, 검색 결과가 비어 있을 때 어떤 결론을 보류해야 하는지 설명합니다.

## 1. 무엇을 읽었나요?

**버킷**은 객체를 담는 저장 공간입니다. **객체 이름**은 버킷 안에서 객체를 가리킵니다. **세대 번호(generation)**는 객체 데이터의 특정 버전을 식별합니다. 같은 이름의 객체라도 시점에 따라 바이트가 다를 수 있습니다. **주체(principal)**는 사용자나 워크로드의 서비스 계정처럼 권한을 받을 수 있는 신원입니다. IAM은 주체가 수행할 수 있는 작업을 결정하고, 감사 설정은 Google Cloud가 그 작업에 관해 어떤 기록을 남길지 결정합니다.

| 작업 또는 기록 | 확인할 수 있는 내용 |
| --- | --- |
| 객체 목록 조회 | 목록 조건에 맞는 객체를 확인합니다. 객체 본문은 반환하지 않습니다. |
| JSON API의 기본 객체 GET | 객체 메타데이터를 반환합니다. |
| `alt=media`가 있는 JSON API 객체 GET | 객체 데이터를 요청합니다. `Range`를 사용하면 일부 구간을 받을 수 있습니다. |
| 관리자 활동 로그 | 버킷 IAM 변경 같은 작업을 확인합니다. 타임라인에 정책 변경을 배치할 때 사용합니다. |
| 데이터 액세스 로그의 `DATA_READ` | 설정과 적용 범위에 따라 목록·메타데이터·데이터 읽기를 기록합니다. Cloud Storage에서는 기본적으로 꺼져 있습니다. |

JSON API 객체 GET 두 종류는 모두 `storage.objects.get` 권한을 사용합니다. 권한 이름과 감사 분류만으로 응답 본문을 알 수 없습니다. 메서드를 해석하기 전에 실제 API와 요청 형태를 확인하세요. JSON API의 GET과 XML API의 GET은 기본 동작이 다릅니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/gcs-object-read-evidence-ko.svg' | relative_url }}" alt="Cloud Storage 요청은 두 종류의 증거를 남길 수 있습니다. 감사 로그에서는 신원과 인가, 처리 결과를 봅니다. 클라이언트나 서비스 기록에서는 응답 유형과 바이트 수를 봅니다. 같은 요청의 기록인지 확인한 뒤 전송 결과를 판단합니다.">
  <figcaption>저장소 감사 이벤트와 데이터 전송 증거를 함께 읽으세요.</figcaption>
</figure>

## 2. 정상 객체 읽기를 따라가기

보고서 생성 작업이 서비스 계정으로 비공개 버킷의 가상 객체 `reports/summary.csv`를 읽는다고 가정합니다. 먼저 메타데이터에서 기대한 세대 번호 `17`을 확인합니다. 다음 요청에서 데이터를 받고 작업 기록에 실제 바이트 수와 체크섬 검증 결과를 남깁니다.

1. 작업이 인증한 뒤 메타데이터를 요청합니다. `DATA_READ` 수집 범위 안이라면 감사 이벤트에서 서비스, 메서드, 객체, 인증된 주체를 볼 수 있습니다. 이 요청이 성공했다면 확인된 결과는 메타데이터 반환입니다.
2. 작업이 별도의 데이터 요청을 보냅니다. `protoPayload.authorizationInfo`에서 해당 리소스와 권한을 검사한 항목을 찾습니다. `granted`는 그 권한 검사의 결과입니다. `protoPayload.status`가 있으면 Google RPC 코드로 작업 결과를 읽습니다. HTTP 상태는 별도의 HTTP 필드나 기록에서 확인합니다.
3. 작업이 객체의 세대 번호와 수신 바이트, 검증 결과를 기록합니다. 두 기록에 공통 요청 ID가 있으면 우선 대조합니다. 없으면 시각, 버킷, 객체, 세대 번호, 호출자를 조합해 보고 매칭의 확실성을 남깁니다. API 성공만으로는 클라이언트가 전송을 완료했거나 데이터를 사용했다고 판단할 수 없습니다.

`allUsers` 또는 `allAuthenticatedUsers`를 통해 허용된 읽기는 데이터 액세스 로그를 켜도 Cloud Audit Logs에 기록되지 않습니다. 콘솔 밖에서 인증된 브라우저로 내려받으면 `principalEmail`과 `callerIp`가 가려질 수 있습니다. Google은 일반 감사에 Cloud Audit Logs를 권장하며 공개 접근 등을 확인해야 할 때 별도의 버킷 사용 로그를 안내합니다. 사용 로그는 미리 설정해야 하고, 늦게 도착하거나 일부가 빠질 수 있습니다. 사용 로그의 `sc_bytes`는 응답으로 보낸 바이트 수입니다. 본문 전송으로 해석하려면 요청과 상태를 함께 확인하고, 수신을 판단하려면 클라이언트 기록을 확인합니다.

## 3. 예상 밖 읽기와 로그 공백 조사하기

너무 넓은 IAM 권한을 부여하면 정상 워크로드가 읽을 필요가 없는 민감한 객체에도 접근할 수 있습니다. 서비스 계정 자격 증명이 다른 곳에서 사용되면 평소와 같은 신원으로 낯선 요청이 남을 수 있습니다. 서명 URL은 가진 사람에게 정해진 시간과 범위 안에서 접근을 허용합니다. 발급 사실만으로 사용 여부를 알 수 없고, 서명 신원만으로 실제 사용자를 식별할 수 없습니다. 낯선 IP 주소나 User-Agent는 정상 배포, 프록시, 클라이언트 업데이트로도 나타납니다. 개별 필드 하나로 사람의 신원을 단정하지 마세요.

1. **수집 범위를 확인합니다.** 버킷 소유 프로젝트나 라우팅된 로그 목적지를 선택합니다. 사건 당시의 `DATA_READ` 적용 범위, 제외 주체, 싱크 경로와 필터, 로그 뷰 접근, 보존 기간을 확인합니다. 기본 로그 버킷에서는 `roles/logging.privateLogViewer` 등 데이터 액세스 로그 조회 권한이 필요합니다. 사용자 정의 목적지에서는 해당 로그 뷰 권한을 확인합니다. UTC로 조회 범위를 기록한 뒤 승인 범위에서 기록이 기대되는 비공개 읽기 요청으로 수집을 점검합니다.
2. **원본을 보존합니다.** 시각, 로그 이름, 리소스, `insertId`, 메서드, 확인 가능한 세대 번호, 인증·위임 맥락, 관련 권한 검사와 작업 상태를 남깁니다. `insertId`는 로그 항목 식별에 도움이 됩니다. 이를 시스템 간 공통 요청 ID로 가정하지 마세요. 이미 수집된 요청·응답 메타데이터를 필요한 범위에서 붙이고, 객체 본문·토큰·서명 URL 쿼리 문자열은 사고 자료에 넣지 않습니다.
3. **비교하고 대응합니다.** 목록, 메타데이터, 본문 전송이 뒷받침된 요청을 각각 집계합니다. 급증했다면 해당 신원의 평소 작업 시간, 객체 집합과 목적지를 확인합니다. 전송량을 추정할 때 재시도와 범위별 응답을 구분합니다. 최근 버킷 IAM 변경과 서비스 계정 활동도 대조하세요. 노출 가능성이 뒷받침되면 담당자와 접근 경로를 차단하고 증거를 보존합니다. 변경 후에는 승인된 읽기와 읽기 권한이 없는 시험 신원의 요청을 각각 검증합니다.

Logs Explorer에서 시험 요청이 포함된 시간대를 지정하고 가상의 버킷 이름을 교체하세요. 아래 식은 읽기 외 작업을 포함한 해당 버킷의 Cloud Storage 데이터 액세스 로그를 찾습니다. 서비스가 실제로 기록한 필드를 확인한 뒤 메서드와 리소스로 좁힙니다. 민감한 로그를 볼 수 있는 범위와 뷰를 사용하세요.

```text
log_id("cloudaudit.googleapis.com/data_access")
resource.type="gcs_bucket"
resource.labels.bucket_name="wiki-audit-lab"
protoPayload.serviceName="storage.googleapis.com"
```

검색 결과가 없으면 프로젝트, 로그 뷰, UTC 시간 범위, 버킷 이름을 점검합니다. 의심한 요청과 별개로 당시 감사 범위와 기록이 기대되는 시험 요청을 확인하세요. 필요한 데이터가 생성되지 않았거나 보존되지 않았다면 당시 접근 여부는 미확인으로 남깁니다. 해당되는 정책 위반은 Google이 안내하는 Policy Denied 로그도 확인합니다. 위 검색식에는 그 로그 유형이 포함되지 않습니다. 한 번의 거부는 그 요청의 결과이며 다음 재시도는 별도 요청입니다.

## 4. 승인된 작업 공간에서 실습하기

<a href="{{ '/assets/labs/gcs-object-read-evidence.py' | relative_url }}" download="gcs-object-read-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/gcs-object-read-evidence-cases.json' | relative_url }}" download="gcs-object-read-evidence-cases.json">가상 사례</a>를 한 폴더에 저장합니다. JSON 필드는 실습용으로 정리한 값이며 Cloud Logging의 원래 필드 이름과 다릅니다. 요청과 대조할 증거도 가상 자료에 들어 있습니다. 스크립트는 로컬 파일만 읽습니다.

```bash
python3 gcs-object-read-evidence.py gcs-object-read-evidence-cases.json
```

```text
listing: listing_observed
metadata: metadata_observed
get_without_detail: request_kind_unresolved
partial_response: partial_content_sent
full_receipt: full_receipt_confirmed
denied_request: request_denied
other_connection: content_delivery_unconfirmed
public_read_gap: coverage_gap
no_matching_entry: no_event_observed
```

파일을 찾지 못하면 현재 폴더와 두 이름을 확인합니다. `partial_response`에서는 해당 요청의 일부 구간 응답을 확인합니다. `full_receipt`에서는 클라이언트가 전체 객체를 수신하고 무결성을 확인한 증거까지 있습니다. `no_matching_entry`는 검색 결과를 나타내며 접근 여부를 확정할 증거는 없습니다.

제품 환경에서도 확인하려면 승인된 시험 프로젝트의 비공개 버킷과 더미 객체를 사용하세요. `DATA_READ`와 로그 조회 권한을 마련한 뒤 승인된 클라이언트에서 메타데이터 조회와 같은 세대의 객체 다운로드를 순서대로 수행합니다. UTC 시간 범위, 받은 파일의 크기와 체크섬을 기록합니다. 검색식으로 기록을 비교한 뒤 읽기 권한이 없는 승인된 시험 신원으로 별도 요청을 확인합니다. 로그 수집 지연을 고려하고, 기록이 없으면 거부를 해석하기 전에 정상 읽기가 로그에 남는지부터 확인하세요. 실습 중 객체는 계속 비공개로 둡니다. Python은 가상 사례로 실행했습니다. 검색식과 제품 절차는 공식 문서로 검토했으며 실제 Google Cloud 프로젝트에서는 실행하지 않았습니다.

## 5. 확인 문제와 완료 기준

- **`storage.objects.get` 검사에서 허용이 기록됐습니다. 전체 바이트를 받았나요?** 작업 결과, 요청 형태, 세대 번호를 확인한 뒤 같은 요청의 전송 또는 클라이언트 검증 증거를 찾습니다.
- **공개 객체에 대한 데이터 액세스 로그가 없습니다. 접근이 없었다고 결론 내릴 수 있나요?** 접근 경로를 확인하고, 미리 구성한 사용 로그나 승인된 서비스 관측을 찾습니다.
- **호출자 IP가 가려졌습니다. 익명 요청인가요?** 인증된 브라우저 다운로드에서도 가려질 수 있습니다. 워크로드나 애플리케이션 증거를 대조한 뒤 판단합니다.

아홉 개 출력이 모두 일치하고, 권한 검사·작업 결과·전송 바이트·검증된 수신의 차이와 읽기 요청이 검색에서 누락될 수 있는 이유를 설명하면 실습을 마친 것입니다.

## 공식 참고자료

2026년 11월 23일에 현재 서비스와 API 기준으로 검토했습니다. Cloud Storage 감사 문서의 갱신일은 2026년 11월 17일 UTC입니다.

- Cloud Storage의 감사 분류, 작업과 수집 제한. [Cloud Storage의 Cloud Audit Logs](https://docs.cloud.google.com/storage/docs/audit-logging)
- JSON API 요청 형태, 세대 번호와 범위 조회. [Objects: get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get)
- 감사 페이로드와 상태 필드. [AuditLog](https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog)
- 설정, 조회 권한과 검색 문법. [데이터 액세스 로그 활성화](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) · [Cloud Audit Logs 개요](https://docs.cloud.google.com/logging/docs/audit) · [Logging 검색 언어](https://docs.cloud.google.com/logging/docs/view/logging-query-language)
- 사용 로그 수집 범위, 전달 제한과 필드. [Cloud Storage 사용 로그와 저장 로그](https://docs.cloud.google.com/storage/docs/access-logs)
- 정해진 시간 동안 URL 소지자에게 주는 접근 권한. [서명 URL](https://docs.cloud.google.com/storage/docs/access-control/signed-urls)

[비교 · Amazon S3 객체 읽기]({{ '/ko/wiki/s3-object-read-evidence/' | relative_url }}) · [관련 · 감사 로그 공백 조사]({{ '/ko/wiki/cloudtrail-log-integrity/' | relative_url }})

[이전 글 · 서비스 계정 위임 조사]({{ '/ko/wiki/gcp-service-account-impersonation-evidence/' | relative_url }})
