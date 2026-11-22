---
title: "엔드포인트 격리 증거 · 실제 차단된 경로 확인하기"
description: "가상 사고 대응 사례 10건으로 격리 요청, 제품의 완료 보고, 독립 관측으로 확인한 차단을 구분합니다."
category: dfir
tags: [Incident Response, Endpoint Isolation, DFIR, Blue Team, EDR, Microsoft Defender]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/endpoint-isolation-evidence/
---

대응 콘솔에서는 **Succeeded**가 보이는데, 방화벽 기록에는 장치가 아직 통신하는 것처럼 보입니다. 어떤 증거를 기준으로 다음 조치를 정해야 할까요? 이 장에서는 격리 작업의 완료 시점과 의도한 범위를 먼저 확인하고, 네트워크에서 실제로 관측한 결과를 대조합니다. 전체 사고 흐름은 [Windows 사고 대응 통합 실습]({{ '/ko/wiki/windows-incident-response-lab/' | relative_url }})에서 살펴볼 수 있습니다.

## 1. 네트워크 격리가 제어하는 범위

**엔드포인트 격리**는 지정한 장치의 네트워크 통신을 제한하는 제품 정책입니다. **사고 확산 억제(containment)**의 범위는 더 넓습니다. 사고에 따라 계정, 세션, 네트워크 수준에서도 별도 조치를 취하고 효과를 확인해야 합니다. 장치를 격리하더라도 관리 통신 경로가 유지되도록 설계하는 경우가 많습니다. 어느 통신이 허용되고 관리를 유지하려면 무엇이 필요한지는 제품, 격리 범위, 설정에 따라 달라집니다.

**작업 기록**은 관리 시스템에서 생성하며 요청과 상태를 보여 줍니다. 독립적인 **네트워크 관측**은 감시 지점을 실제로 통과하거나 목적지에 도달한 통신을 확인하는 데 쓰입니다. 시험 결과는 장치, 시각, 경로, 프로토콜, 방향과 관측 지점으로 범위가 정해집니다. 결론을 확대하기 전에 이 항목을 남기세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/endpoint-isolation-evidence-ko.svg' | relative_url }}" alt="격리 요청과 장치 ID부터 확인합니다. 대기나 실패 상태면 장치 연결과 작업 상세 기록을 봅니다. 성공으로 보고되면 네트워크 경로와 이벤트 시각을 대조하고, 검증한 범위와 공백을 기록합니다.">
  <figcaption>격리 완료를 확인한 뒤 실제 차단을 따로 확인합니다. 관리 기록과 네트워크 관측을 함께 보존하세요.</figcaption>
</figure>

| 확인한 증거 | 뒷받침하는 판단 | 다음에 필요한 자료 |
| --- | --- | --- |
| 요청 ID와 요청 시각 | 관리 시스템이 요청을 접수했거나 기록함 | 해당 장치와 작업의 현재 상태 |
| 제품 상태 `Succeeded` | 제품이 해당 범위에서 완료를 보고함 | 의도한 경로와 일치하는 시험 또는 관측 |
| 일치하는 방화벽 거부 또는 장치 차단 | 해당 관측 지점이 차단을 기록함 | 올바른 출발지, 방향, 규칙, 목적지 |
| 목적지의 새 트랜잭션 | 일치하는 요청이 관측 지점까지 도달함 | 장치 귀속, 격리 범위나 예외, 최종 처리 |
| 콘솔 또는 흐름에서 결과 없음 | 선택한 화면에서 일치 근거를 얻지 못함 | 관측기 상태, 수집 범위, 다른 증거 |

## 2. 정상 격리 타임라인

가상의 노트북 `D-17`이 14:00 UTC에 소유한 실습 서비스에서 승인된 시험 요청을 완료했습니다. 14:02에 대응자가 격리를 요청하고 작업 ID를 남깁니다. 14:04에 콘솔에서 `Succeeded`를 보고합니다. 14:05에는 같은 차단 대상에 대한 새 요청이 거부됐습니다. 조사자는 올바른 장치와 정책의 거부 기록인지 확인합니다. 별도의 대조 호스트로 목적지 로그가 정상 동작하는지 확인하고, 장치에서 새 관리 신호가 수집됐는지도 기록합니다. 이 관측으로 해당 시점에 격리 완료가 보고됐고, 시험한 요청이 차단됐으며, 관리 통신은 유지됐다고 말할 수 있습니다.

14:03에 발생한 흐름을 수집기가 14:07에 받으면 화면에는 늦게 나타납니다. 그래도 이벤트 시각은 14:04 완료 보고보다 앞섭니다. 두 시각과 시간대, 예상 시계 오차를 함께 기록하세요. 오차 범위나 표본 구간이 완료 시점과 겹치면 시간 순서를 확정할 수 없습니다. 흐름 레코드는 일정 구간이나 이미 열린 세션을 요약할 수 있습니다. 개별 패킷이나 집계값보다 새 식별자가 있는 애플리케이션 트랜잭션이 새로운 통신을 확인하는 데 더 직접적인 근거가 됩니다.

## 3. Microsoft Defender 작업 기록 읽기

Microsoft Defender for Endpoint의 격리 API는 HTTP **201 Created**와 `MachineAction`을 반환한다고 문서화돼 있습니다. 작업의 `id`, `machineId`, `type`, `scope`, `status`, `creationDateTimeUtc`, `lastUpdateDateTimeUtc`를 봅니다. 마지막 필드는 상태를 갱신한 시각입니다. 실제 적용 시점을 좁혀야 할 때는 작업 이력과 장치 측 증거를 함께 확인하세요. `Pending`과 `InProgress`는 추적이 필요한 상태입니다. `Failed`, `TimeOut`, `Cancelled`라면 완료를 보고하기 전에 원인을 조사하고 다음 대응을 결정합니다.

Microsoft 문서에 따르면 요청할 때 유휴 상태거나 오프라인인 장치에는 최대 3일 동안 격리를 재시도합니다. 현재 장치 연결과 작업 이력으로 대기와 완료를 구분하세요. 제품에서 지원하는 경우 Action center 이력에서 실제 적용 범위와 예외를 확인합니다. 이후 격리 해제나 상태 변경이 기록됐다면 트래픽 시각과 대조하세요. 운영체제, 에이전트와 VPN 설정은 연결 상태에 영향을 줄 수 있습니다. 관리 통신은 배포 중인 환경과 정책을 기준으로 해석합니다. 이 장의 실습에는 Defender API나 운영 테넌트 조작이 필요하지 않습니다.

## 4. 수집하고 검증한 뒤 대응하기

1. **의도한 경계를 정합니다.** 장치의 안정적인 ID, 인벤토리 변경 이력, 호스트와 사고 담당자, 격리 범위, 허용할 관리 경로와 소유한 시험 목적지를 기록하세요. 이벤트 발생, 상태 갱신, 수집 시각을 별도로 정규화합니다. DNS 이름과 IP는 재사용될 수 있으므로 트래픽을 장치에 연결하기 전에 임대 정보, NAT, 인터페이스 또는 인벤토리 기록을 확인합니다.
2. **관측이 가능한지 확인합니다.** 작업 타임라인과 원본 기록을 보존하세요. 네트워크 측 연결 시각, 인터페이스나 구간, 방향, 프로토콜, 출발지·목적지·포트, 규칙 판단과 수집 범위를 남깁니다. 목적지 로그에 나타나는 새 식별자 또는 승인된 소규모 시험 요청을 활용할 수 있습니다. 허용된 별도의 대조 요청으로 로그 경로가 건강한지 확인하고 공백은 미확인으로 남깁니다. 관측 결과의 수신 여부는 [엔드포인트 수집 증거]({{ '/ko/wiki/endpoint-collection-evidence/' | relative_url }})에서 더 다룹니다.
3. **예상 밖 통신을 조사합니다.** 신뢰할 수 있는 완료 시각 이후, 차단돼야 할 경로에서 트랜잭션이 완료됐다면 격리 공백을 조사합니다. 오래된 기록, 다른 장치와의 혼동, 승인된 예외, 범위 변경 또는 이후의 해제 여부를 먼저 확인하세요. 제품이 성공을 보고해도 실제 차단이 의도와 다를 수 있습니다. 불일치 하나만으로 원인이나 의도를 확정할 수 없습니다.
4. **다음 대응을 기록합니다.** 증거를 보존하고 사고 대응 책임자에게 알립니다. 추가 격리는 장치·네트워크 담당자와 승인 범위를 조율합니다. 필요한 경우 계정이나 세션에 대한 별도 조치의 적용도 확인합니다. 재연결 전에는 복구 결정을 받고, 해제 작업을 검증하며, 재발을 살필 관측 기간을 정하세요. 대시보드의 상태가 바뀌어도 이전 타임라인을 보존합니다.

방어팀과 검증팀이 함께 시험할 때는 서면으로 정한 범위 안의 자체 테스트 장치와 무해한 목적지만 사용하세요. 격리 전 정상 성공, 이후의 차단 예상 요청, 허용된 관리 신호, 관측기가 정상임을 보여 주는 대조 결과를 정의합니다. 승인된 제어를 적용하기 전에 시험 장치를 복구할 담당자와 경로를 마련하세요. 아래 다운로드 실습은 오프라인에서 진행합니다.

## 5. 오프라인 실습 · 가상 관측 열 건

두 파일을 같은 폴더에 내려받고 Python 3.10 이상에서 실행하세요. JSONL은 **정규화한 가상 관측 요약**입니다. `match`는 이미 확인된 장치와 경로의 일치를, `observer_ok`는 해당 관측을 뒷받침할 수집 범위를 표현합니다. `action_updated`는 가상 사례에서 완료가 보고된 시각을, `observed_at`은 출처에 기록된 이벤트 시각을 나타냅니다. 숫자 시각은 상대 초입니다. 스크립트는 로컬 파일을 읽으며 네트워크나 엔드포인트에 접근하지 않습니다.

<a href="{{ '/assets/labs/endpoint-isolation-evidence.py' | relative_url }}" download="endpoint-isolation-evidence.py">endpoint-isolation-evidence.py</a> · <a href="{{ '/assets/labs/endpoint-isolation-evidence-cases.jsonl' | relative_url }}" download="endpoint-isolation-evidence-cases.jsonl">endpoint-isolation-evidence-cases.jsonl</a>

```bash
python3 endpoint-isolation-evidence.py endpoint-isolation-evidence-cases.jsonl
```

```text
blocked_in_scope: blocked_in_test_scope
offline_pending: await_enforcement_evidence
timed_out: inspect_action_failure
permitted_management: expected_exception
late_ingest: before_confirmation
other_device: wrong_device_or_path
unexpected_success: investigate_unexpected_success
observer_blind: insufficient_observation
time_boundary: time_order_uncertain
release_afterward: after_release
```

`late_ingest`는 `received_at`이 더 늦더라도 출처의 이벤트 시각으로 판독합니다. `time_boundary`는 같은 정밀도로 기록된 시각이 같아서 순서를 결정할 수 없습니다. 실행이 안 되면 작업 폴더와 파일명을 확인하세요. 예상과 다른 결과가 나오면 장치·경로 일치, 관측 상태와 작업 순서를 먼저 살펴봅니다. 가상 실습은 Python 3.12에서 실행했습니다. Defender 동작은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **201 응답으로 실제 경로가 차단됐다고 볼 수 있나요?** 대응 작업이 생성됐음을 보여 줍니다. 작업 상태와 경로 단위 관측을 확인하세요.
- **격리 뒤에도 관리 신호가 남을 수 있는 이유는 무엇인가요?** 적용된 정책이 서비스 관리 통신을 허용할 수 있습니다. 해당 신호가 올바른 장치와 승인 범위에 속하는지 확인하세요.
- **센서에서 결과가 없으면 차단을 확인한 건가요?** 해당 화면에서 결과를 얻지 못한 것입니다. 관측기가 그 트래픽을 볼 수 있었는지 확인하고 목적지 기록이나 명시적 차단과 대조합니다.

열 줄의 결과를 재현하고 `observer_blind`와 `unexpected_success`에서 다음에 확인할 증거 출처를 한 가지씩 말해 보세요. `blocked_in_scope`는 장치, 경로, 시각과 남은 한계를 한 문장으로 설명합니다.

## 공식 참고자료

검토일은 2026-11-22입니다. Microsoft 자료는 문서에 명시된 Defender 플랜, 버전, 기능을 대상으로 합니다. 대상 장치의 플랫폼과 적용 정책을 확인하세요.

- 2025년 4월, CSF 2.0 사고 대응. Rev. 2를 대체합니다. [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- 2025년 11월 API 문서. HTTP 응답과 격리 범위. [Microsoft Learn · Isolate machine API](https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine)
- Defender 작업 리소스 스키마와 상태 값. [Microsoft Learn · MachineAction](https://learn.microsoft.com/en-us/defender-endpoint/api/machineaction)
- 2026년 제품 문서. 장치 격리, 오프라인 장치와 플랫폼별 조건. [Microsoft Learn · Device response actions](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- Defender 선택적 격리의 예외와 적용된 정책 이력. [Microsoft Learn · Network isolation exclusions](https://learn.microsoft.com/en-us/defender-endpoint/network-isolation-exclusions)

[이전 · Windows 사고 대응]({{ '/ko/wiki/windows-incident-response-lab/' | relative_url }}) · [관련 · 엔드포인트 수집]({{ '/ko/wiki/endpoint-collection-evidence/' | relative_url }}) · [관련 · 탐지 검증]({{ '/ko/wiki/detection-validation/' | relative_url }})
