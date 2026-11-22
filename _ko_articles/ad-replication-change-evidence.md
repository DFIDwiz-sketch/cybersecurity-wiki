---
title: "Active Directory 복제 조사 · 변경 기록과 DC별 상태"
description: "DC별 속성 값, 버전, 원본·로컬 USN과 Security 5136을 대조합니다."
category: active-directory
tags: [Active Directory, AD DS, AD Replication, Domain Controller, Windows Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/ad-replication-change-evidence/
---

두 도메인 컨트롤러가 같은 객체를 조회해도 서로 다른 값을 돌려줄 수 있습니다. 정상 변경이 각 서버에 다른 시점에 도착했을 수도 있습니다. 먼저 각 기록의 객체, 속성, 서버, 시각을 확인하세요. 이 장은 쓰기 가능한 DC에 복제되는 일반 단일값 속성 하나를 대상으로 합니다.

## 1. 한 DC의 변경이 다른 DC에 도착하는 과정

**DC(도메인 컨트롤러)**는 디렉터리 파티션의 복제본을 보관합니다. **파티션** 또는 **이름 지정 컨텍스트**는 해당 복제본을 호스팅하는 서버들에 복제되는 디렉터리 영역입니다. 쓰기 가능한 DC에서 처음 반영한 수정이 **원본 변경(originating update)**입니다. 다른 DC는 복제 파트너를 통해 변경을 받습니다. 관련 복제본이 같은 상태에 이르는 것을 **수렴**이라고 합니다. 사이트마다 복제 일정이 다르면 일정 시간이 걸릴 수 있습니다.

복제되는 속성에는 가장 최근의 원본 변경을 설명하는 **메타데이터**가 있습니다. **USN(Update Sequence Number)**은 DC의 로컬 변경 순서에서 부여하는 번호입니다. 원본 USN은 변경이 처음 반영된 데이터베이스의 번호입니다. **호출 ID(invocation ID)**는 그 데이터베이스의 실행 세대를 구분하며 지원되는 복구 작업 뒤에는 바뀔 수 있습니다. 로컬 USN은 조회한 DC가 해당 변경을 자신의 순서에서 적용한 위치를 나타냅니다. 서로 다른 DC의 로컬 번호 48,200과 91,100만으로 어느 쪽이 최신인지 판단할 수 없습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ad-replication-change-evidence-ko.svg' | relative_url }}" alt="DC A의 승인된 쓰기에서 감사 기록과 새 속성 메타데이터가 만들어질 수 있습니다. DC B는 나중에 같은 원본 메타데이터를 받고 별도의 로컬 USN을 부여합니다. 각 DC에서 값과 메타데이터를 따로 확인합니다.">
  <figcaption>감사 기록은 변경을, 각 DC의 값과 메타데이터는 해당 복제본에서 관찰한 상태를 설명합니다.</figcaption>
</figure>

## 2. 정상적인 변경 한 건을 따라가세요

가상 환경에서 관리자가 09:00 UTC에 실습용 컴퓨터 객체의 `description`을 수정합니다. 변경은 `dc-a.ad.example`에 들어가고, 감사 범위가 맞으면 이 DC의 Security 5136에 남습니다. 기존 값을 바꾸는 경우 Value Deleted와 Value Added가 함께 남을 수 있습니다. 09:01에 DC A는 버전 4, 원본 호출 ID `inv-a1`, 원본 USN 48,200을 보여 주고 DC B에는 버전 3이 남아 있습니다. 09:04에 DC B가 DC A와 같은 버전 4, 원본 시각, 호출 ID, 원본 USN을 보여 줍니다. DC B의 로컬 USN은 91,100입니다. 실제 속성 값과 원본 메타데이터가 모두 같으면 두 관측에서 수렴을 뒷받침합니다.

| 증거 | 용도와 한계 |
| --- | --- |
| 객체 GUID와 속성의 LDAP 이름 | 같은 객체와 속성을 연결합니다. DN은 위치를 담으며 이름이 바뀌거나 이동하면 달라질 수 있습니다. |
| 버전과 원본 변경 시각 | 어떤 변경이며 원본에 기록된 시각이 언제인지 나타냅니다. 같은 변경을 복제해도 버전이나 원본 시각은 그대로입니다. |
| 원본 호출 ID와 USN | 버전이 같더라도 변경이 시작된 곳과 순서를 구분하는 데 도움이 됩니다. 원본 USN은 같은 호출 ID의 순서에서 비교합니다. |
| 로컬 USN | 조회한 DC의 순서에서 변경이 적용된 위치를 나타냅니다. 각 복제본 안에서 해석합니다. |
| 5136과 속성 값 | 감사 조건에 맞는 변경 기록과 수집 시점의 값은 독립된 관측입니다. 그 사이에 후속 변경이 있을 수 있습니다. |
| 인바운드 복제 파트너 상태 | DC·파트너·파티션별 복제 상태를 보여 줍니다. 파트너 상태가 성공이어도 대상 객체를 직접 확인하세요. |

버전 번호가 같다는 사실만으로 수렴을 확정하기 어렵습니다. 서로 다른 DC에서 거의 동시에 변경하면 버전이 같아도 원본 정보가 다를 수 있습니다. AD는 버전, 원본 시각, 호출 ID를 포함한 메타데이터 비교 규칙으로 충돌을 처리합니다. 현재 메타데이터는 저장된 감사 이력과 함께 보세요. 그룹의 `member`처럼 값마다 따로 추적하는 연결 속성은 이 장의 범위 밖입니다. 구성원별 조사는 연결 값 메타데이터와 그룹 변경 기록을 확보하세요.

## 3. 지연, 수집 오류, 승인되지 않은 변경을 구분하세요

먼저 두 관측의 객체 GUID와 속성이 같은지, 두 DC가 해당 파티션을 호스팅하는지, 조회 시각이 충분히 가까운지 확인하세요. 읽기 실패나 권한 거부는 상태가 미확인이라는 뜻입니다. 정상적인 사이트 간 일정, 파트너 연결 문제, 최근 복구 때문에 복제본이 늦어질 수 있습니다. 원본 메타데이터가 같은데 수집값이 다르면 시각을 기록하며 다시 조회하세요. 정규화 차이와 값·메타데이터를 읽는 사이 변경이 있었는지도 살펴봅니다.

위임이 과도한 계정은 맡은 역할의 범위를 넘어 속성을 바꿀 수 있습니다. 승인된 변경과 대상 객체·OU에 적용되는 권한을 확인하고 원본 DC가 기록한 요청 주체를 보존하세요. 5136이 있다면 원본 DC, 상관 ID, 객체 GUID, 속성이 일치하는 기록끼리 묶어 값 교체를 해석합니다. 같은 상관 ID에는 한 요청이 수정한 다른 속성도 포함될 수 있습니다. 기록상의 주체가 자동화·서비스 계정이라면 별도 실행 기록에서 누가 어떤 절차를 시작했는지 확인한 뒤 사람과 연결하세요.

## 4. 승인된 환경에서 수집하고 대조하세요

1. 포리스트, 파티션, 객체 GUID, 속성, 승인된 변경 시간대와 관련 DC를 정하세요. UTC로 시각을 통일하고 어떤 DC에 질의했는지와 성공 여부를 남깁니다.
2. 원본 DC와 해당 파티션을 가진 다른 쓰기 가능 DC에서 값과 메타데이터를 비교하세요. 원본 출력을 보존합니다. 각각 별도의 질의이므로 시각을 남기고 두 질의 사이에 상태가 바뀌었다면 다시 읽으세요.
3. 관련 DC에서 Security 원본을 수집하세요. 5136에는 **디렉터리 서비스 변경 감사(Audit Directory Service Changes)** 성공 감사와 객체 또는 속성 쓰기에 맞는 **SACL**이 필요합니다. 객체 GUID, 속성, 동작, 주체, 상관 ID, DC와 이벤트 시각을 보존하세요. 기록이 없으면 감사 정책, SACL, 보존과 전달 범위를 확인합니다. 복제를 받은 DC에서 원래 쓰기의 감사 기록이 보인다고 가정하지 마세요.
4. 같은 파티션·DC의 복제 파트너 상태를 확인하세요. 오류 내용, 영향받은 사이트, 전송 방식과 마지막 성공 시각을 관측 구간과 대조합니다. 차이가 지속되면 AD 운영자와 원인을 조사하고, 조치 전 증거를 보존한 뒤 같은 조건으로 다시 조회하세요.

ActiveDirectory PowerShell 모듈을 갖춘 승인된 Windows 시스템에서 읽기 권한과 지정한 DC에 연결할 수 있는 조건이라면 다음 쿼리로 민감하지 않은 속성 하나와 메타데이터를 조회할 수 있습니다. 가상의 DC와 GUID를 승인된 실습 환경 값으로 바꾸세요. 현재 값과 메타데이터는 별도 결과입니다. 원본과 로컬 필드의 의미는 아래 공개 명세에서 확인할 수 있습니다.

```powershell
$objectId = [guid]'11111111-2222-4333-8444-555555555555'
foreach ($dc in 'dc-a.ad.example', 'dc-b.ad.example') {
  $obj = Get-ADObject -Identity $objectId -Server $dc -Properties description -ErrorAction Stop
  [pscustomobject]@{
    DC = $dc
    ObservedUtc = [datetime]::UtcNow
    ObjectGUID = $obj.ObjectGUID
    Description = $obj.Description
  }
  Write-Output "Metadata read started UTC: $([datetime]::UtcNow.ToString('o'))"
  Get-ADReplicationAttributeMetadata -Object $obj -Server $dc -Properties description -ErrorAction Stop |
    Format-List *
}
```

조회가 실패하면 오류를 보존하고 객체 범위, 연결과 권한을 점검하세요. 인바운드 파트너 상태는 대상 DC와 해당 파티션을 지정해 `Get-ADReplicationPartnerMetadata`로 읽을 수 있습니다. 명령은 Microsoft 문서로 검토했습니다. 실제 AD DS와 Windows PowerShell은 이 실습에서 실행하지 않았습니다.

## 5. 가상 관측 여덟 쌍으로 오프라인 실습하기

<a href="{{ '/assets/labs/ad-replication-change-evidence.py' | relative_url }}" download="ad-replication-change-evidence.py">Python 스크립트</a>와 <a href="{{ '/assets/labs/ad-replication-change-evidence-cases.json' | relative_url }}" download="ad-replication-change-evidence-cases.json">가상 JSON 자료</a>를 같은 폴더에 저장하고 승인된 작업 공간에서 Python 3으로 실행하세요. 각 쌍은 한 실습 포리스트에 속하며, 각 기록은 복제본, 객체, 속성과 읽기 결과를 담습니다. 스크립트는 관측 범위, 원본 필드와 가상 값 참조를 대조합니다. AD에 질의하거나 실제 충돌 해결을 재현하지 않습니다.

```bash
python3 ad-replication-change-evidence.py ad-replication-change-evidence-cases.json
```

```text
converged: same_update_and_value
pending: version_difference
competing_writes: same_version_different_origin
read_denied: observation_missing
other_object: scope_mismatch
other_attribute: scope_mismatch
same_stamp_different_value: recheck_value_capture
incomplete_stamp: metadata_missing
```

수렴한 두 관측의 로컬 USN은 의도적으로 다릅니다. 버전이 다르다는 결과는 원인을 알려 주지 않습니다. 읽기가 실패한 쪽은 상태 미확인으로 남겨 두세요. 파일을 열 수 없으면 두 파일 이름과 현재 폴더를 확인하세요. 예상 밖 결과는 객체 ID, 속성, 수집 필드와 원본 식별 정보부터 비교하세요. Python 실행은 이 가상 자료에서 검증했습니다.

## 6. 확인 문제와 완료 기준

- **DC B의 로컬 USN이 더 크면 최신인가요?** 로컬 USN은 각각의 순서에서 의미가 있습니다. 같은 객체와 속성의 원본 메타데이터와 실제 값을 확인하세요.
- **두 DC 모두 버전 4면 수렴했나요?** 원본 메타데이터와 값을 비교해야 합니다. 서로 다른 원본 변경의 버전이 같을 수 있습니다.
- **객체가 바뀌었는데 5136이 없습니다. 변경이 없었던 건가요?** 감사 설정, SACL, 쓰기를 처리한 DC와 보존 범위를 확인하세요. 메타데이터는 현재 상태의 근거가 되지만 요청자를 알려 주지는 않습니다.

여덟 줄이 예상과 일치하고 `pending`, `read_denied`, `same_stamp_different_value`에서 다음에 볼 근거를 설명할 수 있으면 완료입니다.

## 공식 참고자료

2026-11-22 검토. 명령 참조는 Windows Server 2025 보기이며, 5136 자료에는 이전 Windows 10 형식의 예제가 포함됩니다. 운영 중인 DC 빌드에서 필드와 수집 범위를 확인하세요.

- 복제 속성 메타데이터와 충돌 비교 규칙. [Microsoft MS-DRSR · AttributeStamp](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/2973bb80-c8ed-450d-a981-59639e09820b) · [Microsoft MS-ADTS · 속성 메타데이터](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/63fabec7-cb4b-47ed-ab45-9a20e4397d55)
- 감사 조건과 상관 ID. [Microsoft Learn · 이벤트 5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)
- 대상 객체와 속성 메타데이터 조회. [Get-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adobject?view=windowsserver2025-ps) · [Get-ADReplicationAttributeMetadata](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationattributemetadata?view=windowsserver2025-ps)
- 복제 파트너와 실패 진단. [Get-ADReplicationPartnerMetadata](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationpartnermetadata?view=windowsserver2025-ps) · [Microsoft Learn · AD 복제 실패 진단](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/diagnose-replication-failures)

[이전 학습 · Active Directory 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}) · [다음 학습 · 그룹 정책 적용 조사]({{ '/ko/wiki/gpo-application-evidence/' | relative_url }})
