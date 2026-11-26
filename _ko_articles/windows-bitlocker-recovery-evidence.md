---
title: "BitLocker 복구 조사 · 조회, 잠금 해제, 교체를 구분하기"
description: "Entra 복구 정보 조회를 Windows의 복구 증거와 대조하고 새 보호기가 백업됐는지 확인합니다."
category: blue-team
tags: [BitLocker, Windows, Microsoft Entra, Incident Response, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/windows-bitlocker-recovery-evidence/
---

지원팀이 노트북의 BitLocker 복구 기록을 열었고 Entra에는 조회가 남았습니다. 이후 사용자는 노트북이 켜졌다고 보고했습니다. 조사자는 세 질문을 각각 확인합니다. 복구 암호가 공개됐나요? 해당 볼륨에서 실제로 사용됐나요? 복구에 쓰는 보호기를 교체했고 새 정보까지 백업했나요?

## 1. 볼륨, 키 보호기와 기록 식별하기

**BitLocker**는 Windows 볼륨을 암호화합니다. **키 보호기(key protector)**는 BitLocker의 볼륨 마스터 키에 접근하는 방식을 제어합니다. 숫자로 된 **복구 암호**는 48자리 비밀값입니다. 복구 화면의 **복구 키 ID**는 해당 기록을 찾는 식별자이며 ID만으로 볼륨을 잠금 해제할 수 없습니다. Microsoft 화면은 기록과 비밀값을 모두 ‘복구 키’라고 부르는 경우가 있으므로 각 필드가 무엇을 뜻하는지 기록합니다.

관리 기기는 설정에 따라 복구 정보를 Microsoft Entra ID에 백업할 수 있습니다. 다른 환경은 Active Directory Domain Services 또는 별도 승인된 백업 방식을 사용합니다. 정보를 실제로 보관하는 곳을 확인하세요. 기기 표시 이름은 재사용될 수 있고, 기기를 재등록하면 디렉터리 객체가 달라질 수 있습니다. 테넌트, 안정적인 기기 식별자, 볼륨과 보호기 ID가 연결되는지 확인합니다. 화면에 일부 ID만 보인다면 후보를 좁히는 데 쓰고 대상을 추가로 확인합니다.

| 원본 또는 조치 | 무엇을 뒷받침하나요? | 추가 확인 |
| --- | --- | --- |
| 복구 기록 메타데이터 | 조회한 저장소에 해당 ID의 기록이 있음 | 비밀값 열람 여부와 보호기 활성 상태 |
| 해당 기록의 Entra `Read BitLocker key` 성공 | 복구 키 조회 성공이 기록됨 | 승인된 조회였는지와 엔드포인트 결과 |
| 일치하는 엔드포인트 복구 증거 | 관측한 볼륨이 기록된 방식으로 복구됨 | 이전 보호기 잔존 여부와 새 정보 백업 |
| 교체 작업 접수 | 관리 시스템이 작업을 수락함 | 기기 실행, 활성 교체 ID, 백업 확인 |
| 이전 보호기 없음, 새 보호기 활성, 새 백업 일치 | 확인한 기기와 백업 저장소의 교체 정보가 일치함 | 다른 영향받은 볼륨과 계정, 남은 위험 |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-bitlocker-recovery-evidence-ko.svg' | relative_url }}" alt="기기, 볼륨, 보호기 식별자를 먼저 연결합니다. 백업 저장소에서 조회, 엔드포인트에서 복구, 교체와 백업을 각각 확인합니다." style="max-width: 100%; height: auto;">
  <figcaption>그림 1. 조회, 복구, 교체 확인에는 각각 별도의 근거가 필요합니다.</figcaption>
</figure>

## 2. 정상 복구 따라가기

가상 조직의 `LAB-WIN-01`이 UTC 08:00에 계획된 하드웨어 정비 후 복구 화면을 표시합니다. 지원팀은 사용자, 작업 요청, 기기 ID와 복구 식별자를 확인합니다. 08:04에 Entra가 해당 복구 기록의 승인된 조회 성공을 남깁니다. 08:07에는 예상한 볼륨이 그 보호기로 복구됐다는 근거가 엔드포인트에서 확인됩니다. Windows가 시작했다는 기록만 있다면 ‘부팅 확인’으로 적고 어떤 보호기를 썼는지는 미확인으로 둡니다.

승인된 교체 후 기기에서 새 보호기가 활성화됐고 이전 보호기가 해당 볼륨에 없음을 확인합니다. 테넌트에도 같은 새 ID의 기록이 백업되어 있습니다. 교체 작업이 대기 중이거나, 새 기록은 생겼는데 이전 보호기가 남아 있다면 교체 완료 근거가 부족합니다. 승인된 조사 기록에는 새·이전 **식별자**를 남기세요. 복구 암호, 복구 파일, 비밀값이 담긴 응답 원문과 화면 캡처는 첨부하지 않습니다.

## 3. 정상 지원과 오용 가능성 구분하기

승인되지 않은 사람이 복구 암호를 얻고 암호화된 기기나 볼륨에도 접근할 수 있다면 그 암호로 복구할 수 있습니다. 지원 기록 없이 조회가 성공했다면 확인이 필요합니다. 이용자의 셀프서비스, 문서화된 지원 조치, 승인된 복구 시험도 비슷한 흔적을 남깁니다. 실행 주체, 역할, 티켓, 기기 범위와 시간을 대조합니다. 복구가 오프라인에서 또는 로그 보존 범위 밖에서 일어날 수 있으므로 Windows 기록이 없더라도 조회 기록은 조사 근거가 됩니다. 조회만으로 볼륨 잠금 해제나 파일 접근을 확정할 수는 없습니다.

Microsoft Graph v1.0에서 BitLocker 복구 객체를 기본 조회할 때 비밀 속성은 응답에 포함되지 않습니다. 실제 비밀값을 요청하는 조회에는 Entra 감사가 적용됩니다. 활동 목록에는 `KeyManagement` 범주의 `Read BitLocker key`가 있습니다. 비밀 조회 성공, 조회 실패, 메타데이터 관측, 감사 자료 미수집을 각각 구분하세요. 일반 인벤토리 확인만으로 노출을 추론하거나 온프레미스에만 백업하는 경로에서 이 Entra 활동을 기대하면 안 됩니다.

## 4. 블루팀 수집·탐지·대응

1. **관리 작업 근거를 수집합니다.** 감사 로그 조회 권한이 있는 승인된 테넌트에서 `KeyManagement` 및 `Read BitLocker key`로 필터링합니다. UTC 시각, 실행 주체, 대상 객체나 식별자, 결과, 제공된 연계 정보를 보존합니다. 이름 대신 기기 인벤토리로 ID를 매핑하고, 기록이 없다고 해석하기 전에 감사 로그의 보존·내보내기 범위를 확인합니다. 당시 계정 로그인과 권한을 작업 요청과 비교합니다. 무관한 여러 기기를 반복 조회하거나 지원 시간 밖에 조회한 경우는 조사 단서입니다.
2. **엔드포인트 근거는 따로 수집합니다.** BitLocker PowerShell 모듈과 조회 권한이 있는 승인된 Windows 기기에서 아래 명령은 볼륨과 보호 상태만 선택합니다. 이는 현재 상태입니다. 과거를 확인하려면 보존된 BitLocker-API Management·Operational 로그, 부팅·TPM 기록, 승인된 복구 메모를 조회합니다. 기기, 볼륨, 시간과 기록에 실제로 있는 보호기 식별자를 대조합니다. 복구 중 로컬 증거에 접근할 수 없다면 제한을 기록합니다.

~~~powershell
Get-BitLockerVolume |
  Select-Object MountPoint, VolumeStatus, ProtectionStatus
~~~

3. **교체를 검증합니다.** Intune 원격 교체에는 지원되는 Windows 버전, 관리 정책 등 사전 요건이 있습니다. 작업 접수는 관리 계층의 관측입니다. 기기의 보호기 인벤토리와 볼륨 상태, 이전 보호기가 없는지, 백업 저장소의 새 메타데이터가 일치하는지 확인합니다. 기기 담당자와 조치 시점을 조율하고 기록된 복구 경로를 사용할 수 있는 상태를 유지합니다.
4. **확인한 근거에 따라 대응합니다.** 노출이 확인되거나 의심되면 증거를 보존하고 사고 대응 계획에 따라 보호기 교체 및 계정·기기 조치를 조율합니다. 실제 복구가 있었다면 데이터에 접근했는지는 엔드포인트나 관련 리소스 기록에서 따로 확인합니다. 관측하지 못한 항목은 미확인으로 남깁니다.

## 5. 승인된 오프라인 실습

<a href="{{ '/assets/labs/windows-bitlocker-recovery-evidence.py' | relative_url }}" download>Python 검사기</a>와 <a href="{{ '/assets/labs/windows-bitlocker-recovery-evidence.json' | relative_url }}" download>가상 사례</a>를 한 폴더에 보관하고, 소유하거나 승인받은 환경에서 Python 3으로 실행합니다. 실습 파일에는 가상 기기·보호기 식별자와 관측 결과만 있습니다. 비밀값을 포함하지 않으며 검사기는 테넌트나 기기에 연결하지 않습니다.

~~~bash
python3 windows-bitlocker-recovery-evidence.py
~~~

| 사례 | 기대 관측 |
| --- | --- |
| A–C | 승인된 조회와 복구 일치, 메타데이터만 확인, 조회 실패 |
| D–F | 조회 성공 후 복구 미확인, 기기 ID 불일치, 교체 접수 후 확인 없음 |
| G–J | 교체 검증, 잘못된 백업 ID, 이전 보호기 잔존, 백업 근거 없음 |

`10/10 cases matched.`가 나와야 합니다. 대조 실험은 JSON 사본에서 G의 `rotation.backup_id`를 `new-lab-id`에서 `unrelated-id`로 바꾸고 기대값을 유지한 뒤 사본을 검사기 인자로 전달합니다. G의 교체 결과에 `backup-id-mismatch`가 나오고 종료 코드가 1이어야 합니다. 실행이 예상과 다르면 두 파일이 있는지와 JSON 형식을 확인하세요. 오프라인 실습을 직접 실행했습니다. Windows, Intune, Entra의 제품 동작은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

1. **Entra에 기록이 보이면 관리자가 암호를 읽은 건가요?** 인벤토리는 기록의 존재를 보여 줍니다. 관련 감사 원본에서 활동과 결과를 확인합니다.
2. **조회가 성공하면 누군가 디스크 잠금을 해제한 건가요?** 엔드포인트나 신뢰할 수 있는 지원 근거에서 대상 볼륨과 복구 방식을 확인합니다.
3. **교체가 접수됐으면 사고를 종결해도 될까요?** 새 보호기 활성, 이전 보호기의 해당 볼륨 내 부재, 같은 새 백업을 모두 확인합니다.
4. **이름이 같은 기기가 두 대면요?** 테넌트의 안정적인 기기 식별자와 볼륨, 복구 식별자로 구분합니다. 이름은 검색 단서입니다.

**완료 기준.** 열 건과 대조 실험을 재현합니다. 한 지원 건의 타임라인을 조회, 사용, 교체로 나누고 아직 확인하지 못한 사실을 설명합니다. 이어서 [Entra 로그인 증거]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }})와 [Key Vault 조회 증거]({{ '/ko/wiki/azure-key-vault-read-evidence/' | relative_url }})를 읽어 보세요.

## 공식 참고자료

검토일 2026-11-27. 관리되는 Windows의 BitLocker 복구, Microsoft Graph v1.0, Entra 감사 및 현재 Intune 문서를 확인했습니다. 적용 환경의 Windows 버전, 가입 상태, 백업 서비스와 관리 정책을 함께 확인하세요.

- [Microsoft · BitLocker 복구 개요](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview)
- [Microsoft Graph v1.0 · BitLocker 복구 객체](https://learn.microsoft.com/en-us/graph/api/resources/bitlockerrecoverykey?view=graph-rest-1.0), [조회 동작](https://learn.microsoft.com/en-us/graph/api/bitlockerrecoverykey-get?view=graph-rest-1.0)
- [Microsoft Entra · 감사 활동 목록](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities), [Intune BitLocker 관리 및 교체](https://learn.microsoft.com/en-us/intune/intune-service/protect/encrypt-devices)
- [Windows · BitLocker 문제 해결](https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/bitlocker-issues-troubleshooting), [Get-BitLockerVolume](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume)
