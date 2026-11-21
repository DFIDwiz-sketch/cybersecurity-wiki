---
title: "그룹 정책 조사 · AD, SYSVOL, 단말 적용 증거"
description: "도메인 컨트롤러별 정책 버전, 링크와 파일 변경, 단말 적용 결과를 대조합니다."
category: active-directory
tags: [Active Directory, Group Policy, GPO, SYSVOL, Windows Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/gpo-application-evidence/
---

승인된 그룹 정책 변경이 끝났는데 한 PC에 이전 설정이 남아 있습니다. AD에는 어떤 버전이 기록됐나요? PC가 SYSVOL에서 어떤 파일을 받을 수 있었나요? 해당 사용자나 컴퓨터의 정책 처리는 어떻게 끝났나요? 각각 확인하면 복제 지연, 적용 범위, 예상 밖 변경을 구분할 수 있습니다.

## 1. GPO를 구성하는 두 부분과 정책을 읽는 단말

**Active Directory Domain Services**(AD DS)는 디렉터리 서비스입니다. **도메인 컨트롤러**(DC)는 디렉터리 서비스를 제공하고 도메인의 SYSVOL 공유를 제공합니다. **그룹 정책 개체**(GPO)는 컴퓨터나 사용자, 또는 둘 모두에 적용하는 설정 묶음입니다. AD에는 **그룹 정책 컨테이너**(GPC)가 있고 SYSVOL에는 파일로 구성된 **그룹 정책 템플릿**(GPT)이 있습니다. 표시 이름이 중복되거나 바뀔 수 있으므로 도메인과 GPO GUID로 대상을 식별합니다.

**링크**는 GPO를 사이트·도메인·조직 구성 단위(OU)에 연결합니다. 정책 파일을 편집하지 않고도 적용 후보 범위를 바꿀 수 있으며, 링크에는 별도 옵션이 있습니다. 보안 필터와 WMI 필터, 상속, 링크 순서, 루프백도 적용 결과에 영향을 줍니다. 루프백은 사용자의 정책을 선택할 때 로그온한 컴퓨터 위치의 정책을 고려하는 방식입니다. 먼저 사용자 정책인지 컴퓨터 정책인지 정하세요.

| 관점 | 확인할 증거 | 알 수 있는 내용 |
| --- | --- | --- |
| 디렉터리(GPC 및 적용 범위) | GPO GUID, `versionNumber`, `gPCFileSysPath`, GPO·적용 대상 권한, 연결 대상의 `gPLink` | 조회한 DC에서 보인 버전과 범위 |
| 파일(GPT) | 같은 DC의 SYSVOL 경로, `GPT.INI` 버전, 관련 파일의 바이트·해시·ACL | 수집 시점에 그 복제본이 보유한 파일 |
| 단말 처리 | 사용자·컴퓨터 범위의 RSoP, Group Policy Operational 로그, 실제 설정 | 정책이 어떻게 처리됐고 로컬 값은 무엇인지 |
| 변경 감사 | DC Security 5136, 변경 승인 자료, 별도 SYSVOL 파일 증거 | 변경된 디렉터리 속성과 링크·파일 변경을 뒷받침하는 독립 자료 |

**RSoP**는 Resultant Set of Policy, 즉 정책 처리 결과 집합입니다. 사용자나 컴퓨터에 대해 어떤 정책이 적용됐는지 읽을 수 있습니다. 특정 설정의 현재 값은 별도로 확인하세요. GPO 하나에 여러 설정이 포함되며 우선순위와 클라이언트 쪽 확장 기능에 따라 개별 결과가 달라질 수 있습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/gpo-application-evidence-ko.svg' | relative_url }}" alt="GPO GUID로 이름을 지정한 DC의 디렉터리 컨테이너와 SYSVOL 템플릿을 대조합니다. 단말에서 적용 범위, 정책 처리 기록, 실제 설정을 확인합니다.">
  <figcaption>DC마다 두 부분을 비교한 뒤, 단말의 증거로 실제 적용 결과를 확인합니다.</figcaption>
</figure>

## 2. 이름을 지정한 DC에서 두 버전 읽기

디렉터리의 `versionNumber`와 `GPT.INI`의 `Version`은 두 카운터를 하나의 32비트 값에 담습니다. 상위 16비트는 사용자 버전이고 하위 16비트는 컴퓨터 버전입니다. 10진수 `196615`를 65,536으로 나누면 몫 3은 사용자, 나머지 7은 컴퓨터입니다. `196616`은 사용자 3, 컴퓨터 8입니다. 내보내기 도구에 따라 같은 비트가 부호 있는 정수로 나타날 수 있으므로 원래 값을 보존하고 비트 단위로 해석하세요.

먼저 같은 DC에서 두 값을 읽으면서 시각을 기록하고 다른 DC에서 반복합니다. AD 복제와 SYSVOL 복제는 별개입니다. 한 DC에서 두 값이 다를 수 있고, 각 DC에서는 두 값이 같지만 DC 사이에 차이가 날 수도 있습니다. 버전은 카운터이므로 숫자가 같다는 사실만으로 파일 내용 일치, 변경 승인, 단말 적용을 확인할 수 없습니다.

| 관측 | 다음 확인 |
| --- | --- |
| DC A의 AD는 3/8, SYSVOL은 3/7 | 변경 시각과 수집 오류부터 보고 AD와 SYSVOL 복제를 각각 확인합니다. |
| A는 두 값이 3/8, B는 두 값이 3/7 | 두 관측을 보존하고 영향받은 단말의 정책 처리에 관여한 DC를 확인합니다. |
| SYSVOL 값을 읽지 못함 | 실제 읽기·분석 오류를 남깁니다. 서버, 공유, 권한, 파일 이름, 연결 상태를 확인하고 빈 값을 0으로 채우지 않습니다. |
| 둘 다 3/8인데 비교한 같은 파일이 다름 | 상대 경로, 바이트, 시각, 수집 범위, 승인 버전을 대조합니다. 해시는 바이트 대조를 뒷받침하며 수집 출처도 기록합니다. |
| 버전과 비교한 파일이 일치 | 링크 범위와 단말 처리, 문제가 된 실제 설정으로 조사를 이어갑니다. |

## 3. 정상 변경과 예상 밖 변경 따라가기

가상 사례에서는 승인된 컴퓨터 정책 편집으로 컴퓨터 카운터가 7에서 8이 됩니다. 복제가 수렴한 뒤 두 DC 모두 AD와 SYSVOL의 버전을 사용자 3, 컴퓨터 8로 보고합니다. 확인한 관련 파일의 바이트도 같습니다. 단말 보고서의 컴퓨터 범위에는 GPO가 적용됐다고 나옵니다. 별도의 로컬 확인에서도 승인된 설정값이 발견됩니다. 이 증거는 그 시각 해당 단말에 적용됐다는 판단을 뒷받침합니다. 다른 단말은 따로 확인하세요.

OU의 링크를 바꿔도 GPO 자체의 버전과 파일은 그대로일 수 있습니다. 새 링크가 생기면 템플릿 버전 증가 없이 더 많은 단말이 적용 후보가 될 수 있습니다. 실습의 `E01`과 `E02`에서는 같은 OU와 같은 디렉터리 작업의 `gPLink` 값이 제거·추가됩니다. 범위가 넓어졌는지 좁아졌는지 판단하려면 링크 옵션, 필터, 대상, 변경 승인과 단말 결과를 확인합니다.

권한을 과도하게 위임하면 정책 내용이나 적용 범위를 바꿔 여러 시스템에 영향을 줄 수 있습니다. 예상 밖의 링크 확대나 SYSVOL 파일 변경은 승인된 배포와 정상 기준에 비교하세요. 정상 배포, 상속된 권한, 복제 지연에서도 예상과 다른 관측이 나타날 수 있습니다.

## 4. 읽기 전용으로 증거를 수집하고 영향을 확인하기

승인된 Windows 관리 시스템에서 GroupPolicy PowerShell 모듈(RSAT 등), 지정한 DC에 대한 연결, 도메인 정책과 공유의 읽기 권한이 필요합니다. 예시 도메인, DC, GUID를 승인된 범위로 바꾸고 DC별로 반복하며 시각을 남기세요. 첫 명령은 버전과 정책 상태를 표시합니다. 신뢰하는 이름으로 지정한 DC에서 예상 SYSVOL 경로를 따로 읽습니다. 수집한 `gPCFileSysPath`가 예상과 다르면 열기 전에 자산 목록과 대조하세요.

```powershell
$gpo = 'd389ee57-38d4-4c3c-a24b-7797329d53ea'
Get-GPO -Guid $gpo -Domain 'lab.example' -Server 'dc-a.lab.example' |
  Format-List Id, DisplayName, GpoStatus, UserVersion, ComputerVersion
Get-Content -LiteralPath "\\dc-a.lab.example\SYSVOL\lab.example\Policies\{$gpo}\GPT.INI"
```

승인된 영향 단말의 관리자 권한 프롬프트에서 `gpresult /r /scope computer`를 실행하면 컴퓨터 범위의 RSoP를 확인할 수 있습니다. 사용자 정책 문제에선 해당 사용자 세션 또는 승인된 관리 범위에서 사용자 결과를 수집합니다. 사용자와 컴퓨터, 수집 시각, 적용·거부된 GPO와 보고된 사유를 남기세요. 처리 오류를 살피려면 `Microsoft-Windows-GroupPolicy/Operational`에서 `ActivityID`로 단말의 한 번의 정책 처리 이벤트를 묶습니다. 정책을 바꾸거나 새 처리를 요청하기 전에 수집 결과를 보존하세요.

1. **대상과 시각을 정합니다.** 도메인, GPO GUID, 관측별 DC, 사이트 또는 OU, 영향받은 계정과 단말, UTC 구간을 적습니다. 두 부분을 조회하고 관련 정책 파일 또는 승인된 내보내기 자료를 메타데이터와 함께 보존합니다. 같은 상대 경로의 파일을 여러 복제본과 승인 버전에서 비교합니다.
2. **감사 범위를 확인합니다.** DC의 Security 이벤트 5136은 **Audit Directory Service Changes** 성공 감사와 해당 속성 쓰기에 대한 SACL이 필요합니다. SACL은 감사할 작업을 정합니다. 원본 DC, 객체 DN 또는 GUID, 속성, 작업 유형, 상관 ID, 주체와 UTC 시각을 남기세요. Value Deleted와 Value Added가 둘 다 있으면 같은 작업의 값 쌍을 찾습니다. `gPLink`는 연결한 사이트·도메인·OU 객체에 있고 `versionNumber`는 GPC에 있습니다. 필드가 빠지거나 수집기에서 이름이 달라질 수 있으므로 원본 XML도 보존합니다.
3. **자료를 계층별로 대조합니다.** 5136의 상관 ID는 디렉터리 작업을 묶는 데 쓰이고, 단말의 Group Policy `ActivityID`는 별도의 정책 처리 단위를 식별합니다. SYSVOL 파일 변경은 파일 감사나 단말 기록 등 별도로 수집한 자료에서 확인하세요. GPO GUID, 범위, 시간으로 DC·단말 자료를 대조하고 승인 내역, 최초 변경 DC의 근거, 위임 권한, 승인된 설정을 함께 확인합니다. 감사 공백과 불확실한 주체는 기록에 남깁니다.
4. **확인한 영향에 맞춰 대응합니다.** 전달 문제라면 AD 관리자와 두 복제 경로 및 단말 처리 조건을 확인합니다. 승인되지 않은 범위나 내용 변경이 확인되면 관련 로그와 정상 정책을 보존하고, 피해 범위 제한과 승인된 롤백을 조율합니다. 복구 뒤에는 여러 DC와 대표 단말에서 결과를 다시 확인합니다.

## 5. 오프라인 실습 · 열 가지 확인

[가상 기록표]({{ '/assets/labs/gpo-evidence-cases.json' | relative_url }})와 [Python 확인 스크립트]({{ '/assets/labs/gpo-evidence-review.py' | relative_url }})를 같은 폴더에 저장하세요. JSON에서 정책 내용과 감사 값은 실습용 글자입니다. 실제 GUID·해시·이벤트 XML을 제공하는 자료는 아닙니다. 사례별로 한 가지 주된 질문을 다룹니다. Python 3만 사용하며 AD에 연결하지 않습니다.

1. 196615와 196616을 사용자·컴퓨터 버전으로 나눕니다. DC마다 AD와 SYSVOL을 먼저 비교하고 DC 간 결과도 비교합니다.
2. DC, 디렉터리 상관 ID, 객체, 속성을 대조해 `E01`에 해당하는 Added 행을 찾습니다. `E03`과 `E04`를 제외하고, 단말 적용에 대해 아직 알 수 없는 점을 적습니다.
3. 아래 명령을 실행합니다. 마지막 줄은 `10 synthetic checks passed.`입니다.

```bash
python3 gpo-evidence-review.py
```

| 사례 | 기대 결과 |
| --- | --- |
| `G01` | 복제본이 일치하고 단말 적용도 관측했습니다. |
| `G02` / `G03` | 한 DC 내부의 불일치 / 각 내부는 일치하나 DC 간 차이입니다. |
| `G04` / `G05` | SYSVOL 미관측 / 버전 일치와 비교한 파일 내용 차이입니다. |
| `G06` / `G07` / `G08` | 버전이 같은 상태의 링크 변경 / 단말에서 보안 필터에 걸림 / 단말 결과 미관측입니다. |
| `E01`과 버전 확인 | `E02`만 짝이 됩니다. 음수로 표현한 예시는 사용자 32768, 컴퓨터 1입니다. |

기록표를 열지 못하면 두 파일 이름과 폴더를 확인하세요. `G04`가 버전 0과의 불일치로 보인다면 누락 값 처리 방식을 확인합니다. 감사 행이 여러 개 나왔다면 상관 ID 외에도 속성과 DC를 비교하세요. 실제 조사에서는 중복되거나 모호하거나 한쪽만 남은 값도 보존합니다.

**검증 범위.** Python으로 가상 검사 열 가지를 실행했습니다. Windows와 AD 수집 명령은 Microsoft 공식 문서에서 확인했습니다. 실제 DC 복제나 GPO 편집, 단말의 정책 처리는 이 실습에서 실행하지 않았습니다.

## 6. 확인 문제와 해설

1. **두 DC에서 컴퓨터 버전이 다르지만 각 DC의 AD와 SYSVOL은 일치합니다. 다음 자료는 무엇인가요?** 영향을 받은 단말의 정책 처리에 관여한 DC와 처리 시각, 복제 자료를 확인합니다. 현재 관측은 DC 간 차이를 뒷받침합니다.
2. **버전이 같아도 OU 링크 변경으로 적용 범위가 달라질 수 있나요?** 링크는 범위를 지정하는 디렉터리 객체에 있습니다. 범위와 단말의 처리 결과를 별도로 검증합니다.
3. **5136의 삭제·추가 값이 짝을 이루면 SYSVOL 파일 변경도 확인됐나요?** 그 짝은 디렉터리 속성 변경을 뒷받침합니다. 파일 변경은 SYSVOL과 독립적인 증거로 확인합니다.
4. **GPO가 적용으로 표시되지만 한 설정이 다릅니다. 어디를 확인하나요?** 해당 설정, 우선하는 정책, 관련 클라이언트 쪽 확장 기능, 현재 설정을 확인합니다. GPO 하나에 여러 설정이 들어 있습니다.

**완료 기준.** 버전에서 카운터 두 개를 읽고, 가상 사례 여덟 건과 감사 행의 올바른 짝을 설명합니다. 디렉터리와 파일에서 확인한 사실, 단말 결과, 아직 모르는 원인을 구분해 짧은 조사 메모를 작성하세요.

## 7. 공식 참고 자료와 다음 학습

**2026-11-21**에 검토했습니다. 구조와 처리 안내는 문서에 명시된 Windows Server **2016~2025**를 대상으로 합니다. PowerShell은 Windows Server 2025 문서 보기이며, 이전 보안 감사 문서는 5136의 필드와 감사 전제조건을 설명합니다. 운영 중인 Windows 빌드에서 수집을 확인하세요.

- 구성, 처리 순서, 조회와 문제 해결. [그룹 정책 개요](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview) · [그룹 정책 처리](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing) · [문제 해결과 ActivityID](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/applying-group-policy-troubleshooting-guidance)
- 두 버전의 구조와 명령. [MS-GPOL GPO Search](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/b0e5c9e8-e858-4a7a-a94a-4a3d0a9d87a2) · [MS-GPOL 버전 필드](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/59bb540a-64f4-4c52-9c55-5ca2fd2c0270) · [Get-GPO](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpo?view=windowsserver2025-ps) · [gpresult](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult)
- 디렉터리 감사 범위와 속성 값. [Audit Directory Service Changes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-directory-service-changes) · [이벤트 5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)

이전 학습 · [Active Directory 입문]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }})  
다음 학습 · [AD 그룹 구성원 변경 조사]({{ '/ko/wiki/ad-group-membership-evidence/' | relative_url }})
