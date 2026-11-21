---
title: "Active Directory 계정 잠금 · 로그인 실패 추적하기"
description: "Security 이벤트 4740을 기준으로 Kerberos·NTLM 실패와 잠긴 계정의 거절을 구분하고, 도메인 컨트롤러와 엔드포인트에서 근거를 찾습니다."
category: active-directory
tags: [Active Directory, Windows, Authentication, Kerberos, NTLM, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/ad-account-lockout-evidence/
---

**학습 목표.** Active Directory Domain Services(AD DS) 계정 잠금 경보를 보고 영향을 받은 계정을 찾고, 시스템마다 다른 기록이 남는 이유를 설명합니다. 저장된 이전 암호와 승인되지 않은 인증 시도를 구분하려면 무엇을 더 확인해야 하는지도 판단합니다. 이 장은 사내 AD 도메인 계정을 다룹니다. 클라우드 로그인은 [Entra 로그인 증거]({{ '/ko/wiki/entra-signin-evidence/' | relative_url }})를 참고하세요.

## 1. 계정 잠금으로 무엇을 알 수 있나요?

**도메인 컨트롤러(DC)**는 Windows 도메인의 인증 요청을 처리합니다. **계정 잠금**은 조건을 충족하는 실패가 누적됐을 때 새로운 인증 요청을 일시적으로 막을 수 있는 계정 상태입니다. 일반적인 로그인 실패는 요청 한 건의 결과입니다. 잠긴 계정에 대한 거절은 요청을 확인할 당시 계정이 이미 잠겨 있었다는 뜻입니다. 조사할 때는 상태가 바뀐 시점을 먼저 찾고 전후 요청을 시간순으로 정리하세요.

영향받은 계정에 **사건 당시 적용된 잠금 정책**을 확인하세요. **임계값**은 잠금을 유발하는 유효한 잘못된 암호 시도 횟수입니다. **관찰 기간**은 추가 실패가 없을 때 카운터가 초기화되기까지의 시간입니다. **잠금 시간**은 자동으로 잠금이 풀리기까지의 시간입니다. 임계값이 0이면 이 임계값에 따른 잠금이 비활성화됩니다. 잠금이 활성화된 상태에서 잠금 시간이 0이면 관리자가 직접 해제해야 합니다. 세분화된 암호 정책이 사용자나 그룹에 적용되면 도메인 기본값과 다를 수 있습니다. ActiveDirectory 모듈과 조회 권한이 있다면 해당 사용자의 `Get-ADUserResultantPasswordPolicy` 결과를 확인하고, 기본 정책이 적용되는 경우 `Get-ADDefaultDomainPasswordPolicy`도 확인하세요. 조회한 DC와 수집 시각을 기록합니다. 현재 값과 사건 당시 값은 다를 수 있습니다.

<figure>
  <img src="{{ '/assets/diagrams/ad-account-lockout-ko.svg' | relative_url }}" alt="도메인 계정 조사에서 대상 호스트는 로그인 실패 4625를 남길 수 있습니다. DC에서는 Kerberos 4771 또는 NTLM 4776을 볼 수 있고, 4740은 계정이 잠긴 시점의 기준입니다.">
  <figcaption>4740을 타임라인의 기준으로 삼습니다. 대상 호스트와 DC의 기록은 한 요청의 서로 다른 단계를 보여 줄 수 있습니다. 잠금 이후의 요청에는 잠긴 계정 상태 코드가 남을 수 있습니다.</figcaption>
</figure>

## 2. 어떤 시스템에서 어떤 이벤트가 남나요?

이벤트를 생성한 호스트나 원본을 보존하는 수집 경로에서 Security 이벤트 XML을 확보하세요. 아래 표는 AD DS의 암호 인증을 다룹니다. 이벤트가 없다는 사실을 해석하기 전에 각 원본 시스템의 감사 정책과 로그 보존 상태를 확인해야 합니다.

| Security 이벤트 | 수집 조건과 위치 | 필드와 해석 |
| --- | --- | --- |
| **4740** | 잠금에 관여한 DC에서 Audit User Account Management **성공** 감사. 로컬 계정 기록은 별도로 조사 | 대상 SID로 잠긴 계정 식별. Caller Computer Name은 호스트 단서. 성공은 감사 대상인 잠금 작업을 뜻함. |
| **4771** | DC의 KDC에서 Audit Kerberos Authentication Service **실패** 감사 | 실패 코드 `0x18`은 유효하지 않은 사전 인증이며 암호 불일치가 흔한 원인. Client Address 확인. 해당 계정에 사전 인증이 필요하지 않으면 이 이벤트가 생성되지 않음. |
| **4776** | 도메인 NTLM 자격 증명을 검증하는 DC에서 Audit Credential Validation **실패** 감사. 관련 검증 성공도 조사할 경우 **성공** 감사 확인 | `0xC000006A`는 잘못된 암호, `0xC0000234`는 잠긴 계정. Source Workstation은 이름이며 대상 서버는 기록되지 않음. |
| **4625** | 로그온 시도를 처리한 Windows 호스트에서 적용되는 Audit Logon / Audit Account Lockout **실패** 감사 | Status, SubStatus, Logon Type과 기록된 출발지 필드를 검토. `0xC0000234`는 잠긴 계정. 세부 코드 없이 `0xC000006D`만 있으면 일반 실패로 유지. |

**PDC 에뮬레이터** 역할을 가진 DC부터 찾고, 앞선 인증 기록에 등장하는 DC를 포함해 실제 인증을 처리한 DC에서도 수집하세요. Microsoft 문서는 PDC 에뮬레이터가 계정 잠금을 처리하고 다른 DC에서 발생한 잘못된 암호 실패를 전달받아 확인한다고 설명합니다. 로그 범위와 기록된 필드는 출처마다 다를 수 있습니다. AD의 `badPwdCount`는 DC마다 별도로 유지되며 복제되지 않습니다. 사건 뒤에 읽은 값이나 여러 DC의 값을 합친 수치로 잠금을 일으킨 시도 횟수를 재구성할 수 없습니다.

**이벤트 ID와 함께 XML을 읽으세요.** Microsoft의 4740 버전 0 예시에서는 원본 `TargetDomainName` 값이 화면의 호출자 컴퓨터 이름에 해당합니다. 다른 이벤트에서는 같은 XML 필드가 도메인을 나타낼 수 있습니다. 4740의 대상 SID를 보존하고 디렉터리에서 계정을 확인한 뒤, 호출자 이름은 후속 조사의 단서로 사용하세요. 이벤트의 Subject는 DC의 시스템 컨텍스트일 수 있습니다. 그 값만으로 암호를 보낸 사람이나 프로세스를 확인할 수는 없습니다.

## 3. 평소 업무에서도 생길 수 있는 잠금 사례

가상의 보고서 애플리케이션이 `LAB/svc-reports` 자격 증명을 저장한다고 가정합니다. 담당자가 08:55 UTC에 암호를 바꿨지만 REPORT01의 작업 프로세스는 09:03, 09:06, 09:09에 이전 암호로 다시 시도했습니다. DC02에는 NTLM 자격 증명 검증 실패가 남았고, APP01에도 09:03에 대상 쪽의 로그온 실패가 남았습니다. 09:09:01에 DC01이 해당 계정의 4740을 기록했습니다. 09:10에 APP01은 계정이 잠겼다는 이유로 후속 요청을 거절했습니다. 실행 일정과 암호 변경 기록을 확인하고, 담당자가 해당 프로세스에 설정된 계정을 확인하면 이전 자격 증명이라는 설명이 뒷받침됩니다. 시각과 호스트 단서만으로는 최초 요청 프로세스를 특정하기 어렵습니다.

같은 잠금은 한 계정에 대한 반복적인 암호 추측, 여러 계정에 걸친 유효하지 않은 로그인, 업무 접근을 막으려는 행위에서도 발생할 수 있습니다. 호출자 이름에는 인증을 중계한 시스템이 나타날 수 있습니다. 실제 출발지로 판단하기 전에 엔드포인트, 게이트웨이 또는 애플리케이션 기록과 대조하세요.

| 관측 패턴 | 다음에 찾을 근거 |
| --- | --- |
| 암호 변경 이후 관리되는 한 호스트에서 알려진 계정의 실패가 일정 간격으로 반복 | 예약 작업·서비스의 소유자, 실행 이력, 자격 증명 갱신 시각, 담당자가 수정한 뒤 실패가 멈췄는지 확인 |
| 한 주소 주변에 여러 계정의 실패가 모여 있음 | 게이트웨이·프록시·호스트·인증 로그 대조. 여러 클라이언트가 공유하는 주소인지, 후속 로그인 성공이 있었는지, 어떤 계정이 영향을 받았는지 확인 |
| 4740과 이후의 잠긴 계정 거절은 있지만 앞선 이벤트가 거의 없음 | 다른 DC, 감사 정책, 시계 오차, Security 로그 보존 기간, 전달 필터 확인. 공백이 남으면 기록에 명시 |

## 4. 타임라인을 만들고 대응하기

1. 4740에서 대상 SID, 원본 DC, 공급자, 채널, 원본 이벤트 레코드 ID와 UTC 시각을 기록하세요. SID로 디렉터리 계정을 확인합니다. 앞선 이벤트에 사용자 이름만 있다면 조사 자료를 이용해 도메인과 계정을 구분하세요. 식별이 불확실한 기록은 따로 둡니다.
2. 적용된 정책과 알려진 시계 오차를 기준으로 전후 구간을 검색하세요. Kerberos, NTLM, 대상 호스트의 기록을 구분하고 원본 호스트·채널·레코드 ID·시각으로 완전히 같은 내보내기 사본을 제거합니다. 서로 다른 기록도 요청 한 건을 보여 줄 수 있습니다. 같은 시각의 순서는 추가 근거가 있을 때 확정하세요.
3. 이벤트 패턴을 점검 일정, 암호 변경, 작업 또는 서비스 로그, 사건 시점의 네트워크 주소 매핑과 대조합니다. 관련 감사 하위 범주와 전달 범위를 확인하세요. 순서에는 원본 시각을, 수집 지연을 조사할 때는 도착 시각을 사용합니다.
4. 증거를 보존하고 계정·애플리케이션 담당자와 조율하세요. 승인된 서비스에 이전 자격 증명이 남았다면 설정을 수정하고 실패가 더 이상 반복되지 않는 것을 확인한 뒤 잠금 해제를 조율합니다. 승인되지 않은 접근이 의심되면 사고 대응 절차에 따라 출발지나 계정의 영향을 제한하고, 관련 세션과 로그인 성공도 검토하세요. 특권 계정이나 여러 계정에 영향이 있으면 신속히 상위 대응으로 전환합니다.

아래 읽기 전용 PowerShell 예시는 **실행한 호스트**에서 최근 이벤트의 XML을 표시합니다. 소유하거나 승인받은 Windows 호스트에서 Security 읽기 권한으로 실행하세요. 조회 시간을 사건에 맞게 조정합니다. 중앙 수집을 사용한다면 원본 호스트의 채널과 전달 필터를 확인하세요.

```powershell
$filter = @{
    LogName = 'Security'
    Id = 4740, 4771, 4776, 4625
    StartTime = (Get-Date).AddMinutes(-30)
}
Get-WinEvent -FilterHashtable $filter -MaxEvents 200 |
    ForEach-Object { $_.ToXml() }
```

200개 제한은 XML 미리보기용입니다. 이벤트가 많은 환경에서 전체 근거가 필요하면 시간대를 나눠 조회하거나 승인된 방식으로 내보내세요. 결과가 비어 있으면 접근 오류, 로그 보존 상태와 수집 상태를 점검합니다. 이후 접근 권한 행사나 업무 처리의 성공 여부는 별도의 증거로 확인해야 합니다.

## 5. 가상 기록으로 조사하기

[ad-lockout-review.py]({{ '/assets/labs/ad-lockout-review.py' | relative_url }}){: download="ad-lockout-review.py" }와 [ad-lockout-cases.csv]({{ '/assets/labs/ad-lockout-cases.csv' | relative_url }}){: download="ad-lockout-cases.csv" }를 내려받아 본인 작업 공간의 같은 디렉터리에 둡니다. Python 3.8 이상으로 실행하세요.

```sh
python3 ad-lockout-review.py
```

CSV는 Windows 원본 XML에서 구분할 항목을 설명하기 위해 만든 **가상 요약 자료**입니다. 계정은 미리 `DOMAIN/user` 형식으로 식별했습니다. 코드는 해당 이벤트의 상태 또는 하위 상태에서 조사에 사용할 값을 고른 것이고 `clue`에는 이벤트에 따라 주소나 워크스테이션 단서가 들어갑니다. 프로그램은 중복 사본을 제거하고, 예시로 4740 앞뒤 각각 10분을 고정 범위로 사용합니다. 집계 단위는 원본 이벤트 레코드입니다. 실제 AD 정책에 따른 시간 계산이나 시스템 간 동일 요청 판별은 실습 범위 밖입니다.

| 계정 | 앞선 암호 불일치 / 이후 잠긴 계정 거절 | 조사 판단 |
| --- | --- | --- |
| `LAB/svc-reports` | 4 / 2 | 09:03의 DC와 대상 호스트 이벤트가 한 요청의 기록일 수 있음. 판단 전 보고서 작업 이력 확인. |
| `LAB/ari` | 2 / 1 | 일반 실패, 시간 범위 밖의 기록, 다른 도메인의 계정은 암호 불일치 집계에서 제외. 반복된 주소, 게이트웨이와 인접한 `LAB/lee` 이벤트를 대조. |
| `LAB/mira` | 0 / 1 | 잠금과 뒤이은 거절은 확인됨. 앞선 출발지는 미확인. 다음에 수집할 DC와 시간대를 적어 보세요. |

**고유 레코드 17개와 중복 사본 1개**가 출력된 뒤 세 계정의 결과가 나옵니다. 파일 오류가 있으면 두 이름과 디렉터리를 확인하세요. 집계가 다르면 원본 자료를 다시 내려받아 헤더와 시각을 비교합니다. 오프라인 실습은 Python 3.12.14에서 실행해 확인했습니다. PowerShell과 AD DS 동작은 공식 문서로 검토했고, 실제 Windows 도메인에서의 실행은 검증 범위에 포함되지 않습니다.

## 6. 확인 문제와 해설

1. **4740 성공 이벤트의 Subject가 DC 계정입니다. DC 계정이 그 사용자로 로그인한 것인가요?** Subject는 작업의 컨텍스트를 보여 줍니다. 대상 SID에서 잠긴 계정을 확인하고 실패한 인증의 출발지는 다른 로그에서 찾으세요.
2. **DC의 4776 암호 불일치와 서버의 4625가 같은 시각에 기록됐습니다. 두 번의 시도인가요?** 한 요청이 서로 다른 두 곳에 남았을 수도 있습니다. 호스트 역할을 확인하고, 횟수를 확정할 추가 증거가 생길 때까지 두 레코드로 기록하세요.
3. **잠긴 계정 상태의 4625만 보이면 무엇을 알 수 있나요?** 해당 요청을 처리할 때 계정은 이미 잠겨 있었습니다. 상태가 바뀐 시각은 4740이나 다른 권위 있는 근거로 확인하세요. 원인이나 출발지를 판단하기 전에 DC별 수집 범위와 사건 시간대를 확인하세요.

**완료 기준.** 실습에서 세 계정의 결과를 재현하고, 각 계정마다 관측된 상태, 가장 유력한 설명 또는 남은 증거 공백, 다음에 확인할 출처를 한 문장으로 적어 보세요.

## 공식 참고자료

2026년 11월 22일 검토. Windows Security 이벤트 페이지는 과거 예시를 포함한 스키마 참고자료입니다. Windows Server와 PowerShell 자료는 검토 시점의 정책 조회·수집 인터페이스를 설명합니다. 실제 배포 버전에서 필드 표시와 감사 범위를 확인하세요.

- Microsoft [4740 · 계정 잠금](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740) · [4771 · Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771) · [4776 · NTLM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776) · [4625 · 로그온 실패](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- Microsoft [잠금 임계값](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold) · [잠금 시간](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-duration) · [실패 횟수 초기화 시간](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/reset-account-lockout-counter-after)
- Microsoft [PDC 에뮬레이터 역할](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/fsmo-roles#pdc-emulator-fsmo-role) · [Bad-Pwd-Count 스키마 속성](https://learn.microsoft.com/en-us/windows/win32/adschema/a-badpwdcount)
- Microsoft PowerShell [사용자에게 적용된 정책](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduserresultantpasswordpolicy?view=windowsserver2025-ps) · [도메인 기본 정책](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2025-ps) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.6)

[이전 · AD 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}) · [다음 · Windows 로그 연속성]({{ '/ko/wiki/windows-log-continuity/' | relative_url }})
