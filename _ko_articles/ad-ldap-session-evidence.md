---
title: "AD LDAP 서명과 채널 바인딩 · 증거로 연결 거부 조사하기"
description: "LDAP 무결성, TLS, 채널 바인딩을 구분하고 Directory Service 감사 이벤트와 실제 bind 결과를 대조합니다."
category: active-directory
tags: [Active Directory, LDAP, Channel Binding, Windows Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /wiki/ad-ldap-session-evidence/
---

**학습 목표.** 서비스가 LDAP 인증 오류를 보고하고 여러 도메인 컨트롤러에는 채널 바인딩 경고가 남았습니다. 해당 연결에 적용되는 보호를 확인하고, 어떤 클라이언트가 어느 컨트롤러에 접속했는지 대조해 로그에서 어디까지 판단할 수 있는지 알아봅니다.

## 1. 보호 방식마다 답하는 질문이 다릅니다

**LDAP**는 디렉터리 항목에 접근하는 프로토콜입니다. Active Directory **도메인 컨트롤러**(DC)는 디렉터리 서비스를 제공합니다. **bind**는 LDAP 연결의 인증 상태를 설정합니다. 이름과 비밀번호를 쓰는 **단순 bind**는 자격 증명의 보호를 전송 계층에 맡깁니다. **SASL**은 LDAP에서 Kerberos나 Negotiate 등의 인증 메커니즘을 사용할 수 있게 하고, 메커니즘에 따라 메시지 보호도 협상할 수 있습니다. bind가 성공하면 이후 작업에 쓸 신원이 정해집니다. 개별 검색이나 수정의 권한은 별도로 판단합니다.

| 보호 방식 | 보호 범위 | 확인할 것 |
| --- | --- | --- |
| SASL 서명 | 협상 이후 LDAP 메시지의 무결성 | 인증 방식과 실제 협상 결과. 서명만으로는 내용을 숨길 수 없습니다. |
| SASL 봉인(sealing) | 협상한 보안 계층의 기밀성과 무결성 | 라이브러리와 메커니즘이 실제로 봉인을 협상했는지 확인합니다. TLS로도 전송을 보호할 수 있습니다. |
| TLS | 전송 중 기밀성과 무결성. 인증서 검증으로 서버 신원을 신뢰할 근거를 얻습니다. | TLS가 성립했는지, 클라이언트가 예상 이름과 인증서 체인을 검증했는지 확인합니다. |
| 채널 바인딩 토큰(CBT) | 지원되는 TLS 위 SASL 인증을 해당 TLS 채널에 연결 | CBT가 적용되는지, DC의 유효 정책이 무엇을 요구했는지, 검증에 성공했는지 확인합니다. |

**LDAPS**는 TLS부터 시작하며 LDAP에는 보통 TCP 636을 사용합니다. **StartTLS**는 일반적으로 TCP 389에서 시작한 LDAP 연결을 TLS로 전환한 뒤 보호해야 할 자격 증명이나 질의를 보냅니다. 포트는 확인의 출발점입니다. 실제 전송 방식과 StartTLS가 실패했을 때 클라이언트가 중단하는지를 확인하세요. 올바르게 검증한 TLS의 단순 bind는 TLS 보호로 AD 서버의 서명 요구를 충족할 수 있습니다. 이 방식에는 CBT가 적용되지 않습니다. TLS 핸드셰이크만 보고 이후 bind 방식이나 CBT 결과를 알 수는 없습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ad-ldap-session-evidence-ko.svg' | relative_url }}" alt="클라이언트가 도메인 컨트롤러에 LDAP 또는 TLS로 연결한 뒤 단순 bind 또는 SASL bind를 수행합니다. TLS는 전송을 보호하며 CBT는 해당되는 TLS 위 SASL 인증에 적용됩니다. bind가 성공한 뒤 디렉터리 작업의 권한을 확인합니다." width="480" height="384">
  <figcaption>전송 방식, bind 방식, 판정은 서로 다른 관측입니다. 인증 이후에는 작업 권한을 확인합니다.</figcaption>
</figure>

## 2. 정상 bind 한 건 따라가기

가상의 배포에서 `report-reader`가 이름으로 `dc-a`에 연결합니다. 클라이언트는 인증서를 검증하고 TLS를 맺습니다. SASL 메커니즘이 유효한 CBT를 제공했고, 클라이언트 진단과 DC 기록에서 별도로 수락을 확인합니다. 이후 검색은 인증된 서비스 계정과 디렉터리 권한으로 실행됩니다. 다른 앱은 검증된 TLS 위에서 단순 bind를 사용하고 이 bind도 성공합니다. 단순 bind에는 CBT가 없으므로 운영자는 두 성공을 서로 다른 방식으로 기록합니다.

클라이언트가 DC의 인증서를 신뢰하지 못하면 bind 전에 TLS에서 실패할 수 있습니다. TLS는 성립했지만 같은 연결에 대응하는 CBT 검증 실패가 DC에 남았다면 SASL 호환성, 적용 정책과 TLS가 끝나는 지점을 확인합니다. bind가 성공한 뒤 검색이 거부됐으면 요청 작업, 인증된 신원, 디렉터리의 유효 권한과 검색 범위를 살펴보세요.

## 3. 오용 원리와 배포 기본값

보호 없는 단순 bind는 트래픽을 관측할 수 있는 사람에게 비밀번호를 노출할 수 있습니다. 서명이 없는 인증과 메시지는 방식과 적용된 보호에 따라 가로채기, 변조 또는 인증 릴레이의 영향을 받을 수 있습니다. 릴레이는 한 연결에 쓰려던 인증을 다른 곳으로 전달하는 방식입니다. 서명은 별도 보호가 없는 SASL 연결에서 무결성 협상을 요구합니다. CBT는 해당되는 TLS 위 SASL 인증과 실제 채널이 맞지 않는 경우를 확인하는 데 도움이 됩니다. 일반적인 클라이언트 또는 TLS 설정 문제도 CBT 실패를 일으킵니다. 이벤트만으로 의도나 접속 주체를 특정할 수 없습니다.

Microsoft는 **Windows Server 2025 이후에 새로 배포한 AD**에서 기본적으로 서명을 강제한다고 안내합니다. 서명 강제 GPO가 활성화되면 서명 수준 정책보다 우선합니다. 업그레이드는 기존 서명 정책을 보존하며, Server 2025에서 서버 쪽 서명 정책이 없는 경우 더 엄격한 기본값이 적용된다고 설명합니다. Windows Server 2025 신규 배포의 CBT 기본값은 **When supported**입니다. 이 모드에서는 CBT가 적용되는 클라이언트 중 CBT를 지원하는 쪽이 토큰을 제공해야 하며, 지원하지 않는 쪽은 수락될 수 있습니다. **Always**는 적용 대상에 유효한 토큰을 요구하고 **Never**는 검증을 끕니다. 서버 버전만 보고 개별 결과를 추정하지 말고 DC의 유효 정책과 설치 업데이트를 확인하세요. 2020~2024년 업데이트 기록에는 감사 이벤트가 추가되고 활성화 방식이 달라진 과정이 나옵니다. 그 기록을 전 환경에 한꺼번에 정책이 강제됐다는 뜻으로 읽어서는 안 됩니다.

## 4. Directory Service 기록 수집과 해석

관련 DC마다 **Directory Service** 로그를 확인합니다. 공급자 `Microsoft-Windows-ActiveDirectory_DomainService`, 이벤트 XML, 컴퓨터, 시각, 로컬 레코드 ID를 대조합니다. 전달받은 자료에는 원래 채널과 컴퓨터를 남기세요. 진단 설정과 빌드에 따라 수집 범위가 다릅니다. Microsoft는 2889, 3039, 3074, 3075 같은 클라이언트 상세 이벤트에 **16 LDAP Interface Events** 진단 수준 **2(Basic)**를 안내합니다. 승인된 진단 변경의 기간과 범위를 정하고, DC 시계, 보존 기간, 구독 필터와 관련 DC 전부에서 자료를 받았는지 확인하세요.

| 이벤트 | 확인할 수 있는 것 | 결론의 범위 |
| --- | --- | --- |
| 2886 | 느슨한 서명 설정에 대한 알림 | 설정에 대한 신호입니다. 개별 bind 판정은 별도 기록이 필요합니다. |
| 2887 / 2888 | 보호 없이 허용된 bind / 거부된 bind의 24시간 집계 | 사이트나 DC의 추세입니다. 집계에는 해당 프로세스나 연결을 특정할 근거가 없습니다. |
| 2889 | 서명 없는 SASL 또는 평문 단순 bind의 클라이언트 상세 정보. 진단 수준 2 적용 | Binding Type 0은 서명 없는 SASL, 1은 단순 bind입니다. 허용·거부 여부는 유효 정책과 클라이언트 결과를 대조합니다. |
| 3039 | 적용되는 정책에서 TLS 위 LDAP 채널 바인딩 검증 실패 | 동일 클라이언트와 DC의 증거를 연결한 뒤 bind 결과를 확인합니다. When supported 또는 Always와 상세 진단이 필요합니다. |
| 3040 / 3041 | CBT가 Never일 때 완료된 미보호 TLS bind의 24시간 집계 / 설정 알림 | 기준선과 정책 검토에 사용합니다. 특정 연결의 판정은 별도로 확인합니다. |
| 3074 / 3075 | 유효하지 않은 CBT / 누락된 채널 바인딩 정보의 호환성 감사 | 강제 시 동작에 관한 관측입니다. 실제 bind 결과는 별도 자료가 필요합니다. 정책, 진단 수준, 업데이트에 따라 수집 여부가 달라집니다. |

Microsoft는 3074와 3075에 대해 Windows Server 2022의 2023년 8월 업데이트, Windows Server 2019의 2023년 10월 업데이트부터의 동작과 후속 활성화 변경을 명시합니다. `When supported` 또는 `Always` 유효 정책, 진단 수준, 설치 빌드를 확인하세요. 이벤트가 없으면 수집 범위나 설정 문제도 고려합니다.

승인된 DC에서 Windows PowerShell과 로그 읽기 권한이 있을 때 아래 조회로 후보를 제한할 수 있습니다. 메시지나 필드가 없으면 개별 이벤트의 `ToXml()`을 확인하세요. 명령은 Microsoft 문서를 기준으로 검토했습니다.

```powershell
$filter = @{
  LogName = 'Directory Service'
  ProviderName = 'Microsoft-Windows-ActiveDirectory_DomainService'
  Id = 2886,2887,2888,2889,3039,3040,3041,3074,3075
  StartTime = (Get-Date).AddHours(-24)
}
Get-WinEvent -FilterHashtable $filter |
  Select-Object TimeCreated, MachineName, Id, RecordId, Message
```

1. **같은 연결의 증거를 맞춥니다.** UTC, 선택된 DC, 확보 가능한 출발지 주소와 포트, 클라이언트 프로세스나 서비스 담당자, bind 방식과 관측 결과를 기록합니다. 프록시, NAT, 연결이 많은 클라이언트에서는 시각과 IP만으로 다른 연결이 섞일 수 있습니다. TLS가 실제로 끝난 지점을 확인합니다. 암호화된 구간에서 bind 결과는 보통 앱과 DC 진단으로 확인합니다.
2. **어느 보호에서 실패했는지 좁힙니다.** RFC 4511의 코드 8(`strongerAuthRequired`)은 더 강한 인증이 필요하다는 결과입니다. 보호되지 않은 bind와 이를 뒷받침하는 DC 기록이 있으면 서명 정책 문제로 좁힐 수 있습니다. 코드 8이나 일반적인 인증 실패만으로는 단계와 원인을 구분하기 어렵습니다.
3. **대응 범위를 정하고 효과를 검증합니다.** 영향받는 클라이언트와 담당자를 파악하고 기준선과 변경 사항, DC별 정책 차이를 대조하세요. 승인된 시험용 디렉터리에서 규정을 충족하는 클라이언트와 호환성 대조군을 확인합니다. 라이브러리나 설정을 승인받아 바꾼 뒤 대표 앱, 예상된 거부와 후속 디렉터리 작업을 각각 확인하세요. 오용이 의심되면 필요한 최소 증거를 보존하고 디렉터리 감사와 서비스 기록으로 후속 작업을 조사합니다. 일반 보고서에는 원문 비밀번호와 민감한 패킷 본문을 남기지 않습니다.

## 5. 오프라인 증거 실습

<a href="{{ '/assets/labs/ad-ldap-session-evidence.py' | relative_url }}" download>Python 3 판정 도구</a>와 <a href="{{ '/assets/labs/ad-ldap-session-evidence-cases.json' | relative_url }}" download>가상 기록</a>을 같은 폴더에 내려받으세요. 이 도구는 로컬 JSON만 읽으며 DC와 자격 증명이 필요하지 않습니다. 연결 ID는 가상의 수집기가 연결을 대조한 뒤 붙인 값입니다. 실제 DC 이벤트에 이 필드가 있다고 가정하지 마세요. 5초 창은 실습에만 적용합니다.

```sh
python3 ad-ldap-session-evidence.py
```

| 사례 | 구분할 결과 |
| --- | --- |
| A, B, M | 평문 단순 bind 수락, TLS 없이 서명한 SASL, 서명 없는 SASL 수락 |
| C, D, L | TLS 위 단순 bind, CBT 검증이 명시된 TLS, CBT 결과를 모르는 TLS 위 SASL 수락 |
| E, I | 독립적으로 확인한 연결 결과와 이벤트가 각각 CBT·서명 정책 거부를 뒷받침 |
| F, G | 감사와 별도로 수락을 확인한 경우, 감사만 있어 결과가 미확정인 경우 |
| H, J, K | bind 전 TLS 실패, 집계만 관측, bind 거부는 확인했지만 일치하는 3039 없음 |

원본은 `13/13 LDAP evidence cases matched.`를 출력합니다. 음성 대조로 복사한 JSON의 E 사례에서 이벤트의 DC를 `dc-a`에서 `dc-b`로 바꾸고 그 파일을 명령 인수로 넘기세요. E는 `bind-rejected-cause-open`으로 바뀌고, 일치 건수 12건과 종료 코드 1을 기대할 수 있습니다. 열기 오류가 나면 두 파일의 이름과 JSON 문법을 확인하세요. 변경 뒤에도 E가 일치하면 바꾼 DC 필드와 명령에 넘긴 파일을 확인합니다. 클라우드 Python에서 원본과 수정본을 실행했습니다. Windows 정책, 조회 명령과 이벤트 ID는 공식 문서 검토 범위입니다.

## 6. 확인 문제와 해설

1. **포트 389가 보이면 평문인가요?** StartTLS가 성립했는지, SASL이 보안 계층을 협상했는지 확인하세요.
2. **같은 연결의 3075를 찾으면 무엇을 알 수 있나요?** CBT 호환성 감사 기록을 확보한 것입니다. 실제 bind 결과는 클라이언트나 DC의 별도 증거로 확인합니다.
3. **TLS 위 단순 bind에 CBT가 있어야 하나요?** 이 방식에는 CBT가 적용되지 않습니다. TLS와 인증서 검증 여부는 확인하세요.
4. **2888로 실패한 클라이언트를 특정할 수 있나요?** 집계는 거부 횟수를 알려 줍니다. 개별 연결을 찾으려면 클라이언트 상세 기록과 독립적인 연결 자료가 필요합니다.

**완료 기준.** C·E·F·H·K의 판정 이유를 설명하고 두 실습 결과를 재현합니다. 실제 bind 실패를 특정 정책과 연결하려면 어떤 자료가 더 필요한지 제시하세요.

## 공식 참고자료

2026-11-26 기준으로 검토했습니다. RFC는 프로토콜 기준을 정의합니다. Microsoft의 현재 문서는 지원되는 AD DS 버전과 Windows Server 2025의 신규 배포·업그레이드를 구분합니다. 2020~2024년 업데이트 이력은 지원 문서를 참고했습니다.

- LDAP bind, StartTLS와 결과 코드. [RFC 4511, 2006년 6월](https://www.rfc-editor.org/rfc/rfc4511.html) · [RFC 4513, 2006년 6월](https://www.rfc-editor.org/rfc/rfc4513.html)
- Windows 설정과 세션 보호. [LDAP 서명](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) · [LDAP 채널 바인딩](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) · [세션 보안 지침](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023)
- 이벤트와 수집. [Microsoft KB4520412](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412) · [LDAP 서명 활성화](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

[이전 · Active Directory 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}) · [다음 · LDAP와 AD 열거]({{ '/ko/wiki/ldap-ad-enumeration/' | relative_url }})
