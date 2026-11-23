---
title: "RDP 세션 증거 · 연결 해제부터 로그오프까지"
description: "대상 Windows의 RDP 기록을 올바른 Logon ID로 연결하고 네트워크 연결 종료와 세션 종료를 구분합니다."
category: dfir
tags: [Windows Security, Windows, RDP, Event Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/rdp-session-evidence/
---

**학습 목표.** 01:05에 원격 데스크톱 창이 닫혔습니다. 사용자는 로그아웃했을까요? 01:08 접속은 새 데스크톱을 열었을까요? 대상 Windows의 이벤트로 답하고, 증거가 부족하면 어떤 자료가 더 필요한지 설명합니다. 처음이라면 [Windows 보안 이벤트]({{ '/ko/wiki/windows-logs/' | relative_url }})부터 읽거나 [Windows 원격 관리 경로]({{ '/ko/wiki/windows-lateral-movement/' | relative_url }})에서 RDP가 어디에 쓰이는지 살펴보세요.

## 1. 연결, 로그온, 데스크톱은 서로 다른 층입니다

**RDP(Remote Desktop Protocol)**는 다른 Windows 장치에서 실행되는 데스크톱을 원격으로 조작하는 프로토콜입니다. **RDS(Remote Desktop Services)**는 이런 세션을 제공하고 접속을 중개할 수 있습니다. **세션 호스트**는 데스크톱과 애플리케이션이 실제로 실행되는 대상입니다. **RD Gateway**는 접속을 중개할 수 있습니다. 허용 여부와 클라이언트 주소는 게이트웨이가 본 증거이며, 데스크톱이 어떻게 바뀌었는지는 세션 호스트에서 확인합니다.

**연결**은 화면과 입력을 전달하는 통신 경로입니다. **Windows 로그온 세션**은 인증 뒤 사용자나 서비스의 보안 컨텍스트를 유지합니다. **데스크톱 세션**은 사용자의 작업 환경과 실행 중인 프로그램을 담습니다. 사용자가 창을 닫거나 통신이 끊기면 연결은 해제되지만 프로그램은 호스트에서 계속 실행될 수 있습니다. 이후 정책이나 관리 작업으로 세션이 종료될 수 있습니다. **재연결**은 이미 열려 있던 데스크톱으로 돌아가는 동작일 수 있습니다. 화면만 잠겨도 세션은 유지될 수 있으므로 어느 층의 상태가 바뀌었는지 확인합니다.

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/rdp-session-evidence-ko.svg' | relative_url }}" alt="원격 대화형 로그온으로 세션이 시작됩니다. 연결이 해제돼도 세션은 남을 수 있으며, 재연결로 돌아갑니다. 같은 로그온 세션의 4634는 종료를 기록합니다.">
<figcaption>연결 해제와 로그오프는 서로 다른 경로입니다. 그림의 이벤트는 필요한 감사 정책이 적용된 대상 호스트의 Security 채널 예시입니다.</figcaption>
</figure>

## 2. 대상 호스트의 이벤트를 읽는 법

아래 ID는 **Security** 채널과 **Microsoft-Windows-Security-Auditing** 공급자를 기준으로 합니다. 이벤트가 생성되고 수집되려면 해당 감사 정책과 전달 범위가 갖춰져야 합니다. 원격 인증 과정에는 다른 로그온 유형이 함께 보일 수 있습니다. RemoteInteractive 성공은 유형 10으로 찾고, 주변의 유형은 맥락으로 남깁니다.

| 이벤트와 감사 전제 | 기록이 뒷받침하는 사실 | 연결에 사용할 필드 |
| --- | --- | --- |
| 4624 유형 10 · Audit Logon 성공 | 대상에서 원격 대화형 로그온 세션을 생성 | 새 로그온의 SID·계정, XML의 `TargetLogonId`, 로그온 유형, 기록된 출발지 정보. `SubjectLogonId`는 역할이 다름 |
| 4625 · Audit Logon 실패 또는 Audit Account Lockout 관련 | 이 이벤트를 기록한 장치에서 로그온 시도가 실패 | 시도 계정, 유형, 상태·하위 상태, 기록된 출발지 정보. 성공 세션의 식별자로 연결하지 않고 맥락으로 유지 |
| 4779 / 4778 · Audit Other Logon/Logoff Events 성공 | 기존 세션이 연결 해제 / 재연결됨. 빠른 사용자 전환 및 Hyper-V 향상된 세션 등에서도 발생 가능 | XML의 `LogonID`, 계정·도메인, `SessionName`, 기록된 `ClientName`과 `ClientAddress`. 실제 연결 유형과 세션 맥락도 확인 |
| 4647 · Audit Logoff 성공 | 계정이 로그오프를 시작 | XML의 `TargetLogonId`와 계정. 종료를 뒷받침할 증거를 추가 확인 |
| 4634 · Audit Logoff 성공 | 해당 로그온 세션이 종료됨. 다른 로그온 유형도 기록 가능 | XML의 `TargetLogonId`와 `LogonType`. 종료 이유나 사용자의 로그아웃 클릭까지 알려 주지는 않음 |

**대상 컴퓨터, 부팅 구간, Logon ID를 함께 사용하세요.** Logon ID는 해당 호스트의 한 부팅 구간 안에서 쓰이며, 재부팅 뒤 같은 값이 나올 수 있습니다. 원본 값을 남기고 `0x2A1`과 `0x2a1` 같은 16진수 표기를 정규화합니다. 호스트 식별과 부팅 구간은 신뢰할 수 있는 자산 목록 및 호스트 기록으로 확인하세요. 중간에 재부팅이 있었는지 알 수 없다면 연결 결과를 잠정 판단으로 남깁니다. Security의 Logon ID, `quser`의 숫자 세션 ID, `RDP-Tcp#4`라는 세션 이름은 서로 다른 식별자입니다. 계정은 보조 확인에 쓰고, SID가 있으면 SID와 계정·도메인도 대조합니다. 같은 계정명, IP 또는 세션 이름 끝자리만으로는 같은 세션으로 묶기 어렵습니다.

## 3. 정상 예시와 다른 가능성 비교하기

가상의 세션 호스트 `rdsh-a`에서 지원 계정은 01:01에 4624 유형 10으로 로그온했습니다. Logon ID는 `0x2a1`입니다. 01:05의 4779는 같은 ID의 연결 해제를, 01:08의 4778은 재연결을 기록합니다. 재연결에는 다른 클라이언트 주소가 보입니다. 01:10에 4647로 로그오프 시작을, 1초 뒤 4634 유형 10으로 로그온 세션 종료를 확인합니다. 같은 부팅 구간에서 이 다섯 기록을 연결할 수 있습니다. 클라이언트 주소가 달라진 원인은 따로 조사해야 합니다.

| 관측 | 먼저 확인할 정상 가능성 | 조사 우선순위를 높이는 근거 |
| --- | --- | --- |
| 다른 클라이언트 주소로 재연결 | VPN 주소 변경, 게이트웨이 경로, 승인된 작업 단말 변경 | 별도 자료로 승인 밖 단말이나 경로를 확인했거나 계정 소유자가 작업을 부인함. 세션 활동이 승인된 작업 범위를 벗어남 |
| 여러 4625 뒤 4624 | 반복 입력 오류, 클라이언트 재시도 | 여러 계정이나 비정상 경로의 실패 후 접속이 확인되고, 뒤이어 의심스러운 작업이 관측됨 |
| 4779는 있고 4634가 없음 | 사용자 창 닫기, 통신 장애, 유지된 세션, 로그 누락 | 실시간 조회에서 권한 높은 세션이 오래 남아 있고, 시각이나 활동이 정책과 맞지 않음 |
| 4778 앞에 4624가 없음 | 수집 시작 이전의 로그온, 보존 공백, 다른 호스트를 조회함 | 게이트웨이와 호스트의 접속 증거를 별도로 확인했지만 승인된 작업 기록과 일치하지 않음 |

오용은 계정 소유자가 아닌 사람이 그 계정을 쓰거나, 이미 연결 해제된 데스크톱에 승인 없이 접근할 때 생길 수 있습니다. 네트워크 장애, 잠금 정책, 유지보수도 비슷한 기록을 남깁니다. 인증 결과, 세션 상태, 세션 안에서 한 작업을 따로 기록하세요. 방화벽 연결, 게이트웨이 허용 또는 4624만으로 실행한 명령이나 접근한 파일은 알 수 없습니다.

## 4. 타임라인을 보존하면서 수집하고 대응하기

1. **접속 경로와 시각을 맞춥니다.** 게이트웨이·브로커 뒤의 실제 세션 호스트를 찾습니다. UTC 이벤트 시각, 수집 시각, 부팅 구간, 시계 오차를 기록합니다. 승인된 범위에서 대상 Security와 사용 가능한 TerminalServices 운영 채널, 실제 사용한 게이트웨이·브로커 기록, 단말 자료를 확보합니다. 원본 XML, 이벤트 버전, 채널, 공급자, 원본 컴퓨터 이름, 레코드 ID를 남깁니다. 서로 다른 로그나 장치에서 같은 레코드 ID가 나올 수 있습니다.
2. **감사와 전달 범위를 확인합니다.** 대상의 Audit Logon, Audit Logoff, Audit Other Logon/Logoff Events 설정을 확인하고 생성된 이벤트가 수집기에 도달하는지 살핍니다. 승인된 정상 세션으로 실제 환경의 이벤트 버전과 필드를 비교합니다. 특정 ID가 안 보이면 행동이 없었다고 판단하기 전에 로컬 생성, 전달, 보존 중 어디가 비었는지 확인합니다. [Windows 로그 공백 조사]({{ '/ko/wiki/windows-log-continuity/' | relative_url }})를 참고하세요.
3. **타임라인에 증거 열을 나눠 기록합니다.** 대상 세션의 키 아래에 세션 이벤트를 시간 순서대로 두고 게이트웨이의 신원과 클라이언트 주소는 별도 열에 남깁니다. 바뀐 주소가 같은 사람이나 단말에 해당하는지는 VPN·게이트웨이·기기 기록으로 확인합니다. 명령이나 접근 여부는 프로세스 생성, EDR, 애플리케이션 감사 등 사용할 수 있는 기록을 찾습니다. 대상과 시간을 맞추고, 해당 이벤트에 문서화된 로그온 식별자 필드가 있으면 활용합니다.
4. **현재 상태를 확인하고 대응 범위를 정합니다.** 권한이 있는 세션 호스트에서 `quser`로 활성과 연결 해제 상태를 조회할 수 있습니다. 이는 현재 상태를 찍은 스냅숏입니다. 가능하면 상태를 바꾸기 전에 자료를 보존합니다. 승인되지 않은 접속을 확인하면 호스트 담당자와 격리를 조율하고, 해당 데스크톱과 프로그램이 실제로 종료됐는지 확인합니다. 네트워크 연결만 끊으면 데스크톱이 남을 수 있습니다.

필요한 감사가 이미 설정된 승인된 Windows 대상에서 Security 로그 읽기 권한으로 아래 PowerShell을 실행하면 최근 2시간의 후보를 조회할 수 있습니다. 조사에 맞게 기간을 변경하세요. 여러 로그온 유형이 나오므로 원본 XML의 위 필드로 다시 연결합니다. 이벤트 뷰어 표시 이름과 수집기 필드가 모호하면 해당 이벤트에서 `.ToXml()`을 사용해 확인합니다.

```powershell
$filter = @{
    LogName      = 'Security'
    ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id           = 4624, 4625, 4634, 4647, 4778, 4779
    StartTime    = (Get-Date).AddHours(-2)
}
Get-WinEvent -FilterHashtable $filter |
    Select-Object TimeCreated, MachineName, RecordId, Id, Message
```

## 5. 오프라인 실습 · 세션 타임라인 재구성하기

<a href="{{ '/assets/labs/rdp-session-events.csv' | relative_url }}" download>가상 이벤트 CSV</a>와 <a href="{{ '/assets/labs/rdp-session-lab.py' | relative_url }}" download>Python 확인 스크립트</a>를 같은 폴더에 내려받으세요. CSV는 가상의 호스트와 주소가 담긴 학습용 자료입니다. `boot`는 실습에서 제공하는 부팅 구간 정보입니다. Windows 이벤트 원본의 필드는 아닙니다. 스크립트는 실습 데이터의 `RDP-Tcp#` 이름만 알아보도록 작성했습니다. 운영 수집에서 모든 RDS 연결을 판별하는 필터로 사용할 수는 없습니다. Python 3과 제공한 CSV만 사용하며, 호스트에 접속하거나 새 이벤트를 발생시키지 않습니다.

1. 호스트 A의 부팅 구간 A1에서 4624 유형 10을 찾습니다. XML 필드를 반영한 `target_logon_id`와 `logon_id`가 이벤트별로 어떻게 다른지 확인합니다.
2. 호스트·부팅 구간·정규화한 ID로 묶고, 각 그룹을 UTC 순서로 정리하세요. 5번과 11번 행의 번호는 같지만 왜 다른 그룹이어야 하는지 설명합니다.
3. 12번과 9번 행을 비교합니다. 어느 기록이 연결 해제이고 어느 기록이 로그온 세션 종료인가요?
4. `python3 rdp-session-lab.py`를 실행하고 직접 정리한 결과와 비교합니다.

| 그룹 또는 대조 조건 | 기대하는 해석 |
| --- | --- |
| 호스트 A, A1, `0x2a1` | 2 → 4 → 6 → 8 → 9번. 원격 대화형 로그온, 연결 해제, 재연결, 로그오프 시작, 종료 |
| 호스트 B, B1, `0x2a1` | 5번만 해당. 다른 호스트에서 나온 같은 번호는 별도 세션 |
| 호스트 A, A2, `0x2a1` | 11 → 12번. 별도 부팅 구간의 세션. 연결 해제는 관측됐지만 표에 종료 기록은 없음 |
| 호스트 A, A2, `0x404` | 13번. 재연결은 보이지만 시작은 수집되지 않음 |
| 세션 그룹 밖의 맥락 | 1·3·7·10번. 실패한 시도, 유형 3 로그온, 콘솔 전환, 유형 3 로그오프 |

마지막에 `5/5 grouping controls matched.`가 표시됩니다. CSV가 열리지 않으면 이름과 폴더를 확인하세요. 너무 많은 기록이 묶이면 호스트와 부팅 구간을 다시 나누고, 원격 대화형 유형 10 타임라인에 유형 3을 섞지 않았는지 확인합니다. 4번이 빠지면 16진수 표기를 비교하세요. 가상 CSV와 Python 스크립트는 클라우드에서 실행했습니다. Windows 이벤트 생성 조건과 PowerShell 예시는 Microsoft 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

1. **4779가 있으면 프로그램이 종료됐나요?** 연결 해제를 보여 줍니다. 현재 세션 상태나 같은 세션의 종료 및 프로세스 증거를 추가 확인하세요.
2. **계정과 Logon ID가 같지만 대상 호스트가 다릅니다. 같은 키로 묶나요?** Logon ID는 호스트 및 부팅 구간에 한정되므로 그룹을 나눕니다.
3. **4778에 다른 주소가 나왔습니다. 비인가 접속을 판단하려면 무엇을 더 확인하나요?** 게이트웨이·VPN 경로와 승인된 단말을 검증하고, 세션과 작업 내역을 승인 기록에 대조합니다. 주소만으로 사람을 특정할 수는 없습니다.
4. **4647과 4634를 둘 다 보존하는 이유는 무엇인가요?** 4647은 계정의 로그오프 시작을, 4634는 해당 로그온 세션의 종료를 보여 줍니다.

**완료 기준.** 실습의 대조 조건 5개를 설명하고 연결 해제와 로그오프를 구분하세요. 다른 자료가 있어야 답할 수 있는 판단 한 가지를 말할 수 있으면 됩니다.

## 공식 참고자료

검토일 2026-11-21. 이벤트 XML과 감사 하위 범주는 Microsoft의 Windows 감사 레퍼런스에서 확인했습니다. 지원되는 Server 버전의 세션 동작과 조회 권한은 Windows Server 문서를 기준으로 설명했습니다. 사용 중인 버전에서도 수집 조건을 확인하세요.

- Microsoft Security 이벤트 스키마. [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) · [4778](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778) · [4779](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779) · [4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647) · [4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- Windows Server RDS 세션 상태·시간 제한과 현재 상태 조회. [Windows Server 세션 잠금·연결 해제](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/troubleshoot-unexpected-rds-session-locks-or-disconnections) · [quser](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/quser)
- Windows에서의 PowerShell 이벤트 조회, 7.5 문서. [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)

## Windows 특권 로그온 이어서 조사하기

[Windows 특권 로그온 조사]({{ '/ko/wiki/windows-privileged-logon-evidence/' | relative_url }})에서 호스트와 부팅을 기준으로 특권 부여, 프로세스 토큰, 특권 사용 감사를 구분하세요.
