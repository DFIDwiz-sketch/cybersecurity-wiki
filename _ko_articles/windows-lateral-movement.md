---
title: "Windows 횡적 이동 완전 가이드: SMB, RDP, WinRM, WMI, PsExec, 탐지와 방어"
description: "Windows 원격접속·실행 방식과 인증·권한 조건을 비교하고, 대상 서버·DC 로그, Splunk 탐색, 가상 DFIR 실습으로 횡적 이동을 조사합니다."
category: active-directory
tags: [Windows Security, Active Directory, Lateral Movement, SMB, RDP, WinRM, PowerShell, WMI, DCOM, PsExec, Blue Team, DFIR, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-22"
translation_url: /wiki/windows-lateral-movement/
---

> **시리즈 5편.** [AD 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}), [Kerberos]({{ '/ko/wiki/kerberos-authentication/' | relative_url }}), [NTLM]({{ '/ko/wiki/ntlm-authentication/' | relative_url }}), [LDAP·AD 열거]({{ '/ko/wiki/ldap-ad-enumeration/' | relative_url }})를 먼저 읽어보세요. 정상 원격 관리가 악용되었는지 조사하는 문서입니다. 호스트·계정·IP·실습은 가상이며, 점검 명령은 로컬 설정을 조회합니다. 원격 서비스를 활성화하거나 다른 시스템에서 명령을 실행하지 않습니다.

## 1. 횡적 이동은 무엇인가요?

Windows 횡적 이동(Lateral Movement)은 공격자가 확보한 시스템·신원 접근을 이용해 다른 시스템으로 이동하는 행위입니다. 특정 프로토콜 하나의 이름이 아닙니다. 같은 원격 관리 기능을 정상 헬프데스크·배포·자산 관리·사고 대응에도 사용합니다.

**네트워크 도달성 → 인증 → 권한 부여 → 세션·작업 → 필요한 경우 실행 → 업무 영향** 순서로 판단하세요. 열린 포트가 유효한 자격 증명이나 권한을 증명하지 않습니다. 로그인 성공이 원격 명령 실행·자격 증명 탈취를 뜻하지 않으며, 파일을 공유에 복사했어도 실행하지 않았을 수 있습니다.

![네트워크 도달성·인증·권한·작업·증거를 구분하는 흐름]({{ '/assets/diagrams/lateral-chain-ko.svg' | relative_url }})

앞의 LDAP 문서는 어떤 주체가 무엇을 제어할 가능성이 있는지 모델링했습니다. 이제 어떤 호스트에서 어떤 방식으로 권한이 실제 사용되었고 결과가 무엇인지 확인합니다.

## 2. 다섯 가지 원격 관리 경로 비교

| 방식 | 대표 전송 경로 | 제공 기능 | 확인할 전제조건 |
| --- | --- | --- | --- |
| SMB 공유 접근 | TCP 445, 지원·설정된 SMB over QUIC는 UDP 443 | 원격 파일·Named Pipe | 서버·공유 가용성, 공유/NTFS·파이프 권한 |
| PsExec 방식 서비스 실행 | 주로 SMB 445와 지원 경로의 SCM RPC | 서비스를 이용한 원격 프로세스 실행 | 사용하는 경우 관리자 공유 권한, 서비스 제어 권한 |
| RDP | 일반적으로 TCP/UDP 3389, 게이트웨이 구성 시 관측 경로 변동 | 대화형 데스크톱·세션 | RDP 서비스, 로그온 권한, 그룹·정책·게이트웨이 |
| WinRM / PowerShell Remoting | 보통 TCP 5985 HTTP 또는 5986 HTTPS | WS-Management 및 구성된 원격 세션 엔드포인트 | Listener·방화벽·인증·엔드포인트 권한 |
| WMI over DCOM | TCP 135 매핑과 협상된 RPC 포트 | 관리 조회와 허용된 메서드 | DCOM/WMI Namespace 권한·방화벽·UAC/토큰 |

포트는 기본값과 조사 단서이며 프로토콜 확정이나 완전한 방화벽 설계가 아닙니다. WMI/CIM은 WS-Man도 사용할 수 있고 PowerShell 원격 연결은 SSH도 지원합니다. 도구 이름만으로 전송 경로를 단정하지 마세요. 아래는 대표적인 Windows 경로이며 모든 구현을 포괄하지 않습니다.

## 3. 신원·권한·자격 증명 노출은 별개

- **Kerberos 티켓과 NTLM 응답**은 서로 다른 인증 방식입니다. SMB·WinRM 사용만으로 NTLM이라고 판단하지 마세요.
- **권한**은 대상의 서비스·엔드포인트 ACL, 로그온 권한, 공유·NTFS 권한과 정책이 결정합니다.
- **로컬 관리자와 Domain Admin은 다릅니다.** 로컬 계정의 원격 UAC 제한·토큰 필터링 때문에 인증은 되어도 작업이 거부될 수 있습니다.
- **Pass-the-Hash·Pass-the-Ticket·NTLM Relay**는 다른 자격 증명 활용 방식입니다. 네트워크 로그인 성공만으로 구별할 수 없습니다.
- **자격 증명 노출**은 인증·위임·클라이언트·보호 모드에 따라 다르며 포트만으로 확정할 수 없습니다.

Access denied 문제를 해결하려고 UAC·인증 보호를 해제하거나 TrustedHosts를 무작정 넓히지 마세요. 의도한 관리 경로와 정확히 거부된 권한부터 확인합니다. 일반 사용자의 유효한 계정이 서비스 생성이나 원격 셸 권한까지 자동으로 주지는 않습니다.

## 4. SMB와 PsExec 방식 원격 실행

SMB는 파일·Named Pipe를 제공합니다. 대표적인 서비스 실행은 인증, 관리자 공유 접근, 필요한 서비스 구성요소의 배치, RPC를 통한 Service Control Manager(SCM)의 서비스 생성·시작, 구현별 출력 수신으로 이어집니다. 서비스 관리는 SCM이 수행하며 모든 SMB 파일 작업이 실행으로 바뀌는 것은 아닙니다.

Microsoft PsExec는 정상 관리 도구입니다. 옵션에 따라 서비스 이름·복사 프로그램·실행 문맥이 달라지며 유사 도구의 구현도 다릅니다. 고정 서비스·파일명 하나만 찾거나 항상 SYSTEM 실행이라고 가정하지 마세요. 매번 새 서비스를 생성한다고 단정할 수도 없습니다. [Microsoft PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec).

**증거 연결:** 대상의 4624 Type 3 → 관련 5140/5145 → 파일 증거 → 서비스 설치·시작 증거 → 프로세스 트리입니다. 서비스 설치 기록 자체가 실행 성공을 입증하지는 않습니다. 바이너리 경로·서명·해시·부모/자식·계정과 정상 배포 기록을 확인하세요.

5140은 최초 공유 접근 시 세션 수준 기록이며 파일 작업 횟수가 아닙니다. 5145는 접근 검사이지 파일 쓰기 완료 증거가 아닙니다. 상세 조건은 [SMB 가이드]({{ '/ko/wiki/smb-security/' | relative_url }})를 참고하세요.

## 5. RDP: 대화형 원격 접근

RDP는 대화형 세션을 만들거나 기존 세션에 다시 연결합니다. 대상의 **4624 Logon Type 10(RemoteInteractive)**과 TerminalServices 세션 채널, 수집된 4778/4779를 함께 확인하세요. 게이트웨이·프록시 주소, 재연결·세션 재사용에 따라 관측이 달라집니다.

**Type 3은 SMB 전용이 아니며 Type 10도 사람이 공격했다는 증거는 아닙니다.** 정상 헬프데스크일 수 있습니다. NLA는 완전한 원격 데스크톱이 만들어지기 전에 인증하도록 하지만 MFA나 이후 모든 작업의 허용을 뜻하지 않습니다.

Remote Credential Guard는 지원되는 Kerberos 기반 RDP 시나리오에서 자격 증명 노출을 줄입니다. Credential Guard·Restricted Admin과 목적·조건이 다르므로 같은 기능처럼 설명하면 안 됩니다. 지원 OS·헬프데스크 요구사항을 확인하세요. **세션 연결 해제와 로그오프도 다릅니다.** [Remote Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard), [4778 재연결](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778).

## 6. WinRM과 PowerShell Remoting

WinRM은 WS-Management를 구현합니다. Listener와 구성된 PowerShell 세션 엔드포인트의 권한에 따라 관리 작업을 허용합니다. 기본 엔드포인트는 보통 관리자 권한을 요구하지만 위임·JEA 엔드포인트로 좁은 역할만 허용하도록 설계할 수 있습니다.

**HTTP 5985가 곧 PowerShell 명령의 평문 전송을 뜻하지는 않습니다.** 지원되는 Kerberos/NTLM 원격 연결은 인증 후 메시지를 보호할 수 있습니다. HTTPS는 TLS와 인증서를 통한 서버 검증을 제공합니다. Basic 인증을 같은 메시지 보호 방식으로 취급하면 안 됩니다. 실제 인증 방식·TLS·유효 정책을 확인하세요. [WinRM 원격 연결 보안](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security?view=powershell-7.5).

대상 로그인, WinRM 운영 로그, 프로세스 트리, 수집된 스크립트 블록을 연결하세요. `wsmprovhost.exe`는 Windows PowerShell 원격 작업을 호스팅할 수 있지만 모든 버전·엔드포인트를 판별하는 보편적 지표는 아닙니다. WinRM 연결은 관리 조회·이벤트 전달일 수도 있으므로 원격 셸이라고 단정하지 마세요.

Double Hop은 첫 원격 호스트에서 다른 자원에 접근할 때의 위임 문제입니다. 테스트 성공을 위해 CredSSP·무제한 위임·와일드카드 TrustedHosts를 넓히기보다 승인된 신원 설계를 검토하세요. [WinRM 구성](https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management).

## 7. WMI·DCOM·CIM: 실제 작업을 확인하세요

WMI는 단순 원격 실행 도구가 아니라 관리 기반 시설입니다. Provider·Namespace 권한에 따라 자산 조회와 메서드를 제공합니다. 전통적인 원격 WMI는 주로 DCOM/RPC를 사용하지만 CIM 세션은 WS-Man 또는 명시적으로 선택한 DCOM을 사용할 수 있습니다. 따라서 5985 Listener만으로 PowerShell 스크립트인지 CIM 조회인지 알 수 없습니다. [원격 WMI 요건](https://learn.microsoft.com/en-us/windows/win32/wmisdk/connecting-to-wmi-remotely-starting-with-vista).

`WmiPrvSE.exe`는 정상 Provider Host입니다. 특이한 자식 프로세스는 조사 단서지만 승인된 관리 소프트웨어나 로컬 WMI에서 발생할 수도 있습니다. 호출자·가용한 메서드/Namespace·출발지 통신·프로세스 계보를 연결하고, 자산 조회가 항상 프로세스를 생성한다고 가정하지 마세요.

WMI-Activity 로그는 구성에 따라 Provider·작업 맥락을 보완합니다. 기본 이벤트 하나가 모든 성공한 원격 작업을 기록한다고 보장하지 마세요. **WMI 원격 실행과 영구 이벤트 구독을 이용한 지속성은 별개 행위**이며 한 사고에서 함께 나타날 수는 있습니다.

## 8. 올바른 호스트에서 증거 수집하기

| 증거 | 일반적 위치 | 의미·한계 |
| --- | --- | --- |
| 4624 / 4625 | 대상 Security | 성공·실패 로그인, 유형·계정·가용 출발지 |
| 4648 | 명시적 자격 증명을 사용한 출발 호스트 | 명시적 자격 증명 사용 시도, 대상 성공 보장 아님 |
| 4672 | 로그온 호스트 Security | 특수 권한 할당, 실제 사용 증거는 아님 |
| 4769 / 4776 | 도메인 인증 맥락의 DC | 티켓·자격 증명 검증, 전체 원격 실행 기록은 아님 |
| 5140 / 5145 | 공유 서버 Security | 공유 접근·상세 검사, 관련 감사 필요 |
| 7045 / 4697 | 각각 대상 System / Security | 서비스 설치, 4697은 관련 Security 감사 필요 |
| 4688 / Sysmon 1 | 프로세스 호스트 | 프로세스 생성·가용 계보, 명령줄·설정 확인 |
| Sysmon 3 / 11 / 17 / 18 | 구성된 엔드포인트 | 네트워크·파일 생성·Named Pipe 기록 |
| 4778 / 4779, TerminalServices | 세션 호스트 | 재연결·연결 해제·수명주기 맥락 |
| WinRM / WMI-Activity | 관련 관리 호스트 | 버전·구성에 따른 추가 맥락 |
| PowerShell 4104 | 해당 PowerShell 채널 | 기록된 스크립트 내용, 모든 원격 관리의 보편적 기록 아님 |
| 네트워크 Flow / PCAP | 센서 관측 지점 | 양 끝점·전송·시각, 암호화 시 작업 내용 제한 |

Security 감사 정책, System, 필요한 Applications and Services 채널, EDR·네트워크 범위를 의도적으로 구성해야 합니다. Sysmon 네트워크 이벤트·PowerShell 로깅은 항상 켜진 기본값이 아닙니다. 스크립트 로그에는 비밀정보가 들어갈 수 있으므로 접근·보존을 통제하세요. [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [4648](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648), [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [PowerShell 로깅](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1).

**감사 전제조건:** 관련 범위의 Audit Logon, 재연결·연결 해제를 위한 Other Logon/Logoff Events, Credential Validation, Kerberos Service Ticket Operations, Process Creation, 4697의 Security System Extension, File Share·Detailed File Share를 확인합니다. 이 Security 하위 범주와 System·Sysmon·애플리케이션 채널 수집은 구분하세요. 감사 정책뿐 아니라 전달·파싱·보존도 정상이어야 합니다.

## 9. 신원·세션·프로세스를 정확하게 연결하기

![출발지·대상·DC의 증거와 상관분석 기준]({{ '/assets/diagrams/lateral-evidence-ko.svg' | relative_url }})

1. UTC 구간·원래 시간대·시계 오차와 출발지·대상·게이트웨이/NAT를 확인합니다.
2. **도메인+계정 또는 SID**로 신원을 해석합니다. 짧은 이름이 같아도 다른 계정일 수 있습니다.
3. Logon ID는 **같은 호스트·부팅 문맥** 안에서 연결합니다. 대상의 `TargetLogonId`와 후속 `SubjectLogonId`를 비교할 수 있지만, 다른 호스트의 같은 16진수는 전역 세션 키가 아닙니다.
4. 가능하면 Process GUID를 사용합니다. PID는 재사용되므로 시작 시각·부모 맥락을 보존합니다.
5. 가까운 이벤트가 모두 같은 수행자라고 가정하지 마세요. 7045의 서비스 실행 계정은 설치를 요청한 관리자와 다를 수 있습니다.
6. 관련 DC의 티켓·검증 기록을 확인하되 캐시·누락을 고려합니다. 새 4769가 없다고 연결을 부정할 수 없습니다.
7. 출발지·계정·대상·목적을 승인된 작업 시간과 비교하고 차이를 조사합니다.

관측·추론·미확인을 구분한 결론을 작성하세요. 시각이 가깝다는 사실은 조사 단서이지 인과관계의 증명은 아닙니다.

## 10. Splunk 탐색 예제와 전제조건

아래는 **SPL 템플릿**이며 운영 탐지로 실행 검증한 규칙이 아닙니다. 실제 인덱스·시간·호스트·파서 매핑을 확인하세요. 7045는 Security가 아니라 System에서 수집합니다. 첫 검색은 EventCode와 EventID를 통합하여 두 필드가 동시에 존재해야 하는 문제를 피합니다.

### A. 이벤트 수집 확인

```spl
index=* (EventCode IN (4624,4625,4648,4688,4697,4769,4776,5140,5145,7045)
      OR EventID IN (4624,4625,4648,4688,4697,4769,4776,5140,5145,7045))
| eval event_id=coalesce(EventCode,EventID)
| stats count by host sourcetype event_id
| sort - count
```

### B. 네트워크·원격 대화형 로그온 기준선

```spl
index=windows (EventCode=4624 OR EventID=4624)
| eval logon_type=tostring(coalesce(LogonType,Logon_Type))
| eval account=coalesce(TargetUserName,Account_Name,user)
| eval src_ip=coalesce(IpAddress,Source_Network_Address,src_ip)
| eval src_ip=if(isnull(src_ip) OR src_ip="-" OR src_ip="","unknown",src_ip)
| eval account=coalesce(account,"unknown")
| eval auth=coalesce(AuthenticationPackageName,Authentication_Package,AuthenticationPackage,"unknown")
| where logon_type IN ("3","10")
| stats count AS logons values(logon_type) AS logon_types
    values(auth) AS auth_packages
    BY host account src_ip
| sort - logons
```

`unknown`은 출발지·계정 누락을 품질 점검에 남기기 위한 값이지 신원 판정이 아닙니다. Type 3에는 여러 네트워크 서비스가 포함되며 Type 10은 원격 대화형 단서입니다. 낯선 출발지·계정·대상 조합과 승인 관리 호스트를 비교하고 IPv4-mapped IPv6·호스트 이름을 적절히 정규화하세요.

### C. 대상 호스트 타임라인

```spl
index=windows host="APP01"
  (EventCode IN (4624,4688,4697,5140,5145,7045)
   OR EventID IN (4624,4688,4697,5140,5145,7045))
| eval event_id=coalesce(EventCode,EventID)
| table _time host event_id SubjectUserName TargetUserName
    SubjectLogonId TargetLogonId IpAddress ShareName RelativeTargetName
    ServiceName ServiceFileName ImagePath NewProcessName ParentProcessName
| sort 0 _time
```

시간순 워크시트이며 인과관계를 자동으로 Join하는 검색은 아닙니다. 원본 XML·실제 필드를 확인하세요. 모든 행에 모든 열이 채워지지 않아도 됩니다. 서비스 이벤트만으로 설치자를 앞선 로그온에 연결할 수 없으므로 EDR·세션 증거가 필요합니다.

### D. 특정 부모 프로세스에서 시작하는 실행 조사

```spl
index=endpoint sourcetype=process_normalized
| eval parent=lower(coalesce(parent_name,"unknown"))
| where parent IN ("wmiprvse.exe","wsmprovhost.exe","services.exe")
| table _time dest_host user parent_name process_name command_line
    process_guid parent_process_guid logon_id
| sort 0 _time
```

이 검색은 `parent_name`에 기본 파일명이 들어가는 **설명용 정규화 EDR 스키마**를 전제로 합니다. Windows 기본 sourcetype가 아닙니다. 정상 부모 프로세스도 의도적으로 포함하며 자동 악성 판정은 하지 않습니다. 바이너리 출처·명령줄·계정·출발지·변경 티켓을 확인하세요. 0건은 미실행뿐 아니라 스키마·수집 누락일 수 있습니다.

## 11. 가상 조사 실습과 해설

[가상 이벤트 워크시트 CSV 다운로드]({{ '/assets/labs/lateral-movement-events.csv' | relative_url }}). 12건의 선택된 정규화 관측이며 원본 Windows XML·전체 이벤트·즉시 사용할 수 있는 Splunk Lookup이 아닙니다. `source_kind`, `user`, `detail` 등은 교육용 필드입니다. 시각은 UTC이고 192.0.2.0/24는 문서용 주소입니다. CSV의 상세 설명은 공통 기술 식별자를 유지하기 위해 영어로 제공합니다.

| 시각 | 관측 | 첫 해석 |
| --- | --- | --- |
| 01:00 | MGMT01 / 192.0.2.10이 ops_lab로 APP01:445 연결 | 승인 배포 범위 확인 |
| 01:00:01–07 | Type 3, ADMIN$ 검사, 서비스 설치, 자식 프로세스 | 서비스 기반 관리 패턴, 작업자·실행 검증 |
| 01:20 | WS23 / 192.0.2.23이 APP01:5985 연결 | 처음 관측한 관리 출발지 |
| 01:20:01–04 | ops_lab Type 3, 특이한 wsmprovhost 자식, 스크립트 관측 | 세션 연결·승인 여부 우선 조사 |
| 01:30–40 | helpdesk_lab Type 10, 연결 해제·재연결 | 헬프데스크 기록 확인, 해제는 로그오프와 다름 |

**질문:** 각 흐름의 출발 호스트는 어디인가요? 같은 계정이 낯선 출발지에서 사용되었나요? 서비스 행만으로 설치자를 알 수 있나요? 스크립트 행을 같은 세션에 연결할 수 있나요? 정상 지원과 악용을 구별하려면 무엇이 필요한가요?

**해설:** 첫 흐름은 승인 배포와 일치할 가능성이 있지만 실제 변경 기록·바이너리를 검증해야 합니다. 두 번째는 출발지·프로세스 맥락이 달라 조사 우선순위를 높일 근거입니다. 하지만 자료만으로 PtH·Relay·자격 증명 탈취·최종 목표 달성을 입증하지 못합니다. 스크립트에는 Activity/세션 연결이 필요합니다. 마지막 RDP는 정상 지원일 수 있습니다. Logon ID는 APP01 범위이며 서비스 행은 요청한 계정을 확정하지 않습니다.

**후속 조사:** 원본·관련 바이너리를 보존하고 출발 프로세스, 계정 담당자·승인, 추가 대상을 확인합니다. 확인된 악용은 사고 대응 절차로 통제하세요. 서비스 설치만 보고 모든 관리 호스트를 격리하면 안 됩니다.

## 12. 승인된 관리자의 읽기 전용 로컬 점검

관리하는 호스트에서 필요한 경우 관리자 권한으로 실행하세요. 원격 세션 생성·원격 관리 활성화·방화벽 변경을 수행하는 예제가 아닙니다.

```powershell
Get-Service -Name WinRM,TermService,Winmgmt
Get-NetTCPConnection -State Listen |
  Where-Object LocalPort -in 445,3389,5985,5986 |
  Select-Object LocalAddress,LocalPort,OwningProcess
winrm enumerate winrm/config/listener
Get-SmbServerConfiguration |
  Select-Object RequireSecuritySignature,EncryptData,EnableSMB1Protocol
```

역할·에디션에 따라 서비스나 Listener가 없는 것이 정상일 수 있습니다. Listener만으로 특정 사용자의 실행 권한을 입증하지 못하고 RPC·게이트웨이 때문에 포트 목록도 완전하지 않습니다. 유효 엔드포인트·방화벽 정책을 따로 확인하세요.

```powershell
$since = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4688,4697,5140,5145; StartTime=$since} -MaxEvents 100 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$since} -MaxEvents 30 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
```

로컬 로그의 제한된 표본이며 전체 내보내기가 아닙니다. 결과가 없으면 감사·채널 권한·보존·시간을 확인하세요. 로깅 변경이나 세션 정리 전에 원본을 보존합니다.

## 13. 신원·프로토콜·관리 경로별 방어

| 계층 | 조치 | 검증 |
| --- | --- | --- |
| 신원 | 관리자 계정 분리, 로컬 관리자 LAPS, 서비스 계정 최소 권한 | 담당자와 유효 권한 범위 |
| 도달성 | PC 간 관리 제한, 승인 관리 호스트·게이트웨이 | 필요한 경로 허용·불필요 경로 차단 시험 |
| SMB | 적절한 Signing, 필요한 Encryption, NTLM 축소 | 실제 세션 보호·호환성 |
| RDP | 로그온 권한 제한, NLA와 호환 게이트웨이/MFA | 정상 세션 허용·미승인 출발지 차단 |
| WinRM | Listener·방화벽·Endpoint ACL 범위, 필요 시 제한/JEA | 역할이 의도한 작업만 수행 |
| WMI/DCOM | Namespace·활성화 권한과 의존성 검토 | 넓은 권한 없이 정상 자산 관리 |
| 자격 증명 | Credential Guard·적절한 RDP 보호 모드 검토 | OS·지원 조건과 업무 시험 |
| 가시성 | 대상·DC·프로세스·세션 중앙 수집과 보존 | 알려진 실습 활동의 예상 기록 |

도구·서비스 계정·점프 호스트를 맥락 없이 영구 허용하지 마세요. 이들도 침해될 수 있습니다. 목적·출발지·대상·시간·담당자로 예외를 제한하고 검토하세요. 전송 암호화가 인증된 관리자의 명령 권한을 없애지는 않으며 서명만으로 모든 자격 증명 오용을 차단하지 못합니다.

## 14. MITRE ATT&CK 매핑

| 관측 행위 | 관련 매핑 | 주의 |
| --- | --- | --- |
| RDP 이동 | [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | 목적·세션 행동 확인 |
| SMB·관리자 공유 이동 | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | 정상 관리에도 발생 |
| DCOM 원격 서비스 | [T1021.003](https://attack.mitre.org/techniques/T1021/003/) | 모든 WMI와 같은 뜻 아님 |
| WinRM 원격 서비스 | [T1021.006](https://attack.mitre.org/techniques/T1021/006/) | 관리 트래픽만으로 악성 판정 불가 |
| WMI 실행 | [T1047](https://attack.mitre.org/techniques/T1047/) | 조회·실행·지속성 구분 |
| 서비스 실행 | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) | 설치와 실행 구분 |
| PowerShell 실행 | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | 실제 PowerShell 실행 증거가 있을 때 |

한 사고에 원격 서비스와 실행 매핑이 함께 적용될 수 있습니다. 자격 증명 악용 매핑은 전제조건이 입증될 때 적용하며 모든 NTLM 로그온을 PtH라고 분류하지 마세요. [Remote Services 개요](https://attack.mitre.org/techniques/T1021/).

## 15. 문제 해결과 확인 문제

| 주장·증상 | 정정·첫 점검 |
| --- | --- |
| 포트가 열렸으니 실행 성공 | 인증·권한·대상 작업 확인 |
| Type 3이면 SMB·PtH | 여러 서비스가 사용하는 네트워크 로그온 유형 |
| 4648이면 대상 로그인 성공 | 명시적 자격 증명 사용 시도 기록 |
| 7045면 악성 서비스 실행 | 시작·프로세스·정상 배포 검증 |
| HTTP WinRM은 항상 명령 평문 | 인증·협상된 메시지 보호 확인 |
| WMI는 항상 TCP 135 | DCOM과 WS-Man/CIM·실제 엔드포인트 구분 |
| 같은 Logon ID는 호스트 간 같은 세션 | 호스트·부팅 문맥으로 제한하고 신원·시각 연결 |
| 새 4769가 없으니 서비스 접근 없음 | 티켓 캐시·DC 수집 한계 확인 |
| 계정이 맞는데 Access denied | 엔드포인트·서비스·Namespace 권한과 토큰 확인 |

**학습 완료 점검:** 다섯 경로 설명, 로그인과 실행 구분, 출발지·대상·DC 증거 연결, 가상 흐름 해석, 누락 기록, 관측 경로에 맞는 호환 보안 통제 선택을 수행할 수 있어야 합니다.

## 16. 학습 경로 이어가기

[LDAP·AD 열거]({{ '/ko/wiki/ldap-ad-enumeration/' | relative_url }})로 돌아가거나 [SMB 상세]({{ '/ko/wiki/smb-security/' | relative_url }}), [네트워크 증거 연결]({{ '/ko/wiki/network-monitoring/' | relative_url }})을 학습하세요. 수집·검색 문제는 [Windows 로그]({{ '/ko/wiki/windows-logs/' | relative_url }}), [Splunk 기초]({{ '/ko/wiki/splunk-basics/' | relative_url }})와 연결됩니다.

이 문서로 AD·인증·원격 관리의 다섯 문서 제작 순서를 완성합니다. [AD CS 보안]({{ '/ko/wiki/ad-cs-security/' | relative_url }})으로 이어서 학습하세요. 다음 확장 후보는 Windows 지속성과 Sysmon입니다.

**출처 검토: 2026년 10월 22일.** 본문의 Microsoft·MITRE 링크는 제품·이벤트 동작과 기법 분류의 근거입니다. 도표·쿼리·조사 예제·CSV는 직접 구성한 교육 자료이며 버전에 따라 필드·프로세스 패턴이 달라집니다. 게시 과정에서 실제 원격 명령 실행, 디렉터리 수집, 운영 Splunk 테스트를 수행하지 않았습니다.
