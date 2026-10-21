---
title: "NTLM 인증 완전 가이드: NTLMv1/v2, Responder, Relay, Pass-the-Hash, 탐지와 방어"
description: "NTLM 챌린지-응답 구조, NT Hash와 NetNTLMv2 차이, LLMNR/WPAD, NTLM Relay·PtH 공격 원리, Windows 로그·Splunk, SMB/LDAP/EPA 방어를 종합 설명합니다."
category: active-directory
tags: [Windows Security, Active Directory, NTLM, NTLMv2, NetNTLMv2, Responder, LLMNR, WPAD, NTLM Relay, Pass-the-Hash, SMB, Credential Access, Lateral Movement, Blue Team, Red Team, DFIR, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-21"
translation_url: /wiki/ntlm-authentication/
---

> **선행 학습:** [Active Directory 기초]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }})와 [Kerberos 인증]({{ '/ko/wiki/kerberos-authentication/' | relative_url }}). 이 문서는 정상적인 인증과 공격 원리를 이해하여 **탐지·보안 강화·승인된 실습**에 활용하기 위한 자료입니다. 공격 도구의 무단 실행이나 자격 증명 수집 절차는 다루지 않습니다. 예시 시스템과 계정은 가상입니다.

## 1. NTLM이란 무엇인가요?

**NTLM(New Technology LAN Manager)**은 Windows의 역사적인 **챌린지-응답(Challenge–Response)** 기반 인증 기술 계열입니다. 사용자가 파일 공유, 일부 웹 서비스, 레거시 애플리케이션, 도메인이 없는 컴퓨터 등에 접근할 때 사용될 수 있습니다.

핵심은 **비밀번호 원문을 대상 서버에 전송하지 않고**, 서버가 제공한 임의의 Challenge와 계정 비밀정보에서 계산한 Response를 검증한다는 점입니다.

하지만 NTLM은 Kerberos처럼 KDC가 **특정 서비스 이름(SPN)에 묶인 티켓을 발급하는 방식이 아니며**, 일부 구성에서 대상 서버 신원을 충분히 보장하지 못해 **인증 유도·중계(Relay)** 문제가 발생할 수 있습니다.

### 오늘날 NTLM이 사용될 수 있는 상황

- Kerberos용 SPN이 없거나 잘못 등록된 네트워크 서비스
- 도메인에 가입되지 않은 PC·NAS·레거시 애플리케이션
- IP 주소로 접근하는 경우 등 Kerberos가 선택되지 않은 상황
- 호환성 때문에 NTLM 인증을 활성화한 SMB·HTTP·RPC 서비스
- 독립 실행형 Windows의 로컬 계정 인증

**주의:** SPNEGO/Negotiate가 NTLM로 *언제나* 자동 대체하는 것은 아닙니다. 앱 구현, 인증 정책, 서버 지원 방식에 따라 인증 자체가 거부될 수 있습니다.

## 2. NTLM, NTLMv1, NTLMv2, NT Hash, NetNTLM의 차이

| 용어 | 정확한 의미 | 절대로 혼동하지 않을 점 |
| --- | --- | --- |
| **NTLM** | Windows의 인증 프로토콜 계열 또는 NTLM 보안 패키지 | NTLM이라는 단어만으로 버전 식별 불가 |
| **NTLMv1** | 오래된 Challenge–Response 방식 | 사용 중단·제거 대상 |
| **NTLMv2** | HMAC-MD5 기반 응답, 클라이언트 nonce·타임스탬프 등 포함 | NTLMv1보다 안전하지만 Relay 자체를 제거하지는 못함 |
| **NT Hash** | 비밀번호에서 계산한 **MD4 기반 장기 비밀값** | 네트워크에서 캡처한 NetNTLMv2 응답과 다름 |
| **NetNTLMv1/v2** | 네트워크 인증 교환에서 관찰되는 응답 자료를 가리키는 실무 용어 | 계정 DB/LSASS에서 NT Hash를 추출한 것이 아님 |
| **LM Hash** | 역사적으로 사용되던 약한 LAN Manager 비밀번호 해시 | NT Hash 및 NetNTLM과 다름 |
| **NTLMSSP** | NTLM 프로토콜 메시지/협상에 관련된 Windows 보안 지원 제공자 | 전송 프로토콜(예: SMB) 자체는 아님 |

**특히 주의:** "Responder가 NTLM Hash를 캡처한다"는 설명은 일반적으로 지나치게 모호합니다. 일반적인 네트워크 인증 포착은 **NetNTLM 챌린지-응답**을 확보하는 것이지 계정의 **NT Hash 원본**을 곧바로 획득하는 것이 아닙니다.

### NTLMv2 Response는 무엇에 의존하나요?

개념적으로 NTLMv2 응답은 **NT Hash에서 파생한 키**와 서버 Challenge, 클라이언트 Challenge, 타임스탬프, 대상 관련 정보를 결합해 계산합니다. 실제 형식은 여러 필드와 프로토콜 계산을 포함합니다.

- **비밀번호가 충분히 강력하면** 캡처된 응답에 대한 오프라인 암호 추측은 매우 어려워질 수 있습니다.
- **약한 비밀번호라면** 응답 자료를 이용한 오프라인 추측 위험이 생깁니다.
- **Relay는 별개의 공격**이므로 비밀번호가 매우 강력하다고 해서 모든 NTLM Relay 위험이 없어지는 것은 아닙니다.

## 3. NTLMv2 정상 인증 과정: Type 1, 2, 3

![NTLMv2 정상 클라이언트 서버 DC Challenge Response 인증 흐름]({{ '/assets/diagrams/ntlm-auth-flow-ko.svg' | relative_url }})

| NTLMSSP 메시지 | 방향 | 의미 |
| --- | --- | --- |
| **Type 1 — NEGOTIATE** | 클라이언트 → 서버 | 인증 기능과 옵션 협상 |
| **Type 2 — CHALLENGE** | 서버 → 클라이언트 | 서버 Challenge, Target Info 등 |
| **Type 3 — AUTHENTICATE** | 클라이언트 → 서버 | 사용자·도메인·응답 등 인증 증명 |

예를 들어 `CLIENT01` 사용자가 `FILE01`의 SMB 공유에 연결합니다.

1. 클라이언트와 서버가 NTLM 인증을 사용하기로 협상합니다.
2. 서버가 예측하기 어려운 **8바이트 서버 Challenge**를 발급합니다.
3. 클라이언트는 계정 비밀정보에서 계산한 키와 Challenge, NTLMv2 관련 메타데이터로 Response를 만듭니다.
4. 서버는 응답을 검증합니다. **도메인 계정**이라면 서버가 보통 **Netlogon 보안 채널**로 DC에 검증을 요청합니다. **서버의 로컬 계정**이면 로컬 SAM의 비밀정보로 검증할 수 있습니다.
5. 인증이 성공하면 서버가 리소스에 대한 **별도의 접근 권한 검사**를 수행합니다.

**DC에 비밀번호가 그대로 전송되는 것이 아닙니다.** 서버는 Challenge·Response·신원 관련 데이터를 검증에 활용합니다. NTLM 구현은 플랫폼·보안 정책에 따라 메시지 보호와 세션 키를 제공하지만 이것이 서버 대상 식별을 Kerberos와 동등하게 만들어주지는 않습니다.

## 4. Kerberos와 NTLM 비교

| 항목 | Kerberos | NTLMv2 |
| --- | --- | --- |
| 신원 확인 | KDC 기반 서비스 티켓 | Challenge–Response |
| 서비스 식별 | SPN과 서비스 티켓 보호 | Kerberos처럼 SPN에 암호학적으로 묶이는 인증 방식은 아님 |
| 상호 인증 | 지원 | 상대적으로 취약한 서버 신원 검증 |
| 대표 통신 | DC TCP/UDP 88 + 실제 서비스 포트 | SMB 445, HTTP(S), RPC 등 실제 응용 프로토콜 내부 |
| 주요 공격 | Kerberoasting, Golden/Silver Ticket | Relay, NetNTLM Capture, Pass-the-Hash |
| 권장 방향 | 가능한 곳에서 우선 | 감사 후 의존성을 단계적으로 축소 |

**SMB를 사용한다 = NTLM을 사용한다**가 아닙니다. SMB는 Kerberos로도 인증할 수 있습니다. 반대로 NTLM은 SMB 이외의 여러 애플리케이션 인증에서도 사용됩니다.

## 5. NTLM 인증이 도메인 컨트롤러에서 검증되는 구조

| 계정 | 검증 위치·조건 |
| --- | --- |
| **도메인 사용자**가 도메인 멤버 서버에 NTLM 로그인 | 대개 대상 서버 → DC의 Netlogon pass-through 검증 |
| **대상 서버의 로컬 사용자** | 대상 서버의 로컬 SAM에서 검증 가능 |
| **도메인이 없는 독립형 Windows** | 로컬 계정 기반 인증 |
| **신뢰된 다른 도메인 계정** | 도메인 간 신뢰·Netlogon 경로 등에 따라 달라짐 |

**이 차이는 DFIR에서 중요합니다.** 도메인 계정 검증 시 **DC의 4776**을, 실제 SMB 접속이 이루어진 **파일 서버의 4624 Logon Type 3**을 함께 볼 수 있습니다. 다만 4776의 Workstation 정보가 곧 실제 TCP 출발지 IP는 아니므로 대상 호스트·네트워크 로그를 함께 확인해야 합니다.

## 6. LLMNR, NBT-NS, mDNS, WPAD가 NTLM과 연결되는 방식

NTLM 악용은 항상 NTLM 프로토콜 자체에서 시작하는 것은 아닙니다. **이름 조회의 잘못된 신뢰**와 **원격 인증 자동 시도**가 출발점이 될 수 있습니다.

- **LLMNR:** 일부 Windows 네트워크에서 DNS 조회 실패 후 로컬 링크 이름을 찾는 메커니즘.
- **NBT-NS:** 레거시 NetBIOS 이름 조회.
- **mDNS:** 로컬 멀티캐스트 이름 조회; 환경·OS·애플리케이션에 따라 동작이 다름.
- **WPAD:** 웹 프록시 자동 발견. 잘못된 프록시 정보를 신뢰하면 프록시 인증 유도 등 위험이 발생할 수 있음.
- **UNC 경로:** `\\untrusted-host\share` 같은 경로로 접근하는 동작이 외부/비정상 SMB 인증을 시작할 수 있음.

이들 모두가 **항상 NTLM을 발생시키거나 항상 취약하다는 뜻은 아닙니다.** 공격 가능성은 이름 해석 순서, 캐시, 정책, 네트워크 구간, 인증 설정에 따라 달라집니다.

### Responder는 무엇을 하나요?

**Responder**는 로컬 이름 조회를 악용해 가짜 서비스 응답을 제공하거나 인증 교환을 수집하는 도구로 알려져 있습니다. 보안팀은 Responder를 사용한 공격을 이해할 때 **수상한 LLMNR/NBT-NS 응답, 가짜 SMB/HTTP 서비스, 예상하지 못한 NTLM 인증 목적지**를 살펴봐야 합니다.

단순히 가짜 이름 응답에 성공했다고 **평문 비밀번호나 NT Hash가 곧바로 탈취되는 것은 아닙니다.**

## 7. 주요 NTLM 공격 세 가지를 반드시 구분하세요

![NTLM Capture NTLM Relay Pass the Hash 공격 차이]({{ '/assets/diagrams/ntlm-attacks-ko.svg' | relative_url }})

| 공격 | 공격자가 가진 것 | 공격 목표 | 비밀번호 복구 필수? |
| --- | --- | --- | --- |
| **NTLM Capture** | 네트워크에서 관찰한 NetNTLM 응답 | 약한 암호에 대한 오프라인 추측 등 | 응답 활용 목적에 따라 다름 |
| **NTLM Relay** | 지금 진행 중인 NTLM 인증 교환을 중계할 위치·조건 | 피해자 신원으로 다른 서버에 인증 | **아니요** |
| **Pass-the-Hash (PtH)** | 이미 얻은 **NT Hash** | 비밀번호 원문 없이 NTLM 인증 | **아니요** |

### 7.1 NTLM Capture

피해자의 클라이언트가 잘못된 SMB/HTTP 서버에 인증하려고 할 때, 서버 Challenge와 클라이언트 Response 등의 자료가 관찰될 수 있습니다. 이는 **오프라인 비밀번호 추측을 위한 재료**가 될 수 있지만 **NT Hash 그 자체는 아닙니다.**

**탐지:** 낯선 내부 호스트로의 TCP 445/HTTP 연결, 이름 조회 조작 정황, 인증 대상 서버의 갑작스러운 변화, 엔드포인트의 원격 파일 접근 흔적을 확인합니다.

### 7.2 NTLM Relay

공격자가 **피해자의 실시간 NTLM 교환을 제3의 서비스로 전달**해 대상 서비스가 피해자를 인증된 신원으로 받아들이도록 유도합니다.

**성공 조건은 대상 프로토콜의 보호 기능과 실제 계정 권한에 달려 있습니다.** 예를 들어 SMB 서버가 서명을 필수로 요구하는 경우 공격자가 인증 후 세션에 유효한 SMB 서명을 만들기 어려우므로 일반적인 SMB 대상 Relay를 차단할 수 있습니다.

하지만 **SMB에서 시작한 인증을 LDAPS나 HTTP 같은 다른 서비스로 중계**하려는 시나리오에서는 해당 대상의 **Channel Binding/EPA 및 인증 정책**이 중요합니다. Signing을 한 군데서 켰다고 모든 릴레이 문제가 사라지는 것은 아닙니다.

### 7.3 Pass-the-Hash

이 공격에서는 이미 확보한 NT Hash를 이용합니다. 공격자가 **해시를 직접 알고 있기 때문에** NTLM 응답 및 해당 세션 보안에 필요한 계산을 수행할 수 있습니다. 따라서 **SMB Signing만으로 PtH를 원천 차단할 수 없습니다.**

계정 자체가 해당 서버에 로그인·관리할 권한이 있어야 하며 네트워크·NTLM 제한 정책이 허용해야 합니다. PtH 공격 가능성을 줄이려면 **NT Hash 탈취 방지, 관리자 계정 분리, NTLM 축소, LAPS, Credential Guard, 최소 권한**이 중요합니다.

## 8. SMB Signing, LDAP Signing, LDAP CBT, EPA 차이

| 보안 통제 | 적용 위치 | 대표적 역할 |
| --- | --- | --- |
| **SMB Signing** | SMB 클라이언트·서버 | 서명 없는 SMB 메시지 거부로 일반적인 SMB 대상 Relay 방어 |
| **SMB Encryption** | SMB 3.x | 전송 내용의 기밀성·무결성 보호 |
| **LDAP Signing** | LDAP SASL 세션 | 메시지 무결성. **이것만으로 모든 NTLM→LDAP Relay가 막히는 것은 아님** |
| **LDAP Channel Binding (CBT)** | TLS로 보호된 **SASL LDAP/LDAPS** | 인증 교환을 해당 TLS 세션에 묶어 TLS 간 Relay 방어 |
| **HTTP Extended Protection for Authentication (EPA)** | EPA를 지원·요구하는 웹 인증 엔드포인트 | 서비스·채널 바인딩 기반 릴레이 위험 축소 |
| **NTLM 차단** | OS/서비스 정책 | NTLM 사용 자체를 제한해 여러 공격 경로 제거 |

**중요한 2026년 기술적 주의점:** Microsoft의 최신 LDAP 보안 가이드는 **LDAP Signing이 메시지 무결성을 제공하지만 NTLM 릴레이 방어에는 별도 요건이 존재**한다고 설명합니다. 특히 **LDAPS에 TLS만 적용하고 CBT를 적용하지 않으면** NTLM 인증을 다른 TLS 세션으로 중계하는 위험이 남을 수 있습니다.

LDAP **Simple Bind**와 **SASL Bind**는 구분해야 합니다. CBT는 TLS로 보호된 **SASL 인증**에 적용되며, 단순 바인드의 보안 요구사항을 동일한 방식으로 설명하면 안 됩니다.

참고: [Microsoft LDAP Signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing), [LDAP Channel Binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding), [SMB Signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing).

## 9. NTLM 인증과 강제 인증(Forced Authentication)

공격자는 사용자가 의도하지 않게 UNC 경로를 열거나 특정 Windows 기능이 원격 파일/서비스를 참조하도록 만들어 **서버나 사용자가 공격자가 제어하는 서비스에 먼저 인증하도록 유도**할 수 있습니다.

이 공격 계열은 MITRE **[T1187 Forced Authentication](https://attack.mitre.org/techniques/T1187/)**과 연결되며, 문서·아이콘·경로 참조 또는 특정 RPC 기반 시스템 행동과 연계될 수 있습니다.

**조사 질문:** 그 호스트가 왜 평소와 다른 서버로 인증했는가? 직전에 어떤 파일·프로세스·RPC·이름 조회 이벤트가 있었는가? 실제로 NTLM이 사용되었고 어느 계정·주소에 접근했는가?

## 10. 2026년 기준 Windows NTLM의 보안·제품 상태

Microsoft는 **NTLMv1 제거**, **NTLMv2의 장기적인 사용 중단(Deprecated)**, **Kerberos/Negotiate로의 전환**을 공식적으로 안내하고 있습니다. NTLMv2가 **2026년 10월 모든 Windows에서 이미 제거됐다**는 뜻은 아닙니다.

**Windows 11 24H2와 Windows Server 2025의 SMB 클라이언트**에는 **원격 SMB 연결의 NTLM 차단 기능**이 제공됩니다. 이 기능은 SMB **클라이언트 측 제어**이며 다른 모든 애플리케이션의 NTLM을 자동으로 차단하는 기능과 구별해야 합니다.

또한 최신 Windows의 NTLM 정책에는 **Audit(감사) → Block(차단)**으로 이동할 수 있는 설정이 있습니다. 단, 적용 가능 OS·에디션·관리 방식과 허용 목록은 정책별로 달라집니다.

**운영상 주의:** NTLM 차단을 서둘러 적용하면 구형 NAS, IP 기반 공유, 자체 개발 서비스, 도메인 밖 시스템의 로그인이 끊어질 수 있습니다. 따라서 먼저 **의존 시스템을 기록하고 Kerberos/SPN/DNS를 정리**해야 합니다.

공식 자료: [Microsoft NTLM 개요](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview), [Windows Server의 제거·사용 중단 기능](https://learn.microsoft.com/en-us/windows-server/get-started/removed-deprecated-features-windows-server), [SMB NTLM Blocking](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking), [NTLM Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-ntlm).

## 11. Windows NTLM 이벤트: 어디에서 어떤 증거를 확인하나요?

![NTLM 다층 방어 및 감사 흐름]({{ '/assets/diagrams/ntlm-defense-ko.svg' | relative_url }})

| 데이터 | 기록 위치(일반적) | 확인할 사실 |
| --- | --- | --- |
| **4624** | 대상 서버의 Security | 로그인 성공, **Logon Type 3**, Authentication Package, NTLM Package Name, 출발지 |
| **4625** | 로그인 시도 대상 Security | 실패한 인증, Status/SubStatus, 출발지·대상 계정 |
| **4776** | **도메인 계정**이면 주로 DC Security | NTLM 인증 자격 증명 검증, 계정·워크스테이션·오류 코드 |
| **4672** | 로그인 호스트 Security | 로그인 시 특수 권한 부여 |
| **5140 / 5145** | SMB 리소스 서버 Security | 공유 접근, 개별 경로의 접근 권한 검사 |
| **7045** | 대상 시스템의 **System** | 새 Windows 서비스 설치 |
| **8001–8004 계열** | `Microsoft-Windows-NTLM/Operational` | NTLM 제한·감사 정책 활성화 시 관련 송신/수신/도메인 이벤트 |
| **DNS/LLMNR/NBT-NS** | 네트워크 센서·EDR | 비정상 이름 조회 또는 스푸핑 정황 |

### 4624: 실제 NTLM 버전 필드

4624의 **Authentication Package = NTLM** 여부를 먼저 확인하고, 이어 **Package Name (NTLM only)**에서 `NTLM V1` 또는 `NTLM V2`를 확인할 수 있습니다.

그러나 Microsoft 문서에는 **특정 레거시 환경에서 실제 NTLMv2 통신이 4624에 NTLMv1로 잘못 표시될 수 있는 사례**가 있으므로, 의심스러운 V1 기록은 OS·정책·네트워크 증거와 교차 검증해야 합니다.

### 4776: DC에서 얻을 수 있는 것과 없는 것

4776은 **도메인 계정의 NTLM 검증**을 찾는 핵심 이벤트이지만, 일반적인 형태에서 **접근 대상 서버의 정확한 서비스 이름과 실제 클라이언트 IP가 항상 기록되지는 않습니다.**

따라서 `4776`만으로 "어떤 파일 서버로 Relay를 했다" 또는 "PtH였다"라고 단정할 수 없습니다. **대상 서버 4624와 네트워크 통신/엔드포인트 로그**를 함께 봐야 합니다.

### NTLM Operational 감사

관리자가 NTLM 제한 관련 **Audit 정책**을 활성화한 환경에서는 `Applications and Services Logs → Microsoft → Windows → NTLM → Operational` 경로에서 관련 이벤트를 수집할 수 있습니다. **8001–8004**는 환경과 정책에 따라 관측될 수 있으며 **항상 전부 발생하는 기본 로그가 아닙니다.**

## 12. Splunk 탐지: 먼저 필드와 데이터 확인

### A. NTLM 인증 로그 존재 확인

```spl
index=* (EventCode=4624 OR EventID=4624 OR EventCode=4776 OR EventID=4776)
| stats count by host sourcetype EventCode EventID
| sort - count
```

검색 결과가 0건이면 **Windows Security 로그 감사·수집·인덱스·시간 범위·필드 추출**부터 확인하세요.

### B. 원격 NTLM 로그인 기준선 수립

```spl
index=* (EventCode=4624 OR EventID=4624)
| eval auth=coalesce(AuthenticationPackageName,Authentication_Package,AuthenticationPackage)
| eval logon=coalesce(LogonType,Logon_Type)
| eval src=coalesce(IpAddress,Source_Network_Address,src_ip)
| eval user=coalesce(TargetUserName,Account_Name,user)
| where lower(auth)="ntlm" AND tostring(logon)="3"
| stats count as ntlm_logons dc(user) as unique_users
        values(user) as users by host src
| sort - ntlm_logons
```

**주의:** Windows 이벤트의 `IpAddress`가 비어 있거나 `-`인 경우가 있습니다. 출발지는 EDR·방화벽·Zeek 데이터로 보강합니다.

### C. NTLMv1 가능성 점검

```spl
index=* (EventCode=4624 OR EventID=4624)
| eval auth=coalesce(AuthenticationPackageName,Authentication_Package,AuthenticationPackage)
| eval ver=coalesce(LmPackageName,Package_Name_NTLM_only,PackageName)
| where lower(auth)="ntlm"
| stats count by host ver
| sort - count
```

`LmPackageName` 등 필드명은 수집 형식마다 다릅니다. 이벤트 원본의 **Package Name (NTLM only)**을 우선 확인하고, 앞에서 설명한 레거시 오표시 가능성도 고려하세요.

### D. NTLM 인증 실패·계정 분포 탐지

```spl
index=* (EventCode=4776 OR EventID=4776)
| eval user=coalesce(TargetUserName,Account_Name,user)
| eval workstation=coalesce(Workstation,WorkstationName,Source_Workstation)
| eval status=lower(tostring(coalesce(Status,Error_Code)))
| where isnotnull(status) AND status!="0x0" AND status!="0"
| bin _time span=10m
| stats count as attempts dc(user) as users
        values(status) as status_codes by _time workstation
| where attempts>=15 AND users>=5
| sort - attempts
```

**성공코드 `0x0`을 제외한 실패 이벤트**를 집계합니다. 단, 4776의 오류코드 표현은 수집 도구마다 다를 수 있으므로 원본 이벤트와 필드명, 정상 관리 작업을 반드시 교차 확인하세요.

### E. NTLM Operational 감사 이벤트 찾기

```spl
index=* (EventCode=8001 OR EventCode=8002 OR EventCode=8003 OR EventCode=8004
         OR EventID=8001 OR EventID=8002 OR EventID=8003 OR EventID=8004)
| stats count by host sourcetype EventCode EventID
```

로그 채널 감사 정책 활성화 여부와 Splunk 입력 설정이 중요합니다.

## 13. 방어 구성 점검: 조회부터 시작

### A. SMB Signing 확인

```powershell
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
Get-SmbConnection
```

SMB Signing이 필수인지는 **양쪽 정책과 실제 연결 결과**로 확인합니다. Signing이 **Pass-the-Hash 자체를 막지 않는다는 점**도 기억하세요.

### B. NTLM 제한 관련 GPO 위치

```text
Computer Configuration
 └ Windows Settings
   └ Security Settings
     └ Local Policies
       └ Security Options
         ├ Network security: LAN Manager authentication level
         ├ Network security: Restrict NTLM: Audit NTLM authentication in this domain
         ├ Network security: Restrict NTLM: Audit Incoming NTLM Traffic
         └ Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
```

이름·지원 여부는 OS/GPO 버전에 따라 다를 수 있습니다. 가능하면 **Audit 설정으로 사용 현황을 먼저 수집**한 뒤 애플리케이션 소유자와 차단 계획을 수립하세요.

### C. 신규 Windows의 SMB 클라이언트 NTLM 차단 옵션

지원되는 Windows 버전에서 사용 가능 여부를 **먼저 조회**합니다.

```powershell
Get-SmbClientConfiguration | Format-List *NTLM*
```

`BlockNTLM` 같은 속성과 정책 기능은 OS 버전과 업데이트 수준에 따라 달라집니다. 차단 설정 변경은 레거시 공유 접속 중단 위험이 있으므로 별도 승인 후 시험 적용하세요.

### D. LDAP·HTTP 서비스 보안

- LDAP: **SASL Signing**, TLS 사용 시 **LDAP Channel Binding Token 요구**를 서비스 호환성에 맞게 적용합니다.
- HTTP/IIS·AD CS 웹 인증: 적용 가능한 **EPA** 구성과 NTLM 사용 축소를 검토합니다.
- SMB: Signing 요구와 필요 시 Encryption 적용을 확인합니다.
- 파일·관리 서버: 직원 PC 간 불필요한 TCP 445를 차단하고 원격 관리자 권한을 축소합니다.
- 자격 증명: Windows LAPS, Credential Guard, LSASS 보호, 관리자 계정 분리를 고려합니다.

## 14. 실전 DFIR: 의심 NTLM Relay / PtH 구별하기

**가상 상황:** `CLIENT01`이 평소 이용하지 않는 `SERVER02`로 NTLM 인증한 이후, `SERVER02`에서 관리자 공유 접근 및 서비스 설치가 발생했습니다.

1. **인증 신원:** `SERVER02`의 4624에서 `Authentication Package`와 `Logon Type`을 확인합니다.
2. **DC 확인:** 해당 도메인 계정의 4776을 조사하되, **4776의 워크스테이션 정보를 곧바로 네트워크 원본 IP로 단정하지 않습니다.**
3. **출발지:** EDR·Zeek `conn.log`·방화벽에서 실제 SMB/HTTP 연결 방향을 확인합니다.
4. **이름 조회:** 직전에 LLMNR/NBT-NS/WPAD나 UNC 기반 비정상 인증 유도가 있었는지 확인합니다.
5. **후속 행동:** `5140/5145 ADMIN$`, `7045`, `4688`, Sysmon의 프로세스·파이프를 연계합니다.
6. **가설 비교:** 실시간 인증 중계의 흔적이 있는지, 계정 NT Hash 탈취 정황이 있는지, 정식 관리·배포 작업인지 구별합니다.
7. **결론:** 단순 `4624 NTLM`만으로 **Relay 또는 PtH**를 확정하지 않고 추가 증거와 설정 상태로 판정합니다.
8. **대응:** 악성 활동이 확인되면 원본 호스트·계정 위험을 평가하고, 필요한 격리/계정 보호/서버 설정 수정 및 증거 보존을 조직 절차에 따라 수행합니다.

## 15. 오탐과 흔한 오해

- **“NTLM은 비밀번호를 평문으로 보낸다.”** 아닙니다. 챌린지-응답 방식입니다.
- **“NetNTLMv2 응답은 NT Hash다.”** 아닙니다. 계산된 네트워크 응답 자료입니다.
- **“강력한 비밀번호면 Relay도 막힌다.”** 아닙니다. Relay는 실시간 교환의 중계 문제입니다.
- **“SMB Signing이 켜지면 PtH도 불가능하다.”** 아닙니다. 유효 NT Hash를 소유한 공격은 별개입니다.
- **“LDAPS(TLS)이기만 하면 NTLM Relay는 사라진다.”** 아닙니다. TLS 기반 SASL 인증에서는 CBT가 중요합니다.
- **“LDAP Signing만 요구하면 모든 NTLM→LDAP Relay가 막힌다.”** 아닙니다. 실제 연결 방식과 CBT·인증 바인딩을 고려해야 합니다.
- **“Event 4776에 원본 클라이언트 IP가 모두 남는다.”** 아닙니다.
- **“Event 4624 NTLM V1이면 100% NTLMv1이다.”** 레거시 오표시 사례가 있어 검증이 필요합니다.
- **“NTLM을 즉시 끄는 것이 안전하다.”** 레거시 서비스가 중단될 수 있어 사용 현황과 예외를 먼저 확인해야 합니다.

## 16. NTLM을 줄이는 단계별 개선 계획

![NTLM 사용 현황 조사부터 Kerberos 우선 및 NTLM 제한까지 방어 단계]({{ '/assets/diagrams/ntlm-defense-ko.svg' | relative_url }})

1. **Inventory:** 네트워크 서비스, NAS, 앱, 서비스 계정, 사용 도메인을 조사합니다.
2. **Audit:** 대상 서버 4624, DC 4776, NTLM Operational 로그를 수집합니다.
3. **Repair:** DNS/SPN/Kerberos 장애를 해결하고 이름 대신 IP로 접속하는 관행을 줄입니다.
4. **Harden:** SMB Signing, 적절한 LDAP CBT/EPA, 관리자 권한 최소화, 자격 증명 보호를 적용합니다.
5. **Pilot:** 한정된 OU/호스트에서 NTLM 차단과 호환성 검증을 수행합니다.
6. **Enforce:** 검증된 범위로 확대하되 예외를 기록하고 만료·재검토합니다.
7. **Monitor:** 인증 실패와 신규 NTLM 의존성을 감시해 차단 정책을 유지합니다.

**운영 목표는 "NTLM 이벤트가 0건" 자체가 아니라**, 서비스 영향 없이 안전한 Kerberos 인증으로 이동하고 **NTLM에 의존한 공격 표면을 계획적으로 줄이는 것**입니다.

## 17. 관련 MITRE ATT&CK

| 기술 | 링크 | 관련성 |
| --- | --- | --- |
| **T1557.001** | [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001/) | 이름 조회 조작 및 NTLM Relay |
| **T1187** | [Forced Authentication](https://attack.mitre.org/techniques/T1187/) | 비정상 원격 인증 유도 |
| **T1550.002** | [Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) | 탈취 NT Hash로 인증 |
| **T1021.002** | [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) | 횡적 이동 |
| **T1110** | [Brute Force](https://attack.mitre.org/techniques/T1110/) | 온라인 비밀번호 시도 |
| **T1110.002** | [Password Cracking](https://attack.mitre.org/techniques/T1110/002/) | 캡처 응답 자료의 오프라인 추측 |

## 18. 확인 문제

1. **NTLMv2 인증 시 비밀번호 원문이 서버에 전송되나요?** 아니요.
2. **Responder로 수집한 NetNTLMv2는 곧바로 PtH에 필요한 NT Hash인가요?** 아니요.
3. **NTLM Relay에 약한 비밀번호가 반드시 필요한가요?** 아니요.
4. **SMB Signing은 모든 릴레이 대상 서비스를 보호하나요?** 아니요. 대상 서비스별 바인딩/인증 보호 필요.
5. **4776 하나로 PtH를 확정할 수 있나요?** 아니요.
6. **NTLM 차단 전 첫 단계는?** 사용 현황 감사와 Kerberos 의존성 정리.

## 19. 공식 참고 문서 및 다음 위키

- [Microsoft: NTLM Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview)
- [Microsoft: NTLM user authentication](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/ntlm-user-authentication)
- [Microsoft: Windows NTLM deprecation / removed features](https://learn.microsoft.com/en-us/windows-server/get-started/removed-deprecated-features-windows-server)
- [Microsoft: Block NTLM connections on SMB](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)
- [Microsoft: NTLM Policy CSP](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-ntlm)
- [Microsoft: Windows Security Event 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Microsoft: Windows Security Event 4776](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776)
- [Microsoft: SMB Signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing)
- [Microsoft: LDAP Signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing)
- [Microsoft: LDAP Channel Binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
- [위키: Active Directory 입문]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }})
- [위키: Kerberos 인증]({{ '/ko/wiki/kerberos-authentication/' | relative_url }})
- [위키: WPAD 보안]({{ '/ko/wiki/wpad-security/' | relative_url }})
- [위키: SMB 보안·원격 실행]({{ '/ko/wiki/smb-security/' | relative_url }})

**다음 추천 문서:** **4번 LDAP & AD Enumeration 완전 가이드** — LDAP 구조·검색 필터·권한·BloodHound 개념·탐지 및 방어.
