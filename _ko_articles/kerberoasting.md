---
translation_url: /wiki/kerberoasting/
title: "Kerberoasting과 RC4 티켓 탐지"
description: "Kerberos 서비스 티켓 요청과 Windows 이벤트 4769, RC4 사용의 의미를 연결해 조사합니다."
category: active-directory
tags: [Red Team, Blue Team, Active Directory, Kerberos, Detection Engineering]
level: Intermediate
updated: "2026-10-17"
---
## Kerberoasting 개요
Kerberoasting은 도메인 사용자가 SPN(Service Principal Name)에 대한 서비스 티켓을 요청한 뒤 암호화된 티켓 정보를 오프라인에서 분석하는 공격 방식입니다. 티켓 요청과 비밀번호 추측은 분리된 단계입니다.

## 조사해야 할 로그
도메인 컨트롤러의 **이벤트 ID 4769**가 핵심 조사 지점입니다.

| 필드 | 의미 |
| --- | --- |
| Ticket Encryption Type | 0x17은 RC4-HMAC 유형 |
| Account Name | 티켓 요청 계정 |
| Service Name | 서비스 티켓 대상 |
| Client Address | 요청 원본 주소 |

## 탐지 아이디어
짧은 시간에 한 계정이 다수의 서비스 티켓을 요청하고, 특히 RC4 암호화 유형이 집중된다면 추가 조사를 고려합니다.

1. 평소 계정의 서비스 티켓 요청량과 비교합니다.
2. 정상 애플리케이션과 오래된 서비스의 RC4 사용을 확인합니다.
3. 요청 원본 IP와 대상 서비스 계정의 관계를 분석합니다.
4. 관련 인증·프로세스 실행·네트워크 이벤트를 교차 검증합니다.

RC4를 사용했다는 사실 하나만으로 침해를 확정할 수는 없습니다.

## 대응과 예방
지원되는 환경에서 RC4 사용을 줄이고, 서비스 계정의 긴 무작위 암호 또는 gMSA 적용을 검토합니다.

## 참고
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft Event 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
