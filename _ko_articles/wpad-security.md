---
title: "WPAD 보안: 자동 프록시 검색, 스푸핑과 DFIR 분석"
description: "Windows의 WPAD 동작 원리, 악용 가능성, 네트워크 조사 방법과 방어 방법을 설명합니다."
category: network
tags: [Windows Security, WPAD, Network Security, NTLM, LLMNR, Responder, DFIR, Blue Team, Proxy Security]
level: Beginner
updated: "2026-10-17"
translation_url: /wiki/wpad-security/
---

## WPAD란?

**WPAD(Web Proxy Auto-Discovery)**는 Windows나 애플리케이션이 네트워크에서 사용할 **프록시 설정을 자동으로 찾는 메커니즘**입니다. WPAD 자체가 프록시 서버는 아닙니다. 대신 보통 `wpad.dat`라는 이름의 **PAC(Proxy Auto-Configuration)** 파일을 발견하며, PAC 파일은 연결을 직접 할지 어떤 프록시를 사용할지 규칙을 제공합니다.

쉽게 말하면 컴퓨터가 *“이 네트워크에서는 어떤 프록시를 써야 하나요?”*라고 묻는 기능입니다.

## 정상 동작 과정

1. 자동 프록시 검색이 활성화된 클라이언트가 주로 DHCP 또는 DNS를 통해 WPAD 위치를 찾습니다.
2. `wpad.example.com`을 조회하고 `http://wpad.example.com/wpad.dat` 같은 주소에서 PAC 파일을 받을 수 있습니다.
3. PAC 파일에 있는 JavaScript 규칙이 프록시 선택 방법을 지정합니다.
4. 이 설정을 지원하는 브라우저나 애플리케이션이 해당 규칙에 따라 웹 요청을 처리합니다.

예를 들어 다음은 **설명용** PAC 설정입니다.

```javascript
function FindProxyForURL(url, host) {
  return "PROXY proxy.example.com:8080; DIRECT";
}
```

모든 애플리케이션이 WPAD/PAC를 사용하는 것은 아니며, 실제 동작은 프로그램과 클라이언트 설정에 따라 다릅니다.

## 공격자는 WPAD를 어떻게 악용하나요?

공격자가 네트워크에서 WPAD 검색 결과를 조작할 수 있다면 정상 설정 서버를 사칭하여 악성 PAC 파일을 제공할 수 있습니다.

1. 피해자 PC가 WPAD 설정을 검색합니다.
2. 공격자가 가짜 위치 정보를 응답합니다(가능 여부는 네트워크 구성과 보안 설정에 따라 달라집니다).
3. 피해자 PC가 공격자가 제공한 PAC 파일을 다운로드합니다.
4. 지원되는 웹 요청이 공격자의 프록시로 향할 수 있습니다.
5. 특정 인증 및 정책 조건에서는 NTLM 인증 시도가 발생하여 공격자가 **NetNTLM 챌린지-응답** 데이터를 관찰할 가능성이 있습니다.

**중요:** WPAD를 검색했다는 사실만으로 평문 비밀번호, NT 해시 또는 인증 정보가 노출되지는 않습니다. **NetNTLM 챌린지-응답은 NT 해시 자체와 다르며**, 추가 조건에서 오프라인 비밀번호 추측 또는 릴레이 공격에 악용될 수 있습니다. 최신 Windows에는 WPAD 관련 자격 증명 자동 전송을 제한하는 보안 완화책도 있습니다.

### WPAD와 LLMNR / NBT-NS의 차이

| 기술 | 정상 목적 | 악용 가능성 |
| --- | --- | --- |
| WPAD | 프록시 설정 자동 발견 | 악성 PAC 파일 또는 가짜 프록시 |
| DNS | `wpad.example.com` 같은 이름 조회 | DNS 응답 변조 및 악성 서버 유도 |
| LLMNR / NBT-NS | 로컬 네트워크 이름 조회 | 가짜 이름 응답 및 연결 유도 |

즉, **WPAD는 찾으려는 설정이고 DNS/DHCP 등은 이를 발견하는 경로**입니다. 일부 환경에서는 로컬 이름 조회 방식과 결합될 수 있습니다. 따라서 LLMNR을 비활성화하는 것만으로 WPAD 위험 전체가 없어지는 것은 아닙니다.

## DFIR: 무엇을 확인해야 할까요?

- DNS 로그의 `wpad` 및 회사 WPAD 도메인 질의와 응답
- HTTP `/wpad.dat` 다운로드 요청, 출발지·목적지 IP, PAC 파일 내용
- 낯선 프록시 서버를 지정하는 PAC 규칙
- 여러 PC에서 갑자기 발생하는 동일 프록시 서버 연결
- 확인 가능한 경우 HTTP `407 Proxy Authentication Required` 및 `Proxy-Authorization`의 NTLM 흔적. **이것만으로 정보 탈취 성공을 증명할 수는 없습니다.**
- DNS/DHCP의 WPAD 레코드 변경과 endpoint 프록시 설정 변경

### 실전 조사 절차

1. 피해 PC의 자동 프록시 검색 활성화 여부와 정상 프록시 구성을 확인합니다.
2. 피해 PC에 반환된 WPAD 호스트명 및 IP를 식별합니다.
3. PAC 파일을 안전하게 확보하고 내용을 확인합니다. **신뢰하지 않는 PAC 파일을 분석가 PC에서 실행하지 마세요.**
4. 같은 시간대의 DNS, HTTP, 프록시, 네트워크 세션 및 엔드포인트 기록을 연관 분석합니다.
5. WPAD 질의만 보고 침해로 단정하지 말고 실제 인증 시도와 결과를 확인합니다.

### Splunk 탐색 쿼리 예시

```spl
index=* ("wpad.dat" OR "wpad")
| stats count values(uri) as uris values(dest_ip) as destinations by src_ip
| sort - count
```

이 쿼리는 **초기 탐색용 예시**입니다. 실제 인덱스, 필드명, 수집 범위와 정상 WPAD 패턴을 확인한 후 조정하세요.

## 방어 방법

- WPAD가 필요하지 않은 경우 Windows의 **자동으로 설정 검색(Automatically detect settings)** 기능을 비활성화합니다.
- 회사 DNS/DHCP WPAD 정보와 PAC 파일의 수정 권한을 제한합니다.
- 승인되지 않은 WPAD 서버와 프록시 목적지, NTLM 프록시 인증을 모니터링합니다.
- 불필요한 NTLM 사용을 줄이고 적용 가능한 환경에서는 SMB Signing을 강제하여 일부 SMB 릴레이 위험을 낮춥니다. **SMB Signing이 모든 WPAD 공격이나 모든 릴레이 공격을 차단하는 것은 아닙니다.**
- 기존 회사 프록시가 WPAD에 의존한다면 비활성화 전에 일부 사용자 그룹에서 기능 영향을 테스트합니다.

## 참고 자료

- [Microsoft: WinHTTP AutoProxy support](https://learn.microsoft.com/en-us/windows/win32/winhttp/winhttp-autoproxy-support)
- [Microsoft: Proxy Auto-Configuration (PAC) file](https://learn.microsoft.com/en-us/windows/win32/winhttp/proxy-auto-configuration-file)
- [Microsoft Security Bulletin MS16-077](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-077)
