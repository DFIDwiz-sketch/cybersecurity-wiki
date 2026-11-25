---
translation_url: /wiki/windows-logs/
title: "Windows 보안 이벤트 조사 입문"
description: "Windows 인증과 프로세스 로그를 살펴보고 관련 이벤트를 연관 분석합니다."
category: dfir
tags: [DFIR, Blue Team, Windows, Event Logs]
level: Beginner
updated: "2026-10-17"
---
## 주요 이벤트
- **4624:** 로그온 성공
- **4625:** 로그온 실패
- **4688:** 프로세스 생성 (감사 정책 설정 필요)
- **4769:** Kerberos 서비스 티켓 요청

로그 수집 여부는 감사 설정과 정책에 영향을 받습니다. 단일 이벤트로 침해를 단정하지 마세요.

## Linux 인증 로그 조사

[SSH·PAM·sudo 로그와 오프라인 타임라인 실습]({{ '/ko/wiki/linux-auth-evidence/' | relative_url }})

## Windows 이벤트 전달 경로 확인

[원본·구독·수집기·SIEM의 공백을 구별하는 실습]({{ '/ko/wiki/wef-delivery-evidence/' | relative_url }})

## Windows 보안 그룹 변경 조사

[그룹 변경, 로그인과 자원 접근 기록을 같은 장비와 세션 범위에서 대조합니다]({{ '/ko/wiki/ad-group-membership-evidence/' | relative_url }})

## Windows 파일 공유와 NTFS 감사 증거 대조하기

[공유 검사와 파일 권한 사용을 가상 이벤트 여덟 건으로 구분합니다.]({{ '/ko/wiki/smb-file-audit-evidence/' | relative_url }})

## Windows App Control 이벤트 조사

[감사 판정, 실제 차단과 관련 서명 기록을 구분합니다.]({{ '/ko/wiki/app-control-evidence/' | relative_url }})

## Windows 로그 공백 이어서 읽기

[Windows 보안 로그 공백]({{ '/ko/wiki/windows-log-continuity/' | relative_url }}) · 로그 지우기와 보존 손실, 감사 정책 변경, 전달 문제를 구분합니다.

## RDP 세션 타임라인 조사

[RDP 세션 증거]({{ '/ko/wiki/rdp-session-evidence/' | relative_url }})에서 연결 해제, 재연결, 로그오프를 구분합니다.

## Active Directory 계정 잠금 조사

[계정 잠금 증거 추적하기]({{ '/ko/wiki/ad-account-lockout-evidence/' | relative_url }}) · 4740을 기준으로 앞선 인증 실패와 잠금 이후의 거절을 대조합니다.

## Windows 서비스 실행 증거 확인

[Windows 서비스 실행 증거]({{ '/ko/wiki/windows-service-runtime-evidence/' | relative_url }})에서 서비스 설치, 시작 상태, 프로세스 증거와 실제 기능을 확인하는 방법을 살펴봅니다.

## PowerShell 스크립트 블록 조사

[PowerShell 스크립트 블록 조사]({{ '/ko/wiki/powershell-script-block-evidence/' | relative_url }})에서 4104의 조각을 복원하고 프로세스와 실제 결과를 대조합니다.

## Windows 특권 로그온 이어서 조사하기

[Windows 특권 로그온 조사]({{ '/ko/wiki/windows-privileged-logon-evidence/' | relative_url }})에서 호스트와 부팅을 기준으로 특권 부여, 프로세스 토큰, 특권 사용 감사를 구분하세요.

## Windows WFP 연결 감사 조사

[Windows WFP 연결 허용·차단 조사]({{ '/ko/wiki/windows-wfp-connection-evidence/' | relative_url }})에서 Security 5156·5157의 로컬 판단을 프로세스와 서비스 증거에 대조합니다.
