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
