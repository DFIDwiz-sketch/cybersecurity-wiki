---
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
