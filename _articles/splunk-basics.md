---
title: "Splunk로 시작하는 로그 조사"
description: "인덱스와 시간 범위를 점검하고 보안 로그를 조사하는 기본 흐름을 정리합니다."
category: tools
tags: [Blue Team, DFIR, Splunk, SIEM, Logs]
level: Beginner
updated: "2026-10-17"
---
## 수집 범위부터 확인하기
로그 조사 전 인덱스·sourcetype·시간대와 수집 지연을 먼저 확인해야 합니다.

```spl
| tstats count where index=* by index
```

위 예시는 권한과 환경 설정에 따라 결과가 달라집니다.

## 조사 순서
1. 검색 가능한 데이터가 있는지 확인합니다.
2. 관련 계정, 호스트, IP로 탐색 범위를 좁힙니다.
3. 전후 사건과 다른 자료를 연결합니다.
4. 관찰한 사실과 가설을 분리하여 기록합니다.
