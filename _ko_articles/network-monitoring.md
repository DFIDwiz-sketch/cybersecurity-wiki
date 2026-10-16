---
translation_url: /wiki/network-monitoring/
title: "Zeek, Suricata, Arkime 비교"
description: "네트워크 로그, 침입 탐지 경보와 패킷 세션 탐색의 역할을 비교합니다."
category: network
tags: [Blue Team, Network Security, Zeek, Suricata, Arkime, DFIR]
level: Beginner
updated: "2026-10-17"
---
## 함께 사용하는 이유
각 도구의 강점은 서로 다릅니다.

| 도구 | 주요 기능 |
| --- | --- |
| Zeek | 프로토콜 메타데이터와 연결 로그 |
| Suricata | 탐지 룰 기반 경보와 프로토콜 정보 |
| Arkime | 세션 탐색과 패킷 검토 |

## 확인할 것
네트워크 TAP의 위치와 트래픽 가시성, 암호화 여부, 패킷 손실 및 각 데이터의 수집 지연을 함께 점검합니다.
