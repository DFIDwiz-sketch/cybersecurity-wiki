---
title: "User-Agent 종합 가이드: 정상 이름부터 악성코드 조사까지"
description: "100개 참고 항목과 6개 학습 글로 User-Agent의 뜻, 정상·악성 중복, 근거와 조사 방법을 익힙니다."
category: "blue-team"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/wiki/user-agent-guide/"
user_agent_series: true
---
{% include ua-series.html %}

## 이 가이드에서 다루는 범위

User-Agent(UA)는 웹 요청을 보낸 소프트웨어가 **자신을 어떻게 소개했는지** 기록한 값입니다. 브라우저뿐 아니라 업데이트 서비스, API 프로그램, 검색 로봇, 보안 스캐너와 악성코드도 보냅니다. 서버는 화면 호환성·통계·문제 해결 등에 활용하고, 블루팀은 드물거나 부자연스러운 통신을 찾는 보조 단서로 사용합니다.

**2026-11-17에 검토한 공개 자료를 바탕으로 100개 참고 항목을 수록했습니다.** 정상 클라이언트 34개, 악성코드 보고·정상과의 중복·탐지 룰 후보 66개입니다. 일부는 전체 문자열, 일부는 제품 토큰·접두사이므로 “100개 악성코드” 또는 “100개의 독립적인 완전한 UA”를 뜻하지 않습니다.

전 세계에서 관측된 모든 비정상 UA의 완전한 목록은 만들 수 없습니다. 누구나 임의 문자열을 만들 수 있고, 비공개 관측·새 변종·맞춤형 설정도 존재합니다. 이 문서의 관측은 **출처 보고서의 관측**이며, 사용자 조직의 실제 로그를 분석한 결과가 아닙니다. 목록에 없는 악성코드도 정상 브라우저와 똑같은 UA를 사용할 수 있습니다.

## 학습 순서와 결과물

| 순서 | 문서 | 읽고 할 수 있어야 하는 일 |
| --- | --- | --- |
| 1 | [구조와 토큰의 뜻]({{ '/ko/wiki/user-agent-anatomy/' | relative_url }}) | Mozilla·WebKit·Gecko·운영체제·제품 버전 구분 |
| 2 | [정상 브라우저·앱·도구 사전]({{ '/ko/wiki/user-agent-normal-reference/' | relative_url }}) | 제품 이름을 해석하고 정상 사용의 검증 자료 찾기 |
| 3 | [악성코드 연관 문자열 사전]({{ '/ko/wiki/user-agent-malware-reference/' | relative_url }}) | 출처·기간·일치 방식·오탐 가능성을 포함한 후보 작성 |
| 4 | [수집·헌팅·탐지]({{ '/ko/wiki/user-agent-hunting/' | relative_url }}) | 가시성을 점검하고 Splunk·네트워크 자료와 프로세스 증거 연결 |
| 5 | [가상 로그 실습]({{ '/ko/wiki/user-agent-lab/' | relative_url }}) | 20건을 분석해 관측 사실·가설·미확인 사항을 분리 |

## 가장 먼저 기억할 판단 원칙

- `Mozilla`가 있다고 Firefox라는 뜻은 아닙니다. Chrome과 Edge에도 나옵니다.
- `Safari`가 있다고 Safari 브라우저라는 뜻은 아닙니다. Chromium 호환 문자열에도 포함됩니다.
- `python-requests`, `curl`, `PowerShell`은 정상 도구입니다. 공격에 쓰였다는 보고만으로 전체 도구를 악성으로 분류하지 않습니다.
- `Windows Defender`라는 UA는 보안 제품의 서명이나 인증이 아닙니다. BunnyLoader 샘플에서도 위장 이름으로 보고됐습니다.
- HTTPS의 UA는 TLS 안에 있습니다. 일반적인 패시브 TAP에서 암호화 상태로는 읽을 수 없습니다.
- UA 일치는 **조사할 후보**입니다. 악성코드 종류·공격자·감염 성공을 확정하는 증거가 아닙니다.

## 원자료와 다운로드

[전체 CSV]({{ '/assets/data/user-agents.csv' | relative_url }}) · [전체 JSON·출처 목록]({{ '/assets/data/user-agents.json' | relative_url }})

각 항목은 ID, 분류, 문자열·패턴, 일치 방식, 연관 이름, 설명, 근거 유형, 출처 URL·대상 기간, 검토일, 한계를 포함합니다. `reviewed`는 편집자가 확인한 날짜이며 최초·최종 감염 관측일이 아닙니다. `source_period`가 과거이면 현재 유행을 증명하지 않습니다. CSV/JSON은 **자동 차단 목록이 아닙니다.**

## 이후 항목을 추가하는 기준

새 문자열은 원문·공백·대소문자·원자료의 이벤트 ID를 먼저 보존합니다. 보고서에 다운로드 단계의 UA가 나왔다면 최종 악성코드 C2의 UA라고 바꾸어 적지 않습니다. 악성코드가 여러 개 투하됐다는 이유로 하나의 UA를 전부에 배정하지 않습니다. 새 항목에는 원출처와 관측 범위, 일치 방식을 넣고 정상 트래픽과 비교합니다. 검색 결과만 있고 분석 근거를 확인할 수 없으면 “검증 대기”로 남기는 편이 정확합니다.

## 근거 자료

- [RFC 9110 §10.1.5: User-Agent](https://www.rfc-editor.org/rfc/rfc9110.html#name-user-agent)
- [MDN: UA 구조](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent)
- [Splunk: HTTP Malware User Agent, 2026년 갱신](https://research.splunk.com/network/8c4866e4-f488-4253-8537-7dc4f954c292/)
- [악성코드 사례별 원출처]({{ '/ko/wiki/user-agent-malware-reference/' | relative_url }})

{% include ua-series.html %}

## HTTP 요청과 웹 로그 읽기

[HTTP 상태 코드와 프록시·앱 기록 대조 실습]({{ '/ko/wiki/http-evidence/' | relative_url }})
