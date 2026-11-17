---
title: "정상 User-Agent 사전: 브라우저·앱·CLI·크롤러"
description: "34개 정상 제품·토큰의 이름과 뜻, 정상 사용을 확인하는 방법 및 공격 악용과의 경계를 정리합니다."
category: "blue-team"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/wiki/user-agent-normal-reference/"
user_agent_series: true
---
{% include ua-series.html %}

## 정상 제품 이름과 정상 요청은 다릅니다

이 표는 정상 소프트웨어가 사용하는 이름을 설명합니다. 그 이름을 가진 **모든 요청이 정상이라는 허용 목록**은 아닙니다. 제품의 실제 존재, 프로세스 서명·경로, 사용자·작업 소유자, 목적지, 호출 주기와 업무 승인을 확인해야 합니다. 악성코드가 동일한 값을 보낼 수 있고 정상 프로그램 자체가 악용될 수도 있습니다.

## 브라우저·앱 해석 순서

1. 구체적인 제품 토큰부터 찾습니다. `Edg/`, `OPR/`, `SamsungBrowser/`가 있으면 `Chrome/`만 보고 분류하지 않습니다.
2. 앱 내 웹뷰와 독립 브라우저를 구분합니다. Android의 `; wv`는 흔한 단서지만 앱이 UA를 바꿀 수 있습니다.
3. 제품 버전과 엔진 호환 숫자를 구분합니다. `Safari/537.36`을 Safari 앱의 최신 버전이라고 읽지 않습니다.
4. OS·기기 모델은 자기 신고·축약값일 수 있으므로 자산 DB와 비교합니다.
5. 같은 호스트의 여러 UA는 여러 앱·업데이트·병렬 작업 때문일 수 있습니다. 단독으로 UA 회전 공격을 뜻하지 않습니다.

Brave 같은 Chromium 제품은 일반 Chrome과 구별되는 고유 토큰을 항상 제공하지 않습니다. “모든 정상 제품을 UA만으로 구분하는 완벽한 파서”는 만들 수 없습니다. Teams·Slack·Discord 같은 앱도 내장 웹 엔진·운영체제·버전에 따라 형식이 달라집니다. 제품명이 UA에 반드시 들어간다고 가정하지 말고 관리 중인 버전으로 기준선을 수집합니다.

## CLI·개발 라이브러리 해석

`curl/8.x`, `python-requests/2.x`, `PowerShell/...`은 도구나 라이브러리 버전 단서입니다. 조직의 백업·배포·상태 검사·API 연계에서도 흔합니다. UA만 보면 스크립트 작성자·프로세스 경로·명령줄은 알 수 없습니다. `Go-http-client/1.1`의 `1.1`은 Go 언어 버전이 아닙니다. Java의 전통적 `Java/` 형식과 최신·외부 HTTP 라이브러리는 같지 않을 수 있습니다.

Node 환경도 Axios HTTP 어댑터, 내장 Fetch, 독립 Undici, 직접 HTTP 요청의 기본값이 다를 수 있습니다. 브라우저에서 실행되는 Axios는 브라우저 네트워크 계층을 사용하므로 서버측 `axios/`가 반드시 나오지 않습니다. 관리 도구·SDK의 기본값은 버전별 소스와 실제 샘플로 검증하세요.

## 크롤러 이름 검증

`Googlebot`이라는 UA만 믿고 WAF 우회를 허용하면 안 됩니다. Google이 공개한 IP 범위와 대조하거나, 역방향 DNS의 도메인 경계를 확인한 뒤 정방향 조회가 원래 IP로 돌아오는지 확인합니다. `googlebot.com.attacker.example`은 Google 도메인이 아닙니다. 신뢰할 프록시에서만 원래 출발지 헤더를 받아야 하며 임의 `X-Forwarded-For`는 검증 근거가 아닙니다.

OpenAI의 `GPTBot`, `OAI-SearchBot`, `ChatGPT-User`는 용도가 다릅니다. 운영자는 공급자의 최신 문서·IP 범위·robots 정책 적용 범위를 함께 확인합니다. `robots.txt`는 협력적인 크롤러에 대한 요청이며 인증·접근 통제 수단이 아닙니다. 이름 없는 봇을 악성코드로 자동 분류하지 않습니다.

## 검색 가능한 정상 참고표

`contains`는 토큰 포함, `prefix`는 시작 부분, `exact`는 전체 값 일치입니다. 검색창은 편의를 위한 **본문 부분 검색**이며 탐지 엔진이 아닙니다. 표에 표시된 실제 일치 방식과 혼동하지 마세요. 표의 모든 항목은 2026-11-17 검토 기준입니다.

{% include ua-catalog.html kind='normal' %}

## 표에 없는 흔한 정상 형태를 다루는 방법

`okhttp/`, `Apache-HttpClient/`, `CFNetwork/`, `Darwin/`, `Electron/`, `HeadlessChrome/`, `git/`, `AzureCLI/` 같은 표기를 만날 수 있습니다. 이 목록은 이름을 알아두기 위한 예시이며 여기서 각 버전의 기본값을 검증한 사전 항목은 아닙니다. 소스·공급자 문서·설치된 버전의 통신을 확인한 뒤 로컬 기준선에 추가하세요. 자동 브라우저도 헤드리스 표기를 숨기거나 일반 브라우저처럼 동작할 수 있으므로 헤드리스 문자열의 부재는 사람이 사용한다는 증거가 아닙니다.

## 오탐을 줄이는 허용 조건

허용 조건은 `UA만`이 아니라 `자산 그룹 + 실행 주체 + 승인 목적지 + 예정 시간 + UA 범위 + 만료일`로 만듭니다. 예를 들어 백업 서버의 Requests는 정상일 수 있지만 직원 PC에서 처음 등장해 외부 IP로 대량 POST하면 별도 조사가 필요합니다. rclone·RMM 등 정상 도구도 계정·전송 방향·작업 승인 없이 허용하지 않습니다.

## 추가 근거

[Google 요청 검증](https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests) · [OpenAI 봇 안내](https://developers.openai.com/api/docs/bots) · [Requests의 UA 변경 가능성](https://docs.python-requests.org/en/stable/community/faq/) · [악성 사용과 중복 사례]({{ '/ko/wiki/user-agent-malware-reference/' | relative_url }})

{% include ua-series.html %}

[Brave 공식 UA 안내 / Brave UA documentation](https://github.com/brave/brave-browser/wiki/Detecting-Brave-%28for-Websites%29)
