---
title: "User-Agent 구조와 이름의 뜻"
description: "Mozilla, WebKit, KHTML, Gecko, Chrome, Safari, Windows NT와 Client Hints를 구분합니다."
category: "network"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/wiki/user-agent-anatomy/"
user_agent_series: true
---
{% include ua-series.html %}

## 1. 요청에서 어느 위치에 있는가

```http
GET /guide HTTP/1.1
Host: portal.example
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0
Accept: text/html
```

문서용 호스트와 설명용 버전을 사용한 요청입니다. `User-Agent`는 요청 헤더 이름이고 콜론 뒤가 값입니다. HTTP 헤더 이름은 대소문자를 구분하지 않으므로 HTTP/2의 `user-agent`도 같은 필드입니다. **값의 대소문자·공백은 증거로 남겨야 합니다.** 프로토콜이 허용하는 대소문자 처리와 탐지 룰의 문자열 비교 방식은 별개입니다.

RFC의 기본 형식은 제품 이름과 선택적 버전·설명입니다. 여러 제품 토큰이 들어갈 수 있습니다. `CustomHealthCheck/1.0`처럼 짧은 값도 가능하고 UA를 보내지 않도록 구성할 수도 있습니다. 긴 Mozilla 형식이 의무는 아닙니다.

## 2. 긴 문자열을 부분별로 읽기

| 토큰 | 이름·의미 | 잘못된 해석 |
| --- | --- | --- |
| `Mozilla/5.0` | 역사적으로 이어진 호환성 표기 | Firefox 설치·버전 5라고 단정 |
| `Windows NT 10.0` | Windows 계열 플랫폼 표기 | Windows 11일 수 없다고 단정 |
| `Win64; x64` | 64비트 플랫폼 관련 표기 | 실제 프로세스·CPU를 인증한 값으로 취급 |
| `WOW64` | 보통 64비트 Windows에서 32비트 실행 환경을 나타내는 역사적 표기 | 이것만으로 악성 여부 판단 |
| `AppleWebKit/537.36` | WebKit 계보·호환성 토큰; Chromium에도 존재 | Apple 기기 또는 최신 WebKit 버전이라고 단정 |
| `KHTML, like Gecko` | KHTML·Gecko와의 호환성을 나타내는 역사적 설명 | Gecko 엔진을 실제 사용하는 증거로 취급 |
| `Chrome/140.0.0.0` | Chromium 계열 호환·제품 버전 토큰 | 실제 요청 프로그램이 반드시 Chrome이라고 단정 |
| `Safari/537.36` | Safari 관련 호환성 토큰 | 이 숫자를 Safari 앱 버전으로 읽기 |
| `Edg/140.0.0.0` | Chromium 기반 데스크톱 Edge 표기 | 앞에 Chrome이 있으니 무시 |

제품 식별은 단순 첫 토큰보다 구체적인 표기를 우선합니다. 예제는 **Edge를 자처하는 요청**입니다. 같은 형식은 코드로 직접 만들 수 있으므로 실제 Edge 실행 여부는 EDR·프로세스 자료로 확인합니다.

## 3. 다른 정상 형식도 해석하기

Firefox 계열에서는 `rv:`가 Gecko 버전 관련 정보이고, `Gecko/20100101`은 흔히 고정된 호환 날짜입니다. 이 날짜가 2010년이라고 브라우저를 2010년 제품으로 판정하지 않습니다. Safari는 `Version/`와 `Safari/`가 서로 다른 역할을 합니다. `Version/`이 앱 버전 판단에 더 직접적인 단서입니다. iOS용 `CriOS`, `FxiOS`, `EdgiOS`는 제품 표기이며 엔진·플랫폼 정책은 버전·지역에 따라 별도 확인해야 합니다.

운영체제 표기에서 `X11`, `Linux x86_64`, `Macintosh`, `Intel Mac OS X`, `Android`, `iPhone`, `CPU iPhone OS`를 만날 수 있습니다. 언어 토큰 `en-US`가 있어도 사용자 국적이나 위치를 증명하지 않습니다. `U`는 과거 형식의 보안 관련 표기이며 사용자 계정을 뜻하지 않습니다. `Mobile`은 모바일 형식 단서이지 물리적 휴대전화 인증이 아닙니다. 앱 내 웹뷰·데스크톱 모드·위장 설정을 고려합니다.

## 4. UA Reduction 때문에 달라진 판단

UA Reduction은 추적에 쓰일 수 있는 세부 정보를 줄이는 브라우저 동작입니다. 지원하는 Chromium 브라우저에서는 패치 숫자를 `0.0.0`으로 고정하거나 Android 버전·기기 모델을 축약할 수 있습니다. 따라서 `Android 10; K` 또는 고정된 macOS 표기를 곧바로 오래된 실제 OS·악성코드로 분류하지 않습니다.

Windows 10과 11이 모두 `Windows NT 10.0`으로 나타날 수 있습니다. 정확한 OS·아키텍처는 관리 자산·호스트 수집으로 검증하는 편이 낫습니다. 제품 메이저 버전이 장기간 고정되었다면 관리형 업데이트 정책·임베디드 앱·레거시 제품 여부를 확인한 뒤 이상 징후로 다룹니다. “오래된 숫자 = 악성” 룰은 오탐을 만듭니다.

## 5. User-Agent Client Hints 읽기

```http
Sec-CH-UA: "Chromium";v="140", "Microsoft Edge";v="140", "Not_A Brand";v="99"
Sec-CH-UA-Mobile: ?0
Sec-CH-UA-Platform: "Windows"
```

설명용 예입니다. `Sec-CH-UA`는 브랜드·버전 목록, `?0`은 모바일 힌트의 false, `?1`은 true를 나타냅니다. `Accept-CH` 응답으로 추가 힌트를 요청할 수 있지만 브라우저 지원·권한·정책·연결 조건에 따라 제공 범위가 다릅니다. 이상해 보이는 브랜드는 파서가 특정 브랜드 배열에 고착되지 않게 하는 **GREASE** 값일 수 있습니다.

UA-CH와 UA의 불일치는 조사할 단서이지만 위조 방지 서명은 아닙니다. 비브라우저 클라이언트는 비슷한 헤더를 구성할 수 있습니다. `Sec-CH-UA`가 없다는 것만으로 악성으로 판정하지 않습니다. 브라우저 지원 차이와 프록시 제거도 확인합니다.

## 6. UA와 혼동하면 안 되는 값

| 값 | 위치·역할 | 조사 시 한계 |
| --- | --- | --- |
| HTTP UA | 요청 애플리케이션의 자기 신고 | 위조·생략 가능 |
| `Server` | HTTP 응답 서버 제품 표기 | 숨기거나 변경 가능 |
| TLS SNI | TLS 연결의 서버 이름 관련 정보 | HTTP UA와 다르며 ECH로 가려질 수 있음 |
| JA3·JA4 | TLS 등 프로토콜 특성의 파생 지문 | 공유·변경·충돌·우회 가능; 사용자 신원 아님 |
| `navigator.userAgent` | 브라우저 JavaScript에서 읽는 값 | 프록시 로그의 헤더와 수집 지점이 다름 |
| 이메일 `User-Agent`·`X-Mailer` | 일부 메일 클라이언트의 메일 헤더 | 여기의 HTTP 탐지 규칙을 그대로 적용하지 않음 |

## 확인 문제

1. `Chrome/... Safari/... Edg/...`는 무엇을 자처하는가? → Edge입니다. 실제 프로세스는 미확인입니다.
2. `Gecko/20100101`이면 2010년 브라우저인가? → 고정 토큰일 수 있으므로 아닙니다.
3. `Windows NT 10.0`이면 Windows 11이 아닌가? → 둘을 구분하지 못할 수 있습니다.
4. TLS 연결만 수집하면 UA가 보이는가? → 복호화된 HTTP·종단 로그가 없으면 일반적으로 보이지 않습니다.

## 출처

[HTTP 표준](https://www.rfc-editor.org/rfc/rfc9110.html#name-user-agent) · [MDN UA reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/User-Agent) · [UA Reduction](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/User-agent_reduction) · [Microsoft Windows 11 탐지 안내](https://learn.microsoft.com/en-us/microsoft-edge/web-platform/how-to-detect-win11) · [Chrome UA-CH와 GREASE](https://developer.chrome.com/docs/privacy-security/user-agent-client-hints)

{% include ua-series.html %}
