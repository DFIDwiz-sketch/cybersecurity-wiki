---
title: "User-Agent 수집·헌팅·탐지: Splunk·Zeek·Suricata·Arkime"
description: "암호화 가시성, 필드 정규화, 희귀도·전체 일치 탐지, 프로세스 상관과 오탐 검증을 단계별로 설명합니다."
category: "blue-team"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/wiki/user-agent-hunting/"
user_agent_series: true
---
{% include ua-series.html %}

## 1. 어떤 위치에서 관측한 값인가

| 수집원 | UA 가시성 | 시작 전 확인할 사항 |
| --- | --- | --- |
| 평문 HTTP TAP/SPAN | 파서가 헤더를 읽으면 가능 | 양방향 수집·손실·비표준 포트·로그 설정 |
| HTTPS 패시브 TAP | 일반적으로 불가 | TLS 복호화 키·승인된 복호화 출력 유무 |
| 보안 프록시·WAF·웹 서버 | 해당 지점이 해석·기록한 요청에 가능 | TLS 종료 위치·로그 필드·길이 제한·원래 클라이언트 주소 |
| 종단 EDR·브라우저·앱 로그 | 제품·이벤트별로 다름 | UA 필드 실제 존재 여부; 네트워크 이벤트가 헤더를 항상 담지는 않음 |
| 클라우드 로그인 로그 | 서비스가 기록한 UA | 수집·정규화와 토큰 흐름에 따라 관측 의미가 다름 |

TLS 1.3·HTTP/2·HTTP/3에서도 UA가 사라진 것이 아니라 암호화된 애플리케이션 데이터에 들어갈 수 있습니다. 파서의 HTTP 버전 지원·복호화 연동은 설치 버전에서 확인합니다. TCP 443이라는 이유만으로 평문 HTTP 룰이 HTTPS 내용을 읽지 못합니다. SNI·인증서·JA4를 UA의 대체 원문으로 취급하지 마세요. 프록시는 값이나 주소를 바꿀 수 있으므로 어느 홉의 관측인지 기록합니다.

사용하시는 키트처럼 네트워크를 상시 수집하고 Velociraptor Hunt로 호스트 자료를 나중에 모은다면, 과거 프로세스 실행·네트워크 연결이 이미 사라졌을 수 있습니다. Sysmon 1·3과 보안 이벤트 4688은 정책·수집 설정·보존에 좌우되고 보통 HTTP UA 자체를 제공하지 않습니다. Hunt 당시 “현재 연결 없음”을 과거 통신 부재로 쓰지 마세요.

## 2. 원문 보존과 필드 정규화

| 소스 | 예시 UA 필드 | 출발지·연결 키 |
| --- | --- | --- |
| Zeek JSON `http.log` | `user_agent` | `id.orig_h`, `uid`, `trans_depth`, 시각 |
| Suricata HTTP EVE | `http.http_user_agent` | `src_ip`, `flow_id`, `tx_id`가 있으면 활용 |
| Splunk CIM Web | `http_user_agent` | `src`, `dest`, `url`, `http_method` |
| Elastic ECS로 매핑한 로그 | `user_agent.original` | `source.ip`, `destination.ip` 등 실제 매핑 확인 |
| Arkime 세션 검색 | `http.user-agent` | 세션·시각·IP·포트; 한 세션에 여러 값 가능 |

정규화는 원문을 덮어쓰지 말고 별도 `ua` 필드로 합니다. null, 빈 헤더, 필드 누락, Zeek TSV의 unset 표기 `-`는 서로 다릅니다. 길이 제한으로 잘린 값도 따로 표시하세요. UA에 공격 문자열·HTML이 들어갈 수 있으므로 분석 대시보드는 출력 이스케이프를 적용하고 로그 값을 실행하지 않습니다. Cookie·Authorization·토큰은 UA 조사에 필요하다는 이유로 무분별하게 수집·공유하지 않습니다.

## 3. Splunk: 먼저 필드와 기준선 확인

다음은 **설명용 SPL**입니다. `YOUR_WEB_INDEX`와 필드명을 실제 환경으로 바꾸세요. Splunk 서버에서 실행 검증한 룰이 아닙니다. JSON 중첩 필드 추출이 안 되면 sourcetype·`spath`·추출 설정을 먼저 확인합니다.

```spl
index=YOUR_WEB_INDEX earliest=-24h
| eval ua=coalesce(http_user_agent,user_agent,'http.http_user_agent','user_agent.original'),
       src=coalesce(src,src_ip,'id.orig_h'),
       dest=coalesce(dest,dest_ip,'id.resp_h'),
       method=coalesce(http_method,method,'http.http_method')
| eval ua_state=case(isnull(ua),"not_recorded",len(ua)=0,"empty",true(),"present")
| stats count dc(src) as hosts values(sourcetype) as feeds by ua_state
```

먼저 `present`가 충분히 나오는지 보세요. 전부 `not_recorded`라면 탐지 룰을 세게 만드는 것이 아니라 수집을 점검해야 합니다. 이후 같은 정규화를 사용해 UA별 호스트 수·목적지·최초/최종 시각을 비교합니다.

```spl
index=YOUR_WEB_INDEX earliest=-7d
| eval ua=coalesce(http_user_agent,user_agent,'http.http_user_agent','user_agent.original'),
       src=coalesce(src,src_ip,'id.orig_h'), dest=coalesce(dest,dest_ip,'id.resp_h')
| where isnotnull(ua) AND len(ua)>0
| stats count dc(src) as hosts dc(dest) as destinations min(_time) as first_seen max(_time) as last_seen by ua
| sort 0 hosts count
```

작은 `hosts`는 우선 검토할 희귀성입니다. 신규 설치 앱·관리 스크립트도 희귀합니다. 정기 배치와 짧은 기준선을 비교하면 오탐이 생기므로 자산 역할별로 14~30일 정도를 시작점으로 삼고 환경에 맞게 조정합니다. 긴 UA의 숫자를 전부 지우면 악성 식별값과 정상 앱을 합칠 수 있으므로 원문·파싱된 제품군을 둘 다 보관합니다.

## 4. 정확히 일치하는 후보와 기준선 차이

```spl
index=YOUR_WEB_INDEX earliest=-24h
| eval ua=coalesce(http_user_agent,user_agent,'http.http_user_agent','user_agent.original')
| where ua IN ("TeslaBrowser/5.5","record","rc2.0/client","Mozilla/4.08 (Charon; Inferno)")
| table _time src src_ip dest dest_ip ua http_method method url
```

여기서는 `record` 전체 값을 비교합니다. `like(ua,"%record%")`로 바꾸면 범위가 넓어집니다. CSV의 `pattern`을 일반 lookup 키로 사용해도 prefix·contains가 자동 적용되는 것은 아닙니다. 완전 일치 항목만 별도 테이블로 만들거나 매칭 모드를 명시적으로 구현하세요. 자동 대소문자 통합도 원문 일치와 다른 정책입니다.

“처음 본 UA”는 지난 기간에 없던 값이어야 합니다. 현재 검색 결과의 `min(_time)`만으로 조직 역사상 최초라고 쓰지 않습니다. 기준선 저장·보존·수집 장애를 함께 확인하세요. `new UA + new destination + unusual process + repeated POST`처럼 독립 단서가 겹치면 조사 우선순위가 높아집니다. 헤더 순서·TLS 지문도 보조 단서일 뿐 단독 신원 증명은 아닙니다.

## 5. Zeek·Suricata 로그를 직접 보기

JSON Lines 형식의 **Zeek 로그**에서 원래 문자열과 횟수를 확인하는 예입니다. TSV 입력에는 그대로 적용되지 않습니다.

```bash
jq -r 'select(.user_agent != null) | .user_agent' http.json | sort | uniq -c | sort -nr
```

JSON Lines 형식의 Suricata EVE에서 HTTP 트랜잭션만 꺼냅니다. alert 이벤트만 저장해 왔다면 HTTP 자료가 없을 수 있습니다.

```bash
jq -c 'select(.event_type == "http") | {timestamp,src_ip,dest_ip,flow_id,http}' eve.json
```

Zeek는 같은 수집 범위 안에서 `uid`로 연결·DNS·HTTP 기록을 보완할 수 있지만 한 연결에 여러 트랜잭션이 있으므로 시간·깊이를 확인합니다. Suricata `flow_id`와 Zeek `uid`는 같은 ID가 아닙니다. 도구 사이 상관은 시간·센서 위치·5-tuple·설정한 Community ID 등으로 검증합니다. NAT·프록시·로드밸런서가 있으면 주소와 포트가 변할 수 있습니다.

## 6. Suricata 실험용 룰

```text
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"LOCAL UA candidate TeslaBrowser exact"; flow:established,to_server; http.user_agent; content:"TeslaBrowser/5.5"; bsize:16; sid:9900101; rev:1;)
```

이것은 학습용 로컬 룰이며 설치·실행 검증된 운영 룰이 아닙니다. 길이 16바이트인 문자열의 전체 버퍼 일치를 의도합니다. `nocase`를 추가하면 대소문자 변형도 포함하는 다른 조건이 됩니다. 로컬 SID 충돌·HOME_NET/EXTERNAL_NET·HTTP 파서·정규화·룰 로딩을 확인하고 다음처럼 **설치된 버전**에서 문법 검사와 테스트 PCAP 재생을 수행합니다.

```bash
suricata -T -c /etc/suricata/suricata.yaml -S ua-local.rules
```

통과는 구성 문법 확인이며 탐지 정확도나 복호화 성공을 증명하지 않습니다. 정확한 값·뒤에 추가 문자가 있는 값·정상 브라우저·암호화만 있는 트래픽으로 각각 검증합니다. HTTPS PCAP에서 이 룰이 경보를 내지 않는 것은 문자열이 안전해서가 아니라 가시성 한계일 수 있습니다.

## 7. Wireshark·Arkime에서 원문 확인

Wireshark 평문 HTTP 표시 필터 예:

```text
http.user_agent == "TeslaBrowser/5.5"
```

Arkime 검색식·FAQ 예:

```text
http.user-agent == "TeslaBrowser/5.5"
```

필드는 각각 다릅니다. 설치 버전의 필드 자동완성과 실제 수집 여부를 확인하세요. 검색 후 시각·양 끝점·요청·응답과 보존된 패킷을 확인합니다. 세션 검색 결과가 있어도 PCAP은 삭제됐을 수 있습니다. HTTP/2·HTTP/3는 파서·복호화 조건에 따라 해당 필드가 다를 수 있습니다.

## 8. 경보에서 사건 판단으로

1. 원문·이벤트 ID·수집원·시간대·정규화 결과를 보존합니다.
2. 출처의 UA와 **어떤 방식으로** 일치하는지 기록합니다.
3. 자산 역할·승인된 앱·관리 시간·목적지 기준선을 확인합니다.
4. 같은 호스트·계정의 DNS·URL·전송량·로그인·프로세스를 연결합니다. POST나 HTTP 200만으로 유출·감염 성공을 확정하지 않습니다.
5. 의심 프로세스의 경로·서명·해시·부모 프로세스·실행 시각을 수집합니다. 주입 가능성 때문에 브라우저 프로세스 이름만으로 종결하지 않습니다.
6. 확보된 근거에 따라 격리·세션 대응·추가 수집을 결정하고, 조치 요청과 실제 완료를 구분합니다.

**완료 기준:** 재현 가능한 검색, 원문 근거, 정상 사용 검토, 독립된 보강 증거, 판단 한계, 조치·후속 검증 담당자가 기록되어 있어야 합니다.

## 공식 참고

[Zeek HTTP 로그](https://docs.zeek.org/en/current/reference/logs/http.html) · [Suricata HTTP 키워드](https://docs.suricata.io/en/suricata-8.0.8/rules/http-keywords.html) · [Arkime 검색식·FAQ](https://arkime.com/faq#where-do-i-learn-more-about-the-expressions-available) · [Arkime HTTP 파서 필드 정의](https://github.com/arkime/arkime/blob/main/capture/parsers/http.c) · [Wireshark HTTP 필드](https://www.wireshark.org/docs/dfref/h/http.html) · [Splunk 공급자 탐지](https://research.splunk.com/network/8c4866e4-f488-4253-8537-7dc4f954c292/)

{% include ua-series.html %}
