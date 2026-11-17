---
title: "User-Agent 조사 실습: 20건의 가상 로그와 해설"
description: "외부 통신 없이 정상 도구, 악성 연관 문자열, 브라우저 위장, 암호화로 생긴 공백을 비교합니다."
category: "tools"
tags: ["Blue Team", "User-Agent", "HTTP", "Threat Hunting", "Malware Analysis"]
level: "Reference"
updated: "2026-11-17"
translation_url: "/wiki/user-agent-lab/"
user_agent_series: true
---
{% include ua-series.html %}

## 준비물과 실습의 범위

Python 3 표준 라이브러리만 사용합니다. 모든 이벤트·호스트·목적지·프로세스는 작성자가 만든 **가상 자료**입니다. `.example`과 문서용 IP 대역은 실제 IOC가 아닙니다. 악성코드를 실행하거나 외부 서버에 연결하지 않습니다. 여러 악성코드의 특징을 비교하는 교육 자료이며 한 호스트에서 모두 관측된 실제 사고 재현이 아닙니다.

[20건 JSONL]({{ '/assets/labs/user-agent/events.jsonl' | relative_url }}) · [분석기]({{ '/assets/labs/user-agent/analyze.py' | relative_url }}) · [참고 JSON]({{ '/assets/data/user-agents.json' | relative_url }}) · [워크북]({{ '/assets/labs/user-agent/worksheet.md' | relative_url }})

세 파일 `events.jsonl`, `analyze.py`, `user-agents.json`을 같은 폴더에 저장합니다. 로그는 여러 수집원을 단순화한 통합 학습 스키마이며 제품의 원본 내보내기 형식이 아닙니다.

## 1. 분석기를 실행하고 기대 결과 확인

```bash
python analyze.py events.jsonl user-agents.json
```

```text
events=20
ua_present=18 ua_empty=1 ua_unavailable=1
association_candidates=10
candidate_ids=E04,E05,E06,E07,E08,E09,E10,E11,E12,E20
```

후보 10건은 **감염 10건이라는 뜻이 아닙니다.** 분석기는 문헌과 문자열이 일치하는지만 확인하고 업무 승인·프로세스 진위·가족 귀속을 판정하지 않습니다. 패턴은 대소문자·공백을 보존하여 exact·prefix·contains별로 처리하며, 빈값과 미수집값은 패턴 대조에서 제외합니다.

## 2. 무엇이 정상·의심·미확인인가

| 이벤트 | 관측·상황 | 적절한 해석·다음 확인 |
| --- | --- | --- |
| E01~E03 | 브라우저·승인된 CI curl·백업 Requests | 정상 사용을 지지하는 맥락이 있지만 UA가 안전을 증명하지 않음 |
| E04 | 승인 백업의 `python-requests/2.32.3` | 2026년 보고 문자열과 겹쳐 후보가 됨. 업무 기록 확인 후 설명 가능한 일치로 분류 |
| E05~E06 | `TeslaBrowser/5.5`, 새 외부 목적지·POST | Lumma 연관 후보. 실행 파일·전송 내용·목적지를 추가 조사 |
| E07~E08 | 서로 다른 Raccoon 연관값 | 문헌 연관성은 있으나 같은 감염·공격자라고 단정 불가 |
| E09 | `Windows Defender`, 비정상 경로 프로세스 | 보안 제품 이름으로 안심하지 말고 BunnyLoader 관련 가설 검증 |
| E10 | `axios/1.8.2`, 로그인 요청 | 라이브러리·AiTM 연관 후보. 로그인 결과·세션·계정 흐름 확인 |
| E11~E12 | 완전히 같은 Edge 형식 UA | E11은 의심스러운 실행 맥락, E12는 승인된 브라우저. UA만으로 구별 불가 |
| E13 | 패시브 TLS 관측, UA 미수집 | 정상·악성 판정 불가. 종단·프록시 자료가 필요 |
| E14 | 기록된 빈 헤더 | 미수집과 구별. 로깅·앱 설정을 확인하며 악성으로 단정하지 않음 |
| E15~E16 | 같은 Nmap 표기, 서로 다른 승인 상황 | 승인 스캔과 미승인 정찰을 구별. 악성코드 이름으로 분류하지 않음 |
| E17 | Googlebot 자처, 문서용 출발지 | 실제 Google 크롤러라는 증거 없음. UA만 신뢰 금지; 실습 IP로 실제 검증하지 않음 |
| E18 | `recording-client/2` | `record` exact와 불일치. 부분 검색 오탐을 확인하는 음성 대조군 |
| E19 | 승인된 Go 서비스 | Go 기본 UA가 존재한다는 것만으로 의심하지 않음 |
| E20 | 개발 테스트의 `Project1` | 오래된 룰 후보와 일치하나 테스트 맥락이 있음. DarkCloud 감염으로 확정 금지 |

## 3. 근거를 세 칸으로 나누기

E05를 골라 ① 원문으로 확인된 사실 ② 출처에 기반한 가설 ③ 추가로 필요한 자료를 따로 쓰세요. “POST가 있으니 유출 성공”이라고 썼다면 무엇이 빠졌는지 확인합니다. 최소한 실제 목적지 소유·프로세스·요청/응답·데이터 종류가 필요하며 바이트 수만으로 내용은 알 수 없습니다.

E11·E12는 같은 UA이지만 다른 실행 맥락을 갖습니다. E13의 UA 미수집은 E14의 빈 헤더와 다릅니다. 이 세 가지를 구분할 수 있어야 블랙리스트 의존을 피할 수 있습니다.

## 4. 워크북 작성·완료 기준

후보별로 출처 ID, 일치 방식, 수집 지점, 호스트·계정, 목적지, 실행 주체, 정상 설명, 보강 증거, 미확인 사항과 후속 조치를 기록하세요. 완성 문장은 “E05는 Lumma다”가 아니라 “E05는 공개 보고 문자열과 일치하는 의심 통신이며 호스트 검증이 필요하다”처럼 근거의 범위를 표현해야 합니다.

**완료 기준:** 20건 건수·10건 후보를 재현하고, 정상 사용과 겹친 E04·E12·E20을 설명하며, E18의 부분 검색 오탐과 E13의 가시성 공백을 구분하고, 최소 2건의 추가 수집 계획을 작성합니다.

## 검증 범위

이 저장소의 검증 스크립트는 이벤트·카탈로그·CSV의 일관성, 매칭 방식, 후보 ID와 byte 길이를 검사합니다. Splunk·Suricata·Zeek·Arkime 제품에서 이 합성 자료를 실행한 결과라고 주장하지 않습니다. 실제 적용은 별도의 수집·파서·룰 검증이 필요합니다.

{% include ua-series.html %}
