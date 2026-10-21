---
translation_url: /wiki/network-monitoring/
title: "Zeek, Suricata, Arkime 비교"
description: "네트워크 로그, 침입 탐지 경보와 패킷 세션 탐색의 역할을 비교합니다."
category: network
tags: [Blue Team, Network Security, Zeek, Suricata, Arkime, DFIR]
level: Beginner
updated: "2026-10-22"
---
## 1. 같은 트래픽을 보는 세 가지 관점

Zeek, Suricata, Arkime는 서로 보완하는 도구입니다. **Zeek는 통신 행위를 기록하고, Suricata는 룰·프로토콜 조건을 평가하며, Arkime는 세션과 보존된 패킷을 찾는 데 도움을 줍니다.** 한 도구의 결과만으로 침해를 확정하지 마세요.

| 도구 | 주요 출력 | 적합한 질문 | 한계 |
| --- | --- | --- | --- |
| Zeek | 연결·프로토콜 로그, 스크립트에 따른 Notice | 누가 어떤 프로토콜로 통신했는가? | 로그가 전체 PCAP은 아니며 활성 분석기·가시성에 좌우됨 |
| Suricata | EVE JSON 경보·Flow·활성화된 프로토콜/파일 이벤트, 구성에 따른 IDS/IPS | 관측 패턴이 룰이나 프로토콜 조건과 일치했는가? | 경보가 악용 성공은 아니며 무경보가 안전의 증거도 아님 |
| Arkime | 검색 가능한 세션과 보존 PCAP 참조 | 가설을 뒷받침할 세션·패킷이 있는가? | 수집·필터·저장 공간·보존 정책에 따라 패킷이 없을 수 있음 |

Suricata는 시그니처 경보 외의 자료도 제공하고, Zeek는 연결 횟수 이상의 정보를 제공합니다. 도구 이름보다 조사 질문을 먼저 정하세요.

## 2. 결과를 읽기 전에 수집 가시성부터 확인

TAP이나 SPAN/미러 포트가 센서에 트래픽을 제공합니다. 양방향과 내부 구간을 포함해 어느 범위가 보이는지 확인하세요. 경계 센서만으로 직원 PC와 내부 파일 서버 사이 통신을 볼 수 있다고 가정하면 안 됩니다.

- 센서 위치·인터페이스·소프트웨어와 룰 버전·활성 출력을 기록합니다.
- 양방향 수집, 패킷 손실, 캡처 필터, 저장 공간을 점검합니다.
- 시간을 UTC로 정규화하되 원본 시각과 센서별 시계 오차를 보존합니다.
- NAT·프록시·VPN·로드밸런서의 앞뒤 중 어느 주소가 기록되는지 확인합니다.
- 메타데이터와 PCAP 보존 기간을 따로 관리합니다. 세션 검색은 가능해도 패킷은 삭제되었을 수 있습니다.
- 평문 패킷에 자격 증명·개인정보가 포함될 수 있으므로 내보내기 권한을 통제합니다.

Zeek 연결 하나의 `missed_bytes=0`만으로 전체 수집 시스템에 패킷 손실이 없었다고 판단하지 마세요. 캡처·센서 전체의 상태도 확인해야 합니다.

## 3. 대표 로그와 필드

| 자료 | 주요 필드 | 의미·범위 |
| --- | --- | --- |
| Zeek `conn.log` | `ts`, `uid`, `id.orig_h/p`, `id.resp_h/p`, `proto`, `service`, `duration`, 바이트 수, `conn_state` | 연결 메타데이터. Originator/Responder 역할도 맥락 확인 필요 |
| Zeek `dns.log` / `http.log` | `uid`, 질의·응답 또는 HTTP 호스트·URI | 수집된 Zeek 관측 안에서 관련 프로토콜 기록 연결 |
| Suricata `eve.json` | `timestamp`, `event_type`, `flow_id`, 출발지·목적지 IP/포트, `proto` | 하나의 Flow에 여러 이벤트 유형 존재 가능 |
| Suricata 경보 | `alert.signature_id`, `alert.signature`, `alert.action`, `alert.severity` | 룰의 맥락. 심각도·Action이 사고 판정은 아님 |
| Arkime 세션 / PCAP | 세션 식별자, 시간 구간, 양 끝점, 프로토콜, 패킷 가용성 | 검색 결과가 실제 PCAP 보존을 보장하지 않음 |

Zeek의 `uid`, Suricata의 `flow_id`, Arkime 세션 ID는 **서로 다른 식별자**입니다. 원본 센서·데이터셋 범위에서 사용하고 값을 같다고 가정해 도구 간 Join하지 마세요. 도구 간에는 프로토콜·양쪽 IP·포트의 **5-tuple**, 겹치는 시각, 센서 위치로 시작합니다. 방향 반전·포트 재사용·NAT도 고려하세요. 호환되는 Community ID 기능을 명시적으로 활성화했다면 보조 상관 키로 사용할 수 있지만 시각·관측 지점 검증은 여전히 필요합니다.

참고: [Zeek 연결 필드](https://docs.zeek.org/en/current/reference/logs/conn.html), [Suricata EVE 형식](https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-format.html), [Arkime FAQ와 패킷 보존](https://arkime.com/faq).

## 4. 가상 예제로 증거 읽기

아래 주소·ID·경보 문구·이벤트는 모두 **설명용 가상 자료**입니다. 문서용 IP 대역은 실제 침해지표가 아닙니다. JSON은 실제 제품의 일부 필드명을 활용한 예시이며 완전한 내보내기나 운영 센서 실행 결과가 아닙니다.

### Zeek 연결 발췌 예제

```json
{
  "ts": 1792630800,
  "uid": "CLabExample001",
  "id.orig_h": "192.0.2.10",
  "id.orig_p": 51514,
  "id.resp_h": "203.0.113.20",
  "id.resp_p": 80,
  "proto": "tcp",
  "service": "http",
  "duration": 2.4,
  "orig_bytes": 220,
  "resp_bytes": 640,
  "conn_state": "SF",
  "missed_bytes": 0
}
```

HTTP로 분류된 짧은 TCP 통신입니다. `SF`는 Zeek의 연결 상태 해석이며 애플리케이션이 정상이라는 판정이나 공격 성공의 의미는 아닙니다. 바이트 수만으로 정보 유출을 확정할 수도 없습니다.

### Suricata EVE 경보 발췌 예제

```json
{
  "timestamp": "2026-10-22T01:00:01.000000+0000",
  "flow_id": 1000001,
  "event_type": "alert",
  "src_ip": "192.0.2.10",
  "src_port": 51514,
  "dest_ip": "203.0.113.20",
  "dest_port": 80,
  "proto": "TCP",
  "app_proto": "http",
  "alert": {
    "action": "allowed",
    "signature_id": 1000001,
    "signature": "LAB example HTTP request - synthetic",
    "severity": 3
  }
}
```

앞의 연결과 양 끝점이 같은 실습용 경보입니다. `allowed`를 “안전함”으로 읽으면 안 됩니다. IDS는 일반적으로 경보를 발생시켜도 통신을 차단하지 않습니다. IPS에서는 유효 룰·Action·실제 차단을 확인하세요. Severity 3은 룰 우선순위이며 업무 피해가 작다는 증거가 아닙니다. 가상 시그니처는 실제 설치된 운영 룰이 아닙니다.

### Arkime 조사 워크시트

| 검색 조건 | 예시 |
| --- | --- |
| 시간 | 2026-10-22 00:59:50–01:00:15 UTC |
| 프로토콜 | TCP |
| 양 끝점 | 192.0.2.10:51514 ↔ 203.0.113.20:80 |
| 기대 관측 | Zeek 연결 및 EVE 경보와 시간이 겹치는 세션 |
| 패킷 확인 | PCAP 보존 여부를 확인하고 승인된 관련 세션만 내보내기 |

이 표는 검색 계획이며 Arkime 검색 문법이나 실제 세션 존재를 주장하는 자료가 아닙니다. 설치 버전의 Viewer 필드 도움말을 사용하고 측정한 시계 오차에 맞추어 시간 구간을 조정하세요.

## 5. 조사 절차: 경보 → 연결 → 프로토콜 → 패킷

1. **경보 검증:** 센서·시각·시그니처 ID와 가능한 경우 Revision·Action·양 끝점·IDS/IPS 모드를 기록합니다.
2. **연결 맥락:** Zeek의 5-tuple과 시간 구간을 찾고 방향·지속시간·통신량을 비교합니다. 같은 Flow에서 여러 경보가 발생할 수 있으므로 경보 수와 연결 수는 다릅니다.
3. **프로토콜 확인:** 수집되어 있다면 Zeek `uid`로 HTTP·DNS 기록을 연결합니다. 암호화된 HTTP 내용까지 보인다고 가정하지 마세요.
4. **패킷 검토:** 대응 Arkime 세션과 PCAP 보존 상태를 확인하고 요청·응답을 조사합니다. 원본 내보내기와 수집 맥락을 보존합니다.
5. **엔드포인트 연결:** 프로세스·사용자·승인 소프트웨어를 확인합니다. 네트워크 증거가 부족하면 엔드포인트·프록시 자료를 활용합니다.
6. **대안 가설:** 정상 상태 점검·업데이트·승인 스캔·악성 접근을 비교합니다.
7. **정확한 결론:** 룰 일치, 통신 완료, 애플리케이션 작업, 확인된 침해를 구분합니다.

**실습 질문:** 가상 룰이 HTTP `/health.txt` 요청에 반응했습니다. 무엇을 추가로 알아야 할까요? 승인된 자산 관리 에이전트와 예상 응답이라면 정상 설명이 가능하고, 알 수 없는 프로세스와 무단 파일 전달이면 심층 조사 근거가 됩니다. 제공한 JSON에는 URI·프로세스 정보가 없으므로 초기 결론은 **조사 필요, 결과 미확인**입니다.

## 6. 선택 실습: Splunk 탐색 시작점

파서가 각 자료를 `src_ip`, `src_port`, `dest_ip`, `dest_port`, `transport`, `sensor`, `data_source`로 정규화하고 `_time`을 올바르게 처리한 뒤 사용하세요. 이들은 **설명용 정규화 스키마**이며 모든 도구가 기본 제공하는 공통 필드가 아닙니다.

```spl
index=network_lab src_ip="192.0.2.10" dest_ip="203.0.113.20"
  src_port=51514 dest_port=80 transport=tcp
| table _time data_source sensor src_ip src_port dest_ip dest_port transport
    event_type zeek_uid suricata_flow_id arkime_session_id
| sort 0 _time
```

시간 선택기를 실습 구간으로 지정하세요. 관측을 나열하는 검색이며 신뢰할 수 있는 도구 간 자동 Join을 수행하지 않습니다. 원본 ID를 별도 필드로 보존하고 방향을 통일하지 않은 파서라면 역방향 5-tuple도 검색하세요. 0건이면 시간·인덱스·추출·센서 범위·NAT부터 확인합니다.

## 7. 암호화와 흔한 오해

| 관측 | 입증하지 못하는 것 | 다음 증거 |
| --- | --- | --- |
| TLS 연결 | 페이로드가 정상 또는 열람 가능함 | 프로세스·가용 TLS 메타데이터·승인 프록시 자료 |
| SMB over QUIC / UDP 443 | 일반 웹 통신 또는 SMB 파일 작업의 가시성 | 프로토콜 식별·서버 감사·엔드포인트 |
| Suricata 무경보 | 공격이 없었음 | 룰 활성화·가시성·패킷 손실·엔드포인트 |
| Zeek 메타데이터 | 완전한 패킷 캡처 | 수집 범위·원본 PCAP |
| Arkime 세션 검색 성공 | 패킷이 아직 보존됨 | PCAP 가용성·보존 정책·저장 상태 |
| 많은 레코드 | 많은 공격·고유 연결 | 이벤트 유형·Flow ID·중복 센서·시각 |

암호화된 패킷도 시각·전송 행위를 조사하는 데 유용하지만 애플리케이션 본문을 자동으로 보여주지는 않습니다. 복호화에는 승인된 추가 기능과 호환되는 키 자료 등 별도 조건이 필요합니다.

## 8. 증거 보존과 보고

조사 질문, UTC 구간, 시계 오차, 센서 위치, 원본 ID, 5-tuple, 룰 맥락, 수집 누락, 보존 상태를 기록하세요. PCAP 내보내기의 해시를 기록하고 원본 접근을 통제하며 필터 적용 내역을 남깁니다. 네트워크 주소만으로 사람의 신원을 확정하지 마세요.

**학습 완료 점검:** 세 도구의 역할 설명, ID를 동일시하지 않는 가상 Flow 연결, 가시성 공백 식별, 경보와 실제 피해 구분, 추가 증거 요구사항 기록을 수행할 수 있어야 합니다.

## 9. 공식 참고 자료와 다음 학습

- [Zeek: conn.log](https://docs.zeek.org/en/current/reference/logs/conn.html)
- [Suricata: EVE JSON 형식, 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-format.html)
- [Arkime: FAQ](https://arkime.com/faq)
- [SMB 보안]({{ '/ko/wiki/smb-security/' | relative_url }})
- [WPAD 조사]({{ '/ko/wiki/wpad-security/' | relative_url }})

**검토일: 2026년 10월 22일.** 제품 출처는 동작의 근거이며 예제·실습은 가상 자료입니다. 필드·기능은 운영 버전과 대조하세요. 게시 과정에서 실제 트래픽 수집이나 운영 Splunk 검색을 실행하지 않았습니다.
