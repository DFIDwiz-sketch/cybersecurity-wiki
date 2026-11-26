---
title: "Arkime PCAP 내보내기 조사 · 패킷을 읽기 전에 파일 확인하기"
description: "검색된 세션, 방향별 Raw 데이터, 패킷 캡처를 구분하고 오프라인 파일 다섯 가지로 내보내기 결과를 검증합니다."
category: network
tags: [Arkime, PCAP, Wireshark, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/arkime-pcap-export-evidence/
---

**학습 순서** · [Zeek·Suricata·Arkime 비교]({{ '/ko/wiki/network-monitoring/' | relative_url }}) → 내보내기 검증 → [패킷 캡처 누락 조사]({{ '/ko/wiki/capture-visibility/' | relative_url }}).

## 1. 어떤 자료를 내려받았나요?

Arkime에서 검색하는 **세션**은 관측한 통신의 요약입니다. 양쪽 주소와 포트, 시각 범위, 프로토콜 등의 정보가 들어갈 수 있습니다. **보존 패킷**은 이 세션에 대응해 저장한 바이트입니다. 인덱스 항목과 보존 방식, 삭제 시점이 다를 수 있습니다. **내보내기 파일**은 선택한 세션이나 검색 결과를 Viewer가 파일로 만든 것입니다. 어떤 형식으로 어디까지 받았는지 별도로 확인해야 합니다.

**PCAP**은 파일 헤더 뒤에 패킷 레코드가 이어지는 캡처 형식입니다. 각 레코드에는 시각, 저장한 길이, 보고된 원래 패킷 길이가 담깁니다. **PCAPNG**는 블록으로 구성되며 한 파일에 여러 인터페이스와 링크 계층 유형을 담을 수 있습니다. **링크 계층 유형**은 프레임의 첫 바이트를 Ethernet 등 어느 형식으로 읽을지 알려 줍니다. **Snaplen**은 패킷당 저장하도록 설정한 최대 바이트 수입니다. 원래 길이보다 짧아도 저장 길이만큼 들어 있으면 정상적인 레코드일 수 있습니다. 반대로 레코드 헤더가 선언한 저장 길이보다 파일 자체가 먼저 끝나면 읽을 바이트가 부족합니다.

| 자료 | 들어 있는 내용 | 활용 |
|---|---|---|
| 세션 행 또는 CSV | 검색용 메타데이터 또는 선택 필드 | 조사할 세션, 시간 범위, 캡처 노드를 찾습니다. |
| Source/Destination Raw 보기 | 방향별 패킷 데이터 표현입니다. Arkime v7의 Raw API는 패킷 텍스트 응답을 안내합니다. | 해당 방향을 문맥과 함께 읽습니다. 확장자를 바꿔도 캡처 구조가 생기지 않습니다. |
| PCAP·PCAPNG 다운로드 | 시각과 캡처 구조가 포함된 패킷 레코드 | 패킷 분석기로 읽고 범위를 확인한 뒤 보존합니다. |
| 이름이 `.pcap`인 HTML·JSON | Viewer 오류나 로그인 화면 등 응답 본문일 수 있습니다. | 승인된 Viewer 세션에서 HTTP 상태와 응답 메시지를 확인합니다. |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/arkime-pcap-export-evidence-ko.svg' | relative_url }}" alt="세션을 검색하고 원본 노드의 패킷 보존 여부를 확인합니다. PCAP 또는 PCAPNG로 내보낸 뒤 파일 형식, 패킷 수와 범위를 대조합니다." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>검색 결과, 보존 패킷, 내보내기 파일, 분석자의 확인 결과를 각각 기록하세요.</figcaption>
</figure>

## 2. 정상 내보내기 한 건 따라가기

**가상 예시.** Zeek에서 10:14 UTC에 `192.0.2.10:53000`과 `198.51.100.20:9000` 사이 UDP 통신을 찾았다고 가정합니다. 승인된 Arkime Viewer에서 측정한 시계 차이를 감안한 시간 범위로 검색합니다. 세션을 선택하기 전에 캡처 노드, 프로토콜과 시각을 확인하세요. Arkime은 Sessions 페이지의 Actions 메뉴에서 PCAP을 내보내는 방법을 안내합니다. 설치 버전에서 선택한 세션만 적용되는지, 화면에 보이는 항목이나 검색 결과 전체인지 확인하세요. 메뉴 이름과 동작은 버전에 따라 달라질 수 있습니다.

분석용 복사본을 읽으니 Ethernet 프레임 두 개가 나옵니다. 하나는 UDP 요청이고 다른 하나는 반대 방향의 응답입니다. 시각과 양쪽 주소·포트가 예상 범위와 일치합니다. 내보낸 시각과 해시도 기록하세요. 이 결과는 해당 센서와 내보내기 파일에 무엇이 있는지 보여줍니다. 센서가 실제 회선의 모든 프레임을 봤는지, 상대 서비스가 애플리케이션 데이터를 처리했는지는 별도 증거가 필요합니다.

Arkime v7 API 문서에 따르면 서로 다른 링크 계층 유형이 섞인 내보내기는 PCAPNG가 필요합니다. 이런 경우 일반 PCAP을 요청하면 파일 대신 JSON 오류가 돌아올 수 있습니다. 지원되는 PCAPNG 내보내기를 사용하거나 승인된 범위에서 링크 유형이 같은 대상만 선택하고, 확보한 범위를 기록하세요. 판독기만 시험하려고 불필요한 세션까지 수집할 필요는 없습니다.

## 3. 어느 단계부터 확인이 필요한가요?

| 관측 | 어떤 근거인가요? | 다음 확인 |
|---|---|---|
| 세션은 검색되지만 Viewer에서 패킷을 읽을 수 없음 | 메타데이터는 남아 있고 패킷 가용성은 확인이 필요합니다. | 역할, 원본 노드, 저장 위치나 객체 가용성, Viewer 로그를 확인합니다. 로컬 PCAP 공간 정리 뒤에도 세션 인덱스는 남을 수 있습니다. |
| 다운로드한 작은 파일이 HTML·JSON임 | 예상한 캡처 레코드 대신 응답 본문을 받은 것입니다. | 메뉴, HTTP 상태, 메시지를 확인합니다. 로그인 화면, 권한 오류, 다른 형식 요구 등 원인을 보고 승인된 경로로 다시 내보냅니다. |
| 판독기에서 저장 길이가 원래 길이보다 짧은 레코드 확인 | 저장본에 패킷 앞부분만 있습니다. Snaplen이나 이후 패킷 단위 절삭의 결과일 수 있습니다. | 내보내기 설정과 두 길이를 보존합니다. 최초 캡처에 없는 바이트는 확장자를 바꾸거나 다른 분석기로 열어도 복구되지 않습니다. |
| 레코드에 필요한 바이트가 중간에 끝난다는 오류 | 헤더가 선언한 저장 길이만큼 실제 바이트가 없습니다. | 승인된 복사본들의 크기와 해시를 비교한 뒤 전송 또는 저장 오류를 확인합니다. |
| 헤더는 정상이고 패킷 수가 0임 | 분석할 패킷 레코드가 없습니다. | 세션 선택 범위, 시간, 노드, 보존 상태와 Viewer 응답을 확인합니다. |

오해를 부르는 파일명과 불완전한 내보내기는 조사 방향을 바꿀 수 있습니다. 파일 출처와 판독기 오류는 먼저 내보내기 경로의 증거로 다루세요. 권한이나 보존 정책에 예상 밖의 변경이 있었다면 변경 기록과 반복 결과로 뒷받침한 뒤 조사 범위를 넓힙니다. 읽기 오류나 패킷 누락 한 건만으로 의도를 판단하기는 어렵습니다.

## 4. 블루팀 수집·탐지·대응

1. **수집.** 사건 번호, 승인된 검색 조건이나 세션 ID, UTC 범위와 시간대, Viewer와 캡처 노드, 제품 버전, 파일명, 내보내기 범위, 확인 가능한 응답 상태, 바이트 크기와 SHA-256을 기록합니다. 원본은 승인된 증거 저장소에 읽기 전용으로 보존하고 복사본으로 분석하세요. 패킷에 비공개 정보가 포함될 수 있으므로 승인된 저장·전송 범위를 지킵니다. [디지털 증거 보존]({{ '/ko/wiki/evidence-preservation/' | relative_url }})
2. **탐지.** 파일 형식, 레코드 수, 링크 계층 유형, 시간 범위와 필요한 패킷 길이를 기대값과 비교합니다. 실패가 반복되면 노드와 내보내기 유형별로 나눠 봅니다. 승인된 테스트 소스의 정상 파일로 판독기 자체 문제와 저장·권한 문제를 구분하세요.
3. **대응.** 세션은 있지만 PCAP을 읽을 수 없다면 실제 네트워크 결론을 내리기 전에 관측 범위, 권한, 저장소를 확인합니다. 필요한 경우 실패 파일과 응답을 보존한 뒤 승인된 경로로 다시 내보냅니다. 여전히 확보할 수 없다면 가진 증거와 공백 시간대를 남기고 Zeek, Suricata 또는 엔드포인트 자료로 교차 확인하세요.

Wireshark의 `capinfos`, `tshark`가 설치된 환경에서 승인된 캡처 복사본을 읽는 예입니다. `file`은 시그니처를 보므로 마지막 레코드가 잘려도 PCAP으로 표시할 수 있습니다. `capinfos`는 형식, 캡슐화, 패킷 수, snaplen, 시각, 해시를 조회합니다. 아래 표시 필터는 각 프레임에서 저장 길이와 보고된 원래 길이를 비교합니다. 결과가 없다면 해당 조건에 맞는 프레임이 출력되지 않은 것입니다. 경고와 종료 상태도 확인하세요.

~~~sh
file evidence.pcap
capinfos -t -E -c -l -a -e -H evidence.pcap
tshark -n -r evidence.pcap -Y 'frame.cap_len < frame.len' -T fields \
  -e frame.number -e frame.cap_len -e frame.len
~~~

## 5. 오프라인 실습 · 확장자가 같은 파일 다섯 개

Python 3이 있는 승인된 일회용 작업 공간에서 실행하세요. 스크립트는 가상의 Ethernet·IPv4·UDP 패킷 두 개를 파일에 씁니다. 네트워크에는 패킷을 보내지 않습니다. 시각은 고정된 가상 값이며 주소는 문서용입니다. `make`는 기존 파일을 덮어쓰지 않습니다. `check`는 실습 범위의 일반 PCAP 2.4 구조를 점검하고 해시를 계산합니다. PCAPNG 시그니처가 있으면 지원하는 판독기를 쓰라고 안내합니다. 모든 패킷의 실제 내용을 해석하거나 운영 캡처의 완전성을 인증하는 도구는 아닙니다.

- <a href="{{ '/assets/downloads/arkime-pcap-export-evidence/inspect_pcap.py' | relative_url }}" download>PCAP 실습 스크립트 다운로드</a>

~~~sh
python3 inspect_pcap.py make samples
python3 inspect_pcap.py check samples/intact.pcap samples/sliced.pcap samples/header-only.pcap
python3 inspect_pcap.py check samples/broken.pcap samples/response.pcap
~~~

| 파일 | 기대 결과 |
|---|---|
| `intact.pcap` | 레코드 2개, 절삭된 레코드 0개. |
| `sliced.pcap` | 구조가 정상인 레코드 2개, 모두 48바이트만 저장됨. |
| `header-only.pcap` | 정상 헤더, 패킷 레코드 0개. |
| `broken.pcap` | 마지막 레코드의 저장 길이보다 실제 남은 바이트가 적음. |
| `response.pcap` | 확장자는 `.pcap`이지만 내용은 HTML 응답. |

첫 번째 검사는 종료 코드 0, 두 번째는 오류 두 건을 출력하고 종료 코드 1을 반환합니다. 파일이 이미 있어서 생성하지 못하면 새 디렉터리를 사용하세요. 다른 판독기의 패킷 수가 예상과 다르면 입력 경로와 해시, 판독기 오류를 확인합니다. 실제 실행에서 스크립트는 다섯 파일을 모두 예상대로 분류했습니다. `file` 명령은 HTML 하나를 판별했고, 깨진 파일을 포함한 나머지 네 개에서 PCAP 시그니처를 식별했습니다. Arkime과 Wireshark 관련 단계는 제품 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **세션이 검색되면 패킷 파일도 있는 건가요?** 원본 노드의 보존 상태와 Viewer 내보내기를 확인해야 합니다.
- **정상 PCAP에 짧게 저장된 패킷이 있을 수 있나요?** 가능합니다. 레코드의 구조는 정상이어도 저장 길이가 원래 프레임 길이보다 짧을 수 있습니다.
- **SHA-256이 같으면 내보내기가 완전한 건가요?** 해시는 비교한 두 바이트열의 일치를 뒷받침합니다. 세션 선택, 캡처 범위, 관측 시각은 따로 확인하세요.

오류가 나는 파일 두 개를 찾고, 앞부분만 저장한 레코드와 파일 자체가 중간에 끝난 레코드의 차이를 설명하고, 실제 내보내기 파일을 특정 센서와 검색 조건에 연결할 증거를 나열하면 완료입니다.

## 공식 참고자료

**2026-11-27** 검토. Arkime 내보내기는 v7 API와 공급자 Sessions 안내를 기준으로 합니다. 운영 환경에서는 설치된 Viewer와 Wireshark 버전을 확인하세요. IETF 자료는 검토 시점의 일반 PCAP과 PCAPNG를 설명하는 인터넷 초안입니다.

- Arkime · [Sessions와 PCAP 내보내기](https://arkime.com/#sessions-page), [v7 API](https://arkime.com/apiv7), [저장소 설정](https://arkime.com/settings), [보존 문제 점검](https://arkime.com/faq).
- Wireshark · [capinfos](https://www.wireshark.org/docs/man-pages/capinfos.html), [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [프레임 필터 필드](https://www.wireshark.org/docs/dfref/f/frame.html).
- IETF OPSAWG · [PCAP 초안 -09](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/09/), [PCAPNG 초안 -06](https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcapng/06/).
