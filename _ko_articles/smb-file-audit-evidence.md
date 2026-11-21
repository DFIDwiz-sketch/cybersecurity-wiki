---
title: "Windows 파일 공유 감사 · 접근 검사에서 파일 증거까지"
description: "Windows Security 4624·5140·5145·4656·4663을 연결하고, 접근 권한 검사와 실제 파일 작업을 구분합니다."
category: blue-team
tags: [SMB, Windows Security, Windows Logs, File Auditing, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /wiki/smb-file-audit-evidence/
---

**학습 목표.** 누군가 공유 보고서를 읽었다는 경보를 받았다고 가정합니다. Windows가 어느 단계까지 기록했는지, 같은 작업으로 연결할 수 있는 기록은 무엇인지, 전체 복사 여부를 판단하려면 어떤 증거가 더 필요한지 설명합니다. Windows 파일 서버의 NTFS 기반 SMB 공유를 기준으로 합니다.

## 1. 한 요청이 두 권한 검사 지점에 남기는 기록

SMB는 이름이 붙은 **공유**를 네트워크에 제공합니다. 클라이언트에서 쓰는 UNC 경로가 `\\FS01\Reports\daily.csv`라면, 서버에서는 예를 들어 `D:\Shares\Reports`가 공유의 로컬 폴더일 수 있습니다. SMB 접근에는 공유 권한과 파일 시스템 권한이 모두 적용됩니다. **DACL**은 어떤 권한을 허용하거나 거절하는지 정합니다. 파일·폴더의 **SACL**은 적용 중인 감사 정책과 함께 어떤 접근 시도를 기록할지 정합니다. **핸들**은 프로세스나 시스템 구성 요소가 객체를 사용하기 위해 받는 참조입니다. 핸들을 요청한 기록과 그 핸들로 권한을 사용한 기록은 서로 다른 증거입니다.

![네트워크 로그온으로 세션을 확인합니다. SMB 공유 권한 검사와 NTFS 핸들 요청은 별도 단계이며, 실제 사용 권한은 파일 시스템 감사에서 확인합니다.]({{ '/assets/diagrams/smb-file-audit-ko.svg' | relative_url }})

그림은 조사할 때 보는 단계입니다. 한 로그온 세션에서 여러 파일을 처리할 수 있습니다. 실제 기록은 감사 정책, SACL과 수집 상태에 따라 달라집니다.

| 파일 서버의 Security 이벤트 | 확인할 내용 | 수집 전제 |
| --- | --- | --- |
| 4624, Logon Type 3 | 네트워크 로그온. **New Logon** 영역의 XML `TargetLogonId`, SID, 원본 주소가 있을 때 함께 확인 | Audit Logon 성공 감사. Type 3에는 SMB 이외의 네트워크 로그온도 포함 |
| 5140 | 세션의 최초 공유 접근 시도. 공유와 원본 주소 확인 | 해당 결과의 Audit File Share. 파일 작업 횟수로 집계할 수 없음 |
| 5145 | 공유 수준에서 요청 권한 검사. 공유의 로컬 경로, 상대 대상, 원본 주소, 요청 마스크와 결과 확인 | Audit Detailed File Share의 해당 성공·실패 감사. 실패는 공유 수준 검사에 해당 |
| 4656 | 객체 핸들 요청과 결과. 로컬 객체명, 요청 주체 세션, 결과, 제공된 핸들 ID 확인 | 이 NTFS 사례에서는 Audit File System과 일치하는 SACL 필요 |
| 4663 | 감사된 권한 사용. 객체명, 주체 세션, 프로세스·핸들과 마스크 확인 | Audit File System 성공 감사와 일치하는 SACL. 4663에는 실패 이벤트가 없음 |

## 2. 정상적인 보고서 읽기를 따라가세요

09시 UTC에 문서용 주소 `192.0.2.24`의 클라이언트가 `FS01`에 접속합니다. 4624 Type 3의 대상 로그온 ID는 `0x53ab`이고, 5140에는 Reports 공유가 표시됩니다. 클라이언트가 `daily.csv`를 열면 5145에 공유 검사가 성공으로 남습니다. 정규화한 예에서 `ShareLocalPath`는 `D:\Shares\Reports`, `RelativeTargetName`은 `daily.csv`입니다. 합친 로컬 경로는 4663의 `ObjectName`과 일치합니다. 4663의 `0x81`에는 파일 데이터 읽기 `0x1`과 속성 읽기 `0x80`이 들어 있습니다.

같은 서버, 부팅 구간, SID, 경로와 시각인지부터 확인하세요. 4624의 **대상** 로그온 ID와 공유·객체 이벤트의 `SubjectLogonId`를 비교합니다. 로그온 ID는 컴퓨터별 값이고 재부팅 뒤 재사용될 수 있습니다. 4656과 4663에 유효한 핸들 ID와 프로세스 정보가 있으면 동일 호스트에서 객체 수준의 연결을 뒷받침합니다. 5145에는 동일한 핸들 식별자가 없습니다. 여러 읽기가 겹치면 가능한 후보를 보존하세요. DFS 리퍼럴, 볼륨 탑재 지점이나 재분석 지점이 있다면 문자열을 바로 합치기 전에 실제 서버와 공유 매핑을 확인합니다.

| 접근 마스크 비트 | 일반 파일에서 | 디렉터리에서 |
| --- | --- | --- |
| `0x1` | ReadData, 파일 데이터 읽기 | ListDirectory, 디렉터리 목록 조회 |
| `0x2` | WriteData, 파일 데이터 쓰기 | AddFile, 디렉터리에서 파일 만들기 |
| `0x80` | ReadAttributes, 속성 조회 | ReadAttributes, 속성 조회 |

마스크에는 비트가 여러 개 들어갈 수 있습니다. `0x1`과 숫자가 같은 값만 찾으면 `0x81`을 놓칩니다. 대상이 일반 파일인지 디렉터리인지 경로와 당시 파일 목록 등으로 확인하세요. Windows 이벤트의 객체 유형 필드만으로 둘을 가르기 어려울 수 있습니다. 4663의 ReadData는 서버에서 그 권한을 사용한 증거입니다. 전송 바이트와 클라이언트에 전체 사본이 남았는지는 별도 자료로 확인해야 합니다.

## 3. 거절 위치와 비슷해 보이는 정상 동작을 살펴보세요

공유 정책이 파일 시스템에 도달하기 전에 요청을 막을 수 있습니다. Microsoft는 5145 실패가 공유 수준의 거절에서 생성된다고 설명합니다. NTFS 거절을 조사할 때는 적절히 감사된 4656 실패나 클라이언트의 오류 기록을 확인하세요. 4663이 보이지 않는 이유에는 SACL 불일치, 성공 감사 미설정, 보존 기간, 수집 필터, 다른 서버, 실제 권한 사용 미관측 등이 있습니다.

탈취된 계정이나 너무 넓은 권한으로 민감한 파일을 여러 개 읽거나 공유 파일을 변경할 수 있습니다. 보고서 생성, 백업, 백신 검사와 검색 색인도 접근량을 늘릴 수 있습니다. 정상 작업의 계정, 원본, 예정 시각과 비교하고, 조회된 민감 경로를 확인하세요. 4663 마스크로 본문 접근과 메타데이터 조회를 구분할 수 있습니다. 영향은 클라이언트, 엔드포인트와 파일 상태 자료로 검증하세요. 공유 검사만으로 랜섬웨어, 원격 실행이나 외부 반출을 확정할 수 없습니다.

## 4. 블루팀 수집·탐지·대응

1. **실제로 파일을 제공한 호스트에서 시작합니다.** UTC 시각, 대상 서버와 부팅 구간, 원본 주소, SID와 해당 공유 매핑을 적습니다. Security EVTX나 원본 XML을 보존하고, 전달된 수집본에 해당 기간과 이벤트 ID가 포함됐는지 확인하세요. 원본 레코드 ID와 XML 필드명을 남깁니다. 계정의 로그온 문맥을 보존하고, 공유와 세션 자료가 일치하면 원본 네트워크 주소를 연결합니다.
2. **누락을 해석하기 전에 감사 범위를 확인합니다.** 실제 적용된 고급 감사 정책과 NTFS SACL의 계정, 권한, 성공·실패 선택을 확인하세요. Audit File Share와 Audit Detailed File Share는 별도 정책입니다. 상세 공유 감사는 서버 전체에서 많은 기록을 만들 수 있습니다. 파일 시스템 SACL은 승인된 객체로 범위를 정하고, 기록량과 보존 기간, 하류 필터를 검토하세요. 배포한 Windows 버전에서 SACL과 이벤트 수집 동작을 확인해야 합니다.
3. **연결한 뒤 집계합니다.** 대상 서버, 부팅, 세션을 먼저 묶고, 당시의 로컬 객체 경로와 가능한 시간 범위를 대조합니다. 파일 서버의 시간대와 시계 근거를 확인하세요. 별개의 이벤트와 전달 중복을 구분하고 가능한 후보가 여럿이면 남깁니다. 5145 총량을 파일 수로 사용하지 말고, 정상 작업과 원본별 민감 파일 접근 변화를 탐지하세요.
4. **영향을 확인한 뒤 대응합니다.** 파일 상태와 스냅샷, 앱·클라이언트 EDR 자료를 대조하세요. 네트워크 흐름의 전송량은 범위를 가늠하는 데 도움이 되지만 암호화와 동시 동작 때문에 파일 하나에 귀속하기는 어렵습니다. 무단 활동이 근거로 뒷받침되면 파일·계정 담당자와 승인된 접근 제한을 적용합니다. 증거 사본을 보존하고 변경 후에도 정상 작업이 작동하는지 확인하세요.

## 5. 오프라인 실습 · 가상 사례 여덟 건

[이벤트 사례 파일]({{ '/assets/labs/smb-file-audit-cases.json' | relative_url }})과 [Python 검토 스크립트]({{ '/assets/labs/smb-file-audit-review.py' | relative_url }})를 같은 폴더에 받고, Python 3.8 이상에서 `python3 smb-file-audit-review.py`를 실행하세요. 레코드는 실습을 위해 추린 가상 값입니다. EVTX 원본 형식과는 다릅니다. 부팅 식별자와 객체 종류는 조사에서 별도로 얻었다고 가정합니다. 스크립트는 제공된 파일만 읽고 5초의 실습 시간 창을 적용합니다. Windows나 네트워크에는 접속하지 않습니다. 실제 환경의 탐지 임계값은 관측 자료에 맞춰 검증해야 합니다.

| 사례 | 예상 해석 |
| --- | --- |
| LAB-01 | `0x81`에는 파일 데이터 읽기와 속성 조회가 모두 포함됨 |
| LAB-02 | `0x80`으로 속성만 조회 |
| LAB-03 | 공유 수준 권한 검사 실패 |
| LAB-04 | 확인된 네트워크 로그온에 속한 로컬 객체 핸들 요청 거절 |
| LAB-05 | 객체 기록의 서버나 부팅이 다름 |
| LAB-06 | 파일 데이터 쓰기 권한을 사용함. 결과는 파일 상태로 확인 |
| LAB-07 | 별개의 객체 기록 두 개가 후보로 남아 한 건으로 확정할 수 없음 |
| LAB-08 | 디렉터리에서 사용된 `0x1`은 목록 조회 |

결과가 다르면 파일 이름, 마스크 비트, 서버, 부팅과 경로를 확인하세요. 실습은 대소문자를 구분하지 않는 단순 경로를 가정합니다. 운영 환경의 별칭이나 전달 중복은 따로 처리해야 합니다. 승인된 테스트 서버에서는 관리자가 무해한 읽기 전용 공유와 폴더에 필요한 감사를 설정한 뒤, 허가된 계정으로 샘플 파일 하나를 열고 로컬과 전달 기록을 대조할 수 있습니다. 제한된 테스트 계정으로 거절 사례도 확인할 수 있습니다. 탐지 규칙을 시험하기 전에 서버의 이벤트 뷰어와 원본 XML을 비교하세요. 오프라인 사례 여덟 건은 실행했고, 실제 Windows 이벤트 생성과 전달은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **5145는 성공했지만 4663이 없습니다. 클라이언트가 파일을 받았나요?** 확인된 것은 공유 검사입니다. NTFS 감사 범위와 파일 작업 또는 클라이언트 증거를 확보하세요.
- **4663에서 마스크가 `0x1`입니다. 본문을 읽었다고 볼 수 있나요?** 객체 종류를 먼저 확인합니다. 같은 비트가 디렉터리에서는 목록 조회를 뜻합니다.
- **서버 두 대에 `0x53ab`가 보입니다. 하나의 로그온인가요?** 서버와 부팅으로 범위를 정하고 독립적인 신원·원본 필드를 대조하세요.
- **왜 객체 기록 두 개를 모두 남기나요?** 같은 세션과 경로에서 비슷한 시각에 여러 작업이 발생할 수 있습니다. 시각이 가장 가깝다는 사실만으로 작업을 특정하기 어렵습니다.

**완료 기준.** LAB-01과 LAB-05의 조사 메모를 한 건씩 작성하세요. 확인한 권한 단계와 연결에 쓰인 필드를 적고, 파일 작업 결과를 판단할 때 필요한 자료를 하나씩 고릅니다.

[이전 · SMB 기초와 보안]({{ '/ko/wiki/smb-security/' | relative_url }}) · [관련 · Windows 보안 로그]({{ '/ko/wiki/windows-logs/' | relative_url }})

## 공식 참고자료

2026년 11월 21일 검토했습니다. 개별 이벤트 스키마는 Windows 10 시기 문서이며, Windows Server 감사 정책 가이드의 적용 대상은 Server 2016~2025입니다. 대상 환경의 이벤트 버전과 적용 정책을 확인하세요.

- [Microsoft Learn · Windows Server 고급 감사 정책](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft Learn · 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140) · [5145](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145)
- [Microsoft Learn · 파일 시스템 감사](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-file-system) · [4656](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4656) · [4663](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663)

## NTFS USN 변경 저널 조사

[NTFS USN 변경 저널 조사]({{ '/ko/wiki/ntfs-usn-evidence/' | relative_url }}). 파일 이름 변경을 추적하고 저널 공백과 미관측을 구분합니다.
