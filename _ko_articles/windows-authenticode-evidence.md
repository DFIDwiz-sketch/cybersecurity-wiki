---
title: "Windows Authenticode · 게시자, 파일 해시, 실행 정책 확인"
description: "내장 서명과 카탈로그 서명을 구분하고, 타임스탬프와 Windows 서명 검증 결과를 배포본·App Control 증거와 대조합니다."
category: blue-team
tags: [Windows, Authenticode, Code Signing, PKI, App Control, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/windows-authenticode-evidence/
---

PowerShell에서 실행 파일의 서명이 `Valid`로 나오는데 App Control에는 차단이 기록됐습니다. 두 결과 모두 같은 파일을 설명할 수 있습니다. Authenticode는 적용된 검증 정책에 따라 서명으로 보호된 내용과 서명자 신뢰를 평가합니다. App Control은 해당 호스트의 실행 정책을 충족하는지 판단합니다. 기준 해시는 수집한 파일 전체가 어떤 배포본과 같은지 확인하는 데 사용합니다.

## 1. 네 가지 증거가 답하는 질문

**코드 서명 인증서**는 인증 기관의 발급 절차를 거쳐 공개키를 게시자 신원과 연결합니다. 게시자는 개인키로 파일 형식에 맞는 내용을 서명합니다. 검증기는 디지털 서명을 확인하고 서명이 보호하는 범위의 다이제스트를 다시 계산한 뒤 인증서 체인과 신뢰 정책을 평가합니다. Windows의 **Subject Interface Package(SIP)**는 Portable Executable(PE)처럼 지원되는 파일 형식에서 다이제스트를 계산하거나 내장 서명 데이터를 찾는 방식을 정의합니다.

| 증거 | 뒷받침하는 판단 | 확인 범위 |
| --- | --- | --- |
| 내장 Authenticode 서명 | 파일 자체에 들어 있는 서명 정보를 검증 | 해당 검증 정책과 서명이 보호하는 범위에 적용됩니다. |
| 서명된 카탈로그와 일치하는 멤버 해시 | 파일이 서명된 외부 카탈로그의 항목과 일치 | 카탈로그 서명만 유효해도 파일이 그 멤버인지는 따로 확인해야 합니다. 카탈로그 검색은 도구와 호스트에 따라 달라질 수 있습니다. |
| 전체 파일 SHA-256 | 수집한 바이트 전체가 신뢰하는 배포 해시 또는 보존 복사본과 일치 | 비교 기준 자체에 신뢰할 출처가 필요합니다. 해시만으로 게시자를 식별하기 어렵습니다. |
| App Control 결과 | 실제 정책 차단 또는 감사 모드에서 차단 대상이었다는 기록 | 특정 정책과 시도에 적용됩니다. 전체 실행 목록이나 악성 여부를 보여 주지는 않습니다. |

PE의 Authenticode 다이제스트와 전체 파일의 SHA-256은 서로 다른 바이트 범위를 다룰 수 있습니다. Microsoft가 문서화한 PE 서명 계산에서 체크섬과 인증서 테이블 디렉터리 등 일부 필드는 제외됩니다. 따라서 정확한 배포본인지 확인하려면 전체 파일을 비교해야 합니다. 복사본 둘의 서명이 모두 유효하지만 전체 해시가 다르면 두 파일을 보존하고 각 파일의 배포 기록과 서명 근거를 확인하세요.

<figure>
  <img src="{{ '/assets/diagrams/windows-authenticode-evidence-ko.svg' | relative_url }}" width="560" height="334" alt="수집한 파일을 세 방향으로 조사합니다. Windows 서명과 검증된 타임스탬프로 서명 신뢰를, 전체 SHA-256과 기준 해시로 배포본 일치를, App Control 이벤트로 정책 결정을 확인합니다.">
  <figcaption>파일 일치, 서명 검증, 원래 호스트의 로드 정책은 각각 해당 증거와 연결하세요.</figcaption>
</figure>

## 2. 정상 소프트웨어 배포를 따라가기

1. 게시자가 `Viewer.exe`를 만들고 서명합니다. 릴리스에는 문서화된 서명자와 독립적으로 신뢰할 수 있는 배포 채널에서 제공한 SHA-256 값이 있습니다. 카탈로그로 서명한 패키지라면 관련 카탈로그 정보도 함께 보존합니다.
2. 게시자는 **신뢰할 수 있는 타임스탬프**를 받을 수 있습니다. Authenticode의 타임스탬프는 서명과 연결되며, 기록된 시각에 그 서명이 존재했음을 확인하는 데 쓰입니다. 적용 정책에 따라 검증된 타임스탬프는 게시자 인증서 만료 뒤에도 서명을 유효하게 판단할 근거가 될 수 있습니다. 검증하지 않은 시각 문자열이나 타임스탬프용 인증서의 존재만으로 판단하지 말고 체인, 폐기, 정책도 확인하세요. 도구가 보여 주는 경우 타임스탬프 기관, 시각, 검증 결과를 보존합니다.
3. 분석가는 보존한 복사본의 해시를 계산하고 서명 검증을 실행합니다. 도구는 등록된 카탈로그 또는 내장 서명을 사용합니다. 어떤 경로가 선택됐는지, 검증기와 옵션, OS 빌드, 검증 시각과 신뢰 환경을 기록합니다.
4. 파일 로드 시도가 있었다면 별도의 관측입니다. 적용된 App Control 모드와 정책 버전을 확인한 뒤 Code Integrity 로그와 프로세스 또는 모듈 기록을 각각 조사하세요.

**가상 결과.** 보존한 파일은 승인된 배포본의 SHA-256과 일치하고, 검증기가 확인한 서명자도 예상한 게시자입니다. 그럼에도 원래 호스트의 정책이 해당 로드를 허용하지 않아 이벤트 3077이 남을 수 있습니다. 배포본 일치, 서명 검증, 정책 차단을 모두 기록하세요. 배포 자체가 잘못됐다고 판단하기 전에 당시 정책의 범위와 버전을 조사합니다.

서명 키를 탈취하거나 배포 과정이 침해되면 유해한 파일에 정상처럼 보이는 서명이 붙을 수 있습니다. 합법적으로 서명된 도구를 사고에 악용할 수도 있습니다. 파일 출처, 동작, 변경 승인, 정상 해시, 인증서 폐기 공지를 함께 확인하세요. 게시자 표시 이름만 보는 것보다 예상 인증서 지문이나 발급자·일련번호를 대조하는 편이 정확합니다.

## 3. 필요한 기록을 모으고 대조하기

| 출처 | 승인받아 수집할 수 있는 항목 | 사용하는 방법 |
| --- | --- | --- |
| 수집 파일과 릴리스 시스템 | UTC 수집 시각, 출처와 경로, 전체 파일 SHA-256, 승인된 릴리스 식별자, 신뢰하는 매니페스트 또는 배포 기록 | 각 출처가 어느 파일을 뜻하는지 확인합니다. 이름이 같은 물건을 비교하기 전에 수집 경로를 기록하세요. |
| Windows 서명 검증 | 명령, 도구 버전과 옵션, 적용된 신뢰·카탈로그 환경, 서명자 주체와 지문, 상태 및 메시지, 인증서 유효 기간과 검증된 타임스탬프 정보 | 검증이 통과하거나 실패한 이유를 보존합니다. 과거 호스트에서의 결과를 판단하기 전에 조사 시스템과 당시 환경을 비교하세요. |
| App Control과 엔드포인트 로그 | 해당 정책과 이벤트 수집이 있는 환경에서 `Microsoft-Windows-CodeIntegrity/Operational`, 정책 정보, 관련 프로세스·모듈 기록 | 이벤트 3076은 감사 모드에서 차단 대상이었음을, 3077은 적용 정책에 따라 실제로 차단됐음을 나타냅니다. 3089는 관련 평가의 서명 정보이며, 같은 호스트 내에서 이벤트 System 영역의 상관관계 ActivityID로 연결할 수 있습니다. 여러 건이면 각 서명 인덱스를 보존하세요. |

해시가 승인된 배포본과 다르면 파일 자체와 수집 경로, 매니페스트, 서명 증거를 보존하세요. 다른 정상 릴리스인지, 게시자가 예상과 다른지, 필요한 신뢰 결과가 확보되지 않았는지 확인합니다. 배포나 키 침해가 의심되면 신뢰할 수 있는 릴리스 정보와 파일 해시로 범위를 좁히고 관련 단말의 기록을 보존합니다. 허용 규칙을 바꾸기 전에 게시자와 사고 대응 책임자에게 확인하세요. 신뢰 검증이 완료되지 않았다면 오류 원문과 검증 환경의 카탈로그, 신뢰 체인, 승인된 폐기 정보 조회 조건을 기록합니다. 조회에 실패했다는 근거만으로 인증서가 폐기됐다고 볼 수 없습니다.

## 4. Windows에서 읽기 전용으로 확인하기

승인된 Windows 분석 환경에서 통제된 폴더에 보존 복사본을 두고 경로를 바꿔 사용합니다. 이 명령들은 메타데이터를 읽으며 파일을 실행하지 않습니다. 검증에는 호스트 인증서나 카탈로그 상태가 영향을 줄 수 있고, 정책에 따라 승인된 인증서 서비스에 연결해야 할 수 있습니다. 사건 당시 결과를 맞추기 위해 신뢰 저장소를 변경하지 마세요.

```powershell
$file = 'C:\Evidence\Viewer.exe'
Get-FileHash -LiteralPath $file -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $file |
  Select-Object Status, StatusMessage, SignatureType, SignerCertificate, TimeStamperCertificate
```

이 cmdlet은 Windows에서만 지원합니다. 내장 서명과 Windows 카탈로그 서명이 모두 적용되면 Microsoft 문서에 따르면 카탈로그 서명이 선택됩니다. Windows SDK의 **SignTool**은 `/pa`로 사용자 모드 파일에 기본 Authenticode 검증 정책을 적용할 수 있습니다. 첫 명령은 내장 서명을 확인합니다. 두 번째는 등록된 카탈로그를 먼저 찾고, 일치하는 항목이 없으면 내장 서명을 확인합니다. 실행한 명령과 전체 출력, 종료 코드를 각각 보존하세요.

```powershell
signtool verify /pa /v /tw $file
$LASTEXITCODE
signtool verify /a /pa /v /tw $file
$LASTEXITCODE
```

`/tw`는 타임스탬프가 없으면 경고를 요청합니다. SignTool 종료 코드 0은 성공, 1은 실패, 2는 경고와 함께 완료를 나타냅니다. 드라이버는 해당 드라이버 검증 지침을 따르세요. Microsoft의 2026년 7월 지침은 새 서명에 SHA-256 이상과 RFC 3161 타임스탬프를 권장합니다. 오래된 SHA-1과 이전 타임스탬프는 당시 정책을 함께 확인해야 합니다. 위 Windows 명령은 공식 문서로 확인했습니다.

## 5. 오프라인 실습 · 여섯 가지 증거 비교

본인이 관리하는 디렉터리에서 Python 3.9 이상을 사용하세요. 스크립트와 가상 Windows 기록, 무해한 텍스트 파일을 내려받습니다. 스크립트가 실제로 계산하는 것은 텍스트의 전체 파일 해시입니다. 서명, 타임스탬프와 Code Integrity 결정은 가상 입력이며 Windows 실행 파일을 로드하거나 검증하지 않습니다.

- <a href="{{ '/assets/labs/windows-authenticode-evidence/review_signature.py' | relative_url }}" download="review_signature.py">review_signature.py 다운로드</a>
- <a href="{{ '/assets/labs/windows-authenticode-evidence/cases.json' | relative_url }}" download="cases.json">가상 Windows 관측 자료 다운로드</a>
- <a href="{{ '/assets/labs/windows-authenticode-evidence/release-note.txt' | relative_url }}" download="release-note.txt">텍스트 샘플 다운로드</a>

```sh
python3 review_signature.py cases.json release-note.txt
```

| 가상 사례 | 기대 결과 |
| --- | --- |
| 승인 배포본과 유효한 내장 서명 | 전체 해시가 일치하고 검증 결과는 `Valid`입니다. 일치하는 App Control 관측은 없습니다. |
| 카탈로그 일치 | 카탈로그를 고려한 검증은 `Valid`지만 내장 서명만 확인한 경우에는 서명이 없습니다. 감사 모드 기록은 실제 차단으로 해석하지 않습니다. |
| 해시 불일치 | 검증기에 `HashMismatch`가 기록되며 전체 파일 SHA-256도 배포본과 다릅니다. |
| 게시자 인증서 만료 | 가상 환경에서 과거 시각의 검증된 타임스탬프가 있고 서명 결과는 `Valid`입니다. |
| 유효한 서명, 예상 밖 해시, 정책 차단 | 서명 신뢰, 배포본 불일치, 실행 정책 차단이 각각 기록됩니다. 관련 서명 정보 이벤트 두 건을 유지합니다. |
| 신뢰 확인 미완료 | 검증 결과가 미확정입니다. 다른 호스트에서 같은 ActivityID가 나타난 이벤트는 연결하지 않습니다. |

가상 사례 여섯 건과 텍스트 해시 비교가 통과해야 합니다. 실패 사례를 확인하려면 텍스트 복사본에 한 줄을 추가한 뒤 복사본 경로로 다시 실행합니다. 가상 증거 비교는 통과하고 파일 비교는 실패하며 종료 코드는 1입니다. 로그 연결을 확인하려면 다섯 번째 사례에서 관련 `3089` 기록 하나의 호스트를 바꿔 보세요. 서명 정보 이벤트 개수 검사가 실패합니다. 원본 텍스트가 실패하면 새 다운로드의 바이트와 비교하세요. 편집기가 저장할 때 줄바꿈을 바꿀 수 있습니다. 오프라인 비교와 실패 검사는 클라우드에서 실행했습니다. Windows 신뢰 평가와 이벤트 동작은 Microsoft 문서로 검토했습니다.

## 6. 확인 문제와 해설

1. **한 도구에서는 내장 서명이 없고 다른 도구에서는 카탈로그 서명이 유효합니다. 어느 쪽이 맞나요?** 두 결과 모두 가능해요. 도구가 선택한 검증 경로, 호스트의 카탈로그 상태, 해당 파일의 멤버 일치를 확인하세요.
2. **타임스탬프 필드가 있고 서명 인증서는 만료됐습니다. 파일이 유효한가요?** 필드가 있다는 것만으로는 판단하기 어렵습니다. 적용 정책에서 타임스탬프가 검증되는지 확인하고 서명과 신뢰 검증 결과를 수집하세요.
3. **서명자는 예상과 같지만 전체 해시는 다르고 원래 호스트에는 3077이 있습니다. 실행에 성공한 건가요?** 3077은 적용 정책에 따라 해당 시도가 차단됐음을 뒷받침합니다. 해시 차이는 배포 기록에서 조사하고 다른 실행 시도는 별도의 프로세스·모듈 기록에서 확인하세요.

**완료 기준.** 여섯 가상 사례와 두 실패 사례를 재현합니다. 수집 파일의 배포본 일치, 선택된 서명 검증 경로와 타임스탬프 결과, 원래 호스트의 실행 정책 증거를 각각 한 줄로 정리하세요.

## 공식 참고자료

2026년 11월 27일 검토. Microsoft의 실행 파일 서명 문서는 2025년 7월, 타임스탬프 지침은 2026년 7월 갱신본을 확인했습니다. PowerShell 명령은 7.5 문서, App Control 예시는 검토일 기준 Microsoft가 명시한 Windows 클라이언트·서버 범위를 따릅니다.

- Microsoft [실행 파일 서명 이해](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures), [Authenticode 타임스탬프](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures).
- Microsoft [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-7.5), [Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.5), [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).
- Microsoft [App Control 이벤트 ID](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations).
- IETF [RFC 3161 · 타임스탬프 프로토콜, 2001년 8월](https://www.rfc-editor.org/rfc/rfc3161.html).

[이전 · 공개키와 전자서명]({{ '/ko/wiki/public-key-cryptography/' | relative_url }}) · [다음 · App Control 결정]({{ '/ko/wiki/app-control-evidence/' | relative_url }}) · [Mark of the Web 증거 확인]({{ '/ko/wiki/windows-motw-evidence/' | relative_url }})
