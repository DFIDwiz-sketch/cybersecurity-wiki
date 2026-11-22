---
title: "SELinux AVC 조사 · 파일 레이블과 접근 거부 읽기"
description: "프로세스와 파일 레이블을 읽고 AVC와 시스템 호출을 연결해 실제 차단과 기록만 남은 판단을 구분합니다."
category: blue-team
tags: [Linux, SELinux, Linux Audit, File Permissions, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /wiki/selinux-avc-evidence/
---

웹 서비스가 대부분의 페이지를 정상적으로 제공하지만 새로 배포한 페이지에서는 “Permission denied”를 반환합니다. 파일 모드는 `0644`입니다. 이때 어느 프로세스가 무슨 작업을 요청했는지 찾고, 보안 레이블과 SELinux 판단, 시스템 호출 반환값을 대조합니다.

## 1. 파일 접근을 판단하는 두 계층

**임의 접근 제어(DAC)**에는 파일 소유권, 모드 비트, ACL에 따른 권한 검사가 포함됩니다. 상위 디렉터리 탐색 권한과 요청한 프로세스의 자격 정보도 영향을 줍니다. **강제 접근 제어(MAC)**는 시스템 정책에 따른 규칙을 추가합니다. SELinux는 프로세스와 대상 객체의 **컨텍스트**, 즉 보안 레이블을 평가합니다. 컨텍스트는 사용자, 역할, 타입, 해당하는 경우 보안 수준 또는 범위로 구성됩니다. 프로세스의 타입을 흔히 **도메인**이라고 부릅니다. **타입 강제** 정책은 도메인, 대상 타입, 객체 클래스, 요청한 권한의 조합을 평가합니다. 예를 들어 `httpd_t` 도메인이 `httpd_sys_content_t` 타입을 가진 `file`을 읽을 수 있는지 판정합니다.

이 장에서 다루는 RHEL 파일 접근 경로에서는 DAC가 먼저 요청을 거부하면 SELinux 검사에 이르지 않을 수 있습니다. **AVC**는 Access Vector Cache와 관련된 정책 판단 레코드입니다. AVC가 보이지 않는 이유로는 DAC 거부, 감사 기록을 억제하는 `dontaudit` 정책, 수집 공백 등이 있습니다. 로그가 없다는 사실만으로 실패한 계층을 확정할 수 없습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/selinux-avc-evidence-ko.svg' | relative_url }}" alt="파일 요청은 먼저 DAC 검사를 거칩니다. 통과하면 SELinux가 레이블을 평가할 수 있습니다. AVC와 같은 감사 이벤트의 시스템 호출 결과를 대조합니다.">
  <figcaption>파일 모드, 레이블, 정책 판단, 시스템 호출 결과는 각각 다른 질문에 답합니다.</figcaption>
</figure>

| 증거 | 무엇을 알 수 있나요? | 추가 확인 |
| --- | --- | --- |
| 모드, ACL, 프로세스 자격 정보 | 관측한 DAC 조건에서 요청이 허용될지 판단할 단서 | 상위 디렉터리, 마운트 관점과 사건 당시의 상태 |
| `scontext`, `tcontext`, `tclass` | 요청 주체와 대상의 레이블, 객체 클래스 | 해당 배포에서 의도한 레이블 |
| `permissive=0`을 담은 AVC 거부 | 기록의 SELinux 권한 검사가 실제 강제됐음 | 같은 이벤트의 시스템 호출 결과와 사용자에게 나타난 영향 |
| `permissive=1`을 담은 AVC 거부 | 정책상 거부될 조건이지만 해당 검사는 강제되지 않았음 | 다른 원인의 실패를 포함한 실제 시스템 호출 결과 |
| `SYSCALL success`, `exit` | 감사된 시스템 호출의 성공 여부와 반환값 | 애플리케이션 작업 전체가 끝났는지 |

시스템 전체가 강제 모드여도 개별 도메인은 허용 모드일 수 있습니다. 과거 판단을 조사할 때는 오늘 실행한 `getenforce` 결과보다 당시 레코드의 `permissive` 필드가 해당 검사에 더 가까운 증거입니다.

## 2. 정상 조회와 레이블 불일치 따라가기

RHEL 9의 가상 사례에서 `httpd_t` 도메인으로 실행하는 웹 작업 프로세스가 `/var/www/html/` 아래의 정적 페이지를 제공합니다. DAC는 디렉터리 탐색과 파일 읽기를 허용하고, 일반 파일에는 예상한 `httpd_sys_content_t` 타입이 붙어 있습니다. 정책도 허용하면 파일 열기가 성공합니다. 파일 열기 성공은 파일 디스크립터를 얻었다는 증거입니다. 어떤 내용을 응답했는지 알려면 앱 응답 등 추가 관측이 필요합니다.

새 페이지를 배포한 뒤 파일의 실제 레이블은 `user_home_t`이고, 활성 파일 컨텍스트 매핑은 그 경로에 `httpd_sys_content_t`를 기대한다고 가정해 봅시다. 원본 레이블을 보존하는 배포 방식에서 이런 차이가 생길 수 있습니다. 아래는 축약한 가상 감사 로그입니다. `1730120000.010:101`은 한 호스트의 한 부팅 세션에서 같은 이벤트를 가리킵니다.

```text
type=AVC msg=audit(1730120000.010:101): avc: denied { read } for pid=420 comm="httpd" path="/var/www/html/guide.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
type=SYSCALL msg=audit(1730120000.010:101): arch=c000003e syscall=257 success=no exit=-13 pid=420 comm="httpd"
```

이 x86-64 예에서 `257`은 `openat`, `-13`은 `EACCES`입니다. 시스템 호출 번호는 기록된 아키텍처를 기준으로 해석하세요. AVC에는 SELinux의 `read` 거부가 남았고, 같은 이벤트의 시스템 호출도 실패했습니다. 레이블과 프로세스, 이벤트를 보존하고 배포 명세와 예상 레이블을 대조하세요. `exit=-13`만 봤다면 원인을 판단할 증거가 더 필요합니다.

## 3. 수집·탐지·대응

1. **요청을 특정합니다.** 호스트, 확보 가능한 부팅 식별자, UTC 시각, 서비스 유닛과 프로세스, 실제 마운트 또는 컨테이너 관점, 감사 타임스탬프와 일련번호 전체, 대상 객체 정보를 남깁니다. `PATH`와 `CWD`가 있으면 같은 이벤트의 일부로 보존합니다. PID는 재사용될 수 있고, 다른 호스트에 같은 일련번호가 나올 수 있습니다.
2. **정책 범위와 수집 상태를 확인합니다.** 주체·대상 레이블, 객체 클래스, 거부된 권한, `permissive` 값과 시스템 호출 결과를 보존하세요. 현재 모드와 정책 버전을 확인 시각과 함께 기록합니다. 서비스와 Audit 수집 범위, 보존 기간, 수집 손실, 중앙 수집에서 같은 이벤트의 연관 레코드를 보존하는지 확인합니다.
3. **운영 맥락과 대조합니다.** 배포 직후 반복되는 강제 거부는 잘못된 레이블이 원인일 수 있습니다. 반면 웹 도메인이 비공개 파일에 쓰이는 레이블을 예상 밖으로 읽으려 했다면 앱 오류나 의심스러운 활동을 조사할 이유가 됩니다. 배포 시점, 서비스 신원과 경로, 패키지·정책 변경, 별도 앱 로그를 대조하세요. AVC 하나로 침해, 접근 성공, 배후의 개인을 확정할 수 없습니다.
4. **필요한 범위만 바로잡습니다.** 원본 로그와 레이블 증거를 먼저 보존합니다. 공급자가 지원하는 위치의 레이블이 예상과 다르면 담당자와 해당 범위만 교정합니다. 비표준 경로는 정책 담당자와 지속적으로 적용할 파일 컨텍스트 매핑을 검토하세요. 넓은 파일 권한 변경이나 자동 생성된 허용 규칙은 앱 요구보다 접근 범위를 넓힐 수 있습니다. 승인된 시험 환경에서 정상 작업이 성공하고, 정책상 금지된 별도 작업은 여전히 차단되는지 확인합니다.

필요한 도구가 설치된 승인된 RHEL 9 호스트에서 `420`과 경로를 관측한 값으로 바꾸세요. `ausearch`에는 로컬 Linux Audit 저장소의 읽기 권한이 필요합니다. 아래 명령은 상태를 조회하며 파일 레이블을 바꾸지 않습니다.

```bash
getenforce
ps -p 420 -o pid,label,comm
ls -Zd -- /var/www/html/guide.html
matchpathcon -V /var/www/html/guide.html
ausearch -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR -ts recent --raw
```

`matchpathcon -V`는 실제 객체의 컨텍스트와 현재 기본 매핑을 비교합니다. 서비스에 어떤 타입이 적절한지, 프로세스가 읽을 수 있는지까지 판단하지는 않습니다. `recent`는 최근 약 10분을 보는 초기 조회입니다. 과거 사건은 승인 범위 안에서 시간을 넓혀 찾고, 수집기에 자료가 없다면 호스트 원본을 확인하세요. 명령은 공식 문서로 검토했습니다. 아래 실습은 가상 기록을 읽으며 호스트에 SELinux나 Audit를 요구하지 않습니다.

## 4. 오프라인 실습

Python 3.8 이상이 설치된 승인된 학습 환경에서 <a href="{{ '/assets/labs/selinux-avc-evidence.py' | relative_url }}" download="selinux-avc-evidence.py">이벤트 연결 스크립트</a>와 <a href="{{ '/assets/labs/selinux-avc-evidence.json' | relative_url }}" download="selinux-avc-evidence.json">가상 기록</a>을 같은 디렉터리에 저장합니다.

```bash
python3 selinux-avc-evidence.py selinux-avc-evidence.json
```

JSON에는 가상의 호스트와 부팅 식별자, 축약한 AVC·SYSCALL 문자열이 들어 있습니다. 스크립트는 이 예제 형식만 읽고 호스트, 부팅, `audit(...)` 안의 값 전체로 묶은 뒤 `permissive` 필드와 시스템 호출 결과를 비교합니다. 임의의 감사 로그를 해석하거나 당시 정책을 복원하는 도구는 아닙니다.

| 이벤트 | 기대 결과 |
| --- | --- |
| `lab-a/boot-1/101` | 강제 거부와 시스템 호출 실패 |
| `lab-b/boot-2/101` | `lab-a`와 같은 감사 값이지만 다른 호스트에서 기록만 남은 거부와 시스템 호출 성공 |
| `lab-a/boot-1/102` | 시스템 호출 실패, 짝이 되는 AVC는 가상 자료에 없음 |
| `lab-a/boot-1/103` | 강제 거부는 기록됐으나 시스템 호출 결과를 알 수 없음 |
| `lab-a/boot-1/104` | 기록만 남은 거부와 시스템 호출 실패 |
| `lab-a/boot-1/105` | 시스템 호출 성공, 짝이 되는 AVC는 가상 자료에 없음 |
| `lab-a/boot-1/106` | 거부가 기록됐지만 필드 누락으로 강제 여부를 알 수 없음 |

파일을 열 수 없다면 현재 디렉터리와 파일 이름을 확인하세요. 짝을 찾지 못했다면 정책 탓으로 돌리기 전에 호스트, 부팅, 타임스탬프, 일련번호를 비교합니다. 복사본에서 `lab-a` 이벤트 101의 SYSCALL을 제거하면 시스템 호출 결과를 관측하지 못했다는 출력이 나와야 합니다. 게시한 사례는 모두 가상 자료로 실행했습니다.

## 5. 확인 문제와 완료 기준

1. **파일 모드가 `0644`인데 왜 강제 거부가 생길 수 있나요?** 모드는 DAC의 입력만 일부 설명합니다. 프로세스와 대상 레이블의 조합에 대해 SELinux 정책이 별도로 거부할 수 있습니다.
2. **`permissive=1`은 시스템 호출 성공을 뜻하나요?** 기록된 SELinux 검사를 강제하지 않았음을 보여 줍니다. 다른 검사로 작업이 실패할 수 있습니다.
3. **AVC가 없다면 DAC가 차단한 건가요?** AVC가 없는 이유는 하나로 정해지지 않습니다. 수집 범위와 기록 억제, 요청이 SELinux 검사까지 도달했는지 확인합니다.
4. **레이블 불일치를 안전하게 바로잡았는지 어떻게 알 수 있나요?** 의도한 매핑을 변경 후 레이블과 대조합니다. 서비스의 실제 실행 맥락에서 허용 작업과 금지 작업을 각각 시험하고 감사 기록과 서비스 결과를 확인합니다.

호스트별로 일치하는 레코드를 설명하고, 기록만 남은 거부와 실제 차단을 구분하고, 짝을 못 찾은 사례에 어떤 증거가 빠졌는지 말할 수 있으면 완료입니다.

## 공식 참고자료

검토일 2026년 11월 23일. 제품 문서는 RHEL 9를 대상으로 합니다. 다른 배포판을 사용한다면 설치된 정책과 감사 구성을 확인하세요.

- [Red Hat · SELinux 시작하기](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/getting-started-with-selinux_using-selinux)
- [Red Hat · SELinux 문제 해결](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/troubleshooting-problems-related-to-selinux_using-selinux)
- [Linux Audit · ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html) 및 [SELinux 프로젝트 · matchpathcon(8)](https://man7.org/linux/man-pages/man8/matchpathcon.8.html)

[이전 · Linux 파일 권한]({{ '/ko/wiki/linux-file-permissions-evidence/' | relative_url }}) · [다음 · Linux Audit 파일 접근]({{ '/ko/wiki/linux-audit-file-evidence/' | relative_url }})
