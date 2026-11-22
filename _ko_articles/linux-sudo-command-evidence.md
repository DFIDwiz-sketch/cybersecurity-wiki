---
title: "Linux sudo 명령 조사 · 정책 판단에서 실제 결과까지"
description: "가상 사례 12건으로 sudo 인증 문맥, 명령 허용, 실행, 종료 상태와 실제 작업 결과를 구분합니다."
category: dfir
tags: [Linux, sudo, Authentication, Linux Audit, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/linux-sudo-command-evidence/
---

sudo 기록에는 명령과 대상 계정이 나타납니다. 높은 권한으로 어떤 일이 일어났다고 보고하기 전에 그 기록이 어느 단계를 보여 주는지 확인하세요. 정책 판단, 프로세스 시작, 명령 종료, 실제 상태 변경에는 서로 다른 증거가 필요할 수 있습니다. SSH와 PAM 세션부터 익히려면 [Linux 인증 로그 조사]({{ '/ko/wiki/linux-auth-evidence/' | relative_url }})를 먼저 읽으세요.

## 1. sudo는 무엇을 판단하나요?

**sudo**는 호출자가 **대상 계정**의 권한으로 작업을 요청하게 합니다. 대상은 root일 수도 있고 권한이 더 제한된 서비스 계정일 수도 있습니다. **정책 플러그인**은 호출자가 무엇을 요청할 수 있는지 판단합니다. sudoers에서는 그룹, 호스트, 대상 사용자나 그룹, 명령과 인수, 설정 출처에 따라 적용 정책이 달라질 수 있습니다. 어느 계정의 인증을 요구하는지도 정책에 따라 다릅니다. 해당 호스트와 당시의 신원·정책 문맥을 확인하세요.

**인증**은 필요한 자격 증명을 확인하는 단계입니다. sudoers는 `timestamp_type`, `timestamp_timeout` 같은 설정에 따라 이전 인증 타임스탬프를 재사용할 수 있습니다. 일부 정책에는 `NOPASSWD` 태그가 있습니다. 암호를 묻지 않는 데는 정상적인 이유가 있으며, 한 번의 관측으로 인증 캐시와 정책 예외를 구분하기 어렵습니다. 어느 경우에도 다른 명령까지 허용됐다는 뜻은 아닙니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-sudo-command-evidence-ko.svg' | relative_url }}" alt="호출자와 대상 계정을 확인하고 인증 문맥, 정책 판단, 명령 실행과 종료, 실제 작업 결과를 차례로 대조합니다.">
  <figcaption>단계마다 해당 증거를 남기고, 관측이 끊기는 지점에서 판단 범위를 제한합니다.</figcaption>
</figure>

| 확인한 증거 | 뒷받침하는 판단 | 다음에 필요한 증거 |
| --- | --- | --- |
| 입력 요청, 인증 실패 또는 유효한 인증 캐시 | 해당 문맥의 인증 처리 | 요청한 작업의 정책 판단 |
| sudoers의 허용 또는 거절 | 기록된 정책 판단 | 연결된 프로세스 실행이나 실패 |
| Linux Audit 시스템 호출과 프로세스 기록 | 감사 범위 내 시스템 호출의 결과 | 프로그램 종료 또는 별도의 작업 결과 |
| sudo 종료 코드 또는 시그널 | 수집된 경우 해당 명령이 어떻게 끝났는지 | 파일, 서비스, 애플리케이션에서 확인한 결과 |
| 리소스 활동 또는 상태 | 관측 지점에서 실제로 본 사실 | 올바른 프로세스·변경과의 연결 |

## 2. 정상 유지보수 명령 따라가기

가상의 운영자가 `app-lab-01`에서 승인된 서비스 상태 조회를 실행합니다. sudo는 호출자 `alex`, 대상 `root`, `TTY=pts/2`, 작업 디렉터리와 `COMMAND=/usr/bin/systemctl is-active reports.service`를 기록합니다. 운영자는 인증을 재사용할 수 있는 문맥에서 이미 인증했습니다. Audit 또는 엔드포인트 자료에서 일치하는 프로세스를 찾고, 설정된 종료 로그에서 종료 코드 0을 확인합니다. 이 읽기 전용 조회에서 서비스가 정상이라고 보고하려면 명령이 실제로 무엇을 반환했는지 확인하세요. 지속적인 상태 변경은 예상하지 않습니다.

다른 유지보수 사례에서는 승인된 명령으로 애플리케이션 설정이 변경됐습니다. 그 작업의 자체 로그나 버전별 파일 상태를 대조하세요. 종료 코드만으로 어떤 값이 바뀌었는지는 알 수 없습니다. 정책이 허용한 뒤 실행이 실패할 수도 있습니다. 명령이 0이 아닌 값으로 종료됐어도 변경이 일부 적용됐을 수 있으므로 실제 상태를 확인합니다.

## 3. 출처별로 모아 연결하기

1. **정책과 호출 문맥을 보존합니다.** 호스트, 부팅 구간, UTC 시각, 호출·대상 계정, TTY, 작업 경로, 승인된 범위의 인수, 플러그인과 버전을 남깁니다. 관련 설정 이력과 계정·그룹 기록도 보존합니다. 로컬 파일, 포함된 파일, 디렉터리 기반 규칙이 모두 영향을 줄 수 있습니다. 나중에 조회한 정책은 현재 상태입니다. 당시 상태는 보존된 스냅샷과 변경 승인으로 재구성하세요.
2. **실행을 확인합니다.** Linux Audit 또는 엔드포인트 자료에서 관측 가능한 경우 호스트·부팅 구간, 감사 세션이나 신뢰할 수 있는 세션 증거, 실제 프로세스 인스턴스를 연결합니다. 시작 시각, 실행 파일, 부모와 유효 신원을 봅니다. `auid`는 값이 기록된 경우 감사 로그인 UID이고 `euid`는 유효 UID입니다. 높은 `euid`만으로 sudo를 확인할 수 없습니다. Audit `SYSCALL`의 `exit`는 시스템 호출의 반환값이며 프로그램 최종 종료 코드와 별개입니다. 여러 레코드를 묶는 방법은 [Linux Audit 파일 증거]({{ '/ko/wiki/linux-audit-file-evidence/' | relative_url }})에서 확인하세요.
3. **수집 조건과 실제 결과를 확인합니다.** sudoers는 syslog, 지정 파일 또는 설정에 따른 다른 경로로 기록을 보낼 수 있습니다. 상위 매뉴얼에 따르면 `log_exit_status`는 sudo 1.9.8 이상에서 지원하며 기본적으로 꺼져 있습니다. 설치 패키지, 로그 경로와 설정 범위, 보존 기간, 전달 상태를 확인하세요. 입출력 기록과 하위 명령 기록은 서로 다른 제어이며 버전과 호환성, 개인정보 조건이 따릅니다. 허용된 명령이 다른 프로세스를 시작할 수 있으므로 승인된 프로세스 계보와 리소스 증거로 범위를 좁힙니다. 인수와 터미널 출력에 비밀 정보가 들어갈 수 있어 로그 접근을 제한하세요.

sudo가 있는 승인된 시험 호스트라면 대상 명령을 실행하지 않고 자신의 현재 정책을 조회할 수 있습니다. 아래 명령으로 로그가 남을 수 있습니다. `-n`은 대화형 입력 요청을 막습니다. 조회 정책이나 인증 요구 때문에 두 번째 명령이 실패할 수 있으므로 메시지로 어느 단계인지 확인하세요. 이 제품 명령은 패키지 매뉴얼로 검토했습니다.

```bash
sudo --version
sudo -n -l
```

## 4. 추가 조사가 필요한 경우

승인된 계정이라도 업무에 필요한 범위를 넘는 권한을 쓸 수 있고, 침해된 계정이 기존 정상 규칙을 사용할 수도 있습니다. 권한 높은 규칙이 참조하는 파일이나 스크립트가 승인 후 바뀌는 경우도 있습니다. 규칙과 해당 프로그램의 소유자·무결성을 함께 확인하세요. 예상 밖의 호출자나 대상, 서비스 용도, 승인되지 않은 정책 변경, 실제 결과를 기준으로 우선순위를 정합니다. 실패 뒤 허용이 연달아 기록돼도 정상적인 문제 해결일 수 있습니다. 전후 작업과 승인을 확인한 뒤 판단합니다.

설명되지 않는 높은 권한의 작업은 호스트 담당자와 사고 대응 책임자에게 공유합니다. 가능한 경우 승인된 격리 전에 로그와 현재 적용 정책을 보존하세요. 실행 프로그램, 하위 프로세스, 파일과 서비스에 남은 결과를 대조합니다. 증거가 없으면 Audit 규칙 범위, 센서 백로그, 저널 보존과 중앙 전달 공백을 확인하세요. 조치 후에는 복구 계획이 있는 승인된 일회용 시험 호스트에서 무해한 작업으로 예상 허용과 거절을 확인합니다. 아래 다운로드 실습은 가상 자료로만 진행합니다.

## 5. 오프라인 실습 · 가상 관측 열두 건

두 파일을 같은 폴더에 내려받고 Python 3.10 이상에서 실행하세요. JSONL은 공급자 원본 형식이 아닌 정규화된 가상 기록입니다. `invocation`은 실습의 연결 키입니다. 실제 sudo나 Audit에 모든 출처가 공유하는 동일 필드가 있다는 뜻은 아닙니다. 실습은 호스트, 부팅 구간, 세션, 연결 키가 모두 일치하는지 확인합니다. `at`은 상대 초입니다. 이 사례는 서로 다른 단계의 엄격한 시간 순서를 가정합니다. 실제 조사에서는 자체 정규화와 시계 오차 범위가 필요합니다. 스크립트는 로컬 파일만 읽습니다.

<a href="{{ '/assets/labs/linux-sudo-command-evidence.py' | relative_url }}" download="linux-sudo-command-evidence.py">linux-sudo-command-evidence.py</a> · <a href="{{ '/assets/labs/linux-sudo-command-evidence-cases.jsonl' | relative_url }}" download="linux-sudo-command-evidence-cases.jsonl">linux-sudo-command-evidence-cases.jsonl</a>

```bash
python3 linux-sudo-command-evidence.py linux-sudo-command-evidence-cases.jsonl
```

```text
status_read: zero_exit_effect_unknown
change_confirmed: effect_confirmed
allowed_only: allowed_execution_unknown
policy_denied: denied
auth_required: authentication_required
different_boot: execution_unlinked
missing_session: execution_unlinked
execution_rejected: exec_failed
exit_missing: started_exit_unknown
command_nonzero: command_nonzero
other_invocation: exit_unlinked
effect_before_start: zero_exit_effect_unlinked
```

`status_read`의 종료 코드 0은 독립적인 상태 증거를 주지 않습니다. `effect_before_start`에서는 명령보다 이른 관측을 그 명령의 효과로 볼 수 없습니다. 실행이 실패하면 작업 폴더와 파일명을 확인하세요. 사례가 예상과 달리 연결되지 않으면 종료 코드보다 먼저 호스트, 부팅 구간, 세션, 연결 키를 보세요. 가상 실습은 Python 3.12에서 실행했습니다. 실제 sudo와 Audit 동작은 제품 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **암호 입력 요청이 없었으면 정책이 우회됐나요?** 인증 캐시와 해당 정책의 예외, 실제 정책 판단을 확인하세요. 입력 요청이 없다는 사실만으로 원인을 고를 수 없습니다.
- **exec 시스템 호출에서 `success=yes`면 프로그램 작업도 성공했나요?** 기록된 시스템 호출이 성공했다는 뜻입니다. 이후 종료와 실제 결과는 별도의 기록으로 확인합니다.
- **다른 부팅 구간에 같은 PID의 종료 이벤트가 있으면 이어 붙일 수 있나요?** 부팅 구간, 시각과 프로세스 인스턴스를 맞추세요. PID는 재사용됩니다.

열두 줄의 결과를 재현하고 `allowed_only`, `exit_missing`, `effect_before_start`에서 다음에 확인할 자료를 각각 말할 수 있으면 실습을 마친 것입니다.

## 공식 참고자료

검토일은 2026-11-22입니다. Ubuntu 문서는 서로 다른 LTS 패키지를, Red Hat 문서는 RHEL 9를 다룹니다. 상위 매뉴얼은 기능과 기본값을 설명합니다. 조사 환경에서 설치 패키지와 실제 정책을 확인하세요.

- 상위 프로젝트의 정책·로그 문서. 설치된 릴리스와 대조하세요. [sudo 프로젝트 · sudoers 매뉴얼 원본](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in)
- 정책 일치, 인증, 로깅 한계. log_exit_status는 1.9.8 이상에서 지원합니다. [sudoers(5) · 렌더링된 상위 매뉴얼](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- Noble 패키지의 인증 캐시 레코드와 적용 범위. [Ubuntu 24.04 LTS · sudoers_timestamp(5)](https://manpages.ubuntu.com/manpages/noble/man5/sudoers_timestamp.5.html)
- Jammy의 정책 조회, 비대화형 옵션과 종료 상태. [Ubuntu 22.04 LTS · sudo(8)](https://manpages.ubuntu.com/manpages/jammy/man8/sudo.8.html)
- RHEL 9 감사의 로그인 신원과 시스템 호출 결과 필드. [Red Hat Enterprise Linux 9 · 감사](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/epub/security_hardening/understanding-audit-log-files_auditing-the-system)

[이전 · Linux 인증 로그]({{ '/ko/wiki/linux-auth-evidence/' | relative_url }}) · [다음 · Linux Audit 파일 증거]({{ '/ko/wiki/linux-audit-file-evidence/' | relative_url }}) · [관련 · Linux 프로세스 식별]({{ '/ko/wiki/linux-process-evidence/' | relative_url }})
