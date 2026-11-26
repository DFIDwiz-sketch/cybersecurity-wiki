---
title: "Linux capability · 실행 파일 설정부터 스레드 권한까지"
description: "파일과 스레드의 capability를 읽고, 실행 시 적용되는 정책과 실제로 관찰한 작업을 구분합니다."
category: blue-team
tags: [Linux, Linux Capabilities, File Permissions, Linux Audit, Blue Team, DFIR]
level: Intermediate
updated: "2026-11-26"
translation_url: /wiki/linux-capability-evidence/
---

서비스가 root가 아닌 UID로 실행돼도 특정 특권이 필요한 작업은 수행할 수 있습니다. 반대로 같은 실행 파일을 쓰는 서비스도 실행할 때 받은 자격 정보나 제한이 다르면 권한이 더 적을 수 있습니다. 모드 비트, ACL과 경로 탐색은 [Linux 파일 권한]({{ '/ko/wiki/linux-file-permissions-evidence/' | relative_url }})에서 먼저 볼 수 있습니다. 이 장에서는 어떤 스레드에 어떤 권한이 있었는지, 어디서 받았는지, 실제로 사용했는지를 차례로 확인합니다.

## 1. 실행 파일과 스레드에서 각각 무엇을 읽나요?

Linux의 **capability**는 커널이 특정 작업을 검사할 때 사용하는 권한 단위입니다. 커널은 capability 집합을 **스레드별**로 관리합니다. **파일 capability**는 실행 파일의 확장 속성 `security.capability`에 들어 있습니다. 스레드가 `execve()`로 새 프로그램 이미지를 실행할 때 이 속성이 권한 계산에 쓰일 수 있습니다. capability 번호는 비트 위치입니다. 16진수 `0000000000000400`은 10번 비트가 켜진 값이며 `CAP_NET_BIND_SERVICE`에 해당합니다.

| `/proc/<pid>/task/<tid>/status` 필드 | 확인할 수 있는 내용 |
| --- | --- |
| `CapEff`, 유효 집합 | 현재 커널 권한 검사에 쓰일 수 있는 비트. 작업 종류, 네임스페이스, 다른 보안 검사도 결과에 관여 |
| `CapPrm`, 허용 집합 | 정해진 규칙 아래 스레드가 유효 집합에 넣을 수 있는 비트. 지금 활성화되지 않은 권한도 조사 대상 |
| `CapInh`, 상속 가능 집합 | 이후 exec에서 파일의 상속 가능 집합과 겹치면 허용 집합에 들어갈 수 있는 비트 |
| `CapBnd`, 상한 집합 | exec할 때 파일의 허용 집합과 교차하는 비트. 현재 보유 권한을 지우거나 상속 가능 집합을 거치는 경로에 직접 적용되지는 않음 |
| `CapAmb`, 앰비언트 집합 | 특권을 부여하지 않는 일반 파일을 exec할 때 허용·유효 집합에 이어지는 비트. 허용 집합과 상속 가능 집합 양쪽에 있어야 함 |
| `NoNewPrivs` | 파일 capability나 set-user-ID를 통해 exec 시 새 특권을 얻을 수 있는지 확인. `1`이면 새 특권 획득을 막고 자손에도 이어짐. 이미 보유한 권한은 지우지 않음 |

`getcap` 결과가 `cap_net_bind_service=ep`라면 해당 비트가 파일의 허용 집합에 있고 파일의 유효 플래그도 켜져 있습니다. 일반적인 권한 계산에서 이 플래그는 계산된 허용 집합 전체에 적용됩니다. 파일에 capability마다 독립적인 유효 집합이 있는 구조는 아닙니다. exec 이후의 상태는 스레드의 실제 `CapEff`에서 확인하세요.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-capability-evidence-ko.svg' | relative_url }}" alt="실행 파일 속성과 실행 주체의 상태를 exec 시 함께 적용합니다. 실행 뒤 대상 스레드의 권한을 읽고, 관찰한 작업과 결과를 별도로 대조합니다." style="max-width: 100%; height: auto;">
  <figcaption>그림 1. 실행 시 입력값, 실행 뒤 스레드 상태, 실제 작업의 증거가 남는 위치입니다.</figcaption>
</figure>

## 2. 정상 서비스 실행을 따라가세요

다음은 가상 사례입니다. 관리자가 TCP 443번에 바인드해야 하는 웹 서비스를 비root 계정으로 시작합니다. 서비스의 네트워크 네임스페이스에서 `net.ipv4.ip_unprivileged_port_start=1024`입니다. 서비스 관리자의 설정은 `User=websvc`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `NoNewPrivileges=yes`입니다. 예상한 실행 파일에는 파일 capability가 없습니다. 이 예제는 설정과 관측을 읽는 데 사용합니다.

1. 서비스 관리자가 계정과 앰비언트 권한을 준비합니다. systemd는 앰비언트 집합에 추가한 권한을 상속 가능 집합에도 넣는다고 문서화했습니다.
2. 일반 실행 파일이 시작될 때 미리 준비한 앰비언트 비트가 이어질 수 있습니다. `NoNewPrivs=1` 상태에서도 실행 전에 준비된 비트는 유지될 수 있습니다.
3. 바인드를 수행하는 스레드를 해당 시점에 조사했다면 `CapInh`, `CapPrm`, `CapEff`, `CapBnd`, `CapAmb`가 모두 `0000000000000400`으로 보일 수 있습니다. 다른 스레드나 이후 시점의 상태는 달라질 수 있습니다.
4. 해당 프로세스, 소켓 주소와 네트워크 네임스페이스를 연결할 수 있는 성공한 바인드 기록으로 작업 결과를 확인합니다. 리스닝 소켓만 관찰했다면 서비스 관리자가 소켓을 먼저 열고 디스크립터를 넘겼을 가능성도 있습니다. capability가 필요했다고 판단하려면 소켓 활성화 여부와 해당 네임스페이스의 포트 경계를 확인하세요.

일반적인 비root exec에서는 세 곳에서 권한이 들어옵니다. 스레드와 파일의 상속 가능 집합이 겹치는 부분, 파일의 허용 집합과 스레드 상한 집합이 겹치는 부분, 그리고 남아 있는 앰비언트 비트입니다. 특권 파일을 실행하면 앰비언트 집합이 비워집니다. 파일의 유효 플래그가 켜져 있으면 결과 허용 집합이 곧 유효 집합이 됩니다. 플래그가 꺼져 있으면 남아 있는 앰비언트 비트가 유효 집합이 됩니다. UID 0 특례, 사용자 네임스페이스 매핑, 마운트의 `nosuid`, 추적 상태와 no-new-privileges에 따라 적용되는 규칙이 달라질 수 있습니다. capability를 자체 관리하지 않는 실행 파일이 파일의 허용 권한을 모두 받지 못하는 경우에는 커널이 `EPERM`으로 실행을 거부할 수도 있습니다. 사후 스냅샷에서 비트가 보이지 않는다는 이유만으로 어느 조건이 작용했는지 알 수는 없습니다.

## 3. 예상하지 못한 권한 부여를 해석하세요

누군가 허가 없이 실행 파일 속성이나 서비스 실행 설정을 바꾸면 그 프로그램에 업무에 필요한 범위를 넘는 권한이 생길 수 있습니다. 승인된 포트 변경, 패키지 갱신, 컨테이너 배포에서도 비슷한 기록이 나올 수 있습니다. 실행 파일 내용의 SHA-256이 같아도 확장 속성, 소유자, 서비스 실행 설정은 달라질 수 있습니다. 패키지가 파일을 교체했다면 같은 경로에 다른 inode가 생길 수도 있습니다.

`security.capability`가 추가되거나 넓어진 경우는 우선 설정 변경으로 다룹니다. 새 권한의 사용 여부는 해당 파일의 실행 성공과 구체적인 작업 증거를 연결해 판단합니다. 변경 요청이 “capability 제거”였다면 변경 전후의 유효 상태를 비교하고 오래 실행 중인 프로세스도 확인하세요. 디스크의 속성이나 유닛 파일을 바꾸는 것만으로는 실행 중인 모든 스레드의 권한이 바뀌지 않습니다.

## 4. 블루팀 수집·탐지·대응

| 출처 | 수집할 정보와 조건 |
| --- | --- |
| 실행 파일과 파일시스템 | 대상 프로세스 관점의 장치, inode, 숫자 소유자, 모드, 내용 해시, capability 확장 속성, 마운트 플래그. libcap 도구가 있다면 `getcap -n -v /path/to/binary`로 속성과 0이 아닌 네임스페이스 root ID 확인. 승인된 객체를 올바른 마운트 관점에서 조회 |
| 실행 중인 프로세스 | procfs가 있고 접근이 허용되면 `/proc/<pid>/task/<tid>/status`에서 UID/GID와 capability 확인. 부팅 ID, 시작 시각, PID/TID, 실행 파일 식별자, 마운트·사용자·네트워크 네임스페이스와 UID 매핑 보존. libcap의 `capsh --decode=0000000000000400`으로 마스크를 해석할 수 있음 |
| 서비스와 변경 기록 | 유닛과 드롭인, 실행 시각과 실제 실행 주체, 배포 승인 기록 확인. systemd에서는 `systemctl cat UNIT` 결과와 실행 중인 프로세스를 따로 수집. 디스크의 현재 설정은 실행 시 적용된 설정과 다를 수 있음 |
| 과거 감사·EDR 기록 | 수집 범위에 있을 때 exec와 관련 작업의 성공·실패를 확보. 대상 파일시스템의 확장 속성 변경이 실제로 기록되는지 확인. 호스트, 부팅, 프로세스 수명, 장치와 inode, 시각으로 연결. 시작 로그에는 이후 권한 변경이 없을 수 있음 |

승인된 배포 범위 밖의 파일 권한 추가나 서비스 권한 확대를 탐지하세요. 내용과 메타데이터는 각각 기준 상태를 관리합니다. 민감한 서비스에서 예상 밖 권한과 해당 파일의 최근 실행을 함께 발견했다면 우선 조사하고, 다음으로 구체적인 작업 결과를 확인하세요. 가능한 경우 승인된 재시작이나 격리 전에 현재 상태를 보존합니다. 검증된 실행 파일 메타데이터와 서비스 설정으로 복구하고 승인된 시간에 실행 상태를 맞춘 뒤, 재시작한 스레드의 권한과 서비스 기능을 확인하세요. 정상 패키지 변경과 승인된 소켓 활성화도 탐지 대조군에 포함합니다.

## 5. 승인된 오프라인 실습

소유하거나 사용을 승인받은 환경에 <a href="{{ '/assets/labs/linux-capability-evidence.py' | relative_url }}" download>Python 실습 파일</a>을 내려받으세요. 자기 procfs 상태를 읽고 가상 비트 집합을 단순화한 모델에 넣습니다. 이어서 자식 프로세스에서 no-new-privileges를 설정하고 Python 인터프리터를 다시 exec합니다. 네트워크를 사용하지 않으며 파일, 서비스 설정, capability 부여 상태를 바꾸지 않습니다. procfs가 마운트된 Linux, `prctl`을 제공하는 libc와 Python 3가 필요합니다. 일반 사용자로 실행하세요.

```bash
python3 linux-capability-evidence.py
```

| 실습 | 기대 결과 |
| --- | --- |
| 파일 허용 비트가 스레드 상한 집합에 있음 | 파일 유효 플래그를 켜면 모델의 허용·유효 집합에 모두 들어감 |
| 상한 집합이 파일 허용 비트를 제외 | 해당 경로에서는 모델상 권한이 들어오지 않음. 특정 실행 파일이 시작되는지까지 예측하지 않음 |
| 파일과 스레드의 상속 가능 비트가 일치 | 모델에서 상한이 0이어도 허용 집합에 들어갈 수 있음. 유효 플래그와 앰비언트 비트가 없으면 활성 상태는 아님 |
| 일반 파일의 exec와 특권 파일의 exec 비교 | 일반 파일에서는 앰비언트 비트가 두 집합에 이어지지만 특권 파일에서는 앰비언트로부터 들어오는 비트가 사라짐 |
| 실제 자식 프로세스에서 exec 전후 비교 | 부모의 초기 상태와 상관없이 자식의 두 관측에서 `NoNewPrivs=1` |

기대 결과는 모델 대조 다섯 건과 자식의 플래그 상속 한 건입니다. 스냅샷 값은 환경에 따라 달라집니다. procfs 필드가 없거나 `prctl`에 실패한다면 호환성과 실행 제한부터 확인하고, 이를 모델 검증 오류와 구분하세요. 모델은 root 특례, 네임스페이스·마운트 처리, `no_new_privs`의 파일 권한 부여 판단과 실행 거부는 다루지 않습니다. 실제 자식 프로세스에서 확인하는 항목은 플래그 상속입니다. Linux 6.18.57과 Python 3.12.14에서 실행했고, 부모에 이미 켜져 있던 플래그가 자식의 exec 뒤에도 유지됐습니다. systemd 동작, 서비스 바인드, 감사 로그 수집은 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

1. **파일이 `=ep`인데 작업 스레드의 유효 집합이 비어 있으면 무엇을 수집하나요?** 실제 실행된 inode, 파일 속성, 마운트와 네임스페이스를 확인합니다. 실행 주체의 상한·no-new-privileges 설정과 실행 이후의 상태 변경 가능성도 비교합니다.
2. **유효 집합에 10번 비트가 있지만 `getcap`에서는 파일 속성이 보이지 않습니다. 어떻게 설명할 수 있나요?** 실행 주체가 준비한 앰비언트 비트가 일반 exec에서 이어졌을 수 있습니다. 실제 프로세스와 실행 주체의 상태를 함께 읽으세요.
3. **10번 비트가 있는 작업자가 그 권한으로 리스닝 소켓을 열었나요?** 바인드 성공 기록, 해당 네임스페이스의 포트 경계와 소켓 디스크립터의 출처가 필요합니다. capability 스냅샷은 특정 시점에 행사할 수 있었던 권한을 보여 줍니다.

**완료 기준.** 다섯 집합을 구분하고 실습 결과를 재현하며, 실제 작업을 입증하려면 어떤 자료가 필요한지 설명할 수 있습니다. 다음으로 [Linux Audit 파일 접근]({{ '/ko/wiki/linux-audit-file-evidence/' | relative_url }})에서 시스템 호출 기록을, [Linux 소켓 관측 범위]({{ '/ko/wiki/linux-socket-scope-evidence/' | relative_url }})에서 소켓의 가시성을 살펴보세요.

## 공식 참고자료

2026-11-26에 검토했습니다. 매뉴얼은 Linux 인터페이스를, systemd 자료는 버전 262를 다룹니다. 커널 문서의 플래그는 Linux 3.5부터 지원됩니다. 운영 환경에서는 설치된 버전과 서비스 설정을 확인하세요.

- Linux man-pages 6.19의 [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html), [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html), [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
- Linux 커널 사용자 공간 API의 [No New Privileges 플래그](https://docs.kernel.org/userspace-api/no_new_privs.html)와 [IP sysctl 포트 경계](https://docs.kernel.org/networking/ip-sysctl.html#ip-variables)
- libcap과 systemd의 [getcap(8)](https://man7.org/linux/man-pages/man8/getcap.8.html), [systemd.exec](https://www.freedesktop.org/software/systemd/man/262/systemd.exec.html)
