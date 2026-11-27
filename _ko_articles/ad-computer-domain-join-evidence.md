---
title: "Active Directory 도메인 가입 · 컴퓨터 계정과 가입 증거"
description: "컴퓨터 계정 생성, 기존 계정 재사용 심사, 단말의 도메인 가입 결과를 오프라인 기록 아홉 건으로 구분합니다."
category: active-directory
tags: [Active Directory, Domain Join, Windows Logs, Domain Controller, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /wiki/ad-computer-domain-join-evidence/
---

도메인 컨트롤러(DC)에는 `LAB-PC07$` 컴퓨터 계정이 생성됐다고 나오는데, 배포 대기열에는 가입 실패라고 적혀 있습니다. 어느 기록이 틀렸다고 판단하기 전에 DC가 어떤 변경을 기록했는지, 가입 단말이 어떤 결과를 보고했는지, 나중에 단말과 도메인의 신뢰가 정상인지 확인합니다.

## 1. 디렉터리 객체와 실제 단말을 구분하기

**컴퓨터 계정**은 AD DS에서 컴퓨터의 ID를 나타내는 객체입니다. 보통 계정 이름은 `$`로 끝납니다. 권한 판단에는 보안 식별자 **SID**가 쓰이고, 디렉터리 객체는 **objectGUID**로 식별합니다. **고유 이름**(DN)은 디렉터리의 현재 경로로, 객체를 이동하거나 이름을 바꾸면 달라질 수 있습니다. **도메인 가입**은 Windows 단말이 도메인에 참여하도록 구성하는 작업입니다. 가입한 멤버의 현재 신뢰 상태는 Netlogon **보안 채널**로 점검할 수 있습니다.

새로 온라인 가입할 때 DC가 요청의 일부로 컴퓨터 계정을 만들 수 있습니다. 배포 담당자가 계정을 미리 만드는 **사전 준비**(prestaging) 방식도 있습니다. 이때 단말은 기존 객체의 재사용을 시도합니다. 재사용 보안 검사와 AD 쓰기 권한 확인은 별개입니다. 가입 동작이 성공을 보고한 뒤 필요한 재시작을 마치고 현재 신뢰를 확인하세요. 디렉터리 변경, 재사용 허용, 가입 동작 성공, 실제 신뢰 상태는 서로 다른 기록입니다.

<figure>
  <img src="{{ '/assets/diagrams/ad-computer-domain-join-evidence-ko.svg' | relative_url }}" width="560" height="350" alt="DC는 컴퓨터 객체를 만들거나 기존 객체를 찾습니다. 재사용은 허용되거나 차단됩니다. 가입 단말은 최종 결과를 보고하고, 멤버의 보안 채널 검사로 현재 신뢰를 확인할 수 있습니다." />
  <figcaption>디렉터리 이벤트와 단말의 결과를 각각 확보한 뒤 같은 객체와 가입 시도를 연결합니다.</figcaption>
</figure>

| 출처 | 뒷받침하는 내용 | 수집 조건과 판단 한계 |
| --- | --- | --- |
| DC Security **4741 / 4742 / 4743** | 컴퓨터 계정 생성·변경·삭제를 각각 기록합니다. 주체와 대상 SID를 나눠 봅니다. | 관련 DC에서 **Audit Computer Account Management** 성공 감사를 켜고 수집합니다. 4741은 사전 준비일 수 있습니다. 4742는 정상 암호 관리나 표시되지 않는 속성의 변경일 수 있습니다. |
| DC Security **5137** | 디렉터리 객체를 생성했습니다. 컴퓨터의 `ObjectClass`, `ObjectGUID`, `ObjectDN`을 확인합니다. | **Audit Directory Service Changes**와 상위 OU 또는 컨테이너의 **SACL**(어떤 작업을 감사할지 정의하는 목록)에 일치하는 생성 감사가 필요합니다. 4741과 같은 생성을 기록할 수 있습니다. |
| 가입 단말 System, **Netjoin 4100 / 4101** | 기존 계정을 찾았고 재사용이 각각 허용 또는 차단됐습니다. 있는 경우 조회한 DC, 기존 DN과 오류를 보존합니다. | 제공자와 단말을 확인합니다. 4100은 재사용 판단이라 이후 가입 단계에서 실패할 수도 있습니다. |
| 가입 단말 `%windir%\debug\Netsetup.log` | 수행한 동작과 중간 단계, 최종 상태입니다. Microsoft 예시에는 `NetpDoDomainJoin` 최종 상태 `0x0`이 성공, `0xaac`가 재사용 차단으로 나옵니다. | 기본으로 기록됩니다. 시도·대상 도메인·DC를 맞추고 동작의 최종 상태를 읽습니다. 중간 단계의 `0x0`은 전체 성공의 근거가 아닙니다. |
| DC System, **Directory-Services-SAM 16998** | DC의 보안 검사에서 재사용을 거절했습니다. 클라이언트 계정·컴퓨터 계정·소유자 SID가 나올 수 있습니다. | 강화가 적용된 해당 빌드에서 DC의 System을 수집하고 단말의 기록과 연결합니다. |
| 가입 후 신뢰 확인 | 보안 채널 검사 성공은 검사 시각에 해당 도메인 멤버의 신뢰가 정상임을 뒷받침합니다. | 단말, 도메인, 시각과 검사 범위를 기록합니다. 현재 검사와 과거 가입 결과를 구분합니다. |

**버전 범위.** Microsoft는 **2022-10-11** Windows 업데이트부터 계정 재사용 보호를 추가했습니다. 이후 업데이트에서 신뢰할 수 있는 소유자 정책과 DC 검사 방식을 보강했습니다. **2024-08-13** 이후 업데이트에서는 기존 `NetJoinLegacyAccountReuse` 설정 지원이 제거됐습니다. 적용된 패치, 객체 소유자와 허용 그룹, 해당 객체의 별도 권한을 대조하세요. 재사용 정책의 대상은 **신뢰할 수 있는 계정 소유자**이며, 일반 AD 권한도 별도로 평가됩니다. 새 계정 생성에는 이 재사용 정책이 적용되지 않습니다.

## 2. 정상 가입 흐름을 시간순으로 읽기

가상의 정상 사례에서 배포 서비스가 08:45 UTC에 준비 OU의 `LAB-PC07$`을 만듭니다. DC-A에 새 SID의 4741이 남습니다. 09:00에 기술자가 해당 단말을 기존 계정으로 가입시킵니다. 단말은 같은 DN과 DC에 대한 Netjoin 4100과 가입 최종 상태 `0x0`을 남깁니다. 이후 그 멤버에서 보안 채널 검사도 성공합니다. 이 순서대로 사전 생성, 재사용 허용, 가입 동작 성공, 이후의 정상 신뢰를 확인할 수 있습니다.

같은 이름의 교체 단말에서 4101과 최종 상태 `0xaac`가 나왔다면 그 시도의 재사용을 보안 정책이 차단한 것입니다. 정상 재설치 중에도 소유자나 배포 주체가 정책의 기대와 다르면 발생할 수 있습니다. 반대로 4100 뒤 최종 상태가 0이 아니라면 재사용 검사 이후의 단계에서 실패한 것입니다.

디렉터리는 컴퓨터 ID를 권한 판단에 사용합니다. 계정 생성 권한이 넓거나 기존 계정을 과도하게 제어할 수 있으면, 승인된 가입 업무 사이에 미승인 컴퓨터 ID가 들어올 수 있습니다. 등록 일정 밖의 생성·변경은 조사 단서입니다. 정상 운영과 자동 배포도 비슷한 기록을 남길 수 있습니다.

## 3. 블루팀 수집과 대응

1. **가입 단말부터 봅니다.** 다른 시도로 기록이 섞이기 전에 System 이벤트와 해당 시간의 `Netsetup.log`를 내보냅니다. 자산 관리 ID, 호스트 이름, UTC 시각, 대상 도메인, 조회한 DC, 기존 DN, 최종 상태를 남깁니다. 필요한 재시작을 했는지, 단말이 이미 가입된 상태였는지도 기록합니다. 권한이 있는 **도메인 멤버**에서 통신과 Netlogon이 가능하면 `Test-ComputerSecureChannel -Verbose`로 복구 동작 없이 진단할 수 있습니다. Microsoft는 이 명령이 DC에서는 잘못된 오류를 낼 수 있다고 안내합니다. 실행 시각과 반환값을 남깁니다.
2. **디렉터리 객체를 식별합니다.** 관련 DC의 원본 Security와 필요한 System 기록을 수집합니다. 적용 감사 정책과 필요한 SACL, 보존·전달 범위를 확인하세요. DC와 시각, 주체 SID와 대상 SID를 대조하고, 확보 가능한 디렉터리 또는 5137 자료의 `objectGUID`와 DN을 연결합니다. 삭제·재생성 후 이름을 재사용할 수 있습니다. 두 SID가 같아도 주체와 대상을 따로 보존합니다. 4742의 값이 `-`여도 다른 속성의 변경이 없었다고 볼 수는 없습니다.
3. **승인된 업무 흐름을 확인합니다.** 등록 요청, 자산 기록, 배포 서버와 담당자의 이력을 대조합니다. 도메인에 실제 적용된 컴퓨터 계정 할당량과 각 OU에서 컴퓨터 객체 생성 권한을 위임받은 주체를 모두 확인합니다. 할당량을 제한해도 별도로 위임된 권한은 남습니다. Microsoft는 제어된 배포와 신중한 위임을 권장합니다. 속성이나 DC별 상태가 예상과 다르면 승인된 디렉터리 스냅샷과 복제 증거를 확인하세요.
4. **근거에 맞게 대응합니다.** 차단된 정식 배포라면 자산, DC, 계정 식별자, 오류와 적용 정책을 담당자에게 전달해 변경 관리 절차로 해결합니다. 설명되지 않는 컴퓨터 ID 변경은 원본 이벤트와 계정의 보안 정보, 승인 내역을 보존한 뒤 승인된 범위에서 대응합니다. 다음 정상 가입에서 단말·DC·신뢰 기록을 확인합니다. 기록이 없으면 먼저 수집 범위와 여전히 확인할 수 없는 사실을 구분합니다.

## 4. 오프라인으로 방어 판단 검증하기

자기 소유 또는 명시적으로 승인된 폴더에서 Python 3를 사용합니다. <a href="{{ '/assets/labs/ad-computer-domain-join-evidence/ad-join-cases.csv' | relative_url }}" download="ad-join-cases.csv">ad-join-cases.csv</a>를 내려받고 아래 코드를 같은 폴더의 `review_join.py`에 저장한 뒤 `python3 review_join.py`를 실행합니다. 가상의 행만 읽으며 계정을 만들거나 디렉터리를 변경하지 않습니다. 네트워크도 필요 없습니다.

`attempt`와 `object_id`는 실습에서 이미 연결해 준 키입니다. 모든 로그에 공통으로 들어 있는 원본 필드가 아닙니다. 대상 객체는 `object-A`, 단말 시도는 `LAB-PC07/run-1`입니다. 실제 조사에서는 독립적인 기록으로 연결 근거를 확인하세요.

```python
import csv
from collections import defaultdict

expected = {
    "new-join": ("created", "unknown", "reported-success", False),
    "prestage": ("created", "unknown", "unknown", False),
    "reuse-ok": ("changed", "allowed", "reported-success", True),
    "reuse-blocked": ("unknown", "blocked", "reuse-policy-block", False),
    "allow-then-fail": ("unknown", "allowed", "other-failure", False),
    "routine-change": ("changed", "unknown", "unknown", False),
    "same-name-older-object": ("unknown", "unknown", "reported-success", False),
    "mismatched-client-and-retry": ("created", "unknown", "unknown", False),
    "removed": ("deleted", "unknown", "unknown", False),
}

def describe(rows):
    object_rows = [r for r in rows if r["object_id"] == "object-A"]
    directory = {r["event"] for r in object_rows if r["source"] == "dc-security"}
    dc_labels = {"4741": "created", "4742": "changed", "4743": "deleted"}
    directory_state = "+".join(dc_labels[e] for e in dc_labels if e in directory) or "unknown"

    member = [r for r in object_rows if (r["device"], r["attempt"]) == ("LAB-PC07", "run-1")]
    netjoin = {r["event"] for r in member if r["source"] == "client-system-netjoin"}
    reuse = {value for code, value in (("4100", "allowed"), ("4101", "blocked")) if code in netjoin}

    status = {r["value"].lower() for r in member
              if (r["source"], r["event"]) == ("client-netsetup", "final-status")}
    status_labels = {"0x0": "reported-success", "0xaac": "reuse-policy-block"}
    final = "unknown"
    if len(status) == 1:
        final = status_labels.get(next(iter(status)), "other-failure")
    elif len(status) > 1:
        final = "conflicting-status"
    channel = any((r["source"], r["event"], r["value"]) ==
                  ("post-join-check", "secure-channel", "true") for r in member)

    reuse_state = next(iter(reuse)) if len(reuse) == 1 else ("conflicting" if reuse else "unknown")
    return directory_state, reuse_state, final, channel

with open("ad-join-cases.csv", encoding="utf-8", newline="") as stream:
    cases = defaultdict(list)
    for row in csv.DictReader(stream):
        cases[row["case"]].append(row)

actual = {name: describe(rows) for name, rows in cases.items()}
assert actual == expected, f"Expected {expected!r}, got {actual!r}"
for name, result in actual.items():
    print(f"{name}: {result}")
```

**기대 결과.** 아홉 건이 통과합니다. 객체 생성만으로 가입을 확인할 수 없습니다. 재사용이 허용된 다음 실패할 수도 있으며, 일상적인 계정 변경만으로 재사용을 알 수 없습니다. 이전에 같은 이름을 쓴 다른 객체와 다른 단말·재시도는 일치하지 않습니다. 네 번째 결과는 해당 단말 시도와 연결된 보안 채널 성공 기록이 있는지 보여 줍니다.

**실패 점검.** 복사한 CSV의 `new-join` 사례에서 Netsetup 행의 단말만 `LAB-PC08`로 바꾸세요. `LAB-PC07`의 성공 판정이 미확정으로 바뀌어 검증에 실패해야 합니다. 다시 비교할 때는 원래 파일로 되돌립니다. Python이 파일을 열지 못하면 파일 이름과 작업 폴더를 확인하세요. 오프라인 실습과 대조 사례는 클라우드에서 실행했고, 제품 이벤트와 멤버 진단 명령은 Microsoft 문서와 대조했습니다.

## 5. 확인 문제와 완료 기준

1. **4741은 있는데 단말 기록이 없습니다. 가입했나요?** DC는 계정 생성을 기록했습니다. 사전 생성일 수 있으므로 단말의 시도와 신뢰 근거를 찾습니다.
2. **4100이 있고 최종 상태가 0이 아닙니다. 어느 기록이 맞나요?** 둘 다 맞을 수 있습니다. 재사용은 허용됐고 전체 작업은 이후에 실패했습니다.
3. **지난달 4743의 DN과 같지만 SID가 다릅니다. 같은 계정인가요?** 이름과 경로가 재사용될 수 있습니다. SID, GUID와 생성 순서를 대조합니다.

대상 객체의 변경, 재사용 판단, 정확한 단말의 최종 결과, 현재 신뢰 여부와 미확정 내용을 근거와 함께 제시할 수 있으면 학습을 마친 것입니다.

## 공식 참고자료

**검토일 2026-11-27.** 지원되는 Windows 도메인 멤버와 Windows Server AD DS를 대상으로 합니다. 강화 시점은 KB5020276의 Windows 업데이트 날짜를 기준으로 했습니다. 오래된 이벤트 레퍼런스의 필드 설명은 사용 중인 빌드의 XML과 대조하세요.

- [Microsoft Support · KB5020276 도메인 가입 강화](https://support.microsoft.com/en-us/servicing/os/windows/2022/10/kb5020276-netjoin-domain-join-hardening-changes)
- [Microsoft Learn · AD 도메인 가입에 필요한 권한](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/active-directory-domain-join-permissions)
- [Microsoft Learn · 도메인 가입 로그 분석](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/domain-join-log-analysis)
- [Microsoft Learn · 고급 감사 정책](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft Learn · 컴퓨터 계정 변경 이벤트 4742](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4742)
- [Microsoft Learn · 디렉터리 객체 생성 이벤트 5137](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5137)
- [Microsoft Learn · Test-ComputerSecureChannel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-computersecurechannel)

[이전 · Active Directory 완전 입문]({{ '/ko/wiki/active-directory-fundamentals/' | relative_url }}) · [다음 · AD 복제 증거]({{ '/ko/wiki/ad-replication-change-evidence/' | relative_url }}) · [그룹 변경과 접근 증거 비교]({{ '/ko/wiki/ad-group-membership-evidence/' | relative_url }})
