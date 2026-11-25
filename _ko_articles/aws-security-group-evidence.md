---
title: "AWS 보안 그룹 조사 · 규칙 변경부터 실제 통신까지"
description: "CloudTrail 변경 기록, ENI에 적용된 규칙, 흐름 및 앱 증거를 여덟 가지 가상 사례로 대조합니다."
category: cloud
tags: [AWS, Security Groups, CloudTrail, VPC Flow Logs, Network Security, Cloud Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-25"
translation_url: /wiki/aws-security-group-evidence/
---

10:14 UTC에 CloudTrail에 보안 그룹 규칙 변경이 기록됐습니다. 10:17에 대시보드에서 비슷한 주소의 연결이 보입니다. 네 가지 질문을 순서대로 확인하세요. AWS가 변경을 받아들였나요? 당시 대상 리소스에 규칙이 적용됐나요? 그 지점에서 통신을 관측했나요? 애플리케이션은 요청을 어떻게 처리했나요?

## 1. 보안 그룹이 제어하는 범위

**VPC**는 AWS에서 논리적으로 격리한 네트워크이고, **서브넷**은 그 안의 주소 범위입니다. **ENI**(탄력적 네트워크 인터페이스)는 리소스를 VPC에 연결하는 인터페이스입니다. **보안 그룹**은 리소스에 연결하는 네트워크 허용 규칙 모음입니다. 리소스의 ENI를 통해 연결하는 경우가 일반적입니다. 규칙은 **방향**(인바운드 또는 아웃바운드), 프로토콜, 해당하는 포트 또는 ICMP 유형·코드와 함께 인바운드 출발지 또는 아웃바운드 목적지를 지정합니다. CIDR은 주소 범위를 표현합니다. IPv4 규칙의 `0.0.0.0/0`은 이 계층에서 조건에 맞는 모든 IPv4 주소의 트래픽을 허용합니다. IPv6에는 `::/0`처럼 별도 규칙이 필요합니다. 지원되는 조건에서 다른 그룹을 참조하면 그 그룹에 속한 인터페이스의 사설 주소가 일치 대상으로 쓰입니다. 참조한 그룹의 규칙까지 복사되지는 않습니다. 중간 장비를 지나거나 VPC 경계를 넘는 경우 AWS 문서에서 참조 제약을 확인하세요.

보안 그룹에는 허용 규칙만 있습니다. 같은 ENI에 그룹이 여러 개 붙으면 각 그룹의 허용 규칙을 합쳐 적용합니다. 한 그룹에서 규칙을 없애도 다른 그룹에서 같은 트래픽을 허용할 수 있습니다. 보안 그룹은 **상태 저장 방식**입니다. 추적 중인 연결의 응답은 연결 상태를 바탕으로 허용합니다. AWS 문서에는 규칙 변경 이후에도 계속되는 추적 연결과 즉시 끊길 수 있는 비추적 연결이 구분돼 있습니다. 새 연결과 기존 연결을 따로 확인하세요.

| 통제 | 판단 기준 | 확인할 사항 |
| --- | --- | --- |
| 보안 그룹 | ENI에 연결된 허용 규칙과 연결 상태 | 연결된 모든 그룹, 방향, 규칙 ID |
| 네트워크 ACL | 서브넷 경계의 순서 있는 허용·거부 규칙. 연결 상태는 추적하지 않음 | 응답 포트를 포함한 양방향 규칙 |
| 라우팅 테이블 | 목적지 주소 범위와 전달 대상 | 양방향 경로, 게이트웨이, 주소 변환 |
| 애플리케이션 | 리스너와 서비스의 인증·인가 | 리스너 상태, 요청·로그인·작업 기록 |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/aws-security-group-evidence-ko.svg' | relative_url }}" alt="CloudTrail의 규칙 변경을 ENI 이력, 흐름 관측, 앱 감사 기록과 차례로 대조합니다.">
  <figcaption>각 단계에서 확인한 사실과 추가 증거가 필요한 부분을 구분하세요.</figcaption>
</figure>

## 2. 승인된 변경을 따라가 보기

운영팀이 사설 운영망 `10.20.8.0/24`에서만 TCP 8443에 접속하도록 승인했다고 가정합니다. 아래는 가상 기록입니다.

1. 10:14 UTC에 배포 역할로 `sg-app`에 인바운드 규칙을 추가합니다. CloudTrail 관리 이벤트에는 기록된 호출 주체, API, 그룹과 요청 매개변수가 들어 있습니다. 오류 필드와 API별 응답을 확인하세요. 실패한 요청도 CloudTrail에 기록될 수 있습니다.
2. 10:15의 구성 스냅샷에는 `sg-app`이 `eni-app`에 연결되어 있습니다. 스냅샷 생성 시각과 10:14부터 10:15 사이 변경 이력이 충분한지 확인하세요. 지난 9월의 자산 목록만으로 오늘의 연결 상태를 판단하기는 어렵습니다.
3. 10:16~10:17의 `eni-app` 흐름 기록에서 `10.20.8.24:51540` → `10.20.2.18:8443`, 인바운드 TCP, `ACCEPT`, `OK`를 확인합니다. 이 관측 지점에서 트래픽을 봤다는 근거입니다. 다른 관측 기록과 대조할 때는 방향, 주소 변환과 반환 경로를 함께 확인하세요.
4. 10:16:48의 애플리케이션 감사 기록에는 서비스, 출발지, 요청과 상태 점검 성공 결과가 연결돼 있습니다. 요청 처리 결과는 앱에서 확인합니다. 흐름 기록에는 요청 경로나 일치한 보안 그룹 규칙 ID가 나타나지 않습니다.

승인한 규칙에 맞는 트래픽이 한 건도 없을 수 있습니다. 전체 공개 규칙이 실제 구성 문제여도 인터넷에서 해당 리소스로 가는 경로가 없을 수 있습니다. 예상 밖 트래픽은 승인된 스캐너, 상태 점검 또는 공용 NAT에서 나올 수도 있습니다. 미승인 변경 역시 자동화 역할 침해와 단순 구성 실수가 모두 가능한 설명입니다. 역할 이름, 호출자 IP, API 성공 응답만으로 판단하기는 어렵습니다.

## 3. 수집·탐지·대응

**변경 증거를 모읍니다.** 대상 계정과 리전의 EC2 관리 이벤트를 조회합니다. CloudTrail 이벤트 기록의 조회 범위는 리전별 최근 90일입니다. 더 긴 기간이나 여러 계정을 보려면 구성된 추적이나 이벤트 데이터 스토어를 확인합니다. 원본 이벤트, 이벤트·수집 시각, `eventID`, `eventName`, `userIdentity`, `requestParameters`, 응답과 오류 필드를 보존하세요. `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupIngress`, 이름에 `Egress`가 붙은 대응 작업, `ModifySecurityGroupRules`를 살펴보고 ENI에 연결된 그룹 자체의 변경도 확인합니다. 관리형 서비스 소유 ENI라면 해당 서비스 구성 및 감사 이력도 필요합니다. 역할 세션의 발급, 변경 승인 및 배포 실행 기록을 연결하세요. 공유 역할은 추가 근거가 있어야 행위자를 좁힐 수 있습니다.

**사건 시점의 규칙을 복원합니다.** 당시 규칙과 연결 스냅샷을 비교합니다. 해당 리소스 유형이 수집됐다면 AWS Config 구성 이력을 쓰고, 그렇지 않다면 신뢰할 수 있는 배포·자산 기록을 확인합니다. 계정, 리전, VPC, ENI, 그룹 ID, 규칙 ID, 관측 시각을 남기세요. 새 연결에 적용될 규칙을 판단할 때는 연결된 모든 그룹에서 승인된 예외와 IPv6도 함께 봅니다. 라우팅, ACL, 리스너는 각각 확인합니다. 연결이나 규칙 이력이 비어 있는 시간 구간을 표시하세요.

**트래픽 관측 내용을 확인합니다.** Flow Logs가 해당 ENI와 시각을 실제로 포함했는지 봅니다. 수집 필터가 허용, 거부, 전체 중 무엇인지 확인하고, 판단에 쓰는 사용자 지정 필드가 수집됐는지도 봅니다. ENI, 5튜플(양쪽 주소·포트와 프로토콜), 방향, 겹치는 UTC 시간으로 대조하세요. 중계 장비 주변에서는 필요에 따라 수집한 원본 패킷 주소 필드를 함께 봅니다. `SKIPDATA`가 있으면 일부 레코드가 빠진 상태입니다. `REJECT` 행에는 어느 통제가 거부했는지 나오지 않습니다. Reachability Analyzer는 지원되는 경로의 네트워크 구성을 평가합니다. 패킷 전송이나 리스너 응답은 별도의 관측으로 확인합니다.

**근거에 맞게 대응합니다.** 제한된 서비스 포트의 IPv4·IPv6 전체 허용처럼 정책상 민감한 범위 확장이 성공했을 때 알림을 시작합니다. 연결된 ENI, 승인 범위, 변경 기록을 보강하고 예전부터 같은 트래픽을 허용한 규칙이 있었는지 확인하세요. 연결되지 않은 위험 그룹은 구성 개선 대상으로 남기고, 배포된 리소스의 노출 여부는 별도로 기록합니다. 예상 밖 규칙이 연결됐다면 증거를 보존하고 소유자에게 알려 승인된 원복이나 격리를 진행합니다. 모든 그룹을 다시 평가하고 승인 범위 안에서 새 연결과 기존 연결을 따로 검증하세요. 앱 로그가 오용을 뒷받침하면 그 로그를 기준으로 행위와 영향받은 계정 범위를 좁힙니다.

### 승인된 계정에서 읽기 전용으로 조회하기

두 EC2 Describe API 권한을 가진 승인된 계정에서 AWS CLI v2를 사용하세요. 예시 리전과 ID를 승인된 자산 값으로 바꿉니다. 출력에 관측 시각과 AWS 계정을 함께 기록하세요. 이 명령은 조회 시점의 구성을 보여줍니다.

~~~bash
aws ec2 describe-network-interfaces --region us-east-1 \
  --filters Name=group-id,Values=sg-0123456789abcdef0 --output json
aws ec2 describe-security-group-rules --region us-east-1 \
  --filters Name=group-id,Values=sg-0123456789abcdef0 --output json
~~~

ENI가 보이지 않으면 자격 증명, 리전과 관리형 리소스의 조회 범위를 확인하세요. 조사 대상 ENI에 붙은 다른 그룹의 규칙도 모두 조회합니다. 조회 실패나 빈 응답은 시간과 수집 범위를 함께 확인해야 해석할 수 있습니다.

## 4. 오프라인 실습 · 여덟 가지 증거 판단

<a href="{{ '/assets/labs/aws-security-group-review.py' | relative_url }}" download="aws-security-group-review.py">Python 확인 스크립트 다운로드</a> · <a href="{{ '/assets/labs/aws-security-group-cases.json' | relative_url }}" download="aws-security-group-cases.json">가상 JSON 다운로드</a>

두 파일을 한 폴더에 저장하고 해당 폴더에서 Python 3으로 실행하세요. 데이터는 형식을 단순화한 가상 자료입니다. 직접 들어오는 TCP 흐름으로 한정하고 각 증거를 확인됨, 없음, 알 수 없음으로 표현합니다. 실제 AWS 로그를 파싱하거나 네트워크를 모의 실행하지 않습니다. 스크립트는 AWS에 요청을 보내지 않습니다.

~~~bash
python3 aws-security-group-review.py aws-security-group-cases.json
~~~

| 사례 | 관측 | 근거가 뒷받침하는 판단 |
| --- | --- | --- |
| 01 | 승인된 변경, 그룹 연결, 흐름과 앱 기록 일치 | 승인된 변경과 요청 처리 확인 |
| 02 | API 호출 실패 | 해당 이벤트의 변경 시도 실패 |
| 03 | 변경 성공, 확인 범위를 모두 포함한 목록에 연결 없음 | 조사 범위 내 연결 없음 |
| 04 | 그룹이 연결됐지만 흐름이 없고 수집 범위 불완전 | 통신 여부 미확인 |
| 05 | 대상 ENI의 `ACCEPT`, 앱 증거 없음 | 트래픽 관측, 앱 결과 미확인 |
| 06 | 다른 ENI에서만 `ACCEPT` | 대상의 통신 여부 미확인 |
| 07 | 규칙을 제거했지만 다른 연결 그룹이 새 트래픽 허용 | 다른 허용 규칙 존재 |
| 08 | 규칙 제거 뒤에도 추적 중이던 연결 관측 | 기존 흐름 관측, 새 연결 가능 여부 미확인 |

`PASS`가 여덟 줄 나와야 합니다. Python이 파일을 열지 못하면 파일명과 작업 디렉터리를 확인하세요. 사례가 실패하면 기대값을 바꾸기 전에 표와 시나리오를 비교하세요. 05번 사례의 대상 ENI를 바꾸고 결과를 먼저 예측해 보세요. 근거를 말한 뒤 기대값을 수정해 확인합니다. 팀 실습에서는 한 사람이 변경 기록을, 다른 사람이 네트워크와 앱 기록을 확인한 뒤 각자의 결론을 비교해 보세요.

## 5. 확인 문제와 완료 기준

1. **전체 출발지 허용 규칙의 변경이 성공하면 인터넷에서 연결할 수 있나요?** 사건 시점의 연결 상태, 주소 계열, 라우팅, ACL과 리스너를 확인해야 합니다. 그다음 승인된 경로를 별도로 검증하세요.
2. **일치하는 `ACCEPT` 행이 있으면 사용자가 로그인했나요?** 앱의 인증 결과를 찾고 시간, 서비스, 주소와 확보한 요청·세션 ID로 연결해야 합니다.
3. **규칙 제거 후에도 연결이 보이는 이유는 뭔가요?** 다른 그룹의 규칙이 새 트래픽을 허용하거나 이미 추적하던 연결이 계속될 수 있습니다. 당시 규칙·연결 이력과 승인된 새 연결 검증으로 구분합니다.
4. **흐름이 없으면 접근도 없었다고 보고해도 되나요?** 확인한 범위의 증거만 적으세요. 수집 대상, 필터, 지연과 누락을 확인합니다. 앱이나 엔드포인트 로그가 네트워크 기록의 빈 부분을 채울 수 있습니다.

여덟 사례의 판단을 설명하고, 계정·리전·ENI·시간 범위를 적은 짧은 조사 메모를 한 건 작성하면 완료입니다. 결론을 뒷받침하는 증거와 추가 확인이 필요한 질문을 함께 적으세요.

## 공식 참고자료와 다음 학습

검토일은 **2026-11-25**입니다. AWS 공식 문서의 서비스 및 CLI v2 동작을 검토일 기준으로 확인했습니다. 실습은 가상 자료이며 CLI와 Reachability Analyzer 예시는 문서로 확인했습니다.

- Amazon VPC 규칙 구성, 그룹 참조와 제약. [보안 그룹 규칙](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- Amazon EC2 추적·비추적 연결. [보안 그룹 연결 추적](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html)
- 리전별 90일 관리 이벤트 범위. [CloudTrail 이벤트 기록](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- 흐름 집계 필드와 네트워크 구성 분석. [Flow Log 레코드](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html) · [Reachability Analyzer](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html)
- 서브넷 경계의 ACL과 수집된 리소스 구성 이력. [네트워크 ACL](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html) · [AWS Config 구성 이력](https://docs.aws.amazon.com/config/latest/developerguide/view-manage-resource-console.html)
- AWS CLI v2 명령. [ENI 조회](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-interfaces.html) · [보안 그룹 규칙 조회](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-security-group-rules.html)

이전 학습 · [AWS IAM 역할과 CloudTrail 조사 입문]({{ '/ko/wiki/aws-iam-role-evidence/' | relative_url }})  
다음 학습 · [AWS VPC Flow Logs 조사]({{ '/ko/wiki/vpc-flow-log-evidence/' | relative_url }})
