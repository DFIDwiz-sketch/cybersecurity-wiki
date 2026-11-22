---
title: "빌드 출처 증명 · 산출물 해시에서 배포 판단까지"
description: "가상 사례 10건으로 산출물 해시, 서명된 빌드 정보, 승인된 워크플로와 배포 정책을 구분합니다."
category: blue-team
tags: [Software Supply Chain, Build Provenance, GitHub Actions, Cryptography, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /wiki/artifact-provenance-evidence/
---

파일명과 릴리스 태그가 같아도 받은 파일의 내용은 달라질 수 있습니다. **증명(attestation)**은 산출물에 대해 서명된 진술입니다. **빌드 출처 증명(build provenance)**은 그 파일이 어디서 어떻게 만들어졌는지 설명하는 증명의 한 유형입니다. 소비자는 받은 파일을 식별하고, 서명과 신원을 검증한 뒤 배포 정책을 적용합니다. 서명과 키의 동작은 [공개키와 전자서명]({{ '/ko/wiki/public-key-cryptography/' | relative_url }})에서 이어서 볼 수 있습니다.

## 1. 산출물과 서명된 진술 식별하기

- **산출물(artifact)**은 실제 사용하는 파일이나 이미지입니다. SHA-256 해시는 정책이 정한 알고리즘으로 파일의 바이트를 식별합니다. 비교할 해시는 신뢰하는 출처에서 확보해야 합니다. 파일명이나 이미지 태그는 시간이 지나면 다른 내용을 가리킬 수 있습니다. 컨테이너라면 실제 배포할 객체의 다이제스트를 확인하세요.
- **대상(subject)**은 서명된 진술이 어떤 산출물을 설명하는지 나타냅니다. 그 해시가 받은 파일의 계산값과 일치해야 합니다. **진술 유형(predicate type)**은 어떤 종류의 정보인지 나타냅니다. SLSA Build Provenance v1은 `https://slsa.dev/provenance/v1`을 씁니다. **본문(predicate)**에는 빌드 정보가 들어 있습니다. SLSA v1.2는 `buildDefinition.buildType`, 외부 입력, `runDetails.builder.id` 같은 필드를 정의합니다.
- **번들(bundle)**은 서명된 진술과 검증 자료를 묶습니다. **신뢰 기준점(trust root)**은 인증 체인과 해당되는 서명 시각 증거를 검증하기 위해 별도로 신뢰를 설정한 키 자료입니다. **서명자**가 이 진술을 할 권한이 있는지도 확인합니다. 산출물을 생성한 소스 저장소와 서명한 재사용 워크플로의 저장소는 다를 수 있습니다.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/artifact-provenance-evidence-ko.svg' | relative_url }}" alt="받은 파일의 해시를 계산하고 서명된 증명을 검증합니다. 대상 해시와 서명자·소스 정책을 확인한 뒤 배포 정책을 적용합니다.">
  <figcaption>필수 검사에 실패하면 산출물 사용을 보류하고, 처음 실패한 단계의 증거를 보존합니다.</figcaption>
</figure>

| 확인한 증거 | 답하는 질문 | 남은 확인 |
| --- | --- | --- |
| 계산한 해시 | 어떤 바이트를 받았나요? | 의도한 증명 대상과 일치하는지 |
| 서명된 진술과 검증된 체인 | 검증된 서명 신원이 이 진술을 했나요? | 승인된 서명자, 소스, 진술 유형인지 |
| 빌드 출처 증명 | 어느 빌드 환경과 과정을 기록했나요? | 빌더 신원과 승인된 입력 조건 |
| SBOM 또는 VEX | 보고된 구성 요소나 취약점 영향은 무엇인가요? | 제품 또는 해시 대응과 취약점 정책 |
| 배포 감사 기록 | 어떤 객체가 배포 승인 또는 배포됐나요? | 실제 배포 해시와 정책 버전 |

## 2. 정상 릴리스 한 건 따라가기

가상 팀은 저장소 ID `41001`인 `demo-org/release-build`의 태그 `refs/tags/v1.0.0`과 서명 워크플로 `publish.yml`을 승인했습니다. 내려받은 파일의 해시는 증명 대상과 일치합니다. 지원되는 검증 도구가 신뢰 자료로 번들을 확인합니다. 이어서 서명 인증서의 신원과 별도로 기록한 릴리스 정책을 대조하고, 정책에서 요구한다면 소스 커밋도 검사합니다. 승인한 빌드 유형과 입력도 일치합니다. 마지막으로 취약점 검토와 배포 승인이 끝나면 확인된 해시의 산출물을 배포합니다.

같은 소스 커밋을 다시 빌드해도 파일 내용이 달라질 수 있습니다. 해시가 다르면 대상 변형, 패키징, 배포 경로를 조사하세요. 변조 가능성도 남습니다. 정상적으로 서명된 시험 빌드라도 배포 정책을 통과하지 못할 수 있습니다. 빌더가 침해됐거나 설정이 잘못되면 신뢰하는 신원으로 부정확한 진술을 만들 수도 있습니다. GitHub 문서는 워크플로가 진술 본문의 값을 제어할 수 있다고 설명합니다. 인증된 신원 필드를 확인하고, 신뢰하는 빌더의 경계와 허용 입력을 정하세요. 검증 성공만으로 코드의 안전을 판단할 수 없습니다. 취약점 검토는 [SBOM과 VEX]({{ '/ko/wiki/sbom-vex-evidence/' | relative_url }})에서 이어집니다.

## 3. 승인된 GitHub 환경에서 검증하기

아래는 접근 권한이 있는 저장소에서 내려받은 로컬 파일에 적용할 **문서 검토용 예시**입니다. 가상의 파일명, 저장소, 서명자, 태그는 별도로 승인된 정책 값으로 바꾸세요. 해당 옵션을 지원하는 GitHub CLI, 인증된 GitHub API 접근, 조회 가능한 증명이 필요합니다. 설치 버전의 옵션은 `gh attestation verify --help`에서 확인합니다.

```bash
gh attestation verify ./release.bin \
  --repo demo-org/release-build \
  --signer-workflow demo-org/release-build/.github/workflows/publish.yml \
  --source-ref refs/tags/v1.0.0 \
  --predicate-type https://slsa.dev/provenance/v1 \
  --format json
```

CLI 종료 상태를 확인하세요. 안정적인 저장소 ID나 추가 빌드 입력이 승인에 필요하면 검증 결과 JSON을 검사합니다. 재사용 워크플로가 서명했다면 그 워크플로의 신원을 지정하세요. 소스 커밋이나 서명자 리비전을 고정하는 정책은 공식 문서의 `--source-digest`, `--signer-digest`를 확인하고 각각 어느 저장소와 ref를 가리키는지 구분합니다.

실제 증명을 오프라인 검증할 때는 GitHub의 번들·신뢰 기준점 반입 절차를 따릅니다. 신뢰 자료를 받은 경로와 시각을 기록하고 키 교체와 폐기 상태를 반영할 갱신 방법을 마련하세요. 로컬 `--bundle`을 쓰면 이름 검사는 서명 시점의 인증서 이름을 기준으로 합니다. 저장소 이름이 바뀌었거나 재사용됐을 가능성이 있다면 검증된 인증서의 저장소 ID를 별도로 확보한 승인 ID와 대조합니다. 이름이 다시 나타나도 원래 신원이 복원된 것은 아닙니다.

## 4. 수집하고 정책 실패에 대응하기

1. **검증 입력과 결정을 보존합니다.** 산출물 해시, 소스 저장소 이름과 ID, 소스 커밋·ref, 서명 워크플로 신원과 확보 가능한 리비전, 진술 유형, 검증기 버전, 신뢰 기준점 버전 또는 입수 시각, 검증 시각, 정책 리비전을 기록하세요. 번들과 오류 또는 구조화된 검증 결과를 증거 정책에 따라 보관합니다.
2. **처음 실패한 지점을 좁힙니다.** 번들 미확보, 서명 검증 실패, 파일 내용 불일치, 검증 후 정책 불일치를 구분합니다. 번들을 찾지 못하면 소스 저장소, 해시, 접근 권한과 수집 경로를 확인합니다. 서명자가 예상과 다르면 정책을 변경하기 전에 승인 기록과 워크플로 실행을 확인합니다. 해시가 다르면 사용을 보류하고 릴리스·레지스트리 기록을 실제 파일과 대조합니다.
3. **실제 배포 대상을 확인합니다.** 검증한 해시를 배포 승인 또는 실행 기록과 연결하세요. 잘못된 근거로 이미 배포했다면 영향을 받은 해시와 사용처를 찾습니다. 빌드·릴리스 담당자와 추가 배포를 중지하고 신뢰 가능한 대체본을 확인하세요. 승인된 예외가 있었다면 적용 범위를 남깁니다.

## 5. 오프라인 실습 · 가상 판단 열 건

세 파일을 같은 폴더에 내려받고 Python 3.11 이상에서 실행합니다. 스크립트는 **실제 텍스트 파일에서 SHA-256을 계산**합니다. JSON은 별도 서명 검증 결과와 검증된 메타데이터를 가정한 서명 없는 학습용 자료입니다. 스크립트는 예시 판단 규칙만 적용하며 서명·인증서·네트워크를 검증하지 않습니다. 운영 승인에는 사용하지 마세요.

<a href="{{ '/assets/labs/artifact-provenance-evidence-artifact.txt' | relative_url }}" download="artifact-provenance-evidence-artifact.txt">artifact-provenance-evidence-artifact.txt</a> · <a href="{{ '/assets/labs/artifact-provenance-evidence-cases.json' | relative_url }}" download="artifact-provenance-evidence-cases.json">artifact-provenance-evidence-cases.json</a> · <a href="{{ '/assets/labs/artifact-provenance-evidence.py' | relative_url }}" download="artifact-provenance-evidence.py">artifact-provenance-evidence.py</a>

```bash
python3 artifact-provenance-evidence.py \
  artifact-provenance-evidence-artifact.txt \
  artifact-provenance-evidence-cases.json
```

```text
release_match: provenance_policy_pass
different_bytes: subject_mismatch
bad_signature: verification_rejected
unverified_bundle: verification_missing
reused_repo_name: repo_id_mismatch
unexpected_workflow: signer_mismatch
branch_not_release: source_ref_mismatch
sbom_only: predicate_mismatch
repository_id_missing: repo_id_unknown
vulnerability_hold: release_hold
```

정상 사례의 해시가 다르면 파일을 다시 내려받고 이름과 바이트를 확인하세요. 텍스트를 다시 저장할 때 줄바꿈 형식이 바뀌어도 해시는 달라집니다. 복사한 산출물에 문자 한 개를 덧붙인 뒤 복사본 경로로 실행하세요. `release_match`의 출력이 `subject_mismatch`로 바뀌어야 합니다. 원본을 보존해 처음 결과도 재현하세요. 파일 해시와 가상 판단은 Python 3.12로 실행했고, 실제 GitHub 증명 검증은 공식 문서로 검토했습니다.

## 6. 확인 문제와 완료 기준

- **해시는 맞는데 서명 워크플로가 다르면 어떻게 하나요?** 검토할 때까지 사용을 보류합니다. 해시는 파일과 진술을 연결하고 워크플로 검사는 해당 서명자의 승인 여부를 확인합니다.
- **출처 검증을 통과했는데 왜 배포를 보류할 수 있나요?** 빌드 출처와 취약점·배포 승인은 서로 다른 질문에 답합니다. 배포 보류 사유는 그대로 적용됩니다.
- **오프라인 번들의 저장소 이름은 맞지만 독립적인 ID 대조가 없다면요?** 승인된 저장소 ID를 별도로 확보하고 검증된 서명 인증서의 ID와 대조해야 해당 정책에서 신원 확인을 마칠 수 있습니다.

원본 열 건의 결과와 바꾼 파일의 결과를 재현하세요. `reused_repo_name`의 첫 실패 단계와 `vulnerability_hold`에 필요한 별도 승인 증거를 설명하면 실습을 마친 것입니다.

## 공식 참고자료

검토일은 2026-11-22입니다. SLSA 자료는 승인된 v1.2 명세를 기준으로 합니다. GitHub CLI와 Actions 자료는 검토일에 문서화된 기능을 다룹니다. 설치 버전과 배포 범위는 해당 환경에서 확인하세요.

- 승인된 v1.2 형식과 출처 정보의 predicate. [SLSA v1.2 · Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)
- 신뢰 기준점, 빌더 신원, 해시와 소비자 정책. [SLSA v1.2 · Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)
- GitHub Actions 출처 증명과 보장 범위. [GitHub Docs · Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- 문서에 명시된 옵션, 재사용 워크플로 서명자, 검증 결과 JSON. [GitHub CLI · gh attestation verify](https://cli.github.com/manual/gh_attestation_verify)
- 오프라인 신뢰 기준점, 번들 반입과 불변 저장소 ID. [GitHub Docs · Verifying attestations offline](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)

[이전 · 공개키와 전자서명]({{ '/ko/wiki/public-key-cryptography/' | relative_url }}) · [다음 · SBOM과 VEX]({{ '/ko/wiki/sbom-vex-evidence/' | relative_url }}) · [관련 · APT 저장소 무결성]({{ '/ko/wiki/apt-repository-integrity/' | relative_url }})

## Git 커밋의 SSH 서명 조사

[Git 커밋 SSH 서명 조사]({{ '/ko/wiki/git-ssh-commit-signature-evidence/' | relative_url }})에서 실제 서명으로 커밋 객체, 공개키 신뢰, 폐기 상태와 변경 승인 증거를 대조하세요.
