---
title: "Build Provenance Evidence · From Artifact Bytes to a Release Decision"
description: "Verify the difference between an artifact digest, a signed build claim, a trusted workflow and release policy using ten offline cases."
category: blue-team
tags: [Software Supply Chain, Build Provenance, GitHub Actions, Cryptography, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/artifact-provenance-evidence/
---

Two files can have the same name and release tag while containing different bytes. A signed **attestation** is a statement about an artifact. **Build provenance** is a type of attestation that describes where and how those bytes were produced. As a consumer, identify the file, verify the claim and apply your own deployment criteria. The [digital signature chapter]({{ '/wiki/public-key-cryptography/' | relative_url }}) describes the underlying key operations.

## 1. Identify the artifact and the claim

- The **artifact** is the exact file or image being consumed. A SHA-256 digest identifies its bytes within the policy's choice of algorithm. An expected digest must come from a trusted source. A filename or an image tag can refer to different bytes over time. For a container, verify the digest of the exact object that will be deployed.
- The **subject** identifies what the signed statement describes. Match its digest to the artifact you received. The **predicate type** describes the nature of the statement. For SLSA Build Provenance v1 it is `https://slsa.dev/provenance/v1`. The **predicate** contains the build information. SLSA v1.2 defines fields such as `buildDefinition.buildType`, external parameters and `runDetails.builder.id`.
- The **bundle** packages the signed statement and verification material. The **trust root** is the independently trusted key material needed to validate the chain and applicable signing-time evidence. The **signer** must be allowed to make this claim. The repository producing the artifact and the reusable workflow signing it can differ.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/artifact-provenance-evidence-en.svg' | relative_url }}" alt="Hash the artifact, verify the signed claim, match the subject, enforce signer and source policy, then evaluate the release decision.">
  <figcaption>Fail a required check before consuming the artifact. Preserve the evidence for the first failure.</figcaption>
</figure>

| Evidence | Question it answers | Remaining check |
| --- | --- | --- |
| Computed digest | Which bytes did I receive? | Match the intended subject |
| Signed statement and verified chain | Did a verified signing identity make this claim? | Check trusted signer, source and predicate |
| Build provenance | What build origin and process were claimed? | Evaluate builder identity and approved parameters |
| SBOM or VEX | What components are reported or what is the stated vulnerability impact? | Match product or digest and apply vulnerability policy |
| Deployment audit | What was admitted or deployed? | Compare the actual deployed digest and policy version |

## 2. Follow a normal release

A fictional team approves source tag `refs/tags/v1.0.0` in `demo-org/release-build`, repository ID `41001`, and `publish.yml` as the signer workflow. During release verification, the downloaded file's digest matches the attestation subject. A supported verifier validates the bundle with trusted material. The team then checks the signed certificate identity and independently recorded release expectations, including the source commit where its policy requires it. The approved build type and inputs match. The separate vulnerability review and approval allow deployment of that verified digest.

A rebuild may produce different bytes even for the same source commit. A digest mismatch needs investigation of the artifact variant, packaging or distribution path, and can also indicate tampering. A correctly signed test build can fail release policy. A compromised or misconfigured builder can make claims using an otherwise trusted signing identity. GitHub documents that workflow-originated predicate fields can be controlled by the workflow. For strong enforcement, check authenticated identity fields and define boundaries and inputs for the trusted builder. A successful verification alone cannot show whether the code is safe. See [SBOM and VEX triage]({{ '/wiki/sbom-vex-evidence/' | relative_url }}) for the next review.

## 3. Apply verification in an approved GitHub workflow

This is a **documented template** for a local copy of an artifact from a repository you are authorized to access. Replace the fictional file, repository, signer and tag with values from separately approved policy. Use a GitHub CLI release with the listed options, authenticated GitHub API access and an available attestation. Check `gh attestation verify --help` for the installed release. The example illustrates a release-tag policy and was reviewed against the CLI manual.

```bash
gh attestation verify ./release.bin \
  --repo demo-org/release-build \
  --signer-workflow demo-org/release-build/.github/workflows/publish.yml \
  --source-ref refs/tags/v1.0.0 \
  --predicate-type https://slsa.dev/provenance/v1 \
  --format json
```

Use the CLI exit status and inspect verified JSON if your approval requires additional checks such as a stable repository ID or parameters. If a reusable workflow signed the claim, specify that signing workflow. If your policy pins a source commit or signer revision, the CLI documents `--source-digest` and `--signer-digest`. Check which repository and ref each value represents.

For offline verification of real attestations, use GitHub's documented bundle and trusted-root import procedure. Authenticate the trust-root transfer, record when it was obtained, and plan refreshes for rotation and revocation visibility. With a local `--bundle`, repository-name matching reflects the signing certificate at signing time. Check the certificate's stable repository ID against an independently acquired ID if names may have changed or been reused. A reappearing name does not restore the original identity.

## 4. Collect and respond to policy failures

1. **Preserve the inputs and decision.** Record artifact digest, source repository name and ID, source commit/ref, signer workflow identity and revision where available, predicate type, verifier version, trusted-root version or acquisition time, verification timestamp and policy revision. Retain the verified bundle and the verifier's error or structured output under your evidence policy.
2. **Find the failing boundary.** Treat unavailable bundles, invalid signing evidence, different bytes and authenticated policy mismatches as distinct conditions. For a missing bundle, check source repository, digest, access and retrieval health. For an unexpected signer, compare approved changes and the workflow run before changing policy. For a digest mismatch, pause consumption and compare the release and registry records with the actual bytes.
3. **Confirm the deployed object.** Correlate the verified digest to admission or deployment evidence. If a release was previously approved with the wrong evidence, identify affected digests and consumers. Coordinate with build and release owners to stop further rollout and verify a trusted replacement. Record any approved exception and its scope.

## 5. Offline lab · ten fictional decisions

Download all three files into one directory. Use Python 3.11 or later. The script **computes SHA-256 from the actual text file**. The JSON records simulate outcomes of an independent signature verifier and verified metadata. These records are unsigned teaching data. The script implements an example decision rule with no signature, certificate or network validation. Do not use it to approve real artifacts.

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

If the expected passing case mismatches, download the files again and check their names and byte contents. Re-saving the artifact with different line endings changes its digest. In a disposable copy, append one character to the text file and rerun against that copy. `release_match` should become `subject_mismatch`. Preserve the original fixture to reproduce the expected outputs. The file hashing and fixture decisions were executed in Python 3.12. Real GitHub provenance verification was reviewed against official documentation.

## 6. Check your reasoning

- **What if the hash matches but the signer workflow is different?** Hold the artifact for review. The hash establishes the byte association and the workflow check establishes whether the signer is approved.
- **Why hold a release after provenance passes?** Build provenance and vulnerability or release approval answer different questions. A release blocker still applies.
- **What if an offline bundle has the right repository name but no independent ID match?** Establish the approved repository's stable ID and compare it to the verified signing certificate before claiming identity under that policy.

Complete the lab when the ten original decisions and the changed-file check match. Explain the first failed check in `reused_repo_name` and name the separate evidence supporting `vulnerability_hold`.

## Official references

Reviewed 2026-11-22. The SLSA references are pinned to approved specification v1.2. GitHub CLI and GitHub Actions references describe the documented features available at review time. Check the installed version and deployment scope.

- Approved v1.2 format and the provenance predicate. [SLSA v1.2 · Build Provenance](https://slsa.dev/spec/v1.2/build-provenance)
- Trust roots, builder identity, digest and consumer expectations. [SLSA v1.2 · Verifying artifacts](https://slsa.dev/spec/v1.2/verifying-artifacts)
- GitHub Actions attestations and their security boundaries. [GitHub Docs · Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- Current documented flags, reusable workflow signer and verified JSON. [GitHub CLI · gh attestation verify](https://cli.github.com/manual/gh_attestation_verify)
- Offline trust roots, bundle import and stable repository IDs. [GitHub Docs · Verifying attestations offline](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)

[Previous · Public keys and signatures]({{ '/wiki/public-key-cryptography/' | relative_url }}) · [Next · SBOM and VEX]({{ '/wiki/sbom-vex-evidence/' | relative_url }}) · [Related · APT repository integrity]({{ '/wiki/apt-repository-integrity/' | relative_url }})
