---
title: "Git SSH Commit Signature Evidence · Key Trust and Change Approval"
description: "Use real offline signatures to distinguish commit integrity, approved keys, revocation and review evidence."
category: blue-team
tags: [Git, SSH Signatures, OpenSSH, Cryptography, Software Supply Chain, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/git-ssh-commit-signature-evidence/
---

A signed Git commit can pass cryptographic verification while still failing a repository’s release policy. Identify the signed commit object, the key the verifier trusted, and whether that signer could approve the change.

## 1. What the signature covers

A **commit object** records a tree, parent references, author and committer metadata, and a message. The **tree** identifies the committed file snapshot. For an SSH-signed commit, Git embeds a signature covering the commit payload. This chapter uses **SSH signature format** with OpenSSH. Signing and verification can happen offline. No SSH login or connection to a Git host is necessary.

The signer holds a private key. The verifier uses trusted public-key material. With Git’s SSH configuration, an **allowed signers file** binds a public key to one or more **principal** labels. The label helps identify the matching key. Git does not compare that label with the commit’s author email to prove authorship. A **key fingerprint** is a short identifier derived from the public key. Compare it with a trusted registry before accepting a new key.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/git-ssh-commit-signature-evidence-en.svg' | relative_url }}" alt="Start with the exact commit object. Verify the SSH signature and the signer against independently approved trust and revocation data. Then review the change against repository policy.">
  <figcaption>Successful signature verification provides evidence about the object and key. Review, build and release checks use additional evidence.</figcaption>
</figure>

## 2. Follow a normal authenticated change

A fictional maintainer signs a commit that changes a release note. A reviewer records the exact full commit ID from the review record and has an approved signers file from a controlled policy source. The reviewer verifies the commit against that file and the appropriate revocation data, then compares the returned fingerprint with the expected maintainer key. They confirm the code review covered the same commit or the intended range after any history rewrite. The resulting build still needs its own provenance and artifact checks.

| Evidence | What it supports |
| --- | --- |
| Full commit ID and verified signature | Integrity of the signed object under the signing key. The claim is scoped to that object. |
| Allowed principal and fingerprint | Which public key matched the verifier’s approved file and which label the file associates with it. |
| Author and committer fields | Identity claims stored in the commit. These can describe different people and do not independently identify the key holder. |
| PR approval and branch controls | Whether repository review and policy conditions were met for the relevant object or change range. |
| Build provenance and artifact digest | Which workflow produced the named artifact and whether its bytes match the record, when verified under an appropriate policy. |

An amended or rebased commit can be a new object with a different ID even if its resulting files look the same. Verify the precise object being released. A valid tip signature does not grant all ancestors their own trusted signature status. A policy requiring signed commits needs checks for the commits in its defined range.

## 3. Investigate failures and misuse

An unrecognized key can mean a developer has rotated keys while the verifier’s trust file is stale. It can also be an unapproved signing identity. Check approved fingerprints and key lifecycle records through an independent channel. A private-key compromise can allow unauthorized commits to pass signature verification under an otherwise approved key. Compare the signing key, object, PR review and push or CI activity before deciding the scope. Do not enroll a key solely because it is included in the change under investigation. Validate trust policy updates under an already trusted approval process.

A current local verdict can differ from a hosting site’s badge. GitHub documents that previously recorded successful verification can persist in a repository network after rotation, expiry or revocation. Record when the badge was observed and which verification record it represents. Current incident checks should use the appropriate independently obtained trust and revocation data. A timestamp from the signed commit or a local key-validity check is insufficient by itself to establish a trusted signing time.

## 4. Collect, verify and respond

1. Preserve the full commit IDs, refs and observed times, the expected merge or release commit, and scoped review and CI evidence. Record versions of Git and OpenSSH and the source and version of the policy files.
2. Use an explicitly identified approved signers file and, where available, revocation file. Inspect config origin with `git config --show-origin` when troubleshooting. A verifier should obtain its trust configuration independently of the unverified change.
3. Treat unsigned, unverifiable, untrusted and revoked as different investigation outcomes. Check tool output and status. An automation gate should require verification success as well as the separate approval rules. Investigate repeated failures by repository, signing key and recent policy change.
4. For a suspected key compromise, preserve the commit and verification evidence, coordinate rotation and revocation through the owner, and scope affected refs, builds and deployments. Re-run the checks for the affected window with the incident policy.

On a trusted local Git checkout containing the known object, set shell variables `commit`, `allow` and `revoked` to the full commit ID and absolute paths to your approved policy files. The revocation file can be an OpenSSH KRL or a list of revoked public keys. This query does not change repository configuration. If no approved revocation file is available, omit the override only when your policy permits and record the resulting coverage.

```bash
git -c gpg.ssh.allowedSignersFile="$allow" -c gpg.ssh.revocationFile="$revoked" \
  verify-commit "$commit"
git -c gpg.ssh.allowedSignersFile="$allow" -c gpg.ssh.revocationFile="$revoked" \
  show -s --format='%H %G? %GS %GF %GT %ae %ce' "$commit"
```

Use the exit status of `verify-commit` for the signature gate and preserve its diagnostic output. The second command displays the commit ID, signature status, signer, fingerprint, trust level, author email and committer email in that order. Its process exit status does not stand in for the first command’s verdict. If a supposedly trusted signature fails, confirm the exact object, tool availability, file readability and fingerprint. Capture the raw verification failure without changing trust during collection.

## 5. Offline exercise · real signatures on disposable commits

Download the <a href="{{ '/assets/labs/git-ssh-commit-signature-evidence.py' | relative_url }}" download="git-ssh-commit-signature-evidence.py">Python lab</a> to an approved local POSIX workspace. Use Python 3, Git 2.34 or newer with SSH signing support and a maintained OpenSSH `ssh-keygen`. The lab generates two disposable Ed25519 key pairs without passphrases in a private temporary directory, creates a separate Git repository and removes the directory on exit. The keys are for this exercise. It does not contact a server or use your existing keys or Git config.

```bash
python3 git-ssh-commit-signature-evidence.py
```

```text
trusted: accepted
untrusted_key: rejected
unsigned: rejected
revoked_key: rejected
different_author: accepted
```

The first, second and fourth checks verify the **same signed commit** under different trust inputs. The fifth signs a separate commit with the trusted key while recording a different author. The lab also checks that different author field directly. If setup fails, confirm that `git` and `ssh-keygen` are on PATH, that SSH signature support is installed and that the temporary directory is writable. This lab executed actual Git and OpenSSH verification with Git 2.56.1 and OpenSSH 10.0p2. Hosting badges, branch rules and CI behavior were reviewed in documentation.

## 6. Check your understanding

- **Why did the same signed commit fail with another allowed signers file?** The verifier’s trusted keys changed. The commit object and signature bytes stayed the same.
- **Does a passing signature prove the author field personally approved the change?** Consult review records and policy mapping. The signature establishes that the recognized key signed the payload.
- **Can an old hosting badge settle a current key compromise investigation?** Collect the badge’s verification record and evaluate the exact object under the incident trust policy.

Finish when all five results match and you can distinguish approved key membership, present-day revocation and change approval.

## Official references

Reviewed 2026-11-22. Git’s SSH support arrived in 2.34 in 2021. The upstream manuals describe verification with the installed OpenSSH tools, and the GitHub docs apply to hosted verification records.

- SSH signer files, key lifetimes and revocation. [Git configuration manual](https://git-scm.com/docs/git-config)
- Verification invocation and signature display fields. [Git verify-commit](https://git-scm.com/docs/git-verify-commit) · [Git log format](https://git-scm.com/docs/git-log)
- OpenSSH signature verification and allowed signers. [OpenBSD ssh-keygen manual](https://man.openbsd.org/ssh-keygen.1)
- GitHub hosted verification and persisted status. [GitHub Docs · Commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)

[Previous · Public-key cryptography]({{ '/wiki/public-key-cryptography/' | relative_url }}) · [Next · Build provenance verification]({{ '/wiki/artifact-provenance-evidence/' | relative_url }})
