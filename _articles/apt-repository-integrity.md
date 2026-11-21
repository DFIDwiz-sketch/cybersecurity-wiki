---
title: "APT Repository Integrity · Trace Trust from Release to Package"
description: "Follow the signed archive metadata, investigate update errors and package history, and reproduce signature and digest checks offline."
category: blue-team
tags: [Linux, APT, Cryptography, Software Supply Chain, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/apt-repository-integrity/
---

**Learning goal.** Explain why a downloaded Debian package can be checked even though APT normally verifies the archive signature higher up the chain. Learn to identify the first failed check and to distinguish a blocked download from evidence that a package was installed.

## 1. What a package manager needs to trust

A **package** is an archive containing software or data and information such as version, architecture and dependencies. A Debian binary package ends in `.deb`. **dpkg** manages the local package database and handles Debian packages. **APT** uses configured **repositories** to discover versions and dependencies, obtain packages and coordinate installations with dpkg. A repository publishes lists of available packages and the files themselves. A **mirror** serves a copy of the repository.

A **digest** is a short value calculated from file bytes. SHA-256 makes it practical to check whether the bytes match a known value. The expected value needs a trusted source. An **archive signing key** provides that trust at the metadata level. The publisher uses its private key to sign metadata, and APT checks the corresponding OpenPGP signature against keys allowed for that source. See [public-key cryptography]({{ '/wiki/public-key-cryptography/' | relative_url }}) for key and signature fundamentals.

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/apt-repository-integrity-en.svg' | relative_url }}" alt="An allowed public key verifies the Release metadata. Release supplies the digest for Packages. Packages supplies the digest for the downloaded Debian package.">
<figcaption>The signature authenticates the expected digest of the index. The index, once verified, supplies the expected digest of each listed package.</figcaption>
</figure>

## 2. Follow one normal update and download

In a fictional organisation, a Debian host is configured for an approved archive, suite `lab` and component `main`. A **suite** selects an archive track, and a **component** selects a subdivision such as `main`. Architecture limits which indexes the host needs. For a real Debian source, use the suite, components and key documented for that release or vendor.

| Evidence | What it contains | How it is checked |
| --- | --- | --- |
| Source and keyring | Archive URI, suite, component and allowed signing keys | Compare the source definition and key fingerprint with independently approved configuration. |
| `InRelease` or `Release` + `Release.gpg` | Release identity and dates, expected digests and sizes of index files | APT verifies the clear-signed file or the detached signature. It also applies freshness and release-information policy as appropriate. |
| `Packages` index | Package name, version, architecture, filename, size and checksum | The bytes fetched must match the appropriate entry in the authenticated `Release` metadata, including the relevant compressed variant when applicable. |
| `.deb` file | The package bytes selected for download | APT checks the download against the package index. Installation and later on-disk state require separate evidence. |

During `apt-get update`, APT refreshes the lists. During a later package operation it chooses a candidate using current local lists and APT policy, then gets and checks the selected file. For example, the authenticated index for the fictional archive lists `wiki-archive-lab` version `1.0` and a SHA-256 digest for its `.deb`. A mirror returning different bytes fails the package check even when its filename matches. If the verified bytes match, you have evidence of the exact archive-published file. A regular Debian archive verification does not require an individual maintainer signature on the downloaded `.deb`.

`Signed-By` can bind a source to a file or embedded key and, for keyrings, can select fingerprints. Debian 13's APT documentation describes embedded keys in deb822 `.sources` and keyring files under `/etc/apt/keyrings` for locally managed keys or `/usr/share/keyrings` for package-managed keys. The referenced keyring must be readable by APT's sandbox user where applicable. Use the vendor's authenticated instructions and compare the full fingerprint through a known channel. A valid signature from an unrelated key proves nothing about the intended archive.

## 3. Understand failures and abuse

| Symptom | Common explanations | What to compare |
| --- | --- | --- |
| Missing or rejected signing key | Approved rotation not deployed, incorrect keyring, wrong suite or unexpected signer | Source stanza, effective keyring, independently documented fingerprints, untouched metadata and exact diagnostic |
| `Hash Sum mismatch` | Mirror or proxy serving files from different generations, corrupted download or unauthorised modification | Expected and observed digest and size, URL, index variant, timestamps and mirror state |
| Release metadata expired or not yet valid | Stale mirror, old signed data replay or host clock error | Signed `Date` and `Valid-Until` when present, UTC and clock offset, mirror publication time |
| Signature and hashes pass but package is suspect | Publisher, build pipeline or signing key compromise, or a legitimately published vulnerable build | Exact build and digest, publisher advisory, independently collected installation and execution evidence |

An attacker who can change mirror content or redirect requests cannot simply replace bytes and recalculate the downstream hashes. APT would need matching authenticated metadata from a permitted signing key. If the publisher or trusted key is compromised, those checks can still succeed on harmful content. HTTPS authenticates a network endpoint and protects the transport. Archive signing protects the package-to-metadata relationship even when a mirror distributes the files. Preserve both checks where configured.

The time controls answer a different question from the signature. A correctly signed old snapshot can still have a valid signature. APT's expiry handling depends on the source's dates and configured policy. If a fetch fails, an older cache may still be available. Successful later queries of local metadata need a timestamp before you can interpret them as current.

## 4. Collect, triage and verify recovery

1. **Preserve the evidence before refreshing.** Record the failing host, UTC and time offset, OS/APT version, complete command and output, package identity and intended source. In an approved collection, preserve source definitions and keyrings, retained lists under `/var/lib/apt/lists/`, retained files under `/var/cache/apt/archives/`, and available APT/dpkg logs such as `/var/log/apt/history.log`, `/var/log/apt/term.log` and `/var/log/dpkg.log`, including relevant rotations. Locations and retention can vary. Preserve the original bytes and restrict any source URLs that contain credentials.
2. **Compare with an independent baseline.** Match the observed URI, suite, architecture and key fingerprint to a known-good configuration. Use mirror or proxy logs if available to check whether an error affected one host, one path or many hosts. Verify the smallest broken link first. For digest mismatches, compare the same file variant, including compression. Avoid converting a synchronisation failure into an intrusion assertion.
3. **Separate download, install and execution.** On Debian-based hosts, `apt-cache policy openssh-server` queries local candidate/origin information. It needs the host's relevant cached lists, which may be stale. `dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n' openssh-server` queries local dpkg state. The status abbreviation `ii` followed by a space is the usual installed state. Package state alone does not prove the source at installation time. Confirm time and version against available transaction logs, package digest against authenticated historical metadata if retained, and execution against service or process evidence. Missing logs leave a gap.
4. **Restore trust with the owner.** For a legitimate key rotation, use the approved key and source configuration and check that lists and expected versions refresh. For suspected publisher or key compromise, coordinate suspension of the affected source, identify hosts and versions that installed from it, and use the vendor's authenticated incident guidance. Preserve evidence before remediation. Verify recovery against expected fingerprints, package versions and service state.

## 5. Offline lab · identify the first failing link

Download <a href="{{ '/assets/labs/apt-repository-integrity-lab.py' | relative_url }}" download>the Python lab</a>. Run `python3 apt-repository-integrity-lab.py` in a shell on an authorised Debian-family test system with Python 3, `dpkg-deb` and OpenSSL 3.x supporting Ed25519. It creates a real text-only `.deb`, a one-record package index, Release metadata and temporary teaching keys. No packages are installed and no network or administrator privileges are required. All temporary outputs are removed on exit.

The exercise uses a raw Ed25519 signature from OpenSSL for the teaching file `Release.sig`. Real APT verifies OpenPGP archive signatures such as `InRelease` or `Release.gpg`. The lab demonstrates the signature and both SHA-256 checks with actual files. It does not run APT, enforce Release freshness or model all accepted repository formats.

| Control | Expected first result |
| --- | --- |
| Original files, expected public key | Signature, index digest and package digest pass |
| Original files, unrelated public key | Release signature rejected |
| Changed Release only | Release signature rejected |
| Changed index only | Packages index digest or size mismatch |
| Changed package only | Package digest or size mismatch |

Predict the failing step before running the script. Compare controls two and three. They fail at the same step for different reasons, so real triage needs both authenticated key context and the original file. Controls four and five show why the signature passing is only the first check. Expect `5/5 archive-integrity controls matched.` If a required executable is unavailable, check tooling in your test environment. If key generation fails, check the OpenSSL version and available providers. The five controls ran in the cloud with OpenSSL 3.5.7 and dpkg-deb 1.22.22. The production APT behavior and investigation commands are explained from Debian documentation.

## 6. Check understanding and finish

1. **You downloaded an index and its digest from the same untrusted source. What is missing?** An authenticated binding to an allowed signer. The signed Release provides that for the repository index.
2. **A valid signature is present but APT reports an expired Release. Is this contradictory?** The signature covers the bytes. The time policy decides whether those bytes are fresh enough for use.
3. **APT reports a digest mismatch on a host. What supports an installation finding?** Corroborate the package identity and time with dpkg state and transaction records. The mismatch by itself records a failed check.
4. **The package was authenticated and installed. Can you conclude it ran?** Look for separate service, process or application evidence.

**Completion criteria.** Describe all three checks in order, classify the five cases and state which evidence would establish installation or execution. Continue with [SBOM and VEX]({{ '/wiki/sbom-vex-evidence/' | relative_url }}) to assess whether an authenticated build is affected by a vulnerability.

## Official references

Reviewed 2026-11-21. Product scope is Debian 13 (trixie) and OpenSSL 3.5. Check your distribution and version before applying the examples.

- [Debian apt-secure(8)](https://manpages.debian.org/trixie/apt/apt-secure.8.en.html) covers the archive signature and hash chain.
- [Debian sources.list(5)](https://manpages.debian.org/trixie/apt/sources.list.5.en.html) covers deb822, scoped keys and freshness.
- [Debian apt-cache(8)](https://manpages.debian.org/trixie/apt/apt-cache.8.en.html) and [dpkg-query(1)](https://manpages.debian.org/trixie/dpkg/dpkg-query.1.en.html) distinguish cache and local package database queries.
- [OpenSSL 3.5 pkeyutl](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/) covers the lab's signing and verification operation.
