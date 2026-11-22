#!/usr/bin/env python3
"""Run five local Git SSH signature checks with disposable keys."""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def main():
    for executable in ("git", "ssh-keygen"):
        if shutil.which(executable) is None:
            raise SystemExit(f"Required executable not found: {executable}")

    with tempfile.TemporaryDirectory(prefix="git-ssh-signing-lab-") as temp:
        root = Path(temp).resolve()
        repo = root / "repo"
        repo.mkdir()
        templates = root / "empty-templates"
        templates.mkdir()
        env = {
            "PATH": os.environ.get("PATH", os.defpath),
            "LC_ALL": "C",
            "HOME": str(root),
            "XDG_CONFIG_HOME": str(root),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TEMPLATE_DIR": str(templates),
        }

        def run(*args, check=True):
            command = [str(arg) for arg in args]
            result = subprocess.run(
                command, cwd=repo, env=env, text=True, capture_output=True
            )
            if check and result.returncode:
                raise SystemExit(f"{command[0]} failed: {result.stderr.strip()}")
            return result

        signer = root / "signer"
        other = root / "other"
        for key in (signer, other):
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)

        run("git", "init", "-q")
        run("git", "config", "user.name", "Training Maintainer")
        run("git", "config", "user.email", "maintainer@example.test")
        run("git", "config", "gpg.format", "ssh")
        run("git", "config", "user.signingKey", signer)
        run("git", "config", "gpg.ssh.program", "ssh-keygen")

        allowed = root / "allowed-signers"
        unrelated = root / "other-signers"
        revoked = root / "revoked-keys"
        public_key = signer.with_suffix(".pub").read_text(encoding="utf-8")
        other_key = other.with_suffix(".pub").read_text(encoding="utf-8")
        allowed.write_text("maintainer@example.test " + public_key, encoding="utf-8")
        unrelated.write_text("other@example.test " + other_key, encoding="utf-8")
        revoked.write_text(public_key, encoding="utf-8")

        def commit(message, signing_flag, *options):
            run("git", "commit", "-q", "--allow-empty", signing_flag, "-m", message, *options)
            return run("git", "rev-parse", "HEAD").stdout.strip()

        signed = commit("Training: approved signing key", "-S")
        unsigned = commit("Training: unsigned control", "--no-gpg-sign")
        different_author = commit(
            "Training: author metadata is separate", "-S",
            "--author=Training Author <author@example.test>"
        )

        tests = [
            ("trusted", signed, allowed, (), True),
            ("untrusted_key", signed, unrelated, (), False),
            ("unsigned", unsigned, allowed, (), False),
            ("revoked_key", signed, allowed, (f"gpg.ssh.revocationFile={revoked}",), False),
            ("different_author", different_author, allowed, (), True),
        ]

        for name, revision, trust_file, settings, expected in tests:
            config = ["-c", f"gpg.ssh.allowedSignersFile={trust_file}"]
            for setting in settings:
                config.extend(("-c", setting))
            result = run("git", *config, "verify-commit", revision, check=False)
            passed = result.returncode == 0
            print(f"{name}: {'accepted' if passed else 'rejected'}")
            if passed != expected:
                raise SystemExit(f"Unexpected verification result for {name}: {result.stderr.strip()}")

        author = run("git", "show", "-s", "--format=%ae", different_author).stdout.strip()
        if author != "author@example.test":
            raise SystemExit("Unexpected author metadata in the fifth case.")


if __name__ == "__main__":
    main()
