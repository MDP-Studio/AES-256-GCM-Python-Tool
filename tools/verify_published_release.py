"""Verify an AES Secure Vault GitHub release as users actually receive it.

The online path downloads release assets with GitHub CLI, checks GitHub's asset
digests, verifies the published SHA-256 manifest, validates provenance against
the release tag, and requires GitHub artifact attestations. The core verifier
accepts injected metadata and an attestation callback so tests stay offline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Callable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.verify_release_artifacts import parse_manifest_line, sha256


DEFAULT_REPOSITORY = "MDP-Studio/AES-256-GCM-Python-Tool"
SIGNER_WORKFLOW = ".github/workflows/release.yml"


class ReleaseVerificationError(RuntimeError):
    """Raised when published release evidence is incomplete or inconsistent."""


def release_version(tag: str) -> str:
    if not tag.startswith("v") or len(tag) == 1:
        raise ReleaseVerificationError(f"release tag must start with v: {tag!r}")
    return tag[1:]


def expected_release_assets(tag: str) -> tuple[str, ...]:
    version = release_version(tag)
    return (
        f"aes_secure_vault-{version}-py3-none-any.whl",
        f"aes_secure_vault-{version}.tar.gz",
        f"aes-secure-vault-{version}.sbom.cdx.json",
        f"aes-secure-vault-{version}.provenance.local.json",
        f"aes-secure-vault-{version}.sha256",
    )


def _release_asset_map(metadata: dict[str, object]) -> dict[str, dict[str, object]]:
    assets = metadata.get("assets")
    if not isinstance(assets, list):
        raise ReleaseVerificationError("release metadata is missing the assets array")
    result: dict[str, dict[str, object]] = {}
    for raw_asset in assets:
        if not isinstance(raw_asset, dict) or not isinstance(raw_asset.get("name"), str):
            raise ReleaseVerificationError("release metadata contains an invalid asset entry")
        name = str(raw_asset["name"])
        if name in result:
            raise ReleaseVerificationError(f"release metadata contains duplicate asset {name}")
        result[name] = raw_asset
    return result


def _parse_public_checksum_manifest(path: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        parsed = parse_manifest_line(line, line_number)
        if not parsed:
            continue
        expected, relative_path = parsed
        candidate = Path(relative_path)
        if candidate.is_absolute() or candidate.name != relative_path:
            raise ReleaseVerificationError(
                f"checksum line {line_number} must name a flat published asset: {relative_path}"
            )
        if relative_path in entries:
            raise ReleaseVerificationError(f"checksum manifest repeats {relative_path}")
        entries[relative_path] = expected
    if not entries:
        raise ReleaseVerificationError("checksum manifest contains no release assets")
    return entries


def _verify_provenance(path: Path, tag: str, expected_commit: str) -> None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        subject = payload["subject"]
        git = subject["git"]
    except (OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ReleaseVerificationError(f"invalid provenance statement: {exc}") from exc

    version = release_version(tag)
    if subject.get("name") != "aes-secure-vault" or subject.get("version") != version:
        raise ReleaseVerificationError("provenance project name or version does not match release tag")
    if subject.get("releaseId") != tag or git.get("tag") != tag:
        raise ReleaseVerificationError("provenance release ID or git tag does not match release tag")
    if git.get("dirty") is not False:
        raise ReleaseVerificationError("provenance says the release build used a dirty worktree")
    if git.get("commit") != expected_commit:
        raise ReleaseVerificationError(
            f"provenance commit {git.get('commit')} does not match tag commit {expected_commit}"
        )


def verify_published_release(
    metadata: dict[str, object],
    asset_root: Path,
    tag: str,
    expected_commit: str,
    attestation_verifier: Callable[[Path], None] | None,
    require_attestations: bool = True,
) -> dict[str, object]:
    """Verify downloaded assets using injected, offline-testable evidence."""

    if metadata.get("tagName") != tag:
        raise ReleaseVerificationError(
            f"release metadata tag {metadata.get('tagName')!r} does not match {tag!r}"
        )
    if metadata.get("isDraft") is not False:
        raise ReleaseVerificationError("release is absent or still a draft")
    if len(expected_commit) != 40 or any(ch not in "0123456789abcdefABCDEF" for ch in expected_commit):
        raise ReleaseVerificationError("expected tag commit must be a full 40-character SHA")

    required = expected_release_assets(tag)
    asset_metadata = _release_asset_map(metadata)
    missing_metadata = [name for name in required if name not in asset_metadata]
    if missing_metadata:
        raise ReleaseVerificationError(
            "published release is missing required asset metadata: " + ", ".join(missing_metadata)
        )

    actual_digests: dict[str, str] = {}
    for name in required:
        path = asset_root / name
        if not path.is_file():
            raise ReleaseVerificationError(f"downloaded release asset is missing: {name}")
        metadata_size = asset_metadata[name].get("size")
        if not isinstance(metadata_size, int) or metadata_size != path.stat().st_size:
            raise ReleaseVerificationError(f"GitHub release size does not match downloaded asset: {name}")
        digest = asset_metadata[name].get("digest")
        if not isinstance(digest, str) or not digest.startswith("sha256:"):
            raise ReleaseVerificationError(f"GitHub release metadata has no SHA-256 digest for {name}")
        actual = sha256(path)
        if digest[len("sha256:") :].lower() != actual:
            raise ReleaseVerificationError(f"GitHub release digest mismatch for {name}")
        actual_digests[name] = actual

    checksum_name = required[-1]
    manifest_entries = _parse_public_checksum_manifest(asset_root / checksum_name)
    checksum_subjects = set(required[:-1])
    if set(manifest_entries) != checksum_subjects:
        missing = sorted(checksum_subjects - set(manifest_entries))
        extra = sorted(set(manifest_entries) - checksum_subjects)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise ReleaseVerificationError("published checksum manifest is incomplete: " + "; ".join(details))
    for name, expected in manifest_entries.items():
        if actual_digests[name] != expected:
            raise ReleaseVerificationError(f"published checksum mismatch for {name}")

    provenance_name = f"aes-secure-vault-{release_version(tag)}.provenance.local.json"
    _verify_provenance(asset_root / provenance_name, tag, expected_commit.lower())

    attested: list[str] = []
    if require_attestations and attestation_verifier is None:
        raise ReleaseVerificationError("GitHub attestation evidence is required but no verifier was supplied")
    if attestation_verifier is not None:
        for name in required:
            try:
                attestation_verifier(asset_root / name)
            except Exception as exc:
                raise ReleaseVerificationError(f"GitHub attestation verification failed for {name}: {exc}") from exc
            attested.append(name)

    return {
        "schemaVersion": "1.0",
        "repository": metadata.get("url", ""),
        "tag": tag,
        "tagCommit": expected_commit.lower(),
        "assets": [
            {
                "name": name,
                "sha256": actual_digests[name],
                "checksumManifest": name in manifest_entries,
                "githubAttestation": name in attested,
            }
            for name in required
        ],
        "checks": {
            "releaseMetadata": "verified",
            "githubAssetDigests": "verified",
            "checksumManifest": "verified",
            "provenanceTagAndCommit": "verified",
            "githubAttestations": "verified" if attested else "explicitly-skipped",
        },
    }


class GitHubReleaseClient:
    def __init__(self, repository: str, tag: str, attempts: int, retry_delay: float) -> None:
        self.repository = repository
        self.tag = tag
        self.attempts = attempts
        self.retry_delay = retry_delay

    @staticmethod
    def _run(args: list[str]) -> str:
        try:
            completed = subprocess.run(
                ["gh", *args],
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise ReleaseVerificationError("GitHub CLI (gh) is required for online verification") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or str(exc)).strip()
            raise ReleaseVerificationError(f"gh {' '.join(args)} failed: {detail}") from exc
        return completed.stdout

    def release_metadata(self) -> dict[str, object]:
        raw = self._run(
            [
                "release",
                "view",
                self.tag,
                "--repo",
                self.repository,
                "--json",
                "tagName,isDraft,isPrerelease,targetCommitish,url,assets",
            ]
        )
        return json.loads(raw)

    def download(self, destination: Path) -> None:
        destination.mkdir(parents=True, exist_ok=True)
        self._run(
            [
                "release",
                "download",
                self.tag,
                "--repo",
                self.repository,
                "--dir",
                str(destination),
                "--clobber",
            ]
        )

    def tag_commit(self) -> str:
        payload = json.loads(self._run(["api", f"repos/{self.repository}/git/ref/tags/{self.tag}"]))
        target = payload.get("object", {})
        while target.get("type") == "tag":
            target = json.loads(self._run(["api", str(target["url"])]))["object"]
        sha = target.get("sha")
        if target.get("type") != "commit" or not isinstance(sha, str):
            raise ReleaseVerificationError("release tag does not resolve to a commit")
        return sha

    def verify_attestation(self, path: Path, expected_commit: str) -> None:
        signer = f"{self.repository}/{SIGNER_WORKFLOW}"
        args = [
            "attestation",
            "verify",
            str(path),
            "--repo",
            self.repository,
            "--signer-workflow",
            signer,
            "--source-ref",
            f"refs/tags/{self.tag}",
            "--source-digest",
            expected_commit,
        ]
        last_error: ReleaseVerificationError | None = None
        for attempt in range(1, self.attempts + 1):
            try:
                self._run(args)
                return
            except ReleaseVerificationError as exc:
                last_error = exc
                if attempt < self.attempts:
                    print(
                        f"GitHub attestation check {attempt}/{self.attempts} failed for "
                        f"{path.name}; retrying in {self.retry_delay:g} seconds.",
                        file=sys.stderr,
                    )
                    time.sleep(self.retry_delay)
        assert last_error is not None
        raise last_error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=DEFAULT_REPOSITORY)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--asset-root", type=Path, help="download directory or offline asset directory")
    parser.add_argument("--metadata-file", type=Path, help="offline gh release metadata JSON")
    parser.add_argument("--expected-commit", help="offline tag commit; online mode resolves it from GitHub")
    parser.add_argument("--skip-attestations", action="store_true", help="explicit legacy/offline exception")
    parser.add_argument("--attestation-attempts", type=int, default=4)
    parser.add_argument("--retry-delay", type=float, default=5.0)
    parser.add_argument("--report", type=Path, help="write a machine-readable verification result")
    args = parser.parse_args(argv)

    if args.attestation_attempts < 1 or args.retry_delay < 0:
        parser.error("attestation attempts must be positive and retry delay cannot be negative")

    try:
        if args.metadata_file:
            if not args.asset_root or not args.expected_commit:
                parser.error("offline mode requires --asset-root and --expected-commit")
            metadata = json.loads(args.metadata_file.read_text(encoding="utf-8"))
            result = verify_published_release(
                metadata,
                args.asset_root,
                args.tag,
                args.expected_commit,
                attestation_verifier=None,
                require_attestations=not args.skip_attestations,
            )
        else:
            client = GitHubReleaseClient(
                args.repository,
                args.tag,
                args.attestation_attempts,
                args.retry_delay,
            )
            metadata = client.release_metadata()
            expected_commit = args.expected_commit or client.tag_commit()
            if args.asset_root:
                asset_root = args.asset_root
                client.download(asset_root)
                result = verify_published_release(
                    metadata,
                    asset_root,
                    args.tag,
                    expected_commit,
                    None if args.skip_attestations else lambda path: client.verify_attestation(path, expected_commit),
                    require_attestations=not args.skip_attestations,
                )
            else:
                with tempfile.TemporaryDirectory(prefix="aes-secure-vault-release-") as tmp:
                    asset_root = Path(tmp)
                    client.download(asset_root)
                    result = verify_published_release(
                        metadata,
                        asset_root,
                        args.tag,
                        expected_commit,
                        None if args.skip_attestations else lambda path: client.verify_attestation(path, expected_commit),
                        require_attestations=not args.skip_attestations,
                    )

        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, ReleaseVerificationError) as exc:
        print(f"Published release verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
