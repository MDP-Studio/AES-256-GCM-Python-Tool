from __future__ import annotations

from pathlib import Path
import hashlib
import json
import tempfile

import pytest

from tools.generate_release_artifacts import build_public_checksum_lines
from tools.verify_published_release import (
    ReleaseVerificationError,
    expected_release_assets,
    verify_published_release,
)
from tools.verify_release_artifacts import verify_manifest


ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_release_workflow_exists() -> None:
    text = workflow_text()

    assert "name: Release" in text
    assert "python -m build" in text
    assert "tools/generate_release_artifacts.py --require-tag --require-clean" in text
    assert "gh release upload" in text
    assert "gh release create" in text
    assert "tools/verify_published_release.py" in text
    assert "--expected-commit \"${GITHUB_SHA}\"" in text


def test_production_handoff_doc_is_packaged() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    handoff = ROOT / "docs" / "production-handoff.md"

    assert handoff.exists()
    assert "docs/production-handoff.md" in pyproject
    assert "not a production" in handoff.read_text(encoding="utf-8")


def test_public_security_policy_is_discoverable_and_packaged() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert "SECURITY.md" in pyproject
    assert "Security =" in pyproject
    assert "[security policy](SECURITY.md)" in readme
    assert "/security/advisories/new" in policy
    assert "python tools/verify_published_release.py --tag v1.1.1" in policy
    assert "production vault" in policy
    assert "independently certified" in policy


def test_release_workflow_attests_artifacts() -> None:
    text = workflow_text()

    assert "id-token: write" in text
    assert "attestations: write" in text
    assert "actions/attest@v4" in text
    assert "subject-path:" in text
    assert "${{ github.workspace }}/dist/*" in text
    assert "release-artifacts/${{ steps.release-id.outputs.release_id }}/*" in text


def test_scheduled_workflow_verifies_latest_published_release() -> None:
    text = (ROOT / ".github" / "workflows" / "verify-published-release.yml").read_text(
        encoding="utf-8"
    )

    assert "schedule:" in text
    assert "gh release view" in text
    assert "tools/verify_published_release.py" in text
    assert "--skip-attestations" not in text


def test_pypi_publish_is_trusted_publishing_only() -> None:
    text = workflow_text()

    assert "pypa/gh-action-pypi-publish@release/v1" in text
    assert "environment:" in text
    assert "name: pypi" in text
    assert "trusted_publisher_configured" in text
    assert "inputs.publish_to_pypi == true" in text
    assert "https://api.github.com/repos/${GITHUB_REPOSITORY}/environments/pypi" in text
    assert "password:" not in text
    assert "PYPI_API_TOKEN" not in text
    assert "__token__" not in text


def test_pypi_publish_requires_manual_tagged_run() -> None:
    text = workflow_text()

    assert "github.event_name == 'workflow_dispatch' && inputs.publish_to_pypi == true" in text
    assert 'if [[ "${GITHUB_REF}" != refs/tags/v* ]]; then' in text
    assert "PyPI publishing is allowed only from a v* tag" in text


def test_release_verifier_accepts_matching_manifest() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        artifact = root / "release-artifacts" / "v1.1.0" / "sample.txt"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("release payload\n", encoding="utf-8")
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        manifest = root / "manifest.sha256"
        manifest.write_text(f"{digest}  release-artifacts/v1.1.0/sample.txt\n", encoding="utf-8")

        assert verify_manifest(manifest, root) == []


def test_release_verifier_rejects_tamper_and_path_escape() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        artifact = root / "sample.txt"
        artifact.write_text("tampered\n", encoding="utf-8")
        manifest = root / "manifest.sha256"
        manifest.write_text(
            "0" * 64 + "  sample.txt\n" +
            "1" * 64 + "  ../outside.txt\n",
            encoding="utf-8",
        )

        failures = verify_manifest(manifest, root)

    assert any("sha256 mismatch" in failure for failure in failures)
    assert any("path escapes artifact root" in failure for failure in failures)


def _published_release_fixture(root: Path) -> tuple[dict[str, object], str, str]:
    tag = "v1.1.1"
    commit = "a" * 40
    names = expected_release_assets(tag)
    payloads = {
        names[0]: b"wheel payload\n",
        names[1]: b"source payload\n",
        names[2]: b'{"bomFormat":"CycloneDX"}\n',
    }
    provenance = {
        "subject": {
            "name": "aes-secure-vault",
            "version": "1.1.1",
            "releaseId": tag,
            "git": {"commit": commit, "tag": tag, "dirty": False},
        }
    }
    payloads[names[3]] = (json.dumps(provenance) + "\n").encode("utf-8")
    for name, content in payloads.items():
        (root / name).write_bytes(content)
    checksum_lines = [
        f"{hashlib.sha256((root / name).read_bytes()).hexdigest()}  {name}" for name in names[:-1]
    ]
    (root / names[-1]).write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    assets = []
    for name in names:
        path = root / name
        assets.append(
            {
                "name": name,
                "size": path.stat().st_size,
                "digest": f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}",
            }
        )
    return {
        "tagName": tag,
        "isDraft": False,
        "url": "https://github.example/releases/v1.1.1",
        "assets": assets,
    }, tag, commit


def test_public_checksum_manifest_uses_flat_release_names() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        first = root / "dist" / "package.whl"
        second = root / "release-artifacts" / "v1" / "sbom.json"
        first.parent.mkdir(parents=True)
        second.parent.mkdir(parents=True)
        first.write_bytes(b"wheel")
        second.write_bytes(b"sbom")

        lines = build_public_checksum_lines([second, first])

    assert lines[0].endswith("  package.whl")
    assert lines[1].endswith("  sbom.json")
    assert all("dist/" not in line and "release-artifacts/" not in line for line in lines)


def test_published_release_verifier_accepts_offline_fixture_and_injected_attestations() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metadata, tag, commit = _published_release_fixture(root)
        checked: list[str] = []

        report = verify_published_release(
            metadata,
            root,
            tag,
            commit,
            lambda path: checked.append(path.name),
        )

    assert report["checks"]["checksumManifest"] == "verified"
    assert report["checks"]["githubAttestations"] == "verified"
    assert checked == list(expected_release_assets(tag))


def test_published_release_verifier_fails_on_missing_or_tampered_evidence() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metadata, tag, commit = _published_release_fixture(root)
        metadata["assets"] = metadata["assets"][:-1]
        with pytest.raises(ReleaseVerificationError, match="missing required asset metadata"):
            verify_published_release(metadata, root, tag, commit, lambda path: None)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metadata, tag, commit = _published_release_fixture(root)
        (root / expected_release_assets(tag)[0]).write_bytes(b"tampered")
        with pytest.raises(ReleaseVerificationError, match="size does not match|digest mismatch"):
            verify_published_release(metadata, root, tag, commit, lambda path: None)


def test_published_release_verifier_requires_attestation_evidence() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        metadata, tag, commit = _published_release_fixture(root)
        with pytest.raises(ReleaseVerificationError, match="attestation evidence is required"):
            verify_published_release(metadata, root, tag, commit, None)
