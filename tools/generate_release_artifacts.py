"""Generate release SBOM, checksums, and local provenance metadata.

The output is a reviewability aid for tagged educational releases. It is not a
cryptographic certification, a SLSA attestation, or a production-vault claim.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import uuid


ROOT = Path(__file__).resolve().parents[1]


def run_git(args: list[str], fallback: str = "") -> str:
    try:
        return subprocess.check_output(
            ["git", *args],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        if os.environ.get("RELEASE_ARTIFACTS_DEBUG"):
            print(f"git {' '.join(args)} failed: {exc}", file=sys.stderr)
        return fallback


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_project_metadata() -> dict[str, str]:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    runtime = (ROOT / "secure_vault.py").read_text(encoding="utf-8")
    project_block = re.search(r"(?ms)^\[project\]\s*(.*?)(?:^\[|\Z)", pyproject)
    if not project_block:
        raise RuntimeError("pyproject.toml is missing a [project] section")

    def get_string(key: str) -> str:
        match = re.search(rf'(?m)^{re.escape(key)}\s*=\s*"([^"]+)"', project_block.group(1))
        if not match:
            raise RuntimeError(f"pyproject.toml [project] is missing {key}")
        return match.group(1)

    version_match = re.search(r'(?m)^__version__\s*=\s*"([^"]+)"', runtime)
    if not version_match:
        raise RuntimeError("secure_vault.py is missing __version__")

    return {"name": get_string("name"), "version": version_match.group(1)}


def parse_requirement(line: str) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith("-r "):
        return None
    name = re.split(r"\s*(?:===|==|~=|>=|<=|>|<|!=|\[)", stripped, maxsplit=1)[0].strip()
    if not name:
        return None
    return name, stripped


def requirement_components() -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    sources = [
        ("requirements.txt", "runtime"),
        ("requirements-dev.txt", "development-or-build"),
    ]

    for file_name, scope in sources:
        path = ROOT / file_name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            parsed = parse_requirement(line)
            if not parsed:
                continue
            name, requirement = parsed
            key = (name.lower(), scope)
            if key in seen:
                continue
            seen.add(key)
            components.append(
                {
                    "type": "library",
                    "bom-ref": f"pkg:pypi/{name.lower()}",
                    "name": name,
                    "purl": f"pkg:pypi/{name.lower()}",
                    "properties": [
                        {"name": "aes-secure-vault:requirement", "value": requirement},
                        {"name": "aes-secure-vault:dependency-scope", "value": scope},
                    ],
                }
            )

    return sorted(components, key=lambda item: (str(item["name"]).lower(), json.dumps(item)))


def posix_relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def expected_distribution_files(metadata: dict[str, str]) -> list[Path]:
    dist_dir = ROOT / "dist"
    normalized_name = metadata["name"].replace("-", "_")
    expected = [
        dist_dir / f"{normalized_name}-{metadata['version']}-py3-none-any.whl",
        dist_dir / f"{normalized_name}-{metadata['version']}.tar.gz",
    ]
    missing = [path.name for path in expected if not path.is_file()]
    if missing:
        raise RuntimeError("release distributions are missing: " + ", ".join(missing))
    unexpected = sorted(
        path.name for path in dist_dir.iterdir() if path.is_file() and path not in expected
    )
    if unexpected:
        raise RuntimeError(
            "dist contains stale or unexpected release files; clean it before building: "
            + ", ".join(unexpected)
        )
    return expected


def collect_subjects(extra_files: list[Path], dist_files: list[Path]) -> list[dict[str, object]]:
    files = [
        ROOT / "pyproject.toml",
        ROOT / "requirements.txt",
        ROOT / "requirements-dev.txt",
        ROOT / "README.md",
        ROOT / "LICENSE",
        ROOT / "secure_vault.py",
        ROOT / "test_secure_vault.py",
        *dist_files,
        *extra_files,
    ]
    existing_files = [path for path in files if path.exists() and path.is_file()]
    return [
        {
            "path": posix_relative(path),
            "sha256": sha256(path),
            "bytes": path.stat().st_size,
        }
        for path in existing_files
    ]


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def build_public_checksum_lines(paths: list[Path]) -> list[str]:
    """Build the checksum manifest exactly as GitHub Releases publishes it.

    GitHub flattens the files from ``dist/`` and ``release-artifacts/<tag>/``
    into one release asset list. Keeping only basenames here lets a reviewer
    download the public assets into one directory and verify every entry. A
    duplicate basename would make that public layout ambiguous, so fail closed.
    """

    names = [path.name for path in paths]
    if len(names) != len(set(names)):
        raise RuntimeError("release assets contain duplicate basenames")
    return [f"{sha256(path)}  {path.name}" for path in sorted(paths, key=lambda item: item.name)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-tag", action="store_true", help="fail unless HEAD is exactly tagged")
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="fail unless the git worktree is clean",
    )
    args = parser.parse_args()

    metadata = read_project_metadata()
    dist_files = expected_distribution_files(metadata)
    commit = run_git(["rev-parse", "HEAD"], "unknown")
    short_commit = run_git(["rev-parse", "--short", "HEAD"], "unknown")
    branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], "unknown")
    tag = run_git(["describe", "--tags", "--exact-match", "HEAD"], "")
    status = run_git(["status", "--porcelain"], "")
    dirty = bool(status)

    if args.require_tag and not tag:
        print("release artifacts require HEAD to match a git tag", file=sys.stderr)
        return 1
    if tag and tag != f"v{metadata['version']}":
        print(
            f"release tag {tag} does not match project version v{metadata['version']}",
            file=sys.stderr,
        )
        return 1
    if (args.require_clean or args.require_tag) and dirty:
        print("release artifacts require a clean worktree", file=sys.stderr)
        return 1

    release_id = tag or f"{metadata['version']}-{short_commit}"
    out_dir = ROOT / "release-artifacts" / release_id
    out_dir.mkdir(parents=True, exist_ok=True)

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    root_ref = f"pkg:pypi/{metadata['name']}@{metadata['version']}"
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": generated_at,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "tools/generate_release_artifacts.py",
                        "version": "1",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": metadata["name"],
                "version": metadata["version"],
                "purl": root_ref,
            },
        },
        "components": requirement_components(),
        "properties": [
            {
                "name": "aes-secure-vault:release-boundary",
                "value": "Educational authenticated-encryption tool. SBOM is release transparency, not production vault certification.",
            }
        ],
    }

    sbom_path = out_dir / f"{metadata['name']}-{metadata['version']}.sbom.cdx.json"
    write_json(sbom_path, sbom)

    provenance_path = out_dir / f"{metadata['name']}-{metadata['version']}.provenance.local.json"
    subjects = collect_subjects([sbom_path], dist_files)
    provenance = {
        "predicateType": "https://mdpstudio.com.au/provenance/local-build/v1",
        "generatedAt": generated_at,
        "subject": {
            "name": metadata["name"],
            "version": metadata["version"],
            "releaseId": release_id,
            "git": {
                "commit": commit,
                "branch": branch,
                "tag": tag or None,
                "dirty": dirty,
            },
        },
        "build": {
            "python": sys.version.split()[0],
            "commands": [
                "python -m pip install -r requirements-dev.txt",
                "python -m pytest test_secure_vault.py -v",
                "python -m build",
                "python tools/generate_release_artifacts.py --require-tag --require-clean",
            ],
        },
        "owaspMapping": [
            {
                "id": "OWASP Top 10:2025 A03",
                "control": "Software supply chain inventory through SBOM generation.",
                "url": "https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/",
            },
            {
                "id": "OWASP Top 10:2025 A08",
                "control": "Release integrity through checksum artifacts and provenance metadata.",
                "url": "https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/",
            },
        ],
        "releaseBoundary": "This provenance statement is unsigned local build metadata. It does not claim SLSA compliance, compliance readiness, or production-grade cryptography.",
        "subjects": subjects,
    }
    write_json(provenance_path, provenance)

    # This manifest is a verifier for the files users can actually download
    # from the matching GitHub release. Source-file hashes remain available in
    # the provenance statement, but are not presented as downloadable assets.
    checksum_targets = [
        *dist_files,
        sbom_path,
        provenance_path,
    ]
    checksum_path = out_dir / f"{metadata['name']}-{metadata['version']}.sha256"
    checksum_path.write_text(
        "\n".join(build_public_checksum_lines(checksum_targets)) + "\n",
        encoding="utf-8",
    )

    print(f"Release artifacts written to {posix_relative(out_dir)}")
    print(f"- {posix_relative(sbom_path)}")
    print(f"- {posix_relative(provenance_path)}")
    print(f"- {posix_relative(checksum_path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
