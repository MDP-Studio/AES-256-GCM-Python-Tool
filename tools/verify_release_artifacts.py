"""Verify AES Secure Vault release checksum artifacts.

This is a reviewability helper for downloaded release artifacts. It verifies
SHA-256 entries in the generated manifest and refuses paths that escape the
chosen artifact root. It does not verify GitHub or PyPI attestations.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_manifest_line(line: str, line_number: int) -> tuple[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = stripped.split(None, 1)
    if len(parts) != 2:
        raise ValueError(f"line {line_number}: expected '<sha256>  <path>'")
    expected, relative_path = parts
    if len(expected) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in expected):
        raise ValueError(f"line {line_number}: invalid SHA-256 digest")
    return expected.lower(), relative_path.strip()


def resolve_manifest_path(root: Path, relative_path: str) -> tuple[Path | None, str | None]:
    if Path(relative_path).is_absolute():
        return None, f"{relative_path}: absolute paths are not allowed"
    candidate = (root / relative_path).resolve()
    root_resolved = root.resolve()
    if candidate != root_resolved and root_resolved not in candidate.parents:
        return None, f"{relative_path}: path escapes artifact root"
    return candidate, None


def verify_manifest(checksum_file: Path, artifact_root: Path) -> list[str]:
    failures: list[str] = []
    for line_number, line in enumerate(checksum_file.read_text(encoding="utf-8").splitlines(), start=1):
        parsed = parse_manifest_line(line, line_number)
        if not parsed:
            continue
        expected, relative_path = parsed
        target, path_error = resolve_manifest_path(artifact_root, relative_path)
        if path_error:
            failures.append(path_error)
            continue
        assert target is not None
        if not target.exists() or not target.is_file():
            failures.append(f"{relative_path}: missing")
            continue
        actual = sha256(target)
        if actual != expected:
            failures.append(f"{relative_path}: sha256 mismatch expected {expected} got {actual}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("checksum_file", type=Path, help="release .sha256 manifest")
    parser.add_argument(
        "--artifact-root",
        type=Path,
        default=Path.cwd(),
        help="directory containing the files named by the manifest",
    )
    args = parser.parse_args(argv)

    if not args.checksum_file.exists():
        print(f"checksum file not found: {args.checksum_file}", file=sys.stderr)
        return 2

    failures = verify_manifest(args.checksum_file, args.artifact_root)
    if failures:
        print("Release artifact verification failed:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(f"Verified {args.checksum_file} against {args.artifact_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
