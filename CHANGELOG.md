# Changelog

## Unreleased

- Move GitHub checkout, Python setup, and artifact transfer actions to their
  Node 24-compatible major versions for future release and verification runs.

## 1.1.1 - 2026-07-13

- Correct the public checksum manifest to cover the flat GitHub release assets.
- Verify downloaded GitHub release assets, digests, provenance, and attestations
  after publishing and on a weekly schedule.
- Add offline verifier seams and regression tests for missing and tampered
  release evidence.
- Surface the release-verification boundary in the browser UI and documentation.

## 1.1.0 - 2026-05-22

- Add SBOM, checksum, and unsigned local provenance generation.
- Add safe-mode streaming encryption and package release metadata.

The 1.1.0 GitHub release did not upload every file named by its checksum
manifest. Use 1.1.1 or newer for the complete published-artifact ceremony.
