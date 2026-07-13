# Security Policy

AES Secure Vault is an educational authenticated-encryption project. This
policy covers vulnerability reports for the source repository, Python package,
CLI, browser UI, release workflow, and published release evidence. This is not
a production vault or independently certified cryptographic product.

## Supported Versions And Channels

| Channel | Security support |
| --- | --- |
| Latest tagged GitHub release | Supported for reproducible vulnerability reports and security fixes. |
| Older GitHub releases | Unsupported. Reproduce against the latest release before reporting when possible. |
| `main` branch | Development source only. Fixes land here first, with no stability guarantee. |
| PyPI `aes-secure-vault` | Supported only when its version matches a tagged GitHub release. PyPI publishing is manual and may lag GitHub. |

GitHub Releases are the source of truth for downloadable distributions, SBOM,
checksums, local provenance, and GitHub attestations. A GitHub release does not
mean the same version was published to PyPI.

## Report A Vulnerability

Use a private GitHub security advisory:

<https://github.com/MDP-Studio/AES-256-GCM-Python-Tool/security/advisories/new>

Include the affected version or commit, operating system and Python/browser
version, a minimal reproducer, expected versus observed behavior, and impact.
Do not include real secrets, client data, production credentials, or another
person's encrypted material.

Do not open a public issue with exploit details. If private advisory submission
is unavailable, open a minimal public issue asking the maintainers to enable a
private reporting route, without including the vulnerability details. Response
and remediation are best effort; this project has no paid support or response
SLA. Please coordinate disclosure until a fix or clear status is available.

## In Scope

- authentication or integrity bypass in AES-GCM payload handling
- nonce, salt, key-derivation, AAD, or version-binding errors
- plaintext, passphrase, derived-key, or sensitive-path disclosure by the CLI
  or browser UI
- unsafe parsing, path handling, temporary-file replacement, or streaming
  behavior that breaks the documented security boundary
- dependency, build, checksum, provenance, or GitHub attestation failures in
  the project's release workflow
- browser security policy or third-party asset loading that contradicts the
  documented client-only behavior

## Out Of Scope And Boundaries

- weak user-selected passphrases or loss of a passphrase
- production key management, access control, recovery, rotation, backups,
  tenancy, audit logging, availability, or support operations
- memory scraping, endpoint compromise, side channels, or zeroization claims
  outside Python and browser runtime guarantees
- vulnerabilities in GitHub, PyPI, browsers, operating systems, or upstream
  dependencies that do not arise from this project's integration
- social engineering, denial-of-service against public services, automated
  scanning, or testing data and systems you do not own or have permission to use

There is no bug bounty. Test only with synthetic data and systems you control.

## Verify A Published Release

From a clean clone with GitHub CLI installed, verify the current release:

```bash
python tools/verify_published_release.py --tag v1.1.1
```

The command fails if published files, GitHub asset digests, the flat SHA-256
manifest, tag-bound provenance, or GitHub attestations are absent or mismatched.
For another release, replace the tag with the exact published `v*` tag. The
release and scheduled CI workflows do not use the attestation-skip exception.

## Current Security Limitations

- No independent cryptographic audit or formal verification has been completed.
- The project is not FIPS, Common Criteria, SOC 2, or ISO 27001 certified.
- It has no KMS/HSM integration, identity layer, key rotation, recovery, or
  multi-user authorization.
- Python and browser runtimes do not guarantee passphrase or derived-key memory
  zeroization.
- The browser UI loads `argon2-browser` from a CDN with Subresource Integrity;
  offline and supply-chain availability depend on that third-party asset.
- Release checksums, SBOMs, provenance, and attestations improve reviewability.
  They do not certify the cryptographic design for production secrets.

See [docs/production-handoff.md](docs/production-handoff.md) for the controls a
real production design would still need.
