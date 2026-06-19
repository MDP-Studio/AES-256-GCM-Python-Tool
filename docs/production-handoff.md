# Production Handoff Boundary

AES Secure Vault is an educational authenticated-encryption tool. It is useful
for reviewing AES-256-GCM envelopes, Argon2id parameter binding, safe-mode file
streaming, release provenance, and defensive parsing. It is not a production
vault, password manager, KMS client, backup system, or compliance-ready secrets
platform.

Use this checklist before any design tries to move from the package into a real
product.

## Stop Before Real Secrets

Do not store customer data, client files, payment data, API keys, seed phrases,
SSH keys, exchange keys, or production credentials in AES Secure Vault unless a
separate production design has answered the controls below.

| Control | Current project state | Production requirement |
| --- | --- | --- |
| Key source | User passphrase, Argon2id-derived key | KMS/HSM/Vault-backed KEK, per-purpose DEKs, recovery plan |
| Access control | None inside encrypted blob | Identity, authorization, audit logs, and revocation outside crypto |
| Rotation | No built-in re-encrypt workflow | Key epochs, decrypt-only old keys, migration job, rollback plan |
| Nonce tracking | Random nonce per blob or chunk | Collision monitoring or deterministic allocation policy at scale |
| Secret handling | Python memory, no zeroization guarantee | Memory threat model, process hardening, least privilege |
| Operations | Local CLI and library | Backup, restore, monitoring, support, incident response |
| Compliance | No certification claims | Formal evidence, policy mapping, and independent review if required |

## Required Architecture Questions

1. Who can encrypt, decrypt, rotate, export, and delete each protected object?
2. Which key owns the data: tenant, dataset, user, environment, or purpose?
3. What happens if the passphrase, KMS key, dependency, or host is compromised?
4. How are old envelopes re-encrypted after a key or algorithm migration?
5. Which metadata must be authenticated as AAD and which metadata is sensitive?
6. Where are decrypted plaintext and derived keys allowed to exist in memory,
   logs, temp files, crash dumps, and backups?
7. How will support staff debug failures without requesting the plaintext or
   passphrase?

## Safe Production Pattern

For production storage, prefer an envelope managed by a mature platform:

```text
suite_id || key_id || nonce || ciphertext || tag
```

Use a KMS/HSM/Vault-backed key-encryption key to wrap data-encryption keys.
Store the key ID and suite ID as authenticated metadata. Encrypt new data only
with active keys. Allow deactivated keys for decrypt-only reads while a
re-encryption job migrates old data.

When passphrases are unavoidable, Argon2id parameters must be calibrated to the
deployment hardware and rate-limited at the application boundary. KDF strength
does not replace MFA, account lockout, monitoring, or recovery controls.

## Misuse Tests To Add In A Real System

- Re-encryption under a new key preserves plaintext and updates key epoch.
- Old key IDs are accepted for decrypt-only, never for new encryption.
- Tampering with suite ID, key ID, salt, nonce, chunk sequence, final flag, or
  compatibility tags fails closed.
- Oversized, truncated, duplicate-chunk, unknown-version, and extra-field
  envelopes fail without revealing secrets.
- Logs never include plaintext, passphrases, raw envelopes, derived keys, or
  customer identifiers beyond approved metadata.
- Backup restore proves encrypted data, metadata, and key references recover
  together.

## What The Existing Release Evidence Means

The SBOM, SHA-256 manifest, local provenance file, GitHub release assets, and
artifact attestations improve package reviewability. They do not prove that the
tool is safe for production secrets. Treat them as supply-chain transparency
evidence only.

## References

- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800-38d/final) for AES-GCM.
- [NIST SP 800-57 Part 1 Rev 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final) for key lifecycle.
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) for storage design.
- [OWASP Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html) for key management boundaries.
- [cryptography.io](https://cryptography.io/en/latest/) for the underlying Python cryptography library.
