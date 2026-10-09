# Coverage receipts

A **coverage receipt** is a small, portable artifact that states what an RLS
audit checked, what it could not check, the deterministic score, and the
fingerprints of what it found. It is the first step of the
[Doctor 2036 roadmap](https://github.com/subhajitlucky/codebase-doctor/blob/main/DOCTOR_2036_VISION.md):
verification that any agent or CI pipeline can carry, compare, and verify.

```bash
rls-doctor check --receipt receipt.json                          # digest-only
rls-doctor check --schema-file m.sql --receipt receipt.json      # offline audit
rls-doctor check --receipt receipt.json --receipt-key key.pem    # signed
rls-doctor verify-receipt receipt.json                           # exit 0 valid, 2 invalid
```

## Format (`receiptVersion: "1"`)

| Field | Meaning |
| --- | --- |
| `tool` | name and version of the issuing tool |
| `issuedAt` | issuance timestamp (UTC ISO) |
| `subject` | audited schemas and scope (`catalog`, `schema-file`, or `shadow`) |
| `score` | deterministic RLS Score and band |
| `coverage.complete` | false when offline parsing left statements unevaluated |
| `coverage.limitations` | exactly what was not evaluated |
| `findings.total` / `bySeverity` | counts only — never policy text |
| `findings.fingerprints` | stable finding fingerprints, sorted |
| `shadow` | present when the audit ran in a disposable world |
| `digest` | SHA-256 over the canonical JSON body |
| `signature` | optional Ed25519 signature + public key |

## Integrity model

- **Canonicalization**: object keys are sorted recursively, so the same
  receipt body always hashes to the same bytes.
- **Digest**: `sha256` over the canonical body. Any change to any field
  invalidates the receipt — `verify-receipt` exits `2`.
- **Signature (optional)**: when `--receipt-key` supplies an Ed25519 private
  key (PKCS#8 PEM), the receipt carries a signature and the public key.

What the model proves, honestly:

- A digest-only receipt proves **tamper evidence**.
- A signed receipt proves **the holder of that private key issued it**.
  Authenticity requires the public key to be pinned out-of-band.
- Neither form proves the database is safe — only what the audit covered and
  what it found.

## Verification output

```
receipt: rls-doctor 0.5.2 · issued 2026-10-09T07:28:21.784Z
subject: auth, rls_doctor_demo (scope=schema-file)
score: 19/100 (red)
coverage: incomplete
  - A DO block was parsed as unconditional role definitions; ...
findings: 9 (info 1, low 2, medium 1, high 4, critical 1)
signature: none (digest only)
integrity: digest verified
```

Exit codes: `0` valid, `2` invalid, unreadable, or not a receipt. Receipts
never contain policy expressions, connection strings, or credentials — the
same withholding rules as reports.

## Why this exists

Agent swarms need to exchange verification results without trusting each
other. A receipt is the unit of that exchange: bounded, deterministic, and
checkable. It is deliberately boring to parse and impossible to quietly edit.
