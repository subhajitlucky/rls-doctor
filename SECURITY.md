# Security Policy

## Supported versions

The latest published version receives security fixes.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Use GitHub's private
vulnerability reporting on this repository (Security → Report a
vulnerability), or email **subhajitpradhan310@gmail.com**.

Please include the affected version, reproduction steps, impact, and any
proof-of-concept. We aim to acknowledge within 72 hours and to ship a fix or
mitigation as fast as practical.

## Scope

In scope:

- the tool leaking connection strings or catalog content it should withhold
- privilege escalation through probe role impersonation
- path traversal or unsafe handling of schema files
- supply-chain issues in published artifacts (verify provenance attestations
  on npm for released versions)

Out of scope:

- findings the tool reports about your database — those are the product
- analysis false negatives or coverage limits; report those as regular
  issues with a fixture

## Design posture

RLS Doctor only queries PostgreSQL catalogs and never mutates the audited
database. `probe` impersonates application roles inside a `begin ... read
only` transaction that is always rolled back. Connection credentials are
redacted from the tool's own errors, and connection strings should be passed
through `DATABASE_URL`/`SUPABASE_DB_URL` rather than flags.
