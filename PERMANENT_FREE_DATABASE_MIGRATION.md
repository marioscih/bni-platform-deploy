# BNI platform — portable database continuity

## Decision

Keep the existing public API origin and replace only the expiring managed
PostgreSQL instance with a free PostgreSQL service that has no fixed 30-day
database expiry. Mobile applications keep the same HTTPS origin and do not
require reinstalling for this infrastructure change.

No third-party free plan is a contractual lifetime guarantee. The platform
therefore provides an authenticated, provider-portable encrypted backup and a
fail-closed restore path so that the ledger can be moved again without changing
the mobile client.

## Safety properties

- `GET /v2/admin/backup` requires the constant-time checked admin token.
- Complete platform state is encrypted with AES-256-GCM under a dedicated
  backup secret and returned with a SHA-256 transport checksum.
- Backup creation runs ledger and audit-chain reconciliation.
- `POST /v2/admin/restore` verifies the checksum, authenticated encryption,
  schema and ledger invariants.
- Restore is rejected unless the destination state store is pristine.
- Runtime secrets and customer data are never committed to source control.

## Cutover runbook

1. Configure a dedicated `BNI_BACKUP_ENCRYPTION_SECRET` of at least 32 random
   bytes and deploy the backup-enabled backend.
2. Export the active state and require reconciliation `PASS`.
3. Initialize the destination PostgreSQL schema using the tracked migrations.
4. Replace only `DATABASE_URL`; retain existing signing, activation and
   administrative secrets.
5. Wait for `/health/ready` to return `READY`.
6. Restore the encrypted backup exactly once.
7. Verify reconciliation, manifest counts, balances, movement history,
   customer authentication and merchant-terminal state.
8. Retain the source database untouched during the validation window.

## Operating limits

- Free-provider quotas and terms must be monitored.
- A scale-to-zero database or web service can make the first request after
  inactivity slower.
- Regulated production requires paid high availability, formal backup
  retention, alerting, incident response and audited recovery exercises.
