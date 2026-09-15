# BNI Platform v2 — deployment mirror

This repository contains only the deployable Node.js/PostgreSQL backend boundary used by the BNI Home Banking v2 pilot environment.

It intentionally excludes Android sources, signing material, activation credentials, runtime secrets, local state and release artifacts. Runtime secrets are injected by the hosting platform.

## Runtime

- Node.js 22+
- PostgreSQL 18
- `npm ci --omit=dev --ignore-scripts`
- `npm start`
- readiness endpoint: `/health/ready`
- authenticated encrypted export: `GET /v2/admin/backup`
- fail-closed pristine-database restore: `POST /v2/admin/restore`

Production additionally requires `BNI_BACKUP_ENCRYPTION_SECRET` with at least
32 random bytes. See `PERMANENT_FREE_DATABASE_MIGRATION.md` for the portable
database cutover runbook.
