# BNI Platform v2 — deployment mirror

This repository contains only the deployable Node.js/PostgreSQL backend boundary used by the BNI Home Banking v2 pilot environment.

It intentionally excludes Android sources, signing material, activation credentials, runtime secrets, local state and release artifacts. Runtime secrets are injected by the hosting platform.

## Runtime

- Node.js 22+
- PostgreSQL 18
- `npm ci --omit=dev --ignore-scripts`
- `npm start`
- readiness endpoint: `/health/ready`

