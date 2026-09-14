BEGIN;

CREATE TABLE platform_schema_version (
  version integer PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam_customer (
  customer_reference text PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED')),
  created_at timestamptz NOT NULL
);

CREATE TABLE iam_device (
  device_reference text PRIMARY KEY,
  customer_reference text NOT NULL REFERENCES iam_customer(customer_reference),
  public_key_spki bytea NOT NULL,
  app_instance_reference text NOT NULL UNIQUE,
  status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','REVOKED','LOST')),
  attestation_verdict text NOT NULL,
  enrolled_at timestamptz NOT NULL,
  updated_at timestamptz
);

CREATE TABLE ledger_account (
  account_reference text PRIMARY KEY,
  owner_reference text NOT NULL,
  display_name text NOT NULL,
  account_type text NOT NULL CHECK (account_type IN ('CUSTOMER','MERCHANT','SYSTEM')),
  currency char(3) NOT NULL,
  status text NOT NULL CHECK (status IN ('ACTIVE','SUSPENDED','CLOSED')),
  overdraft_minor bigint NOT NULL DEFAULT 0 CHECK (overdraft_minor >= 0),
  allow_negative boolean NOT NULL DEFAULT false,
  version bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL
);

CREATE TABLE ledger_journal (
  journal_reference text PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  journal_type text NOT NULL,
  description text NOT NULL,
  correlation_id text NOT NULL,
  status text NOT NULL CHECK (status IN ('BOOKED','REVERSED')),
  booked_at timestamptz NOT NULL
);

CREATE TABLE ledger_posting (
  posting_reference text PRIMARY KEY,
  journal_reference text NOT NULL REFERENCES ledger_journal(journal_reference),
  account_reference text NOT NULL REFERENCES ledger_account(account_reference),
  delta_minor bigint NOT NULL CHECK (delta_minor <> 0),
  currency char(3) NOT NULL
);

CREATE TABLE platform_outbox (
  event_id text PRIMARY KEY,
  event_type text NOT NULL,
  aggregate_reference text NOT NULL,
  payload jsonb NOT NULL,
  correlation_id text NOT NULL,
  occurred_at timestamptz NOT NULL,
  status text NOT NULL CHECK (status IN ('PENDING','PROCESSING','DELIVERED','DEAD')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL,
  delivered_at timestamptz
);

CREATE TABLE compliance_audit_event (
  event_id text PRIMARY KEY,
  event_type text NOT NULL,
  subject_hash text NOT NULL,
  actor_hash text NOT NULL,
  outcome text NOT NULL,
  correlation_id text NOT NULL,
  details jsonb NOT NULL,
  occurred_at timestamptz NOT NULL
);

CREATE INDEX idx_posting_account ON ledger_posting(account_reference, posting_reference);
CREATE INDEX idx_outbox_delivery ON platform_outbox(status, next_attempt_at);
CREATE INDEX idx_audit_correlation ON compliance_audit_event(correlation_id, occurred_at);

INSERT INTO platform_schema_version(version) VALUES (1);
COMMIT;
