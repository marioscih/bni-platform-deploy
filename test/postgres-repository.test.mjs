import test from "node:test";
import assert from "node:assert/strict";
import { createPlatform } from "../src/platform.mjs";
import { PostgresBankRepository } from "../src/shared/postgres-repository.mjs";
import { BankRepository } from "../src/shared/repository.mjs";

class MemoryPgPool {
  constructor() { this.state = null; this.revision = 0; this.versions = new Set(); }
  async connect() { return { query: this.query.bind(this), release() {} }; }
  async end() {}
  async query(sql, parameters = []) {
    const normalized = String(sql).replace(/\s+/g, " ").trim();
    if (normalized.startsWith("SELECT pg_advisory_")) return { rowCount: 1, rows: [{}] };
    if (normalized.startsWith("SELECT to_regclass")) return { rowCount: 1, rows: [{ relation: this.versions.size ? "platform_schema_version" : null }] };
    if (normalized === "SELECT version FROM platform_schema_version") return { rowCount: this.versions.size, rows: [...this.versions].map((version) => ({ version })) };
    if (normalized.includes("INSERT INTO platform_schema_version(version)")) {
      const version = Number(normalized.match(/INSERT INTO platform_schema_version\(version\) VALUES \((\d+)\)/)?.[1]);
      if (version) this.versions.add(version);
      return { rowCount: 0, rows: [] };
    }
    if (normalized.startsWith("INSERT INTO platform_state_store")) {
      if (this.state == null) { this.state = JSON.parse(parameters[0]); this.revision = 0; }
      return { rowCount: this.state == null ? 0 : 1, rows: [] };
    }
    if (normalized.startsWith("SELECT revision, state FROM platform_state_store")) {
      return this.state == null ? { rowCount: 0, rows: [] } : { rowCount: 1, rows: [{ revision: String(this.revision), state: structuredClone(this.state) }] };
    }
    if (normalized.startsWith("UPDATE platform_state_store")) {
      this.revision = Number(parameters[0]); this.state = JSON.parse(parameters[1]); return { rowCount: 1, rows: [] };
    }
    if (["BEGIN", "COMMIT", "ROLLBACK", "SELECT 1"].includes(normalized)) return { rowCount: 1, rows: [{}] };
    throw new Error(`Unexpected SQL in memory test double: ${normalized.slice(0, 80)}`);
  }
}

test("PostgreSQL repository migrates, commits and survives a new repository instance", async () => {
  const pool = new MemoryPgPool();
  const first = await new PostgresBankRepository({ pool }).initialize();
  await first.transaction((state) => { state.customers.customer_alpha = { customerReference: "customer_alpha", status: "ACTIVE" }; });
  assert.equal(first.snapshot().revision, 1);
  assert.deepEqual([...pool.versions], [1, 2, 3, 4, 5]);

  const second = await new PostgresBankRepository({ pool }).initialize();
  assert.equal(second.snapshot().customers.customer_alpha.status, "ACTIVE");
  assert.equal(second.snapshot().revision, 1);
});

test("PostgreSQL repository restores an authoritative snapshot only while pristine", async () => {
  const source = new BankRepository();
  await source.transaction((state) => { state.customers.customer_restored = { customerReference: "customer_restored", status: "ACTIVE" }; });
  const pool = new MemoryPgPool(); const target = await new PostgresBankRepository({ pool }).initialize();
  await target.replaceSnapshot(source.snapshot());
  assert.equal(target.snapshot().customers.customer_restored.status, "ACTIVE"); assert.equal(target.snapshot().revision, 1);
  await assert.rejects(() => target.replaceSnapshot(source.snapshot()), (error) => error.code === "BACKUP_DESTINATION_NOT_EMPTY");
});

test("PostgreSQL-backed ledger serializes concurrent debits and prevents double spend", async () => {
  const repository = await new PostgresBankRepository({ pool: new MemoryPgPool() }).initialize();
  const platform = createPlatform({ repository, tokenSigningKey: Buffer.alloc(32, 7), activationPepper: "postgres-test-pepper-long-enough" });
  await platform.ledger.createAccount({ accountReference: "system_funding", ownerReference: "system_owner", displayName: "Funding", type: "SYSTEM", overdraftMinor: 1000 });
  await platform.ledger.createAccount({ accountReference: "account_customer", ownerReference: "customer_alpha", displayName: "Customer", type: "CUSTOMER" });
  await platform.ledger.createAccount({ accountReference: "account_target_a", ownerReference: "customer_beta", displayName: "Target A", type: "CUSTOMER" });
  await platform.ledger.createAccount({ accountReference: "account_target_b", ownerReference: "customer_gamma", displayName: "Target B", type: "CUSTOMER" });
  await platform.ledger.postJournal({ idempotencyKey: "funding_customer", type: "FUNDING", description: "Funding", postings: [{ accountReference: "system_funding", deltaMinor: -100 }, { accountReference: "account_customer", deltaMinor: 100 }] });
  const attempts = await Promise.allSettled([
    platform.ledger.postJournal({ idempotencyKey: "debit_attempt_a", type: "TRANSFER", description: "A", postings: [{ accountReference: "account_customer", deltaMinor: -80 }, { accountReference: "account_target_a", deltaMinor: 80 }] }),
    platform.ledger.postJournal({ idempotencyKey: "debit_attempt_b", type: "TRANSFER", description: "B", postings: [{ accountReference: "account_customer", deltaMinor: -80 }, { accountReference: "account_target_b", deltaMinor: 80 }] }),
  ]);
  assert.equal(attempts.filter((entry) => entry.status === "fulfilled").length, 1);
  assert.equal(attempts.filter((entry) => entry.status === "rejected" && entry.reason.code === "INSUFFICIENT_FUNDS").length, 1);
  assert.equal(platform.ledger.account("account_customer", "customer_alpha").balanceMinor, 20);
});
