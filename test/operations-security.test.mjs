import test from "node:test";
import assert from "node:assert/strict";
import { BankRepository, addAudit } from "../src/shared/repository.mjs";
import { LedgerService } from "../src/ledger/ledger-service.mjs";
import { EncryptedBackupService, MetricsRegistry, ReconciliationService } from "../src/audit-operations/operations-service.mjs";
import { RuleRiskEngine } from "../src/fraud-compliance/risk-engine.mjs";

test("audit chain and ledger projections reconcile", async () => {
  const repository = new BankRepository(); const ledger = new LedgerService({ repository });
  await ledger.createAccount({ accountReference: "system_funding", ownerReference: "owner_system", displayName: "Funding", type: "SYSTEM" });
  await ledger.createAccount({ accountReference: "account_alpha", ownerReference: "customer_alpha", displayName: "Conto", type: "CUSTOMER" });
  await ledger.postJournal({ idempotencyKey: "opening_alpha_001", type: "OPENING", description: "Opening", postings: [{ accountReference: "system_funding", deltaMinor: -1000 }, { accountReference: "account_alpha", deltaMinor: 1000 }] });
  assert.equal(new ReconciliationService({ repository }).run().status, "PASS");
});

test("audit tampering is detected", async () => {
  const snapshot = new BankRepository().snapshot(); addAudit(snapshot, { type: "SECURITY_EVENT", subjectReference: "subject_alpha", outcome: "SUCCESS" }); snapshot.audit[0].outcome = "ALTERED";
  const repository = new BankRepository({ snapshot }); assert.equal(new ReconciliationService({ repository }).run().findings[0].code, "AUDIT_CHAIN_BROKEN");
});

test("backup is authenticated and tampering fails closed", async () => {
  const repository = new BankRepository(); const service = new EncryptedBackupService({ repository, encryptionKey: Buffer.alloc(32, 8) }); const backup = service.create();
  assert.equal(service.decrypt(backup).schemaVersion, 1); const tampered = Buffer.from(backup); tampered[tampered.length - 1] ^= 1; assert.throws(() => service.decrypt(tampered), /BACKUP_AUTHENTICATION_FAILED/);
});

test("encrypted backup restores the complete state only into a pristine repository", async () => {
  const source = new BankRepository(); const sourceLedger = new LedgerService({ repository: source });
  await sourceLedger.createAccount({ accountReference: "system_backup", ownerReference: "owner_system", displayName: "Backup funding", type: "SYSTEM" });
  await sourceLedger.createAccount({ accountReference: "account_backup", ownerReference: "customer_backup", displayName: "Conto", type: "CUSTOMER" });
  await sourceLedger.postJournal({ idempotencyKey: "backup_funding_001", type: "OPENING", description: "Opening", postings: [{ accountReference: "system_backup", deltaMinor: -2500 }, { accountReference: "account_backup", deltaMinor: 2500 }] });
  const key = Buffer.alloc(32, 9); const backup = new EncryptedBackupService({ repository: source, encryptionKey: key }).create();
  const target = new BankRepository(); const service = new EncryptedBackupService({ repository: target, encryptionKey: key });
  const manifest = await service.restore(backup);
  assert.equal(manifest.journals, 1); assert.equal(target.snapshot().accounts.account_backup.balanceMinor, 2500); assert.deepEqual(target.snapshot(), source.snapshot());
  await assert.rejects(() => service.restore(backup), (error) => error.code === "BACKUP_DESTINATION_NOT_EMPTY");
});

test("risk engine enforces limits, velocity and device integrity", () => {
  const now = () => new Date("2026-09-13T15:00:00Z"); const engine = new RuleRiskEngine({ now, paymentVelocityCount: 1 });
  const state = { devices: { device_alpha: { attestationVerdict: "UNTRUSTED" } }, bniPayments: {} };
  assert.equal(engine.evaluate({ operation: "BNI_PAY", customerReference: "customer_alpha", deviceReference: "device_alpha", amountMinor: 100 }, state).decision, "DENY");
  assert.equal(engine.evaluate({ operation: "TRANSFER", customerReference: "customer_alpha", amountMinor: 3_000_000 }, state).reasons.includes("SINGLE_TRANSFER_LIMIT"), true);
});

test("metrics calculate bounded p95 and p99", () => { const metrics = new MetricsRegistry(); for (let i=1;i<=100;i++) metrics.observe("api", i); metrics.increment("requests", "status=200"); const snapshot = metrics.snapshot(); assert.equal(snapshot.latency.api.p95Ms, 95); assert.equal(snapshot.latency.api.p99Ms, 99); assert.equal(snapshot.counters["requests|status=200"], 1); });
