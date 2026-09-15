import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { BankError, canonicalFields, canonicalJson, sha256 } from "../shared/kernel.mjs";
import { validateState } from "../shared/repository.mjs";

export class ReconciliationService {
  constructor({ repository } = {}) { this.repository = repository; }
  run() {
    const state = this.repository.snapshot(); const findings = [];
    const derived = Object.fromEntries(Object.keys(state.accounts).map((reference) => [reference, 0]));
    for (const journal of Object.values(state.journals)) {
      const sums = {};
      for (const posting of journal.postings) { sums[posting.currency] = (sums[posting.currency] ?? 0) + posting.deltaMinor; derived[posting.accountReference] = (derived[posting.accountReference] ?? 0) + posting.deltaMinor; }
      for (const [currency, sum] of Object.entries(sums)) if (sum !== 0) findings.push({ code: "UNBALANCED_JOURNAL", reference: journal.journalReference, currency, deltaMinor: sum });
    }
    for (const account of Object.values(state.accounts)) if (derived[account.accountReference] !== account.balanceMinor) findings.push({ code: "BALANCE_PROJECTION_MISMATCH", reference: account.accountReference });
    for (const payment of Object.values(state.bniPayments)) if (payment.status === "APPROVED" && !state.journals[payment.transactionReference]) findings.push({ code: "MISSING_PAYMENT_JOURNAL", reference: payment.paymentIntentId });
    let previous = "0".repeat(64);
    for (const event of state.audit) {
      const expected = auditHash(event, previous, canonicalJson(event.details));
      const validHash = event.eventHash === expected || legacyAuditHashMatches(event, previous);
      if (event.previousHash !== previous || !validHash) findings.push({ code: "AUDIT_CHAIN_BROKEN", reference: event.eventId });
      previous = event.eventHash;
    }
    return { status: findings.length ? "FAIL" : "PASS", findings, revision: state.revision, accounts: Object.keys(state.accounts).length, journals: Object.keys(state.journals).length, auditEvents: state.audit.length };
  }
}

function auditHash(event, previous, detailsJson) {
  return sha256(canonicalFields(previous, event.eventId, event.type, event.subjectHash, event.actorHash, event.outcome, event.correlationId, detailsJson, event.occurredAt));
}

function legacyAuditHashMatches(event, previous) {
  const entries = Object.entries(event.details ?? {});
  if (entries.length > 8) return false;
  return permute(entries, 0, (ordered) => event.eventHash === auditHash(event, previous, JSON.stringify(Object.fromEntries(ordered))));
}

function permute(entries, index, matches) {
  if (index >= entries.length) return matches(entries);
  for (let position = index; position < entries.length; position += 1) {
    [entries[index], entries[position]] = [entries[position], entries[index]];
    if (permute(entries, index + 1, matches)) return true;
    [entries[index], entries[position]] = [entries[position], entries[index]];
  }
  return false;
}

export class EncryptedBackupService {
  constructor({ repository, encryptionKey } = {}) { if (!Buffer.isBuffer(encryptionKey) || encryptionKey.length !== 32) throw new BankError("BACKUP_KEY_REQUIRED", 500); this.repository = repository; this.encryptionKey = encryptionKey; }
  create() { const iv = randomBytes(12); const cipher = createCipheriv("aes-256-gcm", this.encryptionKey, iv); const ciphertext = Buffer.concat([cipher.update(JSON.stringify(this.repository.snapshot())), cipher.final()]); return Buffer.concat([Buffer.from("BNIBAK01"), iv, cipher.getAuthTag(), ciphertext]); }
  decrypt(backup) { if (!Buffer.isBuffer(backup) || backup.subarray(0, 8).toString() !== "BNIBAK01") throw new BankError("BACKUP_INVALID"); try { const iv = backup.subarray(8, 20), tag = backup.subarray(20, 36), ciphertext = backup.subarray(36); const decipher = createDecipheriv("aes-256-gcm", this.encryptionKey, iv); decipher.setAuthTag(tag); const snapshot = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8")); validateState(snapshot); return snapshot; } catch (error) { if (error instanceof BankError) throw error; throw new BankError("BACKUP_AUTHENTICATION_FAILED"); } }
  async restore(backup, { requirePristine = true } = {}) { const snapshot = this.decrypt(backup); if (typeof this.repository.replaceSnapshot !== "function") throw new BankError("BACKUP_RESTORE_UNAVAILABLE", 503); await this.repository.replaceSnapshot(snapshot, { requirePristine }); return this.manifest(snapshot); }
  manifest(snapshot = this.repository.snapshot()) { return { format: "BNIBAK01", schemaVersion: snapshot.schemaVersion, revision: snapshot.revision, customers: Object.keys(snapshot.customers).length, devices: Object.keys(snapshot.devices).length, accounts: Object.keys(snapshot.accounts).length, journals: Object.keys(snapshot.journals).length, paymentIntents: Object.keys(snapshot.paymentIntents).length, auditEvents: snapshot.audit.length }; }
}

export class MetricsRegistry {
  constructor() { this.counters = new Map(); this.durations = new Map(); }
  increment(name, labels = "") { const key = `${name}|${labels}`; this.counters.set(key, (this.counters.get(key) ?? 0) + 1); }
  observe(name, milliseconds) { const values = this.durations.get(name) ?? []; values.push(milliseconds); this.durations.set(name, values.slice(-10_000)); }
  snapshot() { return { counters: Object.fromEntries(this.counters), latency: Object.fromEntries([...this.durations].map(([name, values]) => [name, { count: values.length, p95Ms: percentile(values, .95), p99Ms: percentile(values, .99) }])) }; }
}
function percentile(values, quantile) { if (!values.length) return 0; const ordered = [...values].sort((a,b) => a-b); return ordered[Math.min(ordered.length - 1, Math.ceil(ordered.length * quantile) - 1)]; }
