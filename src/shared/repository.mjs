import { AsyncMutex, BankError, canonicalFields, canonicalJson, clone, iso, opaqueId, publicHash, sha256 } from "./kernel.mjs";

export function emptyState() {
  return {
    schemaVersion: 1,
    revision: 0,
    customers: {}, activations: {}, devices: {}, challenges: {}, sessions: {}, refreshTokens: {},
    accounts: {}, journals: {}, ledgerIdempotency: {}, holds: {},
    beneficiaries: {}, transferQuotes: {}, transfers: {},
    inbox: {}, notificationPreferences: {}, documents: {},
    billQuotes: {}, billPayments: {},
    cards: {}, walletTokens: {},
    merchants: {}, terminals: {}, terminalEnrollments: {}, paymentIntents: {}, bniPayments: {}, refunds: {},
    idempotency: {}, replayNonces: {}, riskCounters: {},
    outbox: {}, audit: [], cases: {},
  };
}

export class BankRepository {
  #mutex = new AsyncMutex();
  #state;
  #afterCommit;

  constructor({ snapshot = null, afterCommit = async () => {} } = {}) {
    this.#state = snapshot ? { ...emptyState(), ...clone(snapshot) } : emptyState();
    this.#afterCommit = afterCommit;
  }

  read(operation = (state) => state) {
    return clone(operation(this.#state));
  }

  snapshot() {
    return clone(this.#state);
  }

  async transaction(operation) {
    return this.#mutex.runExclusive(async () => {
      const draft = clone(this.#state);
      const result = await operation(draft);
      validateState(draft);
      draft.revision += 1;
      await this.#afterCommit(clone(draft));
      this.#state = draft;
      return clone(result);
    });
  }

  async replaceSnapshot(snapshot, { requirePristine = true } = {}) {
    return this.#mutex.runExclusive(async () => {
      if (requirePristine && !isPristineState(this.#state)) throw new BankError("BACKUP_DESTINATION_NOT_EMPTY", 409);
      const next = { ...emptyState(), ...clone(snapshot) };
      validateState(next);
      if (!Number.isSafeInteger(next.revision) || next.revision < 0) throw new BankError("DATABASE_REVISION_INVALID", 500);
      await this.#afterCommit(clone(next));
      this.#state = next;
      return { revision: next.revision };
    });
  }

}

export function isPristineState(state) {
  if (!state || state.revision !== 0) return false;
  return Object.entries(state).every(([key, value]) => {
    if (key === "schemaVersion" || key === "revision") return true;
    if (Array.isArray(value)) return value.length === 0;
    return value && typeof value === "object" ? Object.keys(value).length === 0 : false;
  });
}

export function validateState(state) {
  for (const journal of Object.values(state.journals)) {
    const sums = new Map();
    for (const posting of journal.postings) {
      sums.set(posting.currency, (sums.get(posting.currency) ?? 0) + posting.deltaMinor);
    }
    if ([...sums.values()].some((sum) => sum !== 0)) throw new BankError("LEDGER_UNBALANCED", 500);
  }
  for (const account of Object.values(state.accounts)) {
    if (!Number.isSafeInteger(account.balanceMinor)) throw new BankError("LEDGER_CORRUPTED", 500);
  }
}

export function addAudit(state, { type, subjectReference, actorReference = "system", outcome, correlationId, details = {} }, now = () => new Date()) {
  const forbidden = /token|password|secret|pan|cvc|iban|signature|publicKey/i;
  const safeDetails = Object.fromEntries(Object.entries(details).filter(([key]) => !forbidden.test(key)));
  const event = {
    eventId: opaqueId("audit"), type,
    subjectHash: publicHash(subjectReference), actorHash: publicHash(actorReference),
    outcome, correlationId: correlationId ?? opaqueId("corr"), details: safeDetails,
    occurredAt: iso(now()),
  };
  event.previousHash = state.audit.at(-1)?.eventHash ?? "0".repeat(64);
  event.eventHash = sha256(canonicalFields(event.previousHash, event.eventId, event.type, event.subjectHash, event.actorHash, event.outcome, event.correlationId, canonicalJson(event.details), event.occurredAt));
  state.audit.push(event);
  return event;
}

export function addOutbox(state, { type, aggregateReference, payload, correlationId }, now = () => new Date()) {
  const event = {
    eventId: opaqueId("evt"), type, aggregateReference, payload: clone(payload),
    correlationId: correlationId ?? opaqueId("corr"), occurredAt: iso(now()),
    status: "PENDING", attempts: 0, nextAttemptAt: iso(now()), deliveredAt: null,
  };
  state.outbox[event.eventId] = event;
  return event;
}
