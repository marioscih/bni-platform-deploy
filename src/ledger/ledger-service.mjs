import { BankError, iso, opaqueId, requireMoney, requireOpaque, requireText } from "../shared/kernel.mjs";
import { addAudit, addOutbox } from "../shared/repository.mjs";

const ACCOUNT_TYPES = new Set(["CUSTOMER", "MERCHANT", "SYSTEM"]);

export class LedgerService {
  constructor({ repository, now = () => new Date() } = {}) { this.repository = repository; this.now = now; }

  async createAccount({ accountReference, ownerReference, displayName, type = "CUSTOMER", currency = "EUR", overdraftMinor = 0, allowNegative = false }) {
    return this.repository.transaction((state) => this.createAccountInState(state, { accountReference, ownerReference, displayName, type, currency, overdraftMinor, allowNegative }));
  }

  createAccountInState(state, { accountReference, ownerReference, displayName, type = "CUSTOMER", currency = "EUR", overdraftMinor = 0, allowNegative = false }) {
    requireOpaque(accountReference, "INVALID_ACCOUNT_REFERENCE"); requireOpaque(ownerReference, "INVALID_OWNER_REFERENCE");
    requireText(displayName, "INVALID_ACCOUNT_NAME", 80); requireMoney(0, currency, { allowZero: true });
    if (!ACCOUNT_TYPES.has(type) || !Number.isSafeInteger(overdraftMinor) || overdraftMinor < 0) throw new BankError("INVALID_ACCOUNT_CONFIGURATION");
    if (state.accounts[accountReference]) throw new BankError("ACCOUNT_EXISTS", 409);
    const account = { accountReference, ownerReference, displayName, type, currency, status: "ACTIVE", balanceMinor: 0, overdraftMinor, allowNegative: allowNegative || type === "SYSTEM", createdAt: iso(this.now()) };
    state.accounts[accountReference] = account;
    addAudit(state, { type: "ACCOUNT_CREATED", subjectReference: accountReference, actorReference: ownerReference, outcome: "SUCCESS", details: { type, currency } }, this.now);
    return this.#publicAccount(state, account);
  }

  async postJournal({ journalReference = opaqueId("journal"), idempotencyKey, type, description, postings, correlationId = opaqueId("corr"), metadata = {} }) {
    return this.repository.transaction((state) => this.postJournalInState(state, { journalReference, idempotencyKey, type, description, postings, correlationId, metadata }));
  }

  postJournalInState(state, { journalReference = opaqueId("journal"), idempotencyKey, type, description, postings, correlationId = opaqueId("corr"), metadata = {} }) {
    requireOpaque(journalReference, "INVALID_JOURNAL_REFERENCE"); requireOpaque(idempotencyKey, "INVALID_IDEMPOTENCY_KEY");
    requireText(type, "INVALID_JOURNAL_TYPE", 64); requireText(description, "INVALID_DESCRIPTION", 140);
    const cached = state.ledgerIdempotency[idempotencyKey];
    if (cached) {
      if (cached.fingerprint !== JSON.stringify(postings)) throw new BankError("IDEMPOTENCY_KEY_REUSED", 409);
      return state.journals[cached.journalReference];
    }
    if (!Array.isArray(postings) || postings.length < 2) throw new BankError("INVALID_POSTINGS");
    const sums = new Map(); const deltas = new Map();
    const normalized = postings.map((posting) => {
      const account = state.accounts[requireOpaque(posting.accountReference, "INVALID_ACCOUNT_REFERENCE")];
      if (!account || account.status !== "ACTIVE") throw new BankError("ACCOUNT_NOT_ACTIVE", 409);
      if (!Number.isSafeInteger(posting.deltaMinor) || posting.deltaMinor === 0) throw new BankError("INVALID_POSTING_AMOUNT");
      const currency = posting.currency ?? account.currency;
      if (currency !== account.currency) throw new BankError("ACCOUNT_CURRENCY_MISMATCH");
      sums.set(currency, (sums.get(currency) ?? 0) + posting.deltaMinor);
      deltas.set(account.accountReference, (deltas.get(account.accountReference) ?? 0) + posting.deltaMinor);
      return { postingReference: opaqueId("posting"), accountReference: account.accountReference, deltaMinor: posting.deltaMinor, currency };
    });
    if ([...sums.values()].some((sum) => sum !== 0)) throw new BankError("LEDGER_UNBALANCED");
    for (const [accountReference, delta] of deltas) {
      const account = state.accounts[accountReference];
      const projected = account.balanceMinor + delta;
      const held = this.#heldMinor(state, accountReference);
      if (!account.allowNegative && projected - held < -account.overdraftMinor) throw new BankError("INSUFFICIENT_FUNDS", 409);
    }
    const bookedAt = iso(this.now());
    for (const [accountReference, delta] of deltas) state.accounts[accountReference].balanceMinor += delta;
    const journal = { journalReference, idempotencyKey, type, description, postings: normalized, correlationId, metadata, status: "BOOKED", bookedAt };
    state.journals[journalReference] = journal;
    state.ledgerIdempotency[idempotencyKey] = { journalReference, fingerprint: JSON.stringify(postings) };
    addAudit(state, { type: "JOURNAL_BOOKED", subjectReference: journalReference, outcome: "SUCCESS", correlationId, details: { journalType: type, postingCount: normalized.length } }, this.now);
    addOutbox(state, { type: "JOURNAL_BOOKED", aggregateReference: journalReference, payload: { journalReference, type, accounts: normalized.map((p) => p.accountReference) }, correlationId }, this.now);
    return journal;
  }

  async createHold({ holdReference = opaqueId("hold"), accountReference, amountMinor, currency = "EUR", expiresAt, idempotencyKey }) {
    requireMoney(amountMinor, currency); requireOpaque(accountReference); requireOpaque(holdReference); requireOpaque(idempotencyKey);
    return this.repository.transaction((state) => {
      const key = `hold:${idempotencyKey}`; if (state.idempotency[key]) return state.holds[state.idempotency[key]];
      const account = state.accounts[accountReference]; if (!account || account.status !== "ACTIVE" || account.currency !== currency) throw new BankError("ACCOUNT_NOT_ACTIVE", 409);
      if (this.#availableMinor(state, account) < amountMinor) throw new BankError("INSUFFICIENT_FUNDS", 409);
      const hold = { holdReference, accountReference, amountMinor, currency, status: "ACTIVE", createdAt: iso(this.now()), expiresAt: iso(expiresAt) };
      state.holds[holdReference] = hold; state.idempotency[key] = holdReference;
      return hold;
    });
  }

  async releaseHold({ holdReference, reason = "RELEASED" }) {
    return this.repository.transaction((state) => {
      const hold = state.holds[requireOpaque(holdReference)]; if (!hold) throw new BankError("HOLD_NOT_FOUND", 404);
      if (hold.status === "ACTIVE") { hold.status = reason; hold.releasedAt = iso(this.now()); }
      return hold;
    });
  }

  account(accountReference, requestingOwnerReference) {
    const state = this.repository.snapshot(); const account = state.accounts[requireOpaque(accountReference)];
    if (!account || account.ownerReference !== requestingOwnerReference) throw new BankError("ACCOUNT_NOT_FOUND", 404);
    return this.#publicAccount(state, account);
  }

  accountsForOwner(ownerReference) {
    const state = this.repository.snapshot();
    return Object.values(state.accounts).filter((account) => account.ownerReference === ownerReference && account.status === "ACTIVE").map((account) => this.#publicAccount(state, account));
  }

  movements(accountReference, requestingOwnerReference, { cursor = null, limit = 50 } = {}) {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new BankError("INVALID_PAGE_SIZE");
    const state = this.repository.snapshot(); const account = state.accounts[requireOpaque(accountReference)];
    if (!account || account.ownerReference !== requestingOwnerReference) throw new BankError("ACCOUNT_NOT_FOUND", 404);
    const all = Object.values(state.journals).flatMap((journal) => journal.postings.filter((posting) => posting.accountReference === accountReference).map((posting) => ({
      movementReference: posting.postingReference, transactionReference: journal.journalReference, type: journal.type,
      description: journal.description, amountMinor: posting.deltaMinor, currency: posting.currency,
      status: journal.status, bookedAt: journal.bookedAt, correlationId: journal.correlationId,
    }))).sort((a, b) => b.bookedAt.localeCompare(a.bookedAt) || b.movementReference.localeCompare(a.movementReference));
    const start = cursor ? Math.max(0, all.findIndex((entry) => entry.movementReference === cursor) + 1) : 0;
    const items = all.slice(start, start + limit);
    return { items, nextCursor: start + limit < all.length ? items.at(-1).movementReference : null };
  }

  #heldMinor(state, accountReference) {
    const now = this.now();
    return Object.values(state.holds).filter((hold) => hold.accountReference === accountReference && hold.status === "ACTIVE" && new Date(hold.expiresAt) > now).reduce((sum, hold) => sum + hold.amountMinor, 0);
  }

  #availableMinor(state, account) { return account.balanceMinor - this.#heldMinor(state, account.accountReference) + account.overdraftMinor; }
  #publicAccount(state, account) { return { ...account, availableMinor: this.#availableMinor(state, account) }; }
}
