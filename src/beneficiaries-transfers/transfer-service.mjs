import { BankError, iso, opaqueId, requireMoney, requireOpaque, requireText } from "../shared/kernel.mjs";
import { addAudit, addOutbox } from "../shared/repository.mjs";

export function normalizeIban(value) { return String(value ?? "").replaceAll(/\s/g, "").toUpperCase(); }
export function validIban(value) {
  const iban = normalizeIban(value);
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const digits = /[A-Z]/.test(char) ? String(char.charCodeAt(0) - 55) : char;
    for (const digit of digits) remainder = (remainder * 10 + Number(digit)) % 97;
  }
  return remainder === 1;
}

export function italianBankCoordinates(iban) {
  const normalized = normalizeIban(iban);
  if (!validIban(normalized) || !normalized.startsWith("IT") || normalized.length !== 27) return null;
  return { cin: normalized.slice(4, 5), abi: normalized.slice(5, 10), cab: normalized.slice(10, 15), accountFragment: normalized.slice(-4) };
}

function businessDate(start, days) {
  const value = new Date(start); let remaining = days;
  while (remaining > 0) { value.setUTCDate(value.getUTCDate() + 1); if (value.getUTCDay() !== 0 && value.getUTCDay() !== 6) remaining -= 1; }
  return value.toISOString().slice(0, 10);
}

export class BankDirectory {
  constructor(records = {}) { this.records = { ...records }; }
  lookup(abi) { const value = this.records[abi]; return value ? { abi, bankName: value, source: "CONFIGURED_DIRECTORY", accountExistenceVerified: false } : { abi, bankName: null, source: "UNAVAILABLE", accountExistenceVerified: false }; }
}

export class UnavailableSepaAdapter {
  configured = false;
  async quote() { throw new BankError("SEPA_ADAPTER_NOT_CONFIGURED", 503, true); }
  async submit() { throw new BankError("SEPA_ADAPTER_NOT_CONFIGURED", 503, true); }
}

/** Closed-loop adapter for the explicitly enabled BNI simulator runtime. */
export class SimulatorSepaAdapter {
  configured = true;
  constructor({ clearingAccountReference = "system_sepa_simulator", now = () => new Date() } = {}) {
    this.clearingAccountReference = clearingAccountReference;
    this.now = now;
  }
  async quote({ amountMinor, currency }) {
    if (!Number.isSafeInteger(amountMinor) || amountMinor <= 0 || currency !== "EUR") throw new BankError("SEPA_PROVIDER_INVALID_REQUEST");
    return {
      feeMinor: 0,
      executionDate: this.now().toISOString().slice(0, 10),
      valueDate: businessDate(this.now(), 2),
      providerQuoteReference: opaqueId("simsepaquote"),
    };
  }
  async submit({ transferReference }) {
    return { status: "ACCEPTED", providerTransactionReference: `SIM-${transferReference}` };
  }
}

/** Boundary for an authorised sponsor-bank/PSP implementation. Credentials stay in the adapter runtime. */
export class AuthorizedSepaAdapter {
  configured = true;
  constructor({ quote, submit, clearingAccountReference }) {
    if (typeof quote !== "function" || typeof submit !== "function" || !clearingAccountReference) throw new TypeError("Incomplete SEPA adapter");
    this.quoteOperation = quote; this.submitOperation = submit; this.clearingAccountReference = clearingAccountReference;
  }
  quote(input) { return this.quoteOperation(input); }
  submit(input) { return this.submitOperation(input); }
}

export class TransferService {
  constructor({ repository, ledger, identity, documents, bankDirectory = new BankDirectory(), sepaAdapter = new UnavailableSepaAdapter(), riskEngine = { evaluate: () => ({ decision: "ALLOW", reasons: [] }) }, now = () => new Date(), quoteTtlMs = 180_000 } = {}) {
    Object.assign(this, { repository, ledger, identity, documents, bankDirectory, sepaAdapter, riskEngine, now, quoteTtlMs });
  }

  #resolveInternal(state, normalizedIban, explicitReference = null) {
    if (explicitReference) {
      const account = state.accounts[requireOpaque(explicitReference)];
      if (!account || account.status !== "ACTIVE") throw new BankError("DESTINATION_ACCOUNT_NOT_FOUND", 404);
      if (normalizedIban && account.iban && normalizeIban(account.iban) !== normalizedIban) throw new BankError("DESTINATION_ACCOUNT_MISMATCH", 409);
      return account.accountReference;
    }
    if (!normalizedIban) return null;
    return Object.values(state.accounts).find((account) => account.status === "ACTIVE" && account.iban && normalizeIban(account.iban) === normalizedIban)?.accountReference ?? null;
  }

  #upsertBeneficiaryInState(state, { ownerReference, beneficiaryReference = opaqueId("beneficiary"), displayName, iban, internalAccountReference = null, idempotencyKey = null }) {
    requireOpaque(ownerReference); requireText(displayName, "INVALID_BENEFICIARY_NAME", 100);
    const normalized = normalizeIban(iban);
    if (!internalAccountReference && !validIban(normalized)) throw new BankError("INVALID_IBAN");
    const resolvedInternal = this.#resolveInternal(state, normalized, internalAccountReference);
    const natural = Object.values(state.beneficiaries).find((item) => item.ownerReference === ownerReference && item.status === "ACTIVE" && item.iban === (normalized || null));
    const idem = idempotencyKey ? `beneficiary:${ownerReference}:${requireOpaque(idempotencyKey)}` : null;
    if (idem && state.idempotency[idem]) return state.beneficiaries[state.idempotency[idem]];
    if (natural) {
      natural.displayName = displayName;
      if (resolvedInternal) natural.internalAccountReference = resolvedInternal;
      natural.updatedAt = iso(this.now());
      if (idem) state.idempotency[idem] = natural.beneficiaryReference;
      return natural;
    }
    requireOpaque(beneficiaryReference);
    if (state.beneficiaries[beneficiaryReference]) throw new BankError("BENEFICIARY_EXISTS", 409);
    const coordinates = normalized ? italianBankCoordinates(normalized) : null;
    const beneficiary = {
      beneficiaryReference, ownerReference, displayName, iban: normalized || null,
      internalAccountReference: resolvedInternal, bankCoordinates: coordinates,
      bankDirectory: coordinates ? this.bankDirectory.lookup(coordinates.abi) : null,
      verificationOfPayee: "UNAVAILABLE", status: "ACTIVE", createdAt: iso(this.now()),
    };
    state.beneficiaries[beneficiaryReference] = beneficiary;
    if (idem) state.idempotency[idem] = beneficiaryReference;
    addAudit(state, { type: "BENEFICIARY_CREATED", subjectReference: beneficiaryReference, actorReference: ownerReference, outcome: "SUCCESS", details: { vop: beneficiary.verificationOfPayee } }, this.now);
    return beneficiary;
  }

  async addBeneficiary(input) { return this.repository.transaction((state) => this.#upsertBeneficiaryInState(state, input)); }

  async #quoteTerms({ beneficiary, amountMinor, currency, description, execution }) {
    if (beneficiary.internalAccountReference) return { feeMinor: 0, executionDate: this.now().toISOString().slice(0, 10), valueDate: businessDate(this.now(), 2), rail: "BNI_INTERNAL", providerQuoteReference: null };
    if (!this.sepaAdapter.configured) throw new BankError("SEPA_ADAPTER_NOT_CONFIGURED", 503, true);
    const result = await this.sepaAdapter.quote({ beneficiaryIban: beneficiary.iban, beneficiaryName: beneficiary.displayName, amountMinor, currency, description, execution });
    if (!result || !Number.isSafeInteger(result.feeMinor) || result.feeMinor < 0 || !/^\d{4}-\d{2}-\d{2}$/.test(result.executionDate) || !/^\d{4}-\d{2}-\d{2}$/.test(result.valueDate) || !result.providerQuoteReference) throw new BankError("SEPA_PROVIDER_INVALID_RESPONSE", 502, true);
    return { ...result, rail: "SEPA" };
  }

  #createQuoteInState(state, { customerReference, sourceAccountReference, beneficiaryReference, amountMinor, currency, description, execution, idempotencyKey, terms }) {
    const idem = `transfer-quote:${idempotencyKey}`; if (state.idempotency[idem]) return state.transferQuotes[state.idempotency[idem]];
    const account = state.accounts[sourceAccountReference]; const beneficiary = state.beneficiaries[beneficiaryReference];
    if (!account || account.ownerReference !== customerReference || account.status !== "ACTIVE") throw new BankError("ACCOUNT_NOT_FOUND", 404);
    if (!beneficiary || beneficiary.ownerReference !== customerReference || beneficiary.status !== "ACTIVE") throw new BankError("BENEFICIARY_NOT_FOUND", 404);
    if (account.currency !== currency) throw new BankError("ACCOUNT_CURRENCY_MISMATCH");
    const quoteReference = opaqueId("quote");
    const quote = {
      quoteReference, customerReference, sourceAccountReference, beneficiaryReference,
      counterpartyReference: beneficiary.beneficiaryReference, amountMinor, feeMinor: terms.feeMinor,
      totalDebitMinor: amountMinor + terms.feeMinor, currency, description, execution,
      executionDate: terms.executionDate, valueDate: terms.valueDate, rail: terms.rail,
      providerQuoteReference: terms.providerQuoteReference, status: "QUOTED",
      createdAt: iso(this.now()), expiresAt: iso(new Date(this.now().getTime() + this.quoteTtlMs)), idempotencyKey,
      beneficiary: { displayName: beneficiary.displayName, iban: beneficiary.iban, bankCoordinates: beneficiary.bankCoordinates, bankDirectory: beneficiary.bankDirectory },
    };
    state.transferQuotes[quoteReference] = quote; state.idempotency[idem] = quoteReference;
    return quote;
  }

  async createQuote({ customerReference, sourceAccountReference, beneficiaryReference, amountMinor, currency = "EUR", description, execution = "IMMEDIATE", idempotencyKey }) {
    requireMoney(amountMinor, currency); requireText(description, "INVALID_TRANSFER_DESCRIPTION", 140); requireOpaque(idempotencyKey);
    if (execution !== "IMMEDIATE") throw new BankError("EXECUTION_MODE_NOT_AVAILABLE", 409);
    const beneficiary = this.repository.snapshot().beneficiaries[beneficiaryReference];
    if (!beneficiary || beneficiary.ownerReference !== customerReference) throw new BankError("BENEFICIARY_NOT_FOUND", 404);
    const terms = await this.#quoteTerms({ beneficiary, amountMinor, currency, description, execution });
    return this.repository.transaction((state) => this.#createQuoteInState(state, { customerReference, sourceAccountReference, beneficiaryReference, amountMinor, currency, description, execution, idempotencyKey, terms }));
  }

  /** Atomic prepare prevents orphan beneficiaries when resolution or provider pricing fails. */
  async prepare({ customerReference, sourceAccountReference, displayName, iban, amountMinor, currency = "EUR", description, execution = "IMMEDIATE", idempotencyKey }) {
    requireMoney(amountMinor, currency); requireText(description, "INVALID_TRANSFER_DESCRIPTION", 140); requireOpaque(idempotencyKey);
    if (execution !== "IMMEDIATE") throw new BankError("EXECUTION_MODE_NOT_AVAILABLE", 409);
    const preview = this.repository.snapshot(); const normalized = normalizeIban(iban);
    if (!validIban(normalized)) throw new BankError("INVALID_IBAN");
    const internalAccountReference = this.#resolveInternal(preview, normalized);
    const coordinates = italianBankCoordinates(normalized);
    const provisional = { displayName, iban: normalized, internalAccountReference, bankCoordinates: coordinates, bankDirectory: coordinates ? this.bankDirectory.lookup(coordinates.abi) : null };
    const terms = await this.#quoteTerms({ beneficiary: provisional, amountMinor, currency, description, execution });
    return this.repository.transaction((state) => {
      const existing = state.idempotency[`transfer-prepare:${idempotencyKey}`];
      if (existing) return { beneficiary: state.beneficiaries[existing.beneficiaryReference], quote: state.transferQuotes[existing.quoteReference] };
      const beneficiary = this.#upsertBeneficiaryInState(state, { ownerReference: customerReference, displayName, iban: normalized, internalAccountReference, idempotencyKey });
      const quote = this.#createQuoteInState(state, { customerReference, sourceAccountReference, beneficiaryReference: beneficiary.beneficiaryReference, amountMinor, currency, description, execution, idempotencyKey, terms });
      state.idempotency[`transfer-prepare:${idempotencyKey}`] = { beneficiaryReference: beneficiary.beneficiaryReference, quoteReference: quote.quoteReference };
      return { beneficiary, quote };
    });
  }

  createScaChallenge({ quoteReference, deviceReference }) {
    const quote = this.repository.snapshot().transferQuotes[requireOpaque(quoteReference)];
    if (!quote || quote.status !== "QUOTED" || new Date(quote.expiresAt) <= this.now()) throw new BankError("QUOTE_NOT_AUTHORIZABLE", 409);
    return this.identity.createScaChallenge({ customerReference: quote.customerReference, deviceReference, operation: "TRANSFER", accountReference: quote.sourceAccountReference, counterpartyReference: quote.beneficiaryReference, amountMinor: quote.totalDebitMinor, currency: quote.currency, operationReference: quote.quoteReference, riskContext: "STANDARD", idempotencyKey: quote.idempotencyKey });
  }

  #transferRecord(quote, beneficiary, transferReference, correlationId, status, provider = {}) {
    return { transferReference, quoteReference: quote.quoteReference, customerReference: quote.customerReference, sourceAccountReference: quote.sourceAccountReference, beneficiaryReference: quote.beneficiaryReference, beneficiaryName: beneficiary.displayName, beneficiaryIban: beneficiary.iban, beneficiaryBank: beneficiary.bankDirectory?.bankName ?? null, bankCoordinates: beneficiary.bankCoordinates, amountMinor: quote.amountMinor, feeMinor: quote.feeMinor, totalDebitMinor: quote.totalDebitMinor, currency: quote.currency, description: quote.description, rail: quote.rail, executionDate: quote.executionDate, valueDate: quote.valueDate, status, correlationId, authorizedAt: iso(this.now()), ...provider };
  }

  #receipt(state, transfer, journalReference = null) {
    const account = state.accounts[transfer.sourceAccountReference];
    const fields = [["Ordinante", account?.holderName ?? account?.displayName], ["IBAN ordinante", account?.iban ?? ""], ["Beneficiario", transfer.beneficiaryName], ["IBAN beneficiario", transfer.beneficiaryIban ?? "Conto BNI"], ["Banca beneficiaria", transfer.beneficiaryBank ?? (transfer.rail === "BNI_INTERNAL" ? "BNI" : "")], ["Importo", `${(transfer.amountMinor / 100).toFixed(2)} ${transfer.currency}`], ["Commissione", `${(transfer.feeMinor / 100).toFixed(2)} ${transfer.currency}`], ["Totale", `${(transfer.totalDebitMinor / 100).toFixed(2)} ${transfer.currency}`], ["Causale", transfer.description], ["Stato", transfer.status], ["Data esecuzione", transfer.executionDate], ["Data valuta", transfer.valueDate], ["TRN", journalReference ?? transfer.providerTransactionReference ?? transfer.transferReference], ["Canale", transfer.rail], ["Data autorizzazione", transfer.authorizedAt], ["Correlazione", transfer.correlationId]];
    return this.documents.createReceiptInState(state, { ownerReference: transfer.customerReference, operationReference: transfer.transferReference, type: "TRANSFER_RECEIPT", title: "Distinta bonifico", correlationId: transfer.correlationId, fields });
  }

  async authorize({ quoteReference, challengeId, signature, idempotencyKey }) {
    const initial = await this.repository.transaction((state) => {
      const idem = `transfer-authorize:${requireOpaque(idempotencyKey)}`;
      if (state.idempotency[idem]) return { cached: true, transfer: state.transfers[state.idempotency[idem]] };
      const quote = state.transferQuotes[requireOpaque(quoteReference)];
      if (!quote || quote.status !== "QUOTED" || new Date(quote.expiresAt) <= this.now()) throw new BankError("QUOTE_NOT_AUTHORIZABLE", 409);
      this.identity.verifyScaInState(state, { challengeId, signature, expected: { operation: "TRANSFER", accountReference: quote.sourceAccountReference, counterpartyReference: quote.beneficiaryReference, amountMinor: quote.totalDebitMinor, currency: quote.currency, operationReference: quote.quoteReference, idempotencyKey: quote.idempotencyKey } });
      const beneficiary = state.beneficiaries[quote.beneficiaryReference];
      const risk = this.riskEngine.evaluate({ operation: "TRANSFER", customerReference: quote.customerReference, counterpartyReference: quote.beneficiaryReference, amountMinor: quote.totalDebitMinor, currency: quote.currency }, state);
      if (risk.decision !== "ALLOW") throw new BankError("TRANSFER_DECLINED_BY_RISK", 409);
      const transferReference = opaqueId("transfer"); const correlationId = opaqueId("corr");
      if (quote.rail === "SEPA") {
        const transfer = this.#transferRecord(quote, beneficiary, transferReference, correlationId, "PENDING"); state.transfers[transferReference] = transfer; state.idempotency[idem] = transferReference; quote.status = "CONSUMED";
        addAudit(state, { type: "TRANSFER_SUBMISSION_PENDING", subjectReference: transferReference, actorReference: quote.customerReference, outcome: "PENDING", correlationId }, this.now);
        return { cached: false, external: true, transfer };
      }
      const journal = this.ledger.postJournalInState(state, { idempotencyKey: `ledger_${idempotencyKey}`, type: "TRANSFER", description: `Bonifico a ${beneficiary.displayName}`, correlationId, metadata: { transferReference, beneficiaryName: beneficiary.displayName, beneficiaryIban: beneficiary.iban, beneficiaryBank: beneficiary.bankDirectory?.bankName ?? "BNI", feeMinor: quote.feeMinor, valueDate: quote.valueDate, executionDate: quote.executionDate }, postings: [{ accountReference: quote.sourceAccountReference, deltaMinor: -quote.totalDebitMinor }, { accountReference: beneficiary.internalAccountReference, deltaMinor: quote.amountMinor }, ...(quote.feeMinor ? [{ accountReference: "system_fee_eur", deltaMinor: quote.feeMinor }] : [])] });
      const transfer = this.#transferRecord(quote, beneficiary, transferReference, correlationId, "SETTLED", { transactionReference: journal.journalReference, settledAt: iso(this.now()) });
      transfer.receipt = this.#receipt(state, transfer, journal.journalReference); state.transfers[transferReference] = transfer; state.idempotency[idem] = transferReference; quote.status = "CONSUMED";
      addAudit(state, { type: "TRANSFER_SETTLED", subjectReference: transferReference, actorReference: quote.customerReference, outcome: "SUCCESS", correlationId, details: { amountMinor: quote.amountMinor, currency: quote.currency } }, this.now);
      addOutbox(state, { type: "TRANSFER_SETTLED", aggregateReference: quote.customerReference, payload: { transferReference, transactionReference: journal.journalReference, amountMinor: quote.amountMinor, currency: quote.currency }, correlationId }, this.now);
      return { cached: false, external: false, transfer };
    });
    if (initial.cached || !initial.external) return initial.transfer;
    let provider;
    try { const quote = this.repository.snapshot().transferQuotes[quoteReference]; provider = await this.sepaAdapter.submit({ transferReference: initial.transfer.transferReference, correlationId: initial.transfer.correlationId, providerQuoteReference: quote.providerQuoteReference, amountMinor: initial.transfer.amountMinor, feeMinor: initial.transfer.feeMinor, currency: initial.transfer.currency, beneficiaryIban: initial.transfer.beneficiaryIban, description: initial.transfer.description, idempotencyKey }); }
    catch (error) { if (error instanceof BankError && !error.retryable) provider = { status: "DECLINED", responseCode: error.code }; else return initial.transfer; }
    return this.repository.transaction((state) => {
      const transfer = state.transfers[initial.transfer.transferReference]; if (transfer.status !== "PENDING") return transfer;
      if (!provider || !["ACCEPTED", "SETTLED", "DECLINED"].includes(provider.status)) return transfer;
      transfer.providerTransactionReference = provider.providerTransactionReference ?? null; transfer.providerResponseCode = provider.responseCode ?? null;
      if (provider.status === "DECLINED") { transfer.status = "DECLINED"; transfer.declinedAt = iso(this.now()); addAudit(state, { type: "TRANSFER_DECLINED", subjectReference: transfer.transferReference, actorReference: transfer.customerReference, outcome: "DECLINED", correlationId: transfer.correlationId }, this.now); return transfer; }
      const clearing = this.sepaAdapter.clearingAccountReference; if (!state.accounts[clearing]) throw new BankError("SEPA_CLEARING_ACCOUNT_NOT_CONFIGURED", 503, true);
      const journal = this.ledger.postJournalInState(state, { idempotencyKey: `ledger_${idempotencyKey}`, type: "TRANSFER", description: `Bonifico SEPA a ${transfer.beneficiaryName}`, correlationId: transfer.correlationId, metadata: { transferReference: transfer.transferReference, beneficiaryName: transfer.beneficiaryName, beneficiaryIban: transfer.beneficiaryIban, beneficiaryBank: transfer.beneficiaryBank, feeMinor: transfer.feeMinor, valueDate: transfer.valueDate, executionDate: transfer.executionDate, providerTransactionReference: transfer.providerTransactionReference }, postings: [{ accountReference: transfer.sourceAccountReference, deltaMinor: -transfer.totalDebitMinor }, { accountReference: clearing, deltaMinor: transfer.totalDebitMinor }] });
      transfer.transactionReference = journal.journalReference; transfer.status = provider.status; transfer.settledAt = provider.status === "SETTLED" ? iso(this.now()) : null; transfer.receipt = this.#receipt(state, transfer, journal.journalReference);
      addAudit(state, { type: `TRANSFER_${provider.status}`, subjectReference: transfer.transferReference, actorReference: transfer.customerReference, outcome: provider.status, correlationId: transfer.correlationId }, this.now);
      addOutbox(state, { type: `TRANSFER_${provider.status}`, aggregateReference: transfer.customerReference, payload: { transferReference: transfer.transferReference, transactionReference: journal.journalReference, amountMinor: transfer.amountMinor, currency: transfer.currency }, correlationId: transfer.correlationId }, this.now);
      return transfer;
    });
  }

  get(transferReference, customerReference) {
    const transfer = this.repository.snapshot().transfers[requireOpaque(transferReference)];
    if (!transfer || transfer.customerReference !== customerReference) throw new BankError("TRANSFER_NOT_FOUND", 404);
    return transfer;
  }
}
