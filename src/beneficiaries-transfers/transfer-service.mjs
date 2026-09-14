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

export class BankDirectory {
  constructor(records = {}) { this.records = { ...records }; }
  lookup(abi) { const value = this.records[abi]; return value ? { abi, bankName: value, source: "CONFIGURED_DIRECTORY", accountExistenceVerified: false } : { abi, bankName: null, source: "UNAVAILABLE", accountExistenceVerified: false }; }
}

export class TransferService {
  constructor({ repository, ledger, identity, documents, bankDirectory = new BankDirectory(), riskEngine = { evaluate: () => ({ decision: "ALLOW", reasons: [] }) }, now = () => new Date(), quoteTtlMs = 180_000 } = {}) {
    Object.assign(this, { repository, ledger, identity, documents, bankDirectory, riskEngine, now, quoteTtlMs });
  }

  async addBeneficiary({ ownerReference, beneficiaryReference = opaqueId("beneficiary"), displayName, iban, internalAccountReference = null }) {
    requireOpaque(ownerReference); requireOpaque(beneficiaryReference); requireText(displayName, "INVALID_BENEFICIARY_NAME", 100);
    const normalized = normalizeIban(iban);
    if (!internalAccountReference && !validIban(normalized)) throw new BankError("INVALID_IBAN");
    const coordinates = normalized ? italianBankCoordinates(normalized) : null;
    const directory = coordinates ? this.bankDirectory.lookup(coordinates.abi) : null;
    return this.repository.transaction((state) => {
      if (state.beneficiaries[beneficiaryReference]) throw new BankError("BENEFICIARY_EXISTS", 409);
      if (internalAccountReference && !state.accounts[requireOpaque(internalAccountReference)]) throw new BankError("DESTINATION_ACCOUNT_NOT_FOUND", 404);
      const beneficiary = { beneficiaryReference, ownerReference, displayName, iban: normalized || null, internalAccountReference, bankCoordinates: coordinates, bankDirectory: directory, verificationOfPayee: "UNAVAILABLE", status: "ACTIVE", createdAt: iso(this.now()) };
      state.beneficiaries[beneficiaryReference] = beneficiary;
      addAudit(state, { type: "BENEFICIARY_CREATED", subjectReference: beneficiaryReference, actorReference: ownerReference, outcome: "SUCCESS", details: { vop: beneficiary.verificationOfPayee } }, this.now);
      return beneficiary;
    });
  }

  async createQuote({ customerReference, sourceAccountReference, beneficiaryReference, amountMinor, currency = "EUR", description, execution = "IMMEDIATE", idempotencyKey }) {
    requireMoney(amountMinor, currency); requireText(description, "INVALID_TRANSFER_DESCRIPTION", 140); requireOpaque(idempotencyKey);
    return this.repository.transaction((state) => {
      const idem = `transfer-quote:${idempotencyKey}`; if (state.idempotency[idem]) return state.transferQuotes[state.idempotency[idem]];
      const account = state.accounts[sourceAccountReference]; const beneficiary = state.beneficiaries[beneficiaryReference];
      if (!account || account.ownerReference !== customerReference || account.status !== "ACTIVE") throw new BankError("ACCOUNT_NOT_FOUND", 404);
      if (!beneficiary || beneficiary.ownerReference !== customerReference || beneficiary.status !== "ACTIVE") throw new BankError("BENEFICIARY_NOT_FOUND", 404);
      if (account.currency !== currency) throw new BankError("ACCOUNT_CURRENCY_MISMATCH");
      if (execution !== "IMMEDIATE") throw new BankError("EXECUTION_MODE_NOT_AVAILABLE", 409);
      if (!beneficiary.internalAccountReference) throw new BankError("SEPA_ADAPTER_NOT_CONFIGURED", 503, true);
      const feeMinor = 0; const quoteReference = opaqueId("quote");
      const quote = { quoteReference, customerReference, sourceAccountReference, beneficiaryReference, counterpartyReference: beneficiary.beneficiaryReference, amountMinor, feeMinor, totalDebitMinor: amountMinor + feeMinor, currency, description, execution, status: "QUOTED", createdAt: iso(this.now()), expiresAt: iso(new Date(this.now().getTime() + this.quoteTtlMs)), idempotencyKey };
      state.transferQuotes[quoteReference] = quote; state.idempotency[idem] = quoteReference;
      return quote;
    });
  }

  createScaChallenge({ quoteReference, deviceReference }) {
    const quote = this.repository.snapshot().transferQuotes[requireOpaque(quoteReference)];
    if (!quote || quote.status !== "QUOTED" || new Date(quote.expiresAt) <= this.now()) throw new BankError("QUOTE_NOT_AUTHORIZABLE", 409);
    return this.identity.createScaChallenge({ customerReference: quote.customerReference, deviceReference, operation: "TRANSFER", accountReference: quote.sourceAccountReference, counterpartyReference: quote.beneficiaryReference, amountMinor: quote.totalDebitMinor, currency: quote.currency, operationReference: quote.quoteReference, riskContext: "STANDARD", idempotencyKey: quote.idempotencyKey });
  }

  async authorize({ quoteReference, challengeId, signature, idempotencyKey }) {
    return this.repository.transaction((state) => {
      const idem = `transfer-authorize:${requireOpaque(idempotencyKey)}`;
      if (state.idempotency[idem]) return state.transfers[state.idempotency[idem]];
      const quote = state.transferQuotes[requireOpaque(quoteReference)];
      if (!quote || quote.status !== "QUOTED" || new Date(quote.expiresAt) <= this.now()) throw new BankError("QUOTE_NOT_AUTHORIZABLE", 409);
      this.identity.verifyScaInState(state, { challengeId, signature, expected: { operation: "TRANSFER", accountReference: quote.sourceAccountReference, counterpartyReference: quote.beneficiaryReference, amountMinor: quote.totalDebitMinor, currency: quote.currency, operationReference: quote.quoteReference, idempotencyKey: quote.idempotencyKey } });
      const beneficiary = state.beneficiaries[quote.beneficiaryReference];
      const risk = this.riskEngine.evaluate({ operation: "TRANSFER", customerReference: quote.customerReference, counterpartyReference: quote.beneficiaryReference, amountMinor: quote.totalDebitMinor, currency: quote.currency }, state);
      if (risk.decision !== "ALLOW") throw new BankError("TRANSFER_DECLINED_BY_RISK", 409);
      const transferReference = opaqueId("transfer"); const correlationId = opaqueId("corr");
      const journal = this.ledger.postJournalInState(state, {
        idempotencyKey: `ledger_${idempotencyKey}`, type: "TRANSFER",
        description: `Bonifico a ${beneficiary.displayName}`, correlationId,
        metadata: { transferReference },
        postings: [
          { accountReference: quote.sourceAccountReference, deltaMinor: -quote.totalDebitMinor },
          { accountReference: beneficiary.internalAccountReference, deltaMinor: quote.amountMinor },
          ...(quote.feeMinor ? [{ accountReference: "system_fee_eur", deltaMinor: quote.feeMinor }] : []),
        ],
      });
      const transfer = { transferReference, quoteReference, customerReference: quote.customerReference, sourceAccountReference: quote.sourceAccountReference, beneficiaryReference: quote.beneficiaryReference, amountMinor: quote.amountMinor, feeMinor: quote.feeMinor, currency: quote.currency, description: quote.description, status: "SETTLED", transactionReference: journal.journalReference, correlationId, authorizedAt: iso(this.now()), settledAt: iso(this.now()) };
      state.transfers[transferReference] = transfer; state.idempotency[idem] = transferReference; quote.status = "CONSUMED";
      transfer.receipt = this.documents.createReceiptInState(state, { ownerReference: quote.customerReference, operationReference: transferReference, type: "TRANSFER_RECEIPT", title: "Ricevuta bonifico", correlationId, fields: [["Transazione", journal.journalReference], ["Beneficiario", beneficiary.displayName], ["Importo", `${(quote.amountMinor / 100).toFixed(2)} ${quote.currency}`], ["Stato", transfer.status], ["Data", transfer.settledAt]] });
      addAudit(state, { type: "TRANSFER_SETTLED", subjectReference: transferReference, actorReference: quote.customerReference, outcome: "SUCCESS", correlationId, details: { amountMinor: quote.amountMinor, currency: quote.currency } }, this.now);
      addOutbox(state, { type: "TRANSFER_SETTLED", aggregateReference: quote.customerReference, payload: { transferReference, transactionReference: journal.journalReference, amountMinor: quote.amountMinor, currency: quote.currency }, correlationId }, this.now);
      return transfer;
    });
  }

  get(transferReference, customerReference) {
    const transfer = this.repository.snapshot().transfers[requireOpaque(transferReference)];
    if (!transfer || transfer.customerReference !== customerReference) throw new BankError("TRANSFER_NOT_FOUND", 404);
    return transfer;
  }
}
