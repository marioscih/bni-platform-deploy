import { BankError, iso, opaqueId, requireMoney, requireOpaque } from "../shared/kernel.mjs";
import { addAudit, addOutbox } from "../shared/repository.mjs";

export function validateNoticeCode(type, code) {
  if (type === "PAGOPA") return /^\d{18}$/.test(code);
  if (type === "CBILL") return /^[A-Z0-9]{5,18}$/.test(code);
  return false;
}

export class UnavailableBillsAdapter {
  constructor() { this.configured = false; }
  async inquiry() { throw new BankError("BILLS_PROVIDER_NOT_CONFIGURED", 503, true); }
  async submit() { throw new BankError("BILLS_PROVIDER_NOT_CONFIGURED", 503, true); }
}

export class BillService {
  constructor({ repository, ledger, identity, documents, adapter = new UnavailableBillsAdapter(), now = () => new Date(), quoteTtlMs = 180_000 } = {}) { Object.assign(this, { repository, ledger, identity, documents, adapter, now, quoteTtlMs }); }

  async inquire({ customerReference, sourceAccountReference, type, noticeCode, creditorCode, idempotencyKey }) {
    if (!this.adapter.configured) throw new BankError("BILLS_PROVIDER_NOT_CONFIGURED", 503, true);
    if (!validateNoticeCode(type, noticeCode) || typeof creditorCode !== "string" || creditorCode.length < 3) throw new BankError("INVALID_BILL_CODE");
    const authoritative = await this.adapter.inquiry({ type, noticeCode, creditorCode, idempotencyKey });
    requireMoney(authoritative.amountMinor, authoritative.currency);
    return this.repository.transaction((state) => {
      const account = state.accounts[sourceAccountReference]; if (!account || account.ownerReference !== customerReference) throw new BankError("ACCOUNT_NOT_FOUND", 404);
      const key = `bill-quote:${requireOpaque(idempotencyKey)}`; if (state.idempotency[key]) return state.billQuotes[state.idempotency[key]];
      const quoteReference = opaqueId("billquote");
      const quote = { quoteReference, customerReference, sourceAccountReference, type, noticeCode, creditorCode, creditorName: authoritative.creditorName, amountMinor: authoritative.amountMinor, feeMinor: authoritative.feeMinor ?? 0, currency: authoritative.currency, providerReference: authoritative.providerReference, status: "QUOTED", createdAt: iso(this.now()), expiresAt: iso(new Date(this.now().getTime() + this.quoteTtlMs)), idempotencyKey };
      state.billQuotes[quoteReference] = quote; state.idempotency[key] = quoteReference; return quote;
    });
  }

  createScaChallenge({ quoteReference, deviceReference }) {
    const quote = this.repository.snapshot().billQuotes[requireOpaque(quoteReference)]; if (!quote || quote.status !== "QUOTED") throw new BankError("QUOTE_NOT_AUTHORIZABLE", 409);
    return this.identity.createScaChallenge({ customerReference: quote.customerReference, deviceReference, operation: "BILL_PAYMENT", accountReference: quote.sourceAccountReference, counterpartyReference: quote.providerReference, amountMinor: quote.amountMinor + quote.feeMinor, currency: quote.currency, operationReference: quote.quoteReference, riskContext: "STANDARD", idempotencyKey: quote.idempotencyKey });
  }

  async authorize({ quoteReference, challengeId, signature, idempotencyKey, clearingAccountReference }) {
    if (!this.adapter.configured) throw new BankError("BILLS_PROVIDER_NOT_CONFIGURED", 503, true);
    const payment = await this.repository.transaction((state) => {
      const key = `bill-authorize:${requireOpaque(idempotencyKey)}`; if (state.idempotency[key]) return state.billPayments[state.idempotency[key]];
      const quote = state.billQuotes[requireOpaque(quoteReference)]; if (!quote || quote.status !== "QUOTED" || new Date(quote.expiresAt) <= this.now()) throw new BankError("QUOTE_NOT_AUTHORIZABLE", 409);
      this.identity.verifyScaInState(state, { challengeId, signature, expected: { operation: "BILL_PAYMENT", accountReference: quote.sourceAccountReference, counterpartyReference: quote.providerReference, amountMinor: quote.amountMinor + quote.feeMinor, currency: quote.currency, operationReference: quote.quoteReference, idempotencyKey: quote.idempotencyKey } });
      const paymentReference = opaqueId("billpay"); const correlationId = opaqueId("corr");
      const journal = this.ledger.postJournalInState(state, { idempotencyKey: `ledger_${idempotencyKey}`, type: `${quote.type}_PAYMENT`, description: `Pagamento ${quote.type} - ${quote.creditorName}`, correlationId, postings: [{ accountReference: quote.sourceAccountReference, deltaMinor: -(quote.amountMinor + quote.feeMinor) }, { accountReference: clearingAccountReference, deltaMinor: quote.amountMinor + quote.feeMinor }] });
      const created = { paymentReference, quoteReference, customerReference: quote.customerReference, amountMinor: quote.amountMinor, feeMinor: quote.feeMinor, currency: quote.currency, status: "AUTHORIZED_PENDING_SUBMISSION", transactionReference: journal.journalReference, correlationId, createdAt: iso(this.now()), idempotencyKey };
      state.billPayments[paymentReference] = created; state.idempotency[key] = paymentReference; quote.status = "CONSUMED";
      addOutbox(state, { type: "BILL_PAYMENT_AUTHORIZED", aggregateReference: paymentReference, payload: { paymentReference }, correlationId }, this.now);
      return created;
    });
    let provider;
    try { provider = await this.adapter.submit({ paymentReference: payment.paymentReference, idempotencyKey, quoteReference }); }
    catch { return payment; }
    return this.repository.transaction((state) => {
      const current = state.billPayments[payment.paymentReference];
      if (current.status === "AUTHORIZED_PENDING_SUBMISSION" && provider.status === "ACCEPTED") {
        current.status = "ACCEPTED"; current.providerTransactionReference = provider.providerTransactionReference; current.acceptedAt = iso(this.now());
        const quote = state.billQuotes[current.quoteReference];
        current.receipt = this.documents.createReceiptInState(state, { ownerReference: current.customerReference, operationReference: current.paymentReference, type: "BILL_RECEIPT", title: `Ricevuta ${quote.type}`, correlationId: current.correlationId, fields: [["Transazione", current.transactionReference], ["Creditore", quote.creditorName], ["Importo", `${(current.amountMinor / 100).toFixed(2)} ${current.currency}`], ["Stato", current.status]] });
        addAudit(state, { type: "BILL_PAYMENT_ACCEPTED", subjectReference: current.paymentReference, actorReference: current.customerReference, outcome: "SUCCESS", correlationId: current.correlationId }, this.now);
      }
      return current;
    });
  }
}
