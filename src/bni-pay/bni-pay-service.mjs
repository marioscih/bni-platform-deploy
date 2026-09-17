import { createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { BankError, canonicalFields, fromBase64url, iso, opaqueId, randomToken, requireMoney, requireOpaque, requireText, safeEqual, sha256 } from "../shared/kernel.mjs";
import { addAudit, addOutbox } from "../shared/repository.mjs";

const ACTIVE = "ACTIVE";
const INTENT_STATES = new Set(["PENDING", "APPROVED", "DECLINED", "CANCELLED", "EXPIRED", "REFUNDED"]);

function keyFromSpki(value) {
  try { return createPublicKey({ key: Buffer.from(value, "base64url"), format: "der", type: "spki" }); }
  catch { throw new BankError("INVALID_TERMINAL_PUBLIC_KEY"); }
}

export function terminalRequestMaterial({ merchantId, terminalId, amountMinor, currency, orderId, requestNonce, requestedAt, idempotencyKey }) {
  return canonicalFields("BNI_PAY_CREATE_INTENT_V1", merchantId, terminalId, amountMinor, currency, orderId ?? "", requestNonce, requestedAt, idempotencyKey);
}

export function terminalStatusMaterial({ terminalId, paymentIntentId, requestNonce, requestedAt }) {
  return canonicalFields("BNI_PAY_STATUS_V1", terminalId, paymentIntentId, requestNonce, requestedAt);
}

function canonicalIntent(intent) {
  return canonicalFields("BNI_PAY_INTENT_V1", intent.paymentIntentId, intent.transactionReference, intent.merchantId, intent.terminalId, intent.merchantDisplayName, intent.amountMinor, intent.currency, intent.terminalNonce, intent.createdAt, intent.expiresAt);
}

export class BniPayService {
  constructor({ repository, ledger, identity, documents, enrollmentPepper, intentPrivateKey, intentPublicKey, riskEngine = { evaluate: () => ({ decision: "ALLOW", reasons: [] }) }, now = () => new Date(), intentTtlMs = 120_000 } = {}) {
    if (!intentPrivateKey || !intentPublicKey) throw new BankError("BNI_PAY_SIGNING_KEY_REQUIRED", 500);
    enrollmentPepper ??= identity?.activationPepper;
    if (Buffer.byteLength(enrollmentPepper ?? "") < 16) throw new BankError("TERMINAL_ENROLLMENT_PEPPER_REQUIRED", 500);
    Object.assign(this, { repository, ledger, identity, documents, enrollmentPepper, intentPrivateKey, intentPublicKey, riskEngine, now, intentTtlMs });
  }

  async provisionMerchantTerminal({ merchantId, displayName, settlementAccountReference, terminalId, deviceReference, enrollmentCode, currency = "EUR" }) {
    requireOpaque(merchantId, "INVALID_MERCHANT_ID"); requireText(displayName, "INVALID_MERCHANT_NAME", 120);
    requireOpaque(settlementAccountReference, "INVALID_ACCOUNT_REFERENCE"); requireOpaque(terminalId, "INVALID_TERMINAL_ID"); requireOpaque(deviceReference, "INVALID_DEVICE_REFERENCE");
    if (typeof enrollmentCode !== "string" || !/^[A-Z0-9-]{16,64}$/.test(enrollmentCode)) throw new BankError("INVALID_TERMINAL_ENROLLMENT_CODE");
    return this.repository.transaction((state) => {
      const deviceAlreadyBound = Object.values(state.terminals).some((terminal) => terminal.deviceReference === deviceReference)
        || Object.values(state.terminalEnrollments).some((enrollment) => enrollment.deviceReference === deviceReference && !enrollment.consumedAt);
      if (state.merchants[merchantId] || state.terminals[terminalId] || state.terminalEnrollments[terminalId] || deviceAlreadyBound) throw new BankError("ACCEPTANCE_IDENTITY_EXISTS", 409);
      const account = this.ledger.createAccountInState(state, { accountReference: settlementAccountReference, ownerReference: merchantId, displayName: `Incassi ${displayName}`, type: "MERCHANT", currency });
      const merchant = { merchantId, displayName, settlementAccountReference, status: ACTIVE, createdAt: iso(this.now()) };
      state.merchants[merchantId] = merchant;
      state.terminalEnrollments[terminalId] = { terminalId, merchantId, deviceReference, hash: sha256(`${this.enrollmentPepper}|${enrollmentCode}`), failures: 0, consumedAt: null, createdAt: iso(this.now()) };
      addAudit(state, { type: "MERCHANT_TERMINAL_PROVISIONED", subjectReference: terminalId, actorReference: merchantId, outcome: "PENDING_ENROLLMENT" }, this.now);
      return { merchant, account, terminal: { terminalId, merchantId, deviceReference, status: "PENDING_ENROLLMENT" } };
    });
  }

  async completeTerminalEnrollment({ merchantId, terminalId, enrollmentCode, publicKeySpki }) {
    requireOpaque(merchantId, "INVALID_MERCHANT_ID"); requireOpaque(terminalId, "INVALID_TERMINAL_ID"); keyFromSpki(publicKeySpki);
    const result = await this.repository.transaction((state) => {
      const merchant = state.merchants[merchantId]; const enrollment = state.terminalEnrollments[terminalId];
      if (!merchant || merchant.status !== ACTIVE || !enrollment || enrollment.merchantId !== merchantId || enrollment.consumedAt) throw new BankError("TERMINAL_ENROLLMENT_DENIED", 403);
      const supplied = sha256(`${this.enrollmentPepper}|${enrollmentCode ?? ""}`);
      if (!safeEqual(supplied, enrollment.hash)) {
        enrollment.failures += 1;
        if (enrollment.failures >= 5) enrollment.consumedAt = iso(this.now());
        addAudit(state, { type: "TERMINAL_ENROLLMENT", subjectReference: terminalId, actorReference: merchantId, outcome: "DENIED" }, this.now);
        return { terminalError: "TERMINAL_ENROLLMENT_DENIED" };
      }
      const terminal = { terminalId, merchantId, deviceReference: enrollment.deviceReference, publicKeySpki, status: ACTIVE, createdAt: iso(this.now()) };
      state.terminals[terminalId] = terminal; enrollment.consumedAt = iso(this.now());
      addAudit(state, { type: "TERMINAL_ENROLLED", subjectReference: terminalId, actorReference: merchantId, outcome: "SUCCESS" }, this.now);
      return { terminalId, merchantId, status: ACTIVE };
    });
    if (result.terminalError) throw new BankError(result.terminalError, 403);
    return result;
  }

  async registerMerchant({ merchantId, displayName, settlementAccountReference, status = ACTIVE }) {
    requireOpaque(merchantId, "INVALID_MERCHANT_ID"); requireText(displayName, "INVALID_MERCHANT_NAME", 120); requireOpaque(settlementAccountReference);
    return this.repository.transaction((state) => {
      const account = state.accounts[settlementAccountReference]; if (!account || account.type !== "MERCHANT") throw new BankError("INVALID_SETTLEMENT_ACCOUNT");
      if (state.merchants[merchantId]) throw new BankError("MERCHANT_EXISTS", 409);
      const merchant = { merchantId, displayName, settlementAccountReference, status, createdAt: iso(this.now()) };
      state.merchants[merchantId] = merchant; addAudit(state, { type: "MERCHANT_REGISTERED", subjectReference: merchantId, outcome: "SUCCESS" }, this.now); return merchant;
    });
  }

  async registerTerminal({ terminalId, merchantId, deviceReference, publicKeySpki, status = ACTIVE }) {
    requireOpaque(terminalId, "INVALID_TERMINAL_ID"); requireOpaque(merchantId, "INVALID_MERCHANT_ID"); requireOpaque(deviceReference); keyFromSpki(publicKeySpki);
    return this.repository.transaction((state) => {
      const merchant = state.merchants[merchantId]; if (!merchant || merchant.status !== ACTIVE) throw new BankError("MERCHANT_NOT_ACTIVE", 403);
      if (state.terminals[terminalId] || Object.values(state.terminals).some((terminal) => terminal.deviceReference === deviceReference)) throw new BankError("TERMINAL_EXISTS", 409);
      const terminal = { terminalId, merchantId, deviceReference, publicKeySpki, status, createdAt: iso(this.now()) };
      state.terminals[terminalId] = terminal; addAudit(state, { type: "TERMINAL_REGISTERED", subjectReference: terminalId, actorReference: merchantId, outcome: "SUCCESS" }, this.now); return { ...terminal, publicKeySpki: undefined };
    });
  }

  async changeMerchantStatus({ merchantId, status }) {
    if (![ACTIVE, "SUSPENDED"].includes(status)) throw new BankError("INVALID_MERCHANT_STATUS");
    return this.repository.transaction((state) => { const merchant = state.merchants[requireOpaque(merchantId)]; if (!merchant) throw new BankError("MERCHANT_NOT_FOUND", 404); merchant.status = status; merchant.updatedAt = iso(this.now()); return merchant; });
  }

  async changeTerminalStatus({ terminalId, status }) {
    if (![ACTIVE, "SUSPENDED", "REVOKED"].includes(status)) throw new BankError("INVALID_TERMINAL_STATUS");
    return this.repository.transaction((state) => { const terminal = state.terminals[requireOpaque(terminalId)]; if (!terminal) throw new BankError("TERMINAL_NOT_FOUND", 404); terminal.status = status; terminal.updatedAt = iso(this.now()); return { ...terminal, publicKeySpki: undefined }; });
  }

  async createPaymentIntent({ merchantId, terminalId, amountMinor, currency = "EUR", description = null, orderId = null, requestNonce, requestedAt, idempotencyKey, terminalSignature }) {
    requireMoney(amountMinor, currency); requireOpaque(requestNonce, "INVALID_REQUEST_NONCE"); requireOpaque(idempotencyKey); if (description) requireText(description, "INVALID_DESCRIPTION", 120); if (orderId) requireOpaque(orderId);
    const request = { merchantId, terminalId, amountMinor, currency, orderId, requestNonce, requestedAt, idempotencyKey };
    const material = terminalRequestMaterial(request);
    return this.repository.transaction((state) => {
      const merchant = state.merchants[requireOpaque(merchantId, "INVALID_MERCHANT_ID")]; const terminal = state.terminals[requireOpaque(terminalId, "INVALID_TERMINAL_ID")];
      if (!merchant || merchant.status !== ACTIVE) throw new BankError("MERCHANT_NOT_ACTIVE", 403);
      if (!terminal || terminal.status !== ACTIVE || terminal.merchantId !== merchantId) throw new BankError("TERMINAL_NOT_ACTIVE", 403);
      if (Math.abs(this.now().getTime() - new Date(requestedAt).getTime()) > 60_000) throw new BankError("TERMINAL_REQUEST_EXPIRED", 409);
      if (!cryptoVerify("sha256", Buffer.from(material), keyFromSpki(terminal.publicKeySpki), fromBase64url(terminalSignature))) throw new BankError("INVALID_TERMINAL_SIGNATURE", 403);
      const replayKey = `terminal:${terminalId}:${requestNonce}`; if (state.replayNonces[replayKey]) throw new BankError("TERMINAL_REPLAY_REJECTED", 409);
      const idem = `bni-intent:${idempotencyKey}`; if (state.idempotency[idem]) return this.#publicIntent(state.paymentIntents[state.idempotency[idem]]);
      state.replayNonces[replayKey] = iso(this.now());
      const createdAt = iso(this.now());
      const intent = { paymentIntentId: opaqueId("pi"), transactionReference: opaqueId("txn"), merchantId, terminalId, merchantDisplayName: merchant.displayName, amountMinor, currency, description, orderId, terminalNonce: randomToken(24), status: "PENDING", decisionReason: null, createdAt, expiresAt: iso(new Date(this.now().getTime() + this.intentTtlMs)), correlationId: opaqueId("corr") };
      intent.signature = cryptoSign(null, Buffer.from(canonicalIntent(intent)), this.intentPrivateKey).toString("base64url");
      state.paymentIntents[intent.paymentIntentId] = intent; state.idempotency[idem] = intent.paymentIntentId;
      addAudit(state, { type: "BNI_PAY_INTENT_CREATED", subjectReference: intent.paymentIntentId, actorReference: terminalId, outcome: "SUCCESS", correlationId: intent.correlationId, details: { merchantId, terminalId, amountMinor, currency } }, this.now);
      return this.#publicIntent(intent);
    });
  }

  getPaymentIntent(paymentIntentId) {
    const state = this.repository.snapshot(); const intent = state.paymentIntents[requireOpaque(paymentIntentId)]; if (!intent) throw new BankError("PAYMENT_INTENT_NOT_FOUND", 404);
    const effective = { ...intent };
    if (effective.status === "PENDING" && new Date(effective.expiresAt) <= this.now()) effective.status = "EXPIRED";
    if (!this.verifyIntent(effective)) throw new BankError("PAYMENT_INTENT_SIGNATURE_INVALID", 500);
    return this.#publicIntent(effective);
  }

  verifyIntent(intent) { try { return cryptoVerify(null, Buffer.from(canonicalIntent(intent)), this.intentPublicKey, fromBase64url(intent.signature)); } catch { return false; } }

  nfcPayload(paymentIntentId) {
    const intent = this.getPaymentIntent(paymentIntentId);
    if (intent.status !== "PENDING") throw new BankError(`PAYMENT_INTENT_${intent.status}`, 409);
    return { protocolVersion: "1", paymentIntentId: intent.paymentIntentId, terminalNonce: intent.terminalNonce, intentSignature: intent.signature };
  }

  qrPayload(paymentIntentId) { const intent = this.getPaymentIntent(paymentIntentId); return `bni-pay://pay/${intent.paymentIntentId}`; }

  createScaChallenge({ paymentIntentId, customerReference, customerAccountReference, deviceReference, idempotencyKey }) {
    const intent = this.getPaymentIntent(paymentIntentId); if (intent.status !== "PENDING") throw new BankError(`PAYMENT_INTENT_${intent.status}`, 409);
    return this.identity.createScaChallenge({ customerReference, deviceReference, operation: "BNI_PAY", accountReference: customerAccountReference, counterpartyReference: intent.merchantId, amountMinor: intent.amountMinor, currency: intent.currency, operationReference: intent.paymentIntentId, riskContext: "CONTACTLESS_OR_QR", idempotencyKey });
  }

  async authorize({ paymentIntentId, terminalNonce, customerReference, customerAccountReference, deviceReference, challengeId, signature, authorizationNonce, idempotencyKey }) {
    return this.repository.transaction((state) => {
      const idem = `bni-authorize:${requireOpaque(idempotencyKey)}`;
      if (state.idempotency[idem]) return state.bniPayments[state.idempotency[idem]];
      const intent = state.paymentIntents[requireOpaque(paymentIntentId)]; if (!intent) throw new BankError("PAYMENT_INTENT_NOT_FOUND", 404);
      if (intent.status === "APPROVED" || intent.status === "DECLINED" || intent.status === "REFUNDED") return state.bniPayments[intent.paymentIntentId];
      if (intent.status !== "PENDING") throw new BankError(`PAYMENT_INTENT_${intent.status}`, 409);
      if (new Date(intent.expiresAt) <= this.now()) { intent.status = "EXPIRED"; throw new BankError("PAYMENT_INTENT_EXPIRED", 409); }
      if (terminalNonce !== intent.terminalNonce) throw new BankError("TERMINAL_NONCE_INVALID", 403);
      const replay = `customer:${requireOpaque(authorizationNonce)}`; if (state.replayNonces[replay]) throw new BankError("AUTHORIZATION_REPLAY_REJECTED", 409);
      state.replayNonces[replay] = iso(this.now());
      this.identity.verifyScaInState(state, { challengeId, signature, expected: { operation: "BNI_PAY", accountReference: customerAccountReference, counterpartyReference: intent.merchantId, amountMinor: intent.amountMinor, currency: intent.currency, operationReference: intent.paymentIntentId, idempotencyKey } });
      const merchant = state.merchants[intent.merchantId]; const terminal = state.terminals[intent.terminalId]; const customerAccount = state.accounts[customerAccountReference];
      if (!merchant || merchant.status !== ACTIVE || !terminal || terminal.status !== ACTIVE) throw new BankError("ACCEPTANCE_NOT_ACTIVE", 403);
      if (!customerAccount || customerAccount.ownerReference !== customerReference || customerAccount.status !== ACTIVE) throw new BankError("CUSTOMER_ACCOUNT_NOT_ACTIVE", 403);
      const risk = this.riskEngine.evaluate({ operation: "BNI_PAY", customerReference, deviceReference, merchantId: merchant.merchantId, terminalId: terminal.terminalId, amountMinor: intent.amountMinor, currency: intent.currency }, state);
      if (risk.decision !== "ALLOW") return this.#declineInState(state, intent, customerReference, customerAccountReference, idempotencyKey, risk.reasons.join(",") || "RISK_DECLINE");
      let journal;
      try {
        journal = this.ledger.postJournalInState(state, { journalReference: intent.transactionReference, idempotencyKey: `ledger_${idempotencyKey}`, type: "BNI_PAY", description: `Pagamento BNI Pay - ${merchant.displayName}`, correlationId: intent.correlationId, metadata: { paymentIntentId: intent.paymentIntentId, merchantId: merchant.merchantId, terminalId: terminal.terminalId }, postings: [{ accountReference: customerAccountReference, deltaMinor: -intent.amountMinor }, { accountReference: merchant.settlementAccountReference, deltaMinor: intent.amountMinor }] });
      } catch (error) {
        if (error.code === "INSUFFICIENT_FUNDS") return this.#declineInState(state, intent, customerReference, customerAccountReference, idempotencyKey, "INSUFFICIENT_FUNDS");
        throw error;
      }
      intent.status = "APPROVED"; intent.approvedAt = iso(this.now());
      const payment = { paymentIntentId: intent.paymentIntentId, transactionReference: journal.journalReference, customerReference, customerAccountReference, merchantId: merchant.merchantId, terminalId: terminal.terminalId, merchantDisplayName: merchant.displayName, amountMinor: intent.amountMinor, currency: intent.currency, status: "APPROVED", decisionReason: null, approvedAt: intent.approvedAt, correlationId: intent.correlationId };
      payment.receipt = this.documents.createReceiptInState(state, { ownerReference: customerReference, operationReference: payment.paymentIntentId, type: "BNI_PAY_RECEIPT", title: "Ricevuta BNI Pay", correlationId: payment.correlationId, fields: [["Transazione", payment.transactionReference], ["Esercente", merchant.displayName], ["Importo", `${(payment.amountMinor / 100).toFixed(2)} ${payment.currency}`], ["Metodo", "BNI Pay"], ["Stato", payment.status], ["Data", payment.approvedAt]] });
      state.bniPayments[intent.paymentIntentId] = payment; state.idempotency[idem] = intent.paymentIntentId;
      addAudit(state, { type: "BNI_PAY_APPROVED", subjectReference: intent.paymentIntentId, actorReference: customerReference, outcome: "APPROVED", correlationId: intent.correlationId, details: { merchantId: merchant.merchantId, terminalId: terminal.terminalId, amountMinor: intent.amountMinor, currency: intent.currency } }, this.now);
      addOutbox(state, { type: "BNI_PAY_APPROVED", aggregateReference: customerReference, payload: { paymentIntentId: intent.paymentIntentId, transactionReference: journal.journalReference, amountMinor: intent.amountMinor, currency: intent.currency }, correlationId: intent.correlationId }, this.now);
      return payment;
    });
  }

  async cancel({ paymentIntentId, merchantId, terminalId, idempotencyKey }) {
    return this.repository.transaction((state) => {
      const key = `bni-cancel:${requireOpaque(idempotencyKey)}`; if (state.idempotency[key]) return this.#publicIntent(state.paymentIntents[state.idempotency[key]]);
      const intent = state.paymentIntents[requireOpaque(paymentIntentId)]; if (!intent || intent.merchantId !== merchantId || intent.terminalId !== terminalId) throw new BankError("PAYMENT_INTENT_NOT_FOUND", 404);
      if (intent.status !== "PENDING") throw new BankError("PAYMENT_INTENT_NOT_CANCELLABLE", 409);
      intent.status = "CANCELLED"; intent.cancelledAt = iso(this.now()); state.idempotency[key] = intent.paymentIntentId; return this.#publicIntent(intent);
    });
  }

  async declineByCustomer({ paymentIntentId, terminalNonce, customerReference, authorizationNonce, idempotencyKey }) {
    return this.repository.transaction((state) => {
      const idem = `bni-customer-decline:${requireOpaque(idempotencyKey)}`;
      if (state.idempotency[idem]) return state.bniPayments[state.idempotency[idem]];
      const intent = state.paymentIntents[requireOpaque(paymentIntentId)]; if (!intent) throw new BankError("PAYMENT_INTENT_NOT_FOUND", 404);
      if (intent.status === "DECLINED") return state.bniPayments[intent.paymentIntentId];
      if (intent.status !== "PENDING" || new Date(intent.expiresAt) <= this.now()) throw new BankError("PAYMENT_INTENT_NOT_DECLINABLE", 409);
      if (terminalNonce !== intent.terminalNonce) throw new BankError("TERMINAL_NONCE_INVALID", 403);
      const replay = `customer-decline:${requireOpaque(authorizationNonce)}`; if (state.replayNonces[replay]) throw new BankError("AUTHORIZATION_REPLAY_REJECTED", 409);
      state.replayNonces[replay] = iso(this.now());
      const payment = this.#declineInState(state, intent, customerReference, null, idempotencyKey, "CUSTOMER_DECLINED");
      state.idempotency[idem] = intent.paymentIntentId;
      return payment;
    });
  }

  async refundFull({ paymentIntentId, merchantId, idempotencyKey }) {
    return this.repository.transaction((state) => {
      const key = `bni-refund:${requireOpaque(idempotencyKey)}`; if (state.idempotency[key]) return state.refunds[state.idempotency[key]];
      const intent = state.paymentIntents[requireOpaque(paymentIntentId)]; const payment = state.bniPayments[paymentIntentId]; const merchant = state.merchants[merchantId];
      if (!intent || !payment || payment.status !== "APPROVED" || intent.merchantId !== merchantId || !merchant) throw new BankError("PAYMENT_NOT_REFUNDABLE", 409);
      const refundReference = opaqueId("refund"); const correlationId = opaqueId("corr");
      const journal = this.ledger.postJournalInState(state, { idempotencyKey: `ledger_refund_${idempotencyKey}`, type: "BNI_PAY_REFUND", description: "Rimborso BNI Pay", correlationId, metadata: { originalTransactionReference: payment.transactionReference }, postings: [{ accountReference: merchant.settlementAccountReference, deltaMinor: -payment.amountMinor }, { accountReference: payment.customerAccountReference, deltaMinor: payment.amountMinor }] });
      const refund = { refundReference, originalPaymentIntentId: paymentIntentId, originalTransactionReference: payment.transactionReference, transactionReference: journal.journalReference, merchantId, customerReference: payment.customerReference, amountMinor: payment.amountMinor, currency: payment.currency, status: "APPROVED", approvedAt: iso(this.now()), correlationId };
      state.refunds[refundReference] = refund; state.idempotency[key] = refundReference; payment.status = "REFUNDED"; intent.status = "REFUNDED";
      addAudit(state, { type: "BNI_PAY_REFUNDED", subjectReference: refundReference, actorReference: merchantId, outcome: "APPROVED", correlationId, details: { amountMinor: refund.amountMinor, currency: refund.currency } }, this.now);
      return refund;
    });
  }

  merchantHistory(merchantId) {
    const state = this.repository.snapshot(); const merchant = state.merchants[requireOpaque(merchantId)]; if (!merchant) throw new BankError("MERCHANT_NOT_FOUND", 404);
    const items = Object.values(state.bniPayments).filter((payment) => payment.merchantId === merchantId).sort((a, b) => (b.approvedAt ?? "").localeCompare(a.approvedAt ?? ""));
    const today = iso(this.now()).slice(0, 10); const dailyTotalMinor = items.filter((item) => item.status === "APPROVED" && item.approvedAt?.startsWith(today)).reduce((sum, item) => sum + item.amountMinor, 0);
    return { items, dailyTotalMinor, currency: merchant ? state.accounts[merchant.settlementAccountReference].currency : "EUR" };
  }

  async authenticateTerminalStatus({ terminalId, paymentIntentId, requestNonce, requestedAt, terminalSignature }) {
    const material = terminalStatusMaterial({ terminalId, paymentIntentId, requestNonce, requestedAt });
    return this.repository.transaction((state) => {
      const terminal = state.terminals[requireOpaque(terminalId)]; const intent = state.paymentIntents[requireOpaque(paymentIntentId)];
      if (!terminal || terminal.status !== ACTIVE || !intent || intent.terminalId !== terminalId) throw new BankError("TERMINAL_ACCESS_DENIED", 403);
      if (Math.abs(this.now().getTime() - new Date(requestedAt).getTime()) > 60_000) throw new BankError("TERMINAL_REQUEST_EXPIRED", 409);
      if (!cryptoVerify("sha256", Buffer.from(material), keyFromSpki(terminal.publicKeySpki), fromBase64url(terminalSignature))) throw new BankError("INVALID_TERMINAL_SIGNATURE", 403);
      const replay = `terminal-status:${terminalId}:${requireOpaque(requestNonce)}`; if (state.replayNonces[replay]) throw new BankError("TERMINAL_REPLAY_REJECTED", 409); state.replayNonces[replay] = iso(this.now());
      return this.#publicIntent(intent);
    });
  }

  #declineInState(state, intent, customerReference, customerAccountReference, idempotencyKey, reason) {
    intent.status = "DECLINED"; intent.decisionReason = reason; intent.declinedAt = iso(this.now());
    const payment = { paymentIntentId: intent.paymentIntentId, transactionReference: intent.transactionReference, customerReference, customerAccountReference, merchantId: intent.merchantId, terminalId: intent.terminalId, merchantDisplayName: intent.merchantDisplayName, amountMinor: intent.amountMinor, currency: intent.currency, status: "DECLINED", decisionReason: reason, declinedAt: intent.declinedAt, correlationId: intent.correlationId };
    state.bniPayments[intent.paymentIntentId] = payment; state.idempotency[`bni-authorize:${idempotencyKey}`] = intent.paymentIntentId;
    addAudit(state, { type: "BNI_PAY_DECLINED", subjectReference: intent.paymentIntentId, actorReference: customerReference, outcome: "DECLINED", correlationId: intent.correlationId, details: { reason, amountMinor: intent.amountMinor, currency: intent.currency } }, this.now);
    return payment;
  }

  #publicIntent(intent) {
    if (!INTENT_STATES.has(intent.status)) throw new BankError("INVALID_PAYMENT_INTENT_STATE", 500);
    return { paymentIntentId: intent.paymentIntentId, transactionReference: intent.transactionReference, merchantId: intent.merchantId, terminalId: intent.terminalId, merchantDisplayName: intent.merchantDisplayName, amountMinor: intent.amountMinor, currency: intent.currency, description: intent.description, orderId: intent.orderId, terminalNonce: intent.terminalNonce, status: intent.status, decisionReason: intent.decisionReason, createdAt: intent.createdAt, expiresAt: intent.expiresAt, signature: intent.signature, signatureAlgorithm: "Ed25519" };
  }
}

export function generateIntentSigningKeyPair() { return generateKeyPairSync("ed25519"); }
