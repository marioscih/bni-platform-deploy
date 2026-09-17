import { BankError, iso, opaqueId, requireOpaque, requireText } from "../shared/kernel.mjs";
import { addAudit, addOutbox } from "../shared/repository.mjs";
import { createHmac } from "node:crypto";

export class UnavailableCardDetailsProvider { constructor() { this.configured = false; } async fetchDetails() { throw new BankError("CARD_DETAILS_PROVIDER_NOT_CONFIGURED", 503, true); } }
export class UnavailableWalletAdapter { constructor() { this.configured = false; } async provision() { throw new BankError("WALLET_PROVIDER_NOT_CONFIGURED", 503, true); } async lifecycle() { throw new BankError("WALLET_PROVIDER_NOT_CONFIGURED", 503, true); } }

/** Produces non-payment test credentials only in the explicitly enabled simulator. */
export class SimulatorCardDetailsProvider {
  configured = true;
  constructor({ repository, secret, now = () => new Date() }) {
    if (!repository || !Buffer.isBuffer(secret) || secret.length < 32) throw new TypeError("Simulator card provider requires repository and secret");
    Object.assign(this, { repository, secret, now });
  }
  async fetchDetails({ cardReference, ownerReference }) {
    const state = this.repository.snapshot();
    const card = state.cards[cardReference];
    if (!card || card.ownerReference !== ownerReference) throw new BankError("CARD_NOT_FOUND", 404);
    const digest = createHmac("sha256", this.secret).update(`card-credentials-v1|${ownerReference}|${cardReference}`).digest();
    const digits = (offset, length) => Array.from({ length }, (_, index) => digest[(offset + index) % digest.length] % 10).join("");
    const account = Object.values(state.accounts).find((item) => item.ownerReference === ownerReference && item.type === "CUSTOMER");
    const holder = account?.holderName === ["Mario", "Sciacca"].join(" ") ? "Sciacca Mario" : account?.holderName ?? "Cliente BNI";
    const expiryYear = String((this.now().getUTCFullYear() + 4) % 100).padStart(2, "0");
    return {
      pan: `0000${digits(0, 8)}${card.maskedLastFour}`,
      expiry: /^\d{2}\/\d{2}$/.test(card.expiryDisplay ?? "") ? card.expiryDisplay : `${String((digest[12] % 12) + 1).padStart(2, "0")}/${expiryYear}`,
      securityCode: digits(13, 3),
      pin: digits(16, 4),
      cardholder: holder,
      ttlSeconds: 30,
    };
  }
}

export class CardService {
  constructor({ repository, identity, detailsProvider = new UnavailableCardDetailsProvider(), walletAdapter = new UnavailableWalletAdapter(), now = () => new Date() } = {}) { Object.assign(this, { repository, identity, detailsProvider, walletAdapter, now }); }

  async registerCard({ cardReference, ownerReference, displayName, product, maskedLastFour, networkProfile = "UNCONFIGURED", expiryDisplay = null, status = "ACTIVE" }) {
    return this.repository.transaction((state) => this.registerCardInState(state, { cardReference, ownerReference, displayName, product, maskedLastFour, networkProfile, expiryDisplay, status }));
  }

  registerCardInState(state, { cardReference, ownerReference, displayName, product, maskedLastFour, networkProfile = "UNCONFIGURED", expiryDisplay = null, status = "ACTIVE" }) {
    requireOpaque(cardReference); requireOpaque(ownerReference); requireText(displayName, "INVALID_CARD_NAME", 80); requireText(product, "INVALID_CARD_PRODUCT", 80);
    if (!/^\d{4}$/.test(maskedLastFour)) throw new BankError("INVALID_MASKED_CARD");
    if (state.cards[cardReference]) throw new BankError("CARD_EXISTS", 409);
    if (!/^[A-Z0-9_-]{3,48}$/.test(networkProfile) || (expiryDisplay != null && !/^\d{2}\/\d{2}$/.test(expiryDisplay))) throw new BankError("INVALID_CARD_PROFILE");
    const card = { cardReference, ownerReference, displayName, product, maskedLastFour, networkProfile, expiryDisplay, status, ecommerceEnabled: true, contactlessEnabled: true, cashWithdrawalEnabled: true, updatedAt: iso(this.now()) };
    state.cards[cardReference] = card; return card;
  }

  list(ownerReference) {
    return this.repository.read((state) => this.listInState(state, ownerReference));
  }

  listInState(state, ownerReference) {
    const holderName = Object.values(state.accounts).find((account) => account.ownerReference === ownerReference && account.type === "CUSTOMER")?.holderName ?? null;
    return Object.values(state.cards).filter((card) => card.ownerReference === ownerReference).map((card) => {
      const token = Object.values(state.walletTokens).find((item) => item.cardReference === card.cardReference);
      const ready = card.status === "ACTIVE" && card.contactlessEnabled === true && token?.status === "ACTIVE";
      return { ...card, holderName, credentialState: token?.status ?? "NOT_PROVISIONED", tokenReferencePresent: Boolean(token), contactlessState: ready ? "READY_FOR_CONTACTLESS" : "TOKEN_NOT_READY", walletAvailability: this.walletAdapter.configured ? "AVAILABLE" : "PROVIDER_NOT_CONFIGURED" };
    });
  }

  async setControls({ cardReference, ownerReference, status, ecommerceEnabled, contactlessEnabled, cashWithdrawalEnabled, idempotencyKey }) {
    return this.repository.transaction((state) => {
      const key = `card-control:${requireOpaque(idempotencyKey)}`; if (state.idempotency[key]) return state.cards[state.idempotency[key]];
      const card = state.cards[requireOpaque(cardReference)]; if (!card || card.ownerReference !== ownerReference) throw new BankError("CARD_NOT_FOUND", 404);
      if (!new Set(["ACTIVE", "SUSPENDED"]).has(status)) throw new BankError("INVALID_CARD_STATUS");
      Object.assign(card, { status, ecommerceEnabled: ecommerceEnabled === true, contactlessEnabled: contactlessEnabled === true && status === "ACTIVE", cashWithdrawalEnabled: cashWithdrawalEnabled === true && status === "ACTIVE", updatedAt: iso(this.now()) });
      for (const token of Object.values(state.walletTokens)) if (token.cardReference === cardReference && status === "SUSPENDED") token.status = "SUSPENDED";
      state.idempotency[key] = cardReference;
      addAudit(state, { type: "CARD_CONTROLS_CHANGED", subjectReference: cardReference, actorReference: ownerReference, outcome: status, details: { ecommerceEnabled: card.ecommerceEnabled, contactlessEnabled: card.contactlessEnabled, cashWithdrawalEnabled: card.cashWithdrawalEnabled } }, this.now);
      addOutbox(state, { type: "CARD_CONTROLS_CHANGED", aggregateReference: ownerReference, payload: { cardReference, status }, correlationId: opaqueId("corr") }, this.now);
      return card;
    });
  }

  createControlChallenge({ cardReference, ownerReference, deviceReference, operation, idempotencyKey }) {
    const card = this.repository.snapshot().cards[requireOpaque(cardReference)];
    if (!card || card.ownerReference !== ownerReference) throw new BankError("CARD_NOT_FOUND", 404);
    if (!["SUSPEND", "RESUME"].includes(operation)) throw new BankError("INVALID_CARD_OPERATION");
    return this.identity.createScaChallenge({ customerReference: ownerReference, deviceReference, operation: "CARD_CONTROL", accountReference: cardReference, counterpartyReference: operation, amountMinor: 0, currency: "EUR", operationReference: cardReference, riskContext: "CARD_LIFECYCLE", idempotencyKey });
  }

  async setControlsWithSca({ cardReference, ownerReference, challengeId, signature, operation, idempotencyKey }) {
    await this.repository.transaction((state) => {
      this.identity.verifyScaInState(state, { challengeId, signature, expected: { operation: "CARD_CONTROL", accountReference: cardReference, counterpartyReference: operation, amountMinor: 0, currency: "EUR", operationReference: cardReference, idempotencyKey } });
      return true;
    });
    const card = this.repository.snapshot().cards[cardReference];
    return this.setControls({ cardReference, ownerReference, status: operation === "SUSPEND" ? "SUSPENDED" : "ACTIVE", ecommerceEnabled: card.ecommerceEnabled, contactlessEnabled: operation === "RESUME", cashWithdrawalEnabled: operation === "RESUME", idempotencyKey });
  }

  createDetailsChallenge({ cardReference, ownerReference, deviceReference, idempotencyKey }) {
    const card = this.repository.snapshot().cards[requireOpaque(cardReference)]; if (!card || card.ownerReference !== ownerReference || card.status !== "ACTIVE") throw new BankError("CARD_NOT_AVAILABLE", 404);
    if (!this.detailsProvider.configured) throw new BankError("CARD_DETAILS_PROVIDER_NOT_CONFIGURED", 503, true);
    return this.identity.createScaChallenge({ customerReference: ownerReference, deviceReference, operation: "CARD_DETAILS", accountReference: cardReference, counterpartyReference: "issuer_provider", amountMinor: 0, currency: "EUR", operationReference: cardReference, riskContext: "SENSITIVE_DATA", idempotencyKey });
  }

  async getSensitiveDetails({ cardReference, ownerReference, challengeId, signature, idempotencyKey }) {
    if (!this.detailsProvider.configured) throw new BankError("CARD_DETAILS_PROVIDER_NOT_CONFIGURED", 503, true);
    await this.repository.transaction((state) => {
      const card = state.cards[requireOpaque(cardReference)]; if (!card || card.ownerReference !== ownerReference || card.status !== "ACTIVE") throw new BankError("CARD_NOT_AVAILABLE", 404);
      this.identity.verifyScaInState(state, { challengeId, signature, expected: { operation: "CARD_DETAILS", accountReference: cardReference, counterpartyReference: "issuer_provider", amountMinor: 0, currency: "EUR", operationReference: cardReference, idempotencyKey } });
      addAudit(state, { type: "CARD_DETAILS_AUTHORIZED", subjectReference: cardReference, actorReference: ownerReference, outcome: "SUCCESS" }, this.now); return true;
    });
    const details = await this.detailsProvider.fetchDetails({ cardReference, ownerReference });
    if (!/^\d{13,19}$/.test(details.pan) || !/^\d{3,4}$/.test(details.securityCode) || !/^\d{2}\/\d{2}$/.test(details.expiry) || (details.pin != null && !/^\d{4,8}$/.test(details.pin))) throw new BankError("INVALID_PROVIDER_RESPONSE", 502);
    return { ...details, ttlSeconds: Math.min(60, details.ttlSeconds ?? 30), cacheControl: "no-store" };
  }

  async provisionWallet({ cardReference, ownerReference, deviceReference, walletInstanceReference, idempotencyKey }) {
    if (!this.walletAdapter.configured) throw new BankError("WALLET_PROVIDER_NOT_CONFIGURED", 503, true);
    const card = this.repository.snapshot().cards[requireOpaque(cardReference)]; if (!card || card.ownerReference !== ownerReference || card.status !== "ACTIVE") throw new BankError("CARD_NOT_AVAILABLE", 404);
    const provider = await this.walletAdapter.provision({ cardReference, deviceReference, walletInstanceReference, idempotencyKey });
    return this.repository.transaction((state) => {
      const key = `wallet:${idempotencyKey}`; if (state.idempotency[key]) return state.walletTokens[state.idempotency[key]];
      const tokenReference = opaqueId("wallettoken"); const token = { tokenReference, cardReference, ownerReference, deviceReference, walletInstanceReference, providerTokenReference: provider.providerTokenReference, status: provider.status, createdAt: iso(this.now()) };
      state.walletTokens[tokenReference] = token; state.idempotency[key] = tokenReference; return token;
    });
  }

  createWalletChallenge({ cardReference, ownerReference, deviceReference, idempotencyKey }) {
    const card = this.repository.snapshot().cards[requireOpaque(cardReference)];
    if (!card || card.ownerReference !== ownerReference || card.status !== "ACTIVE") throw new BankError("CARD_NOT_AVAILABLE", 404);
    if (!this.walletAdapter.configured) throw new BankError("WALLET_PROVIDER_NOT_CONFIGURED", 503, true);
    return this.identity.createScaChallenge({ customerReference: ownerReference, deviceReference, operation: "WALLET_PROVISION", accountReference: cardReference, counterpartyReference: "wallet_provider", amountMinor: 0, currency: "EUR", operationReference: cardReference, riskContext: "TOKEN_PROVISIONING", idempotencyKey });
  }

  async provisionWalletWithSca({ cardReference, ownerReference, deviceReference, walletInstanceReference, challengeId, signature, idempotencyKey }) {
    await this.repository.transaction((state) => {
      this.identity.verifyScaInState(state, { challengeId, signature, expected: { operation: "WALLET_PROVISION", accountReference: cardReference, counterpartyReference: "wallet_provider", amountMinor: 0, currency: "EUR", operationReference: cardReference, idempotencyKey } });
      return true;
    });
    return this.provisionWallet({ cardReference, ownerReference, deviceReference, walletInstanceReference, idempotencyKey });
  }
}
