import { BankError, iso, opaqueId, requireOpaque, requireText } from "../shared/kernel.mjs";
import { addAudit, addOutbox } from "../shared/repository.mjs";

export class UnavailableCardDetailsProvider { constructor() { this.configured = false; } async fetchDetails() { throw new BankError("CARD_DETAILS_PROVIDER_NOT_CONFIGURED", 503, true); } }
export class UnavailableWalletAdapter { constructor() { this.configured = false; } async provision() { throw new BankError("WALLET_PROVIDER_NOT_CONFIGURED", 503, true); } async lifecycle() { throw new BankError("WALLET_PROVIDER_NOT_CONFIGURED", 503, true); } }

export class CardService {
  constructor({ repository, identity, detailsProvider = new UnavailableCardDetailsProvider(), walletAdapter = new UnavailableWalletAdapter(), now = () => new Date() } = {}) { Object.assign(this, { repository, identity, detailsProvider, walletAdapter, now }); }

  async registerCard({ cardReference, ownerReference, displayName, product, maskedLastFour, status = "ACTIVE" }) {
    requireOpaque(cardReference); requireOpaque(ownerReference); requireText(displayName, "INVALID_CARD_NAME", 80); requireText(product, "INVALID_CARD_PRODUCT", 80);
    if (!/^\d{4}$/.test(maskedLastFour)) throw new BankError("INVALID_MASKED_CARD");
    return this.repository.transaction((state) => {
      if (state.cards[cardReference]) throw new BankError("CARD_EXISTS", 409);
      const card = { cardReference, ownerReference, displayName, product, maskedLastFour, status, ecommerceEnabled: true, contactlessEnabled: true, cashWithdrawalEnabled: true, updatedAt: iso(this.now()) };
      state.cards[cardReference] = card; return card;
    });
  }

  list(ownerReference) { return this.repository.read((state) => Object.values(state.cards).filter((card) => card.ownerReference === ownerReference)); }

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
    if (!/^\d{13,19}$/.test(details.pan) || !/^\d{3,4}$/.test(details.securityCode) || !/^\d{2}\/\d{2}$/.test(details.expiry)) throw new BankError("INVALID_PROVIDER_RESPONSE", 502);
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
}
