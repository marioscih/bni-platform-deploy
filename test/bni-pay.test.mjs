import test from "node:test";
import assert from "node:assert/strict";
import { BankRepository } from "../src/shared/repository.mjs";
import { IdentityService, TokenService, generateDevelopmentDeviceKeyPair } from "../src/identity-access/identity-service.mjs";
import { LedgerService } from "../src/ledger/ledger-service.mjs";
import { DocumentService } from "../src/documents/document-service.mjs";
import { BniPayService, generateIntentSigningKeyPair, terminalRequestMaterial } from "../src/bni-pay/bni-pay-service.mjs";

async function setup({ customerBalance = 50_000, riskEngine } = {}) {
  let millis = Date.parse("2026-09-13T14:00:00Z"); const now = () => new Date(millis);
  const repository = new BankRepository(); const ledger = new LedgerService({ repository, now }); const documents = new DocumentService({ repository, now });
  const identity = new IdentityService({ repository, tokenService: new TokenService({ signingKey: Buffer.alloc(32, 3), now }), activationPepper: "bni-pay-test-pepper", now });
  const customerKey = generateDevelopmentDeviceKeyPair(); const terminalKey = generateDevelopmentDeviceKeyPair();
  await identity.bootstrapCustomer({ customerReference: "customer_alpha", activationCode: "ACTIVATE-2026-A" });
  const enrollment = await identity.beginEnrollment({ customerReference: "customer_alpha", deviceReference: "device_alpha", publicKeySpki: customerKey.publicKeySpki, activationCode: "ACTIVATE-2026-A" });
  await identity.completeEnrollment({ challengeId: enrollment.challengeId, signature: customerKey.sign(enrollment.material), appInstanceReference: "instance_alpha" });
  await ledger.createAccount({ accountReference: "system_funding", ownerReference: "owner_system", displayName: "Funding", type: "SYSTEM" });
  await ledger.createAccount({ accountReference: "account_alpha", ownerReference: "customer_alpha", displayName: "Conto", type: "CUSTOMER" });
  await ledger.createAccount({ accountReference: "merchant_account", ownerReference: "merchant_alpha", displayName: "Merchant", type: "MERCHANT" });
  if (customerBalance) await ledger.postJournal({ idempotencyKey: "opening_customer_001", type: "OPENING", description: "Opening", postings: [{ accountReference: "system_funding", deltaMinor: -customerBalance }, { accountReference: "account_alpha", deltaMinor: customerBalance }] });
  const signing = generateIntentSigningKeyPair();
  const service = new BniPayService({ repository, ledger, identity, documents, intentPrivateKey: signing.privateKey, intentPublicKey: signing.publicKey, riskEngine, now });
  await service.registerMerchant({ merchantId: "merchant_alpha", displayName: "Caffè Centrale", settlementAccountReference: "merchant_account" });
  await service.registerTerminal({ terminalId: "terminal_alpha", merchantId: "merchant_alpha", deviceReference: "pos_device_alpha", publicKeySpki: terminalKey.publicKeySpki });
  return { repository, ledger, documents, identity, customerKey, terminalKey, service, now, advance: (ms) => { millis += ms; } };
}

async function intent(f, { amountMinor = 1_250, nonce = "terminal_nonce_001", idempotencyKey = "intent_create_001" } = {}) {
  const request = { merchantId: "merchant_alpha", terminalId: "terminal_alpha", amountMinor, currency: "EUR", orderId: "order_alpha_001", requestNonce: nonce, requestedAt: f.now().toISOString(), idempotencyKey };
  return f.service.createPaymentIntent({ ...request, description: "Ordine", terminalSignature: f.terminalKey.sign(terminalRequestMaterial(request)) });
}

async function approve(f, paymentIntent, idempotencyKey = "payment_authorize_001") {
  const challenge = await f.service.createScaChallenge({ paymentIntentId: paymentIntent.paymentIntentId, customerReference: "customer_alpha", customerAccountReference: "account_alpha", deviceReference: "device_alpha", idempotencyKey });
  return f.service.authorize({ paymentIntentId: paymentIntent.paymentIntentId, terminalNonce: paymentIntent.terminalNonce, customerReference: "customer_alpha", customerAccountReference: "account_alpha", deviceReference: "device_alpha", challengeId: challenge.challengeId, signature: f.customerKey.sign(challenge.material), authorizationNonce: `auth_nonce_${idempotencyKey}`, idempotencyKey });
}

test("merchant-authenticated intent is signed and exposes only opaque NFC/QR data", async () => {
  const f = await setup(); const created = await intent(f);
  assert.equal(f.service.verifyIntent(created), true);
  const tampered = { ...created, amountMinor: created.amountMinor + 1 }; assert.equal(f.service.verifyIntent(tampered), false);
  const nfc = f.service.nfcPayload(created.paymentIntentId); assert.deepEqual(Object.keys(nfc).sort(), ["intentSignature", "paymentIntentId", "protocolVersion", "terminalNonce"]); assert.equal(nfc.intentSignature, created.signature);
  const qr = f.service.qrPayload(created.paymentIntentId); assert.match(qr, /^bni-pay:\/\/pay\/pi_/); assert.doesNotMatch(qr, /account|customer|1250|Caff/);
});

test("BNI Pay approval atomically debits customer, credits merchant and creates receipt", async () => {
  const f = await setup(); const created = await intent(f); const payment = await approve(f, created);
  assert.equal(payment.status, "APPROVED"); assert.equal(payment.transactionReference, created.transactionReference);
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 48_750);
  assert.equal(f.ledger.account("merchant_account", "merchant_alpha").balanceMinor, 1_250);
  assert.equal(f.documents.get(payment.receipt.documentReference, "customer_alpha").bytes.subarray(0, 8).toString(), "%PDF-1.4");
});

test("authorization retry returns the same result without a second debit", async () => {
  const f = await setup(); const created = await intent(f); const first = await approve(f, created);
  const second = await f.service.authorize({ paymentIntentId: created.paymentIntentId, terminalNonce: created.terminalNonce, customerReference: "customer_alpha", customerAccountReference: "account_alpha", deviceReference: "device_alpha", challengeId: "unused_challenge", signature: "unused_signature", authorizationNonce: "unused_nonce_0001", idempotencyKey: "payment_authorize_001" });
  assert.equal(second.transactionReference, first.transactionReference);
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 48_750);
});

test("backend ignores a tampered client amount and books original intent amount", async () => {
  const f = await setup(); const created = await intent(f, { amountMinor: 100 });
  const clientView = { ...created, amountMinor: 99_999 };
  const payment = await approve(f, clientView);
  assert.equal(payment.amountMinor, 100);
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 49_900);
});

test("merchant name is backend-owned and cannot be spoofed by NFC", async () => {
  const f = await setup(); const created = await intent(f); const nfc = { ...f.service.nfcPayload(created.paymentIntentId), merchantDisplayName: "Impostore" };
  const fetched = f.service.getPaymentIntent(nfc.paymentIntentId);
  assert.equal(fetched.merchantDisplayName, "Caffè Centrale");
});

test("insufficient funds declines without approved journal", async () => {
  const f = await setup({ customerBalance: 100 }); const created = await intent(f, { amountMinor: 200 }); const payment = await approve(f, created);
  assert.equal(payment.status, "DECLINED"); assert.equal(payment.decisionReason, "INSUFFICIENT_FUNDS");
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 100);
  assert.equal(f.ledger.account("merchant_account", "merchant_alpha").balanceMinor, 0);
});

test("suspended terminal cannot create an intent", async () => {
  const f = await setup(); await f.service.changeTerminalStatus({ terminalId: "terminal_alpha", status: "SUSPENDED" });
  await assert.rejects(() => intent(f), /TERMINAL_NOT_ACTIVE/);
});

test("pending intent can be cancelled while approved payment requires refund", async () => {
  const f = await setup(); const pending = await intent(f);
  const cancelled = await f.service.cancel({ paymentIntentId: pending.paymentIntentId, merchantId: "merchant_alpha", terminalId: "terminal_alpha", idempotencyKey: "cancel_intent_001" }); assert.equal(cancelled.status, "CANCELLED");
  const second = await intent(f, { nonce: "terminal_nonce_002", idempotencyKey: "intent_create_002" }); await approve(f, second, "payment_authorize_002");
  await assert.rejects(() => f.service.cancel({ paymentIntentId: second.paymentIntentId, merchantId: "merchant_alpha", terminalId: "terminal_alpha", idempotencyKey: "cancel_intent_002" }), /NOT_CANCELLABLE/);
  const refund = await f.service.refundFull({ paymentIntentId: second.paymentIntentId, merchantId: "merchant_alpha", idempotencyKey: "refund_payment_002" });
  assert.equal(refund.status, "APPROVED"); assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 50_000); assert.equal(f.ledger.account("merchant_account", "merchant_alpha").balanceMinor, 0);
});

test("risk decline and expiry never debit the account", async () => {
  const f = await setup({ riskEngine: { evaluate: () => ({ decision: "DENY", reasons: ["VELOCITY"] }) } });
  const created = await intent(f); const declined = await approve(f, created); assert.equal(declined.status, "DECLINED"); assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 50_000);
  const g = await setup(); const expiring = await intent(g); g.advance(121_000);
  assert.equal(g.service.getPaymentIntent(expiring.paymentIntentId).status, "EXPIRED");
  assert.equal(g.ledger.account("account_alpha", "customer_alpha").balanceMinor, 50_000);
});

test("merchant history uses backend status and daily total", async () => {
  const f = await setup(); const created = await intent(f); await approve(f, created);
  const history = f.service.merchantHistory("merchant_alpha"); assert.equal(history.items.length, 1); assert.equal(history.dailyTotalMinor, 1_250);
});
