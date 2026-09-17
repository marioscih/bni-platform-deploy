import test from "node:test";
import assert from "node:assert/strict";
import { BankRepository } from "../src/shared/repository.mjs";
import { IdentityService, TokenService, generateDevelopmentDeviceKeyPair } from "../src/identity-access/identity-service.mjs";
import { LedgerService } from "../src/ledger/ledger-service.mjs";

function fixture() {
  let millis = Date.parse("2026-09-13T10:00:00Z");
  const now = () => new Date(millis);
  const repository = new BankRepository();
  const tokenService = new TokenService({ signingKey: Buffer.alloc(32, 7), now });
  const identity = new IdentityService({ repository, tokenService, now, activationPepper: "phase2-test-pepper" });
  const ledger = new LedgerService({ repository, now });
  return { repository, identity, ledger, now, advance: (delta) => { millis += delta; } };
}

async function enrolled(f) {
  const key = generateDevelopmentDeviceKeyPair();
  await f.identity.bootstrapCustomer({ customerReference: "customer_alpha", activationCode: "ACTIVATE-2026-A" });
  const started = await f.identity.beginEnrollment({ customerReference: "customer_alpha", deviceReference: "device_alpha", publicKeySpki: key.publicKeySpki, activationCode: "ACTIVATE-2026-A" });
  await f.identity.completeEnrollment({ challengeId: started.challengeId, signature: key.sign(started.material), appInstanceReference: "instance_alpha" });
  return key;
}

test("device enrollment verifies possession and consumes one-time activation", async () => {
  const f = fixture(); const key = await enrolled(f);
  assert.ok(key.publicKeySpki.length > 80);
  await assert.rejects(() => f.identity.beginEnrollment({ customerReference: "customer_alpha", deviceReference: "device_beta", publicKeySpki: key.publicKeySpki, activationCode: "ACTIVATE-2026-A" }), /ENROLLMENT_DENIED/);
  assert.equal(f.repository.snapshot().devices.device_alpha.status, "ACTIVE");
});

test("login challenge cannot be replayed and PKCE is enforced", async () => {
  const f = fixture(); const key = await enrolled(f);
  const login = await f.identity.beginLogin({ customerReference: "customer_alpha", deviceReference: "device_alpha" });
  const codeChallenge = (await import("node:crypto")).createHash("sha256").update("verifier-secret").digest("hex");
  const authorized = await f.identity.completeLogin({ challengeId: login.challengeId, signature: key.sign(login.material), codeChallenge });
  await assert.rejects(() => f.identity.completeLogin({ challengeId: login.challengeId, signature: key.sign(login.material) }), /CHALLENGE_INVALID_OR_REPLAYED/);
  await assert.rejects(() => f.identity.exchangeAuthorizationCode({ authorizationCode: authorized.authorizationCode, codeVerifier: "wrong" }), /INVALID_PKCE_VERIFIER/);
  const tokens = await f.identity.exchangeAuthorizationCode({ authorizationCode: authorized.authorizationCode, codeVerifier: "verifier-secret" });
  assert.equal(f.identity.authenticate(tokens.accessToken).device, "device_alpha");
});

test("refresh rotation detects reuse and revokes the session", async () => {
  const f = fixture(); const key = await enrolled(f);
  const login = await f.identity.beginLogin({ customerReference: "customer_alpha", deviceReference: "device_alpha" });
  const auth = await f.identity.completeLogin({ challengeId: login.challengeId, signature: key.sign(login.material) });
  const first = await f.identity.exchangeAuthorizationCode({ authorizationCode: auth.authorizationCode });
  await f.identity.refresh({ refreshToken: first.refreshToken });
  await assert.rejects(() => f.identity.refresh({ refreshToken: first.refreshToken }), /REFRESH_REUSE_DETECTED/);
  assert.throws(() => f.identity.authenticate(first.accessToken), /SESSION_REVOKED/);
});

test("lost device blocks login and future authorization", async () => {
  const f = fixture(); await enrolled(f);
  await f.identity.changeDeviceStatus({ deviceReference: "device_alpha", status: "LOST" });
  await assert.rejects(() => f.identity.beginLogin({ customerReference: "customer_alpha", deviceReference: "device_alpha" }), /DEVICE_BINDING_REJECTED/);
});

test("ledger accepts balanced journal and derives available balance", async () => {
  const f = fixture();
  await f.ledger.createAccount({ accountReference: "system_funding", ownerReference: "owner_system", displayName: "Funding", type: "SYSTEM", allowNegative: true });
  await f.ledger.createAccount({ accountReference: "account_alpha", ownerReference: "customer_alpha", displayName: "Conto corrente", type: "CUSTOMER" });
  await f.ledger.postJournal({ idempotencyKey: "opening_alpha_001", type: "OPENING", description: "Opening balance", postings: [{ accountReference: "system_funding", deltaMinor: -10000 }, { accountReference: "account_alpha", deltaMinor: 10000 }] });
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").availableMinor, 10000);
});

test("unbalanced postings and overdraft are rejected atomically", async () => {
  const f = fixture();
  await f.ledger.createAccount({ accountReference: "account_alpha", ownerReference: "customer_alpha", displayName: "Conto", type: "CUSTOMER" });
  await f.ledger.createAccount({ accountReference: "account_beta", ownerReference: "customer_beta", displayName: "Conto", type: "CUSTOMER" });
  await assert.rejects(() => f.ledger.postJournal({ idempotencyKey: "bad_balance_001", type: "TRANSFER", description: "Bad", postings: [{ accountReference: "account_alpha", deltaMinor: -100 }, { accountReference: "account_beta", deltaMinor: 99 }] }), /LEDGER_UNBALANCED/);
  await assert.rejects(() => f.ledger.postJournal({ idempotencyKey: "bad_funds_001", type: "TRANSFER", description: "Bad", postings: [{ accountReference: "account_alpha", deltaMinor: -100 }, { accountReference: "account_beta", deltaMinor: 100 }] }), /INSUFFICIENT_FUNDS/);
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 0);
});

test("idempotent journal retry never posts twice", async () => {
  const f = fixture();
  await f.ledger.createAccount({ accountReference: "system_funding", ownerReference: "owner_system", displayName: "Funding", type: "SYSTEM" });
  await f.ledger.createAccount({ accountReference: "account_alpha", ownerReference: "customer_alpha", displayName: "Conto", type: "CUSTOMER" });
  const input = { idempotencyKey: "opening_alpha_001", type: "OPENING", description: "Opening", postings: [{ accountReference: "system_funding", deltaMinor: -1000 }, { accountReference: "account_alpha", deltaMinor: 1000 }] };
  const one = await f.ledger.postJournal(input); const two = await f.ledger.postJournal(input);
  assert.equal(one.journalReference, two.journalReference);
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 1000);
});

test("concurrent debits cannot double-spend", async () => {
  const f = fixture();
  await f.ledger.createAccount({ accountReference: "system_funding", ownerReference: "owner_system", displayName: "Funding", type: "SYSTEM" });
  await f.ledger.createAccount({ accountReference: "account_alpha", ownerReference: "customer_alpha", displayName: "Conto", type: "CUSTOMER" });
  await f.ledger.createAccount({ accountReference: "merchant_one", ownerReference: "merchant_owner", displayName: "Merchant", type: "MERCHANT" });
  await f.ledger.postJournal({ idempotencyKey: "opening_alpha_001", type: "OPENING", description: "Opening", postings: [{ accountReference: "system_funding", deltaMinor: -1000 }, { accountReference: "account_alpha", deltaMinor: 1000 }] });
  const debit = (key) => f.ledger.postJournal({ idempotencyKey: key, type: "PAYMENT", description: "Payment", postings: [{ accountReference: "account_alpha", deltaMinor: -700 }, { accountReference: "merchant_one", deltaMinor: 700 }] });
  const results = await Promise.allSettled([debit("payment_one"), debit("payment_two")]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 300);
});

test("SCA signature is bound to amount and counterparty", async () => {
  const f = fixture(); const key = await enrolled(f);
  const challenge = await f.identity.createScaChallenge({ customerReference: "customer_alpha", deviceReference: "device_alpha", operation: "TRANSFER", accountReference: "account_alpha", counterpartyReference: "beneficiary_beta", amountMinor: 2500, currency: "EUR", operationReference: "transfer_alpha", riskContext: "STANDARD", idempotencyKey: "transfer_key_001" });
  await assert.rejects(() => f.repository.transaction((state) => f.identity.verifyScaInState(state, { challengeId: challenge.challengeId, signature: key.sign(challenge.material), expected: { operation: "TRANSFER", amountMinor: 2600, counterpartyReference: "beneficiary_beta" } })), /SCA_DYNAMIC_LINK_MISMATCH/);
  const accepted = await f.repository.transaction((state) => f.identity.verifyScaInState(state, { challengeId: challenge.challengeId, signature: key.sign(challenge.material), expected: { operation: "TRANSFER", amountMinor: 2500, counterpartyReference: "beneficiary_beta" } }));
  assert.equal(accepted.amountMinor, 2500);
});
