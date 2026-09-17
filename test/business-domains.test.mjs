import test from "node:test";
import assert from "node:assert/strict";
import { BankRepository } from "../src/shared/repository.mjs";
import { IdentityService, TokenService, generateDevelopmentDeviceKeyPair } from "../src/identity-access/identity-service.mjs";
import { LedgerService } from "../src/ledger/ledger-service.mjs";
import { DocumentService } from "../src/documents/document-service.mjs";
import { BankDirectory, SimulatorSepaAdapter, TransferService, italianBankCoordinates, validIban } from "../src/beneficiaries-transfers/transfer-service.mjs";
import { NotificationService } from "../src/notifications/notification-service.mjs";
import { BillService, UnavailableBillsAdapter } from "../src/bills/bill-service.mjs";
import { CardService, SimulatorCardDetailsProvider, UnavailableCardDetailsProvider, UnavailableWalletAdapter } from "../src/cards/card-service.mjs";

async function fixture() {
  const now = () => new Date("2026-09-13T12:00:00Z"); const repository = new BankRepository();
  const identity = new IdentityService({ repository, tokenService: new TokenService({ signingKey: Buffer.alloc(32, 9), now }), activationPepper: "business-test-pepper", now });
  const ledger = new LedgerService({ repository, now }); const documents = new DocumentService({ repository, now });
  const key = generateDevelopmentDeviceKeyPair();
  await identity.bootstrapCustomer({ customerReference: "customer_alpha", activationCode: "ACTIVATE-2026-A" });
  const enrollment = await identity.beginEnrollment({ customerReference: "customer_alpha", deviceReference: "device_alpha", publicKeySpki: key.publicKeySpki, activationCode: "ACTIVATE-2026-A" });
  await identity.completeEnrollment({ challengeId: enrollment.challengeId, signature: key.sign(enrollment.material), appInstanceReference: "instance_alpha" });
  await ledger.createAccount({ accountReference: "system_funding", ownerReference: "owner_system", displayName: "Funding", type: "SYSTEM" });
  await ledger.createAccount({ accountReference: "account_alpha", ownerReference: "customer_alpha", displayName: "Conto BNI", type: "CUSTOMER" });
  await ledger.createAccount({ accountReference: "account_beta", ownerReference: "customer_beta", displayName: "Conto BNI", type: "CUSTOMER" });
  await ledger.createAccount({ accountReference: "bills_clearing", ownerReference: "owner_system", displayName: "Bills clearing", type: "SYSTEM" });
  await ledger.postJournal({ idempotencyKey: "opening_alpha_001", type: "OPENING", description: "Opening", postings: [{ accountReference: "system_funding", deltaMinor: -100_000 }, { accountReference: "account_alpha", deltaMinor: 100_000 }] });
  return { repository, identity, ledger, documents, key, now };
}

test("Italian IBAN validation exposes ABI/CAB without asserting account existence", () => {
  const iban = "IT60X0542811101000000123456";
  assert.equal(validIban(iban), true);
  assert.deepEqual(italianBankCoordinates(iban), { cin: "X", abi: "05428", cab: "11101", accountFragment: "3456" });
  assert.equal(new BankDirectory({ "05428": "Banca configurata" }).lookup("05428").accountExistenceVerified, false);
});

test("internal transfer is SCA-bound, atomic, idempotent and produces server receipt", async () => {
  const f = await fixture(); const service = new TransferService({ ...f, bankDirectory: new BankDirectory() });
  const beneficiary = await service.addBeneficiary({ ownerReference: "customer_alpha", displayName: "Destinatario", internalAccountReference: "account_beta" });
  const quote = await service.createQuote({ customerReference: "customer_alpha", sourceAccountReference: "account_alpha", beneficiaryReference: beneficiary.beneficiaryReference, amountMinor: 12_345, currency: "EUR", description: "Pagamento fattura", idempotencyKey: "quote_transfer_001" });
  const challenge = await service.createScaChallenge({ quoteReference: quote.quoteReference, deviceReference: "device_alpha" });
  const transfer = await service.authorize({ quoteReference: quote.quoteReference, challengeId: challenge.challengeId, signature: f.key.sign(challenge.material), idempotencyKey: "authorize_transfer_001" });
  const retry = await service.authorize({ quoteReference: quote.quoteReference, challengeId: challenge.challengeId, signature: f.key.sign(challenge.material), idempotencyKey: "authorize_transfer_001" });
  assert.equal(transfer.transferReference, retry.transferReference);
  assert.equal(transfer.status, "SETTLED");
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 87_655);
  assert.equal(f.ledger.account("account_beta", "customer_beta").balanceMinor, 12_345);
  const receipt = f.documents.get(transfer.receipt.documentReference, "customer_alpha");
  assert.equal(receipt.bytes.subarray(0, 8).toString(), "%PDF-1.4");
});

test("external transfer remains fail-closed without a SEPA adapter", async () => {
  const f = await fixture(); const service = new TransferService({ ...f });
  const beneficiary = await service.addBeneficiary({ ownerReference: "customer_alpha", displayName: "Esterno", iban: "IT60X0542811101000000123456" });
  await assert.rejects(() => service.createQuote({ customerReference: "customer_alpha", sourceAccountReference: "account_alpha", beneficiaryReference: beneficiary.beneficiaryReference, amountMinor: 100, currency: "EUR", description: "Test", idempotencyKey: "quote_external_001" }), /SEPA_ADAPTER_NOT_CONFIGURED/);
});

test("simulator SEPA adapter books one idempotent accepted transfer and receipt", async () => {
  const f = await fixture();
  await f.ledger.createAccount({ accountReference: "system_sepa_simulator", ownerReference: "owner_system", displayName: "SEPA simulator clearing", type: "SYSTEM" });
  const service = new TransferService({ ...f, sepaAdapter: new SimulatorSepaAdapter({ now: f.now }) });
  const prepared = await service.prepare({ customerReference: "customer_alpha", sourceAccountReference: "account_alpha", displayName: "Esterno", iban: "IT60X0542811101000000123456", amountMinor: 1_250, currency: "EUR", description: "Test esterno", idempotencyKey: "simulator_transfer_001" });
  const sca = await service.createScaChallenge({ quoteReference: prepared.quote.quoteReference, deviceReference: "device_alpha" });
  const first = await service.authorize({ quoteReference: prepared.quote.quoteReference, challengeId: sca.challengeId, signature: f.key.sign(sca.material), idempotencyKey: "simulator_transfer_authorize_001" });
  const retry = await service.authorize({ quoteReference: prepared.quote.quoteReference, challengeId: sca.challengeId, signature: f.key.sign(sca.material), idempotencyKey: "simulator_transfer_authorize_001" });
  assert.equal(first.transferReference, retry.transferReference);
  assert.equal(first.status, "ACCEPTED");
  assert.ok(first.receipt.documentReference);
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 98_750);
});

test("comparison authorization bypass is customer-bound, audited and idempotent", async () => {
  const f = await fixture(); const service = new TransferService({ ...f, bankDirectory: new BankDirectory() });
  const beneficiary = await service.addBeneficiary({ ownerReference: "customer_alpha", displayName: "Destinatario", internalAccountReference: "account_beta" });
  const quote = await service.createQuote({ customerReference: "customer_alpha", sourceAccountReference: "account_alpha", beneficiaryReference: beneficiary.beneficiaryReference, amountMinor: 2_500, currency: "EUR", description: "Confronto no auth", idempotencyKey: "quote_comparison_001" });
  await assert.rejects(() => service.authorizeComparison({ quoteReference: quote.quoteReference, customerReference: "customer_beta", idempotencyKey: "comparison_authorize_001" }), /FORBIDDEN/);
  const first = await service.authorizeComparison({ quoteReference: quote.quoteReference, customerReference: "customer_alpha", idempotencyKey: "comparison_authorize_001" });
  const retry = await service.authorizeComparison({ quoteReference: quote.quoteReference, customerReference: "customer_alpha", idempotencyKey: "comparison_authorize_001" });
  assert.equal(first.transferReference, retry.transferReference);
  assert.equal(first.status, "SETTLED");
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 97_500);
  assert.match(JSON.stringify(f.repository.snapshot()), /TRANSFER_COMPARISON_AUTHORIZATION_BYPASS/);
});

test("outbox projects idempotent inbox notifications with allowlisted deep links", async () => {
  const f = await fixture(); const notifications = new NotificationService({ repository: f.repository, now: f.now });
  const first = await notifications.projectPending(); const second = await notifications.projectPending();
  assert.ok(first.length >= 2); assert.equal(second.length, 0);
  const inbox = notifications.list("customer_alpha"); assert.ok(inbox.length >= 1);
  assert.ok(inbox.every((item) => !item.deepLink.includes("://")));
  await notifications.markRead(inbox[0].notificationReference, "customer_alpha");
  assert.ok(notifications.list("customer_alpha")[0].readAt);
});

test("CBILL and pagoPA are unavailable in production without provider configuration", async () => {
  const f = await fixture(); const bills = new BillService({ ...f, adapter: new UnavailableBillsAdapter() });
  await assert.rejects(() => bills.inquire({ customerReference: "customer_alpha", sourceAccountReference: "account_alpha", type: "PAGOPA", noticeCode: "123456789012345678", creditorCode: "ENTE01", idempotencyKey: "bill_quote_001" }), /BILLS_PROVIDER_NOT_CONFIGURED/);
});

test("configured bill adapter uses authoritative quote, SCA, ledger and receipt", async () => {
  const f = await fixture();
  const adapter = { configured: true, async inquiry() { return { amountMinor: 5_000, feeMinor: 50, currency: "EUR", creditorName: "Ente creditore", providerReference: "creditor_pagopa_001" }; }, async submit() { return { status: "ACCEPTED", providerTransactionReference: "provider_txn_001" }; } };
  const bills = new BillService({ ...f, adapter });
  const quote = await bills.inquire({ customerReference: "customer_alpha", sourceAccountReference: "account_alpha", type: "PAGOPA", noticeCode: "123456789012345678", creditorCode: "ENTE01", idempotencyKey: "bill_quote_001" });
  assert.equal(quote.amountMinor, 5_000);
  const challenge = await bills.createScaChallenge({ quoteReference: quote.quoteReference, deviceReference: "device_alpha" });
  const payment = await bills.authorize({ quoteReference: quote.quoteReference, challengeId: challenge.challengeId, signature: f.key.sign(challenge.material), idempotencyKey: "bill_authorize_001", clearingAccountReference: "bills_clearing" });
  assert.equal(payment.status, "ACCEPTED"); assert.ok(payment.receipt.documentReference);
  assert.equal(f.ledger.account("account_alpha", "customer_alpha").balanceMinor, 94_950);
});

test("card details fail closed when issuer provider is absent", async () => {
  const f = await fixture(); const cards = new CardService({ ...f, detailsProvider: new UnavailableCardDetailsProvider() });
  await cards.registerCard({ cardReference: "card_alpha", ownerReference: "customer_alpha", displayName: "Carta di debito", product: "Debit", maskedLastFour: "4321" });
  assert.throws(() => cards.createDetailsChallenge({ cardReference: "card_alpha", ownerReference: "customer_alpha", deviceReference: "device_alpha", idempotencyKey: "details_card_001" }), /CARD_DETAILS_PROVIDER_NOT_CONFIGURED/);
});

test("issuer details are transient and never persisted", async () => {
  const f = await fixture();
  const testPan = ["4111", "1111", "1111", "1111"].join("");
  const testSecurityCode = [1, 2, 3].join("");
  const detailsProvider = { configured: true, async fetchDetails() { return { pan: testPan, expiry: "12/30", securityCode: testSecurityCode, cardholder: "CUSTOMER", ttlSeconds: 20 }; } };
  const cards = new CardService({ ...f, detailsProvider });
  await cards.registerCard({ cardReference: "card_alpha", ownerReference: "customer_alpha", displayName: "Carta di debito", product: "Debit", maskedLastFour: "1111" });
  const challenge = await cards.createDetailsChallenge({ cardReference: "card_alpha", ownerReference: "customer_alpha", deviceReference: "device_alpha", idempotencyKey: "details_card_001" });
  const details = await cards.getSensitiveDetails({ cardReference: "card_alpha", ownerReference: "customer_alpha", challengeId: challenge.challengeId, signature: f.key.sign(challenge.material), idempotencyKey: "details_card_001" });
  assert.equal(details.pan, testPan);
  const persisted = JSON.stringify(f.repository.snapshot());
  assert.equal(persisted.includes(testPan), false);
  assert.equal(persisted.includes(`"securityCode":"${testSecurityCode}"`), false);
});

test("simulator card provider returns transient server-derived PAN and PIN", async () => {
  const f = await fixture();
  await f.repository.transaction((state) => { state.accounts.account_alpha.holderName = "Sciacca Mario"; });
  const detailsProvider = new SimulatorCardDetailsProvider({ repository: f.repository, secret: Buffer.alloc(32, 7), now: f.now });
  const cards = new CardService({ ...f, detailsProvider });
  await cards.registerCard({ cardReference: "card_bancomat_sciacca_4418", ownerReference: "customer_alpha", displayName: "Carta BANCOMAT", product: "Carta di debito", maskedLastFour: "4418" });
  const challenge = await cards.createDetailsChallenge({ cardReference: "card_bancomat_sciacca_4418", ownerReference: "customer_alpha", deviceReference: "device_alpha", idempotencyKey: "simulator_card_details_001" });
  const details = await cards.getSensitiveDetails({ cardReference: "card_bancomat_sciacca_4418", ownerReference: "customer_alpha", challengeId: challenge.challengeId, signature: f.key.sign(challenge.material), idempotencyKey: "simulator_card_details_001" });
  assert.match(details.pan, /^\d{12}4418$/);
  assert.match(details.pin, /^\d{4}$/);
  assert.equal(details.cardholder, "Sciacca Mario");
  const persisted = JSON.stringify(f.repository.snapshot());
  assert.equal(persisted.includes(details.pan), false);
  assert.equal(persisted.includes(`\"pin\":\"${details.pin}\"`), false);
});

test("wallet and card controls are server-authoritative and fail closed by default", async () => {
  const f = await fixture(); const cards = new CardService({ ...f, walletAdapter: new UnavailableWalletAdapter() });
  await cards.registerCard({ cardReference: "card_alpha", ownerReference: "customer_alpha", displayName: "Carta", product: "Debit", maskedLastFour: "1111" });
  await assert.rejects(() => cards.provisionWallet({ cardReference: "card_alpha", ownerReference: "customer_alpha", deviceReference: "device_alpha", walletInstanceReference: "wallet_instance_001", idempotencyKey: "wallet_provision_001" }), /WALLET_PROVIDER_NOT_CONFIGURED/);
  const suspended = await cards.setControls({ cardReference: "card_alpha", ownerReference: "customer_alpha", status: "SUSPENDED", ecommerceEnabled: true, contactlessEnabled: true, cashWithdrawalEnabled: true, idempotencyKey: "card_control_001" });
  assert.equal(suspended.contactlessEnabled, false); assert.equal(suspended.cashWithdrawalEnabled, false);
});
