import { BankRepository, addAudit } from "./shared/repository.mjs";
import { BankError, iso } from "./shared/kernel.mjs";
import { IdentityService, TokenService, SlidingWindowRateLimiter } from "./identity-access/identity-service.mjs";
import { LedgerService } from "./ledger/ledger-service.mjs";
import { DocumentService } from "./documents/document-service.mjs";
import { BankDirectory, TransferService, UnavailableSepaAdapter, normalizeIban, validIban } from "./beneficiaries-transfers/transfer-service.mjs";
import { NotificationService, UnavailablePushAdapter } from "./notifications/notification-service.mjs";
import { BillService, UnavailableBillsAdapter } from "./bills/bill-service.mjs";
import { CardService, UnavailableCardDetailsProvider, UnavailableWalletAdapter } from "./cards/card-service.mjs";
import { BniPayService, generateIntentSigningKeyPair } from "./bni-pay/bni-pay-service.mjs";
import { RuleRiskEngine } from "./fraud-compliance/risk-engine.mjs";
import { EncryptedBackupService, ReconciliationService } from "./audit-operations/operations-service.mjs";

export function createPlatform({ repository = new BankRepository(), tokenSigningKey, tokenIssuer, tokenAudience, activationPepper, intentSigningKeyPair = generateIntentSigningKeyPair(), bankDirectory = new BankDirectory(), sepaAdapter = new UnavailableSepaAdapter(), billsAdapter = new UnavailableBillsAdapter(), cardDetailsProvider = new UnavailableCardDetailsProvider(), walletAdapter = new UnavailableWalletAdapter(), pushAdapter = new UnavailablePushAdapter(), riskEngine = null, backupEncryptionKey = null, comparisonNoAuthTransfers = false, now = () => new Date() } = {}) {
  riskEngine ??= new RuleRiskEngine({ now });
  const tokenService = new TokenService({ signingKey: tokenSigningKey, issuer: tokenIssuer, audience: tokenAudience, now });
  const identity = new IdentityService({ repository, tokenService, activationPepper, now });
  const ledger = new LedgerService({ repository, now }); const documents = new DocumentService({ repository, now });
  const transfers = new TransferService({ repository, ledger, identity, documents, bankDirectory, sepaAdapter, riskEngine, now });
  const notifications = new NotificationService({ repository, pushAdapter, now });
  const bills = new BillService({ repository, ledger, identity, documents, adapter: billsAdapter, now });
  const cards = new CardService({ repository, identity, detailsProvider: cardDetailsProvider, walletAdapter, now });
  const bniPay = new BniPayService({ repository, ledger, identity, documents, enrollmentPepper: activationPepper, intentPrivateKey: intentSigningKeyPair.privateKey, intentPublicKey: intentSigningKeyPair.publicKey, riskEngine, now });
  const rateLimiter = new SlidingWindowRateLimiter({ limit: 30, windowMs: 60_000, now });
  const reconciliation = new ReconciliationService({ repository });
  const backup = backupEncryptionKey ? new EncryptedBackupService({ repository, encryptionKey: backupEncryptionKey }) : null;
  return {
    repository, identity, ledger, documents, transfers, notifications, bills, cards, bniPay, rateLimiter,
    features: Object.freeze({ comparisonNoAuthTransfers: comparisonNoAuthTransfers === true }),
    operations: { reconciliation, backup },
    provisioning: {
      correctAccountHolder({ accountReference, holderName, idempotencyKey }) {
        return repository.transaction((state) => {
          const key = `account-holder:${String(idempotencyKey ?? "")}`;
          if (!/^[A-Za-z0-9_-]{8,128}$/.test(String(idempotencyKey ?? ""))) throw new BankError("INVALID_IDEMPOTENCY_KEY");
          const account = state.accounts[String(accountReference ?? "")];
          if (!account || account.type !== "CUSTOMER") throw new BankError("ACCOUNT_NOT_FOUND", 404);
          const canonical = String(holderName ?? "").trim();
          if (canonical !== "Sciacca Mario") throw new BankError("INVALID_ACCOUNT_HOLDER");
          if (state.idempotency[key]) return { accountReference: account.accountReference, holderName: account.holderName, updatedAt: account.holderUpdatedAt };
          account.holderName = canonical; account.holderUpdatedAt = iso(now()); state.idempotency[key] = account.accountReference;
          addAudit(state, { type: "ACCOUNT_HOLDER_CORRECTED", subjectReference: account.accountReference, actorReference: "operations", outcome: "SUCCESS" }, now);
          return { accountReference: account.accountReference, holderName: account.holderName, updatedAt: account.holderUpdatedAt };
        });
      },
      provisionCustomer(input) {
        return repository.transaction((state) => {
          const customer = identity.bootstrapCustomerInState(state, input);
          const account = ledger.createAccountInState(state, {
            accountReference: input.accountReference,
            ownerReference: input.customerReference,
            displayName: input.accountDisplayName ?? "Conto BNI",
            type: "CUSTOMER",
            currency: input.currency ?? "EUR",
          });
          return { customer, account };
        });
      },
      migrateCardProfiles(input) {
        return repository.transaction((state) => {
          const migrationReference = String(input.migrationReference ?? "");
          const ownerReference = String(input.ownerReference ?? "");
          if (!/^[A-Za-z0-9_-]{8,128}$/.test(migrationReference)) throw new BankError("INVALID_MIGRATION_REFERENCE");
          if (!/^[A-Za-z0-9_-]{8,128}$/.test(ownerReference)) throw new BankError("INVALID_OWNER_REFERENCE");
          if (!state.customers[ownerReference]) throw new BankError("CUSTOMER_NOT_FOUND", 404);
          if (!Array.isArray(input.cards) || input.cards.length < 1 || input.cards.length > 10) throw new BankError("INVALID_CARD_PROFILES");
          const idempotencyKey = `card-profiles:${migrationReference}`;
          if (state.idempotency[idempotencyKey]) return { migrationReference, cards: cards.listInState(state, ownerReference) };
          for (const profile of input.cards) {
            const existing = state.cards[String(profile.cardReference ?? "")];
            if (existing) {
              if (existing.ownerReference !== ownerReference || existing.maskedLastFour !== profile.maskedLastFour) throw new BankError("CARD_PROFILE_CONFLICT", 409);
              continue;
            }
            cards.registerCardInState(state, { ...profile, ownerReference });
          }
          state.idempotency[idempotencyKey] = ownerReference;
          addAudit(state, { type: "CARD_PROFILES_MIGRATED", subjectReference: ownerReference, actorReference: "operations", outcome: "SUCCESS", details: { cardCount: input.cards.length } }, now);
          return { migrationReference, cards: cards.listInState(state, ownerReference) };
        });
      },
      migrateAccountHistory(input) {
        return repository.transaction((state) => {
          const migrationReference = String(input.migrationReference ?? "");
          if (!/^[A-Za-z0-9_-]{8,128}$/.test(migrationReference)) throw new BankError("INVALID_MIGRATION_REFERENCE");
          const idempotencyKey = `account-history:${migrationReference}`;
          const account = state.accounts[String(input.accountReference ?? "")];
          if (!account || account.type !== "CUSTOMER" || account.status !== "ACTIVE") throw new BankError("ACCOUNT_NOT_FOUND", 404);
          if (state.idempotency[idempotencyKey]) return { migrationReference, account: { ...account, availableMinor: account.balanceMinor }, importedMovements: Number(state.idempotency[idempotencyKey].split(":")[1] ?? 0) };
          if (account.balanceMinor !== 0 || Object.values(state.journals).some((journal) => journal.postings.some((posting) => posting.accountReference === account.accountReference))) throw new BankError("ACCOUNT_HISTORY_NOT_EMPTY", 409);

          const holderName = String(input.holderName ?? "").trim();
          const iban = normalizeIban(input.iban);
          if (holderName.length < 2 || holderName.length > 100) throw new BankError("INVALID_ACCOUNT_HOLDER");
          if (!validIban(iban)) throw new BankError("INVALID_IBAN");
          if (!Number.isSafeInteger(input.targetBalanceMinor) || input.targetBalanceMinor < 0) throw new BankError("INVALID_TARGET_BALANCE");
          if (!Array.isArray(input.movements) || input.movements.length > 100) throw new BankError("INVALID_MIGRATION_MOVEMENTS");

          const movements = input.movements.map((movement, index) => {
            const deltaMinor = movement.deltaMinor;
            const bookedAt = new Date(movement.bookedAt);
            if (!Number.isSafeInteger(deltaMinor) || deltaMinor === 0 || Number.isNaN(bookedAt.getTime()) || bookedAt.getTime() > now().getTime() + 300_000) throw new BankError("INVALID_MIGRATION_MOVEMENT");
            const description = String(movement.description ?? "").trim();
            const type = String(movement.type ?? "MIGRATED_MOVEMENT").trim();
            if (description.length < 1 || description.length > 140 || !/^[A-Z0-9_]{2,64}$/.test(type)) throw new BankError("INVALID_MIGRATION_MOVEMENT");
            return { index, deltaMinor, bookedAt: iso(bookedAt), description, type };
          }).sort((left, right) => left.bookedAt.localeCompare(right.bookedAt) || left.index - right.index);

          const contraReference = `system_migration_${account.currency.toLowerCase()}`;
          if (!state.accounts[contraReference]) ledger.createAccountInState(state, { accountReference: contraReference, ownerReference: "system_bni_migration", displayName: "BNI Migration Control", type: "SYSTEM", currency: account.currency });
          const movementTotal = movements.reduce((sum, movement) => sum + movement.deltaMinor, 0);
          const openingDelta = input.targetBalanceMinor - movementTotal;
          if (!Number.isSafeInteger(openingDelta) || openingDelta <= 0) throw new BankError("INVALID_OPENING_BALANCE");
          const openingBookedAt = new Date(input.openingBookedAt);
          if (Number.isNaN(openingBookedAt.getTime()) || openingBookedAt.getTime() > now().getTime() + 300_000) throw new BankError("INVALID_BOOKING_DATE");

          account.holderName = holderName;
          account.iban = iban;
          ledger.postJournalInState(state, {
            journalReference: `journal_${migrationReference}_opening`, idempotencyKey: `ledger_${migrationReference}_opening`, type: "MIGRATED_OPENING_BALANCE",
            description: String(input.openingDescription ?? "Saldo iniziale migrato"), correlationId: `corr_${migrationReference}`,
            metadata: { migrationReference }, bookedAt: iso(openingBookedAt), postings: [
              { accountReference: contraReference, deltaMinor: -openingDelta },
              { accountReference: account.accountReference, deltaMinor: openingDelta },
            ],
          });
          for (const movement of movements) ledger.postJournalInState(state, {
            journalReference: `journal_${migrationReference}_${movement.index + 1}`,
            idempotencyKey: `ledger_${migrationReference}_${movement.index + 1}`,
            type: movement.type, description: movement.description, correlationId: `corr_${migrationReference}_${movement.index + 1}`,
            metadata: { migrationReference, imported: true }, bookedAt: movement.bookedAt, postings: [
              { accountReference: contraReference, deltaMinor: -movement.deltaMinor },
              { accountReference: account.accountReference, deltaMinor: movement.deltaMinor },
            ],
          });
          if (account.balanceMinor !== input.targetBalanceMinor) throw new BankError("MIGRATION_BALANCE_MISMATCH", 500);
          state.idempotency[idempotencyKey] = `${account.accountReference}:${movements.length + 1}`;
          addAudit(state, { type: "ACCOUNT_HISTORY_MIGRATED", subjectReference: account.accountReference, actorReference: "system_bni_migration", outcome: "SUCCESS", details: { movementCount: movements.length + 1, targetBalanceMinor: input.targetBalanceMinor, currency: account.currency } }, now);
          return { migrationReference, account: { ...account, availableMinor: account.balanceMinor }, importedMovements: movements.length + 1 };
        });
      },
    },
    capabilities() {
      return {
        accounts: true, transfersInternal: true, transfersSepa: sepaAdapter.configured === true, notificationsInbox: true,
        push: pushAdapter.configured === true, documents: true, bills: billsAdapter.configured === true,
        cards: true, cardDetails: cardDetailsProvider.configured === true, wallet: walletAdapter.configured === true,
        bniPay: true, genericPosCardPayment: false,
      };
    },
  };
}
