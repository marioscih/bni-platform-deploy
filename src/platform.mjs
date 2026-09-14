import { BankRepository } from "./shared/repository.mjs";
import { IdentityService, TokenService, SlidingWindowRateLimiter } from "./identity-access/identity-service.mjs";
import { LedgerService } from "./ledger/ledger-service.mjs";
import { DocumentService } from "./documents/document-service.mjs";
import { BankDirectory, TransferService } from "./beneficiaries-transfers/transfer-service.mjs";
import { NotificationService, UnavailablePushAdapter } from "./notifications/notification-service.mjs";
import { BillService, UnavailableBillsAdapter } from "./bills/bill-service.mjs";
import { CardService, UnavailableCardDetailsProvider, UnavailableWalletAdapter } from "./cards/card-service.mjs";
import { BniPayService, generateIntentSigningKeyPair } from "./bni-pay/bni-pay-service.mjs";
import { RuleRiskEngine } from "./fraud-compliance/risk-engine.mjs";

export function createPlatform({ repository = new BankRepository(), tokenSigningKey, tokenIssuer, tokenAudience, activationPepper, intentSigningKeyPair = generateIntentSigningKeyPair(), bankDirectory = new BankDirectory(), billsAdapter = new UnavailableBillsAdapter(), cardDetailsProvider = new UnavailableCardDetailsProvider(), walletAdapter = new UnavailableWalletAdapter(), pushAdapter = new UnavailablePushAdapter(), riskEngine = null, now = () => new Date() } = {}) {
  riskEngine ??= new RuleRiskEngine({ now });
  const tokenService = new TokenService({ signingKey: tokenSigningKey, issuer: tokenIssuer, audience: tokenAudience, now });
  const identity = new IdentityService({ repository, tokenService, activationPepper, now });
  const ledger = new LedgerService({ repository, now }); const documents = new DocumentService({ repository, now });
  const transfers = new TransferService({ repository, ledger, identity, documents, bankDirectory, riskEngine, now });
  const notifications = new NotificationService({ repository, pushAdapter, now });
  const bills = new BillService({ repository, ledger, identity, documents, adapter: billsAdapter, now });
  const cards = new CardService({ repository, identity, detailsProvider: cardDetailsProvider, walletAdapter, now });
  const bniPay = new BniPayService({ repository, ledger, identity, documents, enrollmentPepper: activationPepper, intentPrivateKey: intentSigningKeyPair.privateKey, intentPublicKey: intentSigningKeyPair.publicKey, riskEngine, now });
  const rateLimiter = new SlidingWindowRateLimiter({ limit: 30, windowMs: 60_000, now });
  return {
    repository, identity, ledger, documents, transfers, notifications, bills, cards, bniPay, rateLimiter,
    provisioning: {
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
    },
    capabilities() {
      return {
        accounts: true, transfersInternal: true, transfersSepa: false, notificationsInbox: true,
        push: pushAdapter.configured === true, documents: true, bills: billsAdapter.configured === true,
        cards: true, cardDetails: cardDetailsProvider.configured === true, wallet: walletAdapter.configured === true,
        bniPay: true, genericPosCardPayment: false,
      };
    },
  };
}
