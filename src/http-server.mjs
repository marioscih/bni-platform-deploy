import { createServer } from "node:http";
import { BankError, opaqueId, safeEqual, sha256 } from "./shared/kernel.mjs";

const MAX_BODY = 64 * 1024;
const MAX_BACKUP_BODY = 4 * 1024 * 1024;

async function body(request, maximum = MAX_BODY) {
  let total = 0; const chunks = [];
  for await (const chunk of request) { total += chunk.length; if (total > maximum) throw new BankError("REQUEST_TOO_LARGE", 413); chunks.push(chunk); }
  if (chunks.length === 0) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { throw new BankError("INVALID_JSON"); }
}

function json(response, status, data, correlationId, headers = {}) {
  const bytes = Buffer.from(JSON.stringify(data));
  response.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": bytes.length, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Correlation-ID": correlationId, ...headers }); response.end(bytes);
}

function requiredIdempotency(request, input) { const value = request.headers["idempotency-key"] ?? input.idempotencyKey; if (typeof value !== "string") throw new BankError("IDEMPOTENCY_KEY_REQUIRED"); return value; }
function bearer(request) { const value = request.headers.authorization; if (typeof value !== "string" || !value.startsWith("Bearer ")) throw new BankError("UNAUTHENTICATED", 401); return value.slice(7); }

export function createPlatformHttpServer(platform, { adminToken = null, requireTlsForwarding = true } = {}) {
  return createServer(async (request, response) => {
    const correlationId = typeof request.headers["x-correlation-id"] === "string" ? request.headers["x-correlation-id"].slice(0, 96) : opaqueId("corr");
    try {
      if (requireTlsForwarding && request.headers["x-forwarded-proto"] !== "https") throw new BankError("HTTPS_REQUIRED", 400);
      const url = new URL(request.url, "https://platform.invalid"); const path = url.pathname; const method = request.method;
      platform.rateLimiter.consume(`${request.socket.remoteAddress ?? "unknown"}:${path}`);
      if (method === "GET" && path === "/health/live") return json(response, 200, { status: "UP" }, correlationId);
      if (method === "GET" && path === "/health/ready") {
        await platform.repository.ping?.();
        await platform.repository.refresh?.();
        return json(response, 200, { status: "READY", dependencies: { repository: "UP", externalProviders: "OPTIONAL_OR_DISABLED" } }, correlationId);
      }
      await platform.repository.refresh?.();
      if (method === "GET" && path === "/v2/capabilities") return json(response, 200, { data: platform.capabilities() }, correlationId);

      if ((method === "GET" || method === "POST") && path.startsWith("/v2/admin/")) {
        if (!adminToken || typeof request.headers["x-bni-admin-token"] !== "string" || !safeEqual(request.headers["x-bni-admin-token"], adminToken)) throw new BankError("FORBIDDEN", 403);
        if (method === "GET" && path === "/v2/admin/backup") {
          if (!platform.operations.backup) throw new BankError("BACKUP_NOT_CONFIGURED", 503);
          const backup = platform.operations.backup.create();
          return json(response, 200, { data: { backup: backup.toString("base64url"), sha256: sha256(backup), manifest: platform.operations.backup.manifest(), reconciliation: platform.operations.reconciliation.run() } }, correlationId);
        }
        if (method !== "POST") throw new BankError("NOT_FOUND", 404);
        const input = await body(request, path === "/v2/admin/restore" ? MAX_BACKUP_BODY : MAX_BODY);
        if (path === "/v2/admin/restore") {
          if (!platform.operations.backup || typeof input.backup !== "string" || !/^[A-Za-z0-9_-]+$/.test(input.backup)) throw new BankError("BACKUP_INVALID");
          const backup = Buffer.from(input.backup, "base64url");
          if (typeof input.sha256 !== "string" || !safeEqual(input.sha256, sha256(backup))) throw new BankError("BACKUP_CHECKSUM_MISMATCH");
          return json(response, 200, { data: { manifest: await platform.operations.backup.restore(backup), reconciliation: platform.operations.reconciliation.run() } }, correlationId);
        }
        if (path === "/v2/admin/provision-customer") return json(response, 201, { data: await platform.provisioning.provisionCustomer(input) }, correlationId);
        if (path === "/v2/admin/provision-merchant-terminal") return json(response, 201, { data: await platform.bniPay.provisionMerchantTerminal(input) }, correlationId);
        if (path === "/v2/admin/customers") return json(response, 201, { data: await platform.identity.bootstrapCustomer(input) }, correlationId);
        if (path === "/v2/admin/accounts") return json(response, 201, { data: await platform.ledger.createAccount(input) }, correlationId);
        if (path === "/v2/admin/journals") return json(response, 201, { data: await platform.ledger.postJournal(input) }, correlationId);
        if (path === "/v2/admin/merchants") return json(response, 201, { data: await platform.bniPay.registerMerchant(input) }, correlationId);
        if (path === "/v2/admin/terminals") return json(response, 201, { data: await platform.bniPay.registerTerminal(input) }, correlationId);
        if (path === "/v2/admin/cards") return json(response, 201, { data: await platform.cards.registerCard(input) }, correlationId);
        throw new BankError("NOT_FOUND", 404);
      }

      if (method === "POST" && path === "/v2/mobile/enrollment/start") return json(response, 200, { data: await platform.identity.beginEnrollment(await body(request)) }, correlationId);
      if (method === "POST" && path === "/v2/mobile/enrollment/complete") return json(response, 200, { data: await platform.identity.completeEnrollment(await body(request)) }, correlationId);
      if (method === "POST" && path === "/v2/mobile/login/start") return json(response, 200, { data: await platform.identity.beginLogin(await body(request)) }, correlationId);
      if (method === "POST" && path === "/v2/mobile/login/complete") return json(response, 200, { data: await platform.identity.completeLogin(await body(request)) }, correlationId);
      if (method === "POST" && path === "/v2/merchant/enrollment/complete") return json(response, 200, { data: await platform.bniPay.completeTerminalEnrollment(await body(request)) }, correlationId);
      if (method === "POST" && path === "/oauth/token") {
        const input = await body(request);
        if (input.grantType === "authorization_code") return json(response, 200, { data: await platform.identity.exchangeAuthorizationCode(input) }, correlationId);
        if (input.grantType === "refresh_token") return json(response, 200, { data: await platform.identity.refresh(input) }, correlationId);
        throw new BankError("UNSUPPORTED_GRANT_TYPE");
      }

      if (method === "POST" && path === "/v2/merchant/payment-intents") return json(response, 201, { data: await platform.bniPay.createPaymentIntent(await body(request)) }, correlationId);
      const merchantStatus = path.match(/^\/v2\/merchant\/payment-intents\/([^/]+)\/status$/);
      if (method === "GET" && merchantStatus) return json(response, 200, { data: await platform.bniPay.authenticateTerminalStatus({ terminalId: request.headers["x-terminal-id"], paymentIntentId: merchantStatus[1], requestNonce: request.headers["x-request-nonce"], requestedAt: request.headers["x-requested-at"], terminalSignature: request.headers["x-terminal-signature"] }) }, correlationId);

      const principal = platform.identity.authenticate(bearer(request));
      if (method === "GET" && path === "/v2/accounts") return json(response, 200, { data: platform.ledger.accountsForOwner(principal.sub) }, correlationId);
      const movement = path.match(/^\/v2\/accounts\/([^/]+)\/movements$/);
      if (method === "GET" && movement) return json(response, 200, { data: platform.ledger.movements(movement[1], principal.sub, { cursor: url.searchParams.get("cursor"), limit: Number(url.searchParams.get("limit") || 50) }) }, correlationId);
      if (method === "POST" && path === "/v2/beneficiaries") return json(response, 201, { data: await platform.transfers.addBeneficiary({ ...(await body(request)), ownerReference: principal.sub }) }, correlationId);
      if (method === "POST" && path === "/v2/transfers/quotes") { const input = await body(request); return json(response, 201, { data: await platform.transfers.createQuote({ ...input, customerReference: principal.sub, idempotencyKey: requiredIdempotency(request, input) }) }, correlationId); }
      const transferSca = path.match(/^\/v2\/transfers\/([^/]+)\/sca$/); if (method === "POST" && transferSca) return json(response, 200, { data: await platform.transfers.createScaChallenge({ quoteReference: transferSca[1], deviceReference: principal.device }) }, correlationId);
      const transferAuth = path.match(/^\/v2\/transfers\/([^/]+)\/authorize$/); if (method === "POST" && transferAuth) { const input = await body(request); return json(response, 200, { data: await platform.transfers.authorize({ ...input, quoteReference: transferAuth[1], idempotencyKey: requiredIdempotency(request, input) }) }, correlationId); }
      if (method === "GET" && path === "/v2/notifications") return json(response, 200, { data: platform.notifications.list(principal.sub) }, correlationId);
      const notificationRead = path.match(/^\/v2\/notifications\/([^/]+)\/read$/); if (method === "POST" && notificationRead) return json(response, 200, { data: await platform.notifications.markRead(notificationRead[1], principal.sub) }, correlationId);
      if (method === "GET" && path === "/v2/documents") return json(response, 200, { data: platform.documents.list(principal.sub) }, correlationId);
      const document = path.match(/^\/v2\/documents\/([^/]+)$/); if (method === "GET" && document) { const item = platform.documents.get(document[1], principal.sub); response.writeHead(200, { "Content-Type": "application/pdf", "Content-Length": item.bytes.length, "Cache-Control": "no-store", "Content-Disposition": "attachment", "X-Correlation-ID": correlationId }); return response.end(item.bytes); }
      if (method === "GET" && path === "/v2/cards") return json(response, 200, { data: platform.cards.list(principal.sub) }, correlationId);
      const cardControl = path.match(/^\/v2\/cards\/([^/]+)\/controls$/); if (method === "POST" && cardControl) { const input = await body(request); return json(response, 200, { data: await platform.cards.setControls({ ...input, cardReference: cardControl[1], ownerReference: principal.sub, idempotencyKey: requiredIdempotency(request, input) }) }, correlationId); }
      const cardChallenge = path.match(/^\/v2\/cards\/([^/]+)\/details\/sca$/); if (method === "POST" && cardChallenge) { const input = await body(request); return json(response, 200, { data: await platform.cards.createDetailsChallenge({ cardReference: cardChallenge[1], ownerReference: principal.sub, deviceReference: principal.device, idempotencyKey: requiredIdempotency(request, input) }) }, correlationId); }
      const cardDetails = path.match(/^\/v2\/cards\/([^/]+)\/details$/); if (method === "POST" && cardDetails) { const input = await body(request); return json(response, 200, { data: await platform.cards.getSensitiveDetails({ ...input, cardReference: cardDetails[1], ownerReference: principal.sub, idempotencyKey: requiredIdempotency(request, input) }) }, correlationId, { "Pragma": "no-cache" }); }
      if (method === "POST" && path === "/v2/bills/inquiry") { const input = await body(request); return json(response, 200, { data: await platform.bills.inquire({ ...input, customerReference: principal.sub, idempotencyKey: requiredIdempotency(request, input) }) }, correlationId); }
      const billSca = path.match(/^\/v2\/bills\/([^/]+)\/sca$/); if (method === "POST" && billSca) return json(response, 200, { data: await platform.bills.createScaChallenge({ quoteReference: billSca[1], deviceReference: principal.device }) }, correlationId);
      const billAuth = path.match(/^\/v2\/bills\/([^/]+)\/authorize$/); if (method === "POST" && billAuth) { const input = await body(request); return json(response, 200, { data: await platform.bills.authorize({ ...input, quoteReference: billAuth[1], idempotencyKey: requiredIdempotency(request, input) }) }, correlationId); }
      const customerIntent = path.match(/^\/v2\/bni-pay\/payment-intents\/([^/]+)$/); if (method === "GET" && customerIntent) return json(response, 200, { data: platform.bniPay.getPaymentIntent(customerIntent[1]) }, correlationId);
      const bniSca = path.match(/^\/v2\/bni-pay\/payment-intents\/([^/]+)\/sca$/); if (method === "POST" && bniSca) { const input = await body(request); return json(response, 200, { data: await platform.bniPay.createScaChallenge({ ...input, paymentIntentId: bniSca[1], customerReference: principal.sub, deviceReference: principal.device, idempotencyKey: requiredIdempotency(request, input) }) }, correlationId); }
      const bniAuth = path.match(/^\/v2\/bni-pay\/payment-intents\/([^/]+)\/authorize$/); if (method === "POST" && bniAuth) { const input = await body(request); return json(response, 200, { data: await platform.bniPay.authorize({ ...input, paymentIntentId: bniAuth[1], customerReference: principal.sub, deviceReference: principal.device, idempotencyKey: requiredIdempotency(request, input) }) }, correlationId); }
      throw new BankError("NOT_FOUND", 404);
    } catch (error) {
      const bankError = error instanceof BankError ? error : new BankError("INTERNAL_ERROR", 500);
      json(response, bankError.httpStatus, { error: { code: bankError.code, retryable: bankError.retryable } }, correlationId);
    }
  });
}
