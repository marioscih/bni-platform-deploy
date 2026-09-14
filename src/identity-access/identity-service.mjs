import {
  createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify,
} from "node:crypto";
import {
  BankError, base64url, canonicalFields, fromBase64url, hmac, iso, opaqueId,
  randomToken, requireOpaque, safeEqual, sha256,
} from "../shared/kernel.mjs";
import { addAudit, addOutbox } from "../shared/repository.mjs";

const ACTIVE = "ACTIVE";
const DEVICE_STATES = new Set([ACTIVE, "SUSPENDED", "REVOKED", "LOST"]);

function keyFromSpki(value) {
  try {
    return createPublicKey({ key: Buffer.from(value, "base64url"), format: "der", type: "spki" });
  } catch {
    throw new BankError("INVALID_DEVICE_PUBLIC_KEY");
  }
}

function verifyDevice(publicKeySpki, material, signature) {
  try {
    return cryptoVerify("sha256", Buffer.from(material), keyFromSpki(publicKeySpki), fromBase64url(signature));
  } catch {
    return false;
  }
}

export class TokenService {
  constructor({ signingKey, issuer = "https://identity.bni.invalid", audience = "bni-mobile", now = () => new Date(), accessTtlMs = 300_000, refreshTtlMs = 30 * 86_400_000 } = {}) {
    if (!signingKey || Buffer.byteLength(signingKey) < 32) throw new BankError("TOKEN_SIGNING_KEY_REQUIRED", 500);
    this.signingKey = Buffer.from(signingKey);
    this.issuer = issuer;
    this.audience = audience;
    this.now = now;
    this.accessTtlMs = accessTtlMs;
    this.refreshTtlMs = refreshTtlMs;
  }

  issueAccess({ customerReference, deviceReference, sessionId, scopes }) {
    const issued = this.now();
    const payload = {
      iss: this.issuer, aud: this.audience, sub: customerReference, device: deviceReference,
      sid: sessionId, scope: [...scopes].sort().join(" "), jti: opaqueId("jti"),
      iat: Math.floor(issued.getTime() / 1000), exp: Math.floor((issued.getTime() + this.accessTtlMs) / 1000),
    };
    const encoded = base64url(JSON.stringify(payload));
    return { token: `${encoded}.${hmac(this.signingKey, encoded)}`, expiresAt: iso(new Date(payload.exp * 1000)), payload };
  }

  verifyAccess(token) {
    if (typeof token !== "string") throw new BankError("UNAUTHENTICATED", 401);
    const [encoded, signature, extra] = token.split(".");
    if (!encoded || !signature || extra || !safeEqual(signature, hmac(this.signingKey, encoded))) throw new BankError("UNAUTHENTICATED", 401);
    let payload;
    try { payload = JSON.parse(fromBase64url(encoded).toString("utf8")); } catch { throw new BankError("UNAUTHENTICATED", 401); }
    if (payload.iss !== this.issuer || payload.aud !== this.audience || payload.exp <= Math.floor(this.now().getTime() / 1000)) {
      throw new BankError("SESSION_EXPIRED", 401);
    }
    return payload;
  }
}

export class SlidingWindowRateLimiter {
  constructor({ limit = 10, windowMs = 60_000, now = () => new Date() } = {}) {
    this.limit = limit; this.windowMs = windowMs; this.now = now; this.entries = new Map();
  }

  consume(key) {
    const cutoff = this.now().getTime() - this.windowMs;
    const entries = (this.entries.get(key) ?? []).filter((value) => value > cutoff);
    if (entries.length >= this.limit) throw new BankError("RATE_LIMITED", 429, true);
    entries.push(this.now().getTime());
    this.entries.set(key, entries);
  }
}

export class IdentityService {
  constructor({ repository, tokenService, now = () => new Date(), challengeTtlMs = 90_000, activationPepper = "" } = {}) {
    if (!repository || !tokenService) throw new BankError("IDENTITY_CONFIGURATION_INVALID", 500);
    if (Buffer.byteLength(activationPepper) < 16) throw new BankError("ACTIVATION_PEPPER_REQUIRED", 500);
    this.repository = repository; this.tokenService = tokenService; this.now = now;
    this.challengeTtlMs = challengeTtlMs; this.activationPepper = activationPepper;
  }

  async bootstrapCustomer({ customerReference, activationCode, status = ACTIVE }) {
    return this.repository.transaction((state) => this.bootstrapCustomerInState(state, { customerReference, activationCode, status }));
  }

  bootstrapCustomerInState(state, { customerReference, activationCode, status = ACTIVE }) {
    requireOpaque(customerReference, "INVALID_CUSTOMER_REFERENCE");
    if (typeof activationCode !== "string" || !/^[A-Z0-9-]{12,64}$/.test(activationCode)) throw new BankError("INVALID_ACTIVATION_CODE");
    if (state.customers[customerReference]) throw new BankError("CUSTOMER_EXISTS", 409);
    state.customers[customerReference] = { customerReference, status, createdAt: iso(this.now()) };
    state.activations[customerReference] = { hash: sha256(`${this.activationPepper}|${activationCode}`), consumedAt: null, failures: 0 };
    addAudit(state, { type: "CUSTOMER_BOOTSTRAPPED", subjectReference: customerReference, outcome: "SUCCESS" }, this.now);
    return { customerReference, status };
  }

  async beginEnrollment({ customerReference, deviceReference, publicKeySpki, activationCode }) {
    requireOpaque(customerReference, "INVALID_CUSTOMER_REFERENCE"); requireOpaque(deviceReference, "INVALID_DEVICE_REFERENCE");
    keyFromSpki(publicKeySpki);
    const result = await this.repository.transaction((state) => {
      const customer = state.customers[customerReference];
      const activation = state.activations[customerReference];
      if (!customer || customer.status !== ACTIVE || !activation || activation.consumedAt) throw new BankError("ENROLLMENT_DENIED", 403);
      const supplied = sha256(`${this.activationPepper}|${activationCode ?? ""}`);
      if (!safeEqual(supplied, activation.hash)) {
        activation.failures += 1;
        if (activation.failures >= 5) activation.consumedAt = iso(this.now());
        addAudit(state, { type: "DEVICE_ENROLLMENT_STARTED", subjectReference: customerReference, outcome: "DENIED" }, this.now);
        return { terminalError: "ENROLLMENT_DENIED" };
      }
      const nonce = randomToken(32); const expiresAt = iso(new Date(this.now().getTime() + this.challengeTtlMs));
      const challengeId = opaqueId("enroll");
      const material = canonicalFields("ENROLL_DEVICE_V1", challengeId, customerReference, deviceReference, nonce, expiresAt);
      state.challenges[challengeId] = { challengeId, type: "ENROLLMENT", customerReference, deviceReference, publicKeySpki, nonce, expiresAt, material, consumedAt: null };
      addAudit(state, { type: "DEVICE_ENROLLMENT_STARTED", subjectReference: deviceReference, actorReference: customerReference, outcome: "CHALLENGE_ISSUED" }, this.now);
      return { challengeId, nonce, expiresAt, material };
    });
    if (result.terminalError) throw new BankError(result.terminalError, 403);
    return result;
  }

  async completeEnrollment({ challengeId, signature, appInstanceReference, attestation = { verdict: "NOT_AVAILABLE" } }) {
    requireOpaque(challengeId, "INVALID_CHALLENGE_ID"); requireOpaque(appInstanceReference, "INVALID_APP_INSTANCE_REFERENCE");
    return this.repository.transaction((state) => {
      const challenge = this.#activeChallenge(state, challengeId, "ENROLLMENT");
      if (!verifyDevice(challenge.publicKeySpki, challenge.material, signature)) throw new BankError("INVALID_DEVICE_SIGNATURE", 403);
      if (state.devices[challenge.deviceReference]) throw new BankError("DEVICE_EXISTS", 409);
      const device = {
        deviceReference: challenge.deviceReference, customerReference: challenge.customerReference,
        appInstanceReference, publicKeySpki: challenge.publicKeySpki, status: ACTIVE,
        attestationVerdict: ["MEETS_STRONG_INTEGRITY", "MEETS_DEVICE_INTEGRITY", "NOT_AVAILABLE"].includes(attestation.verdict) ? attestation.verdict : "UNTRUSTED",
        enrolledAt: iso(this.now()), lastSeenAt: iso(this.now()),
      };
      state.devices[device.deviceReference] = device; challenge.consumedAt = iso(this.now());
      state.activations[device.customerReference].consumedAt = iso(this.now());
      addAudit(state, { type: "DEVICE_ENROLLED", subjectReference: device.deviceReference, actorReference: device.customerReference, outcome: "SUCCESS", details: { attestationVerdict: device.attestationVerdict } }, this.now);
      addOutbox(state, { type: "DEVICE_ENROLLED", aggregateReference: device.customerReference, payload: { deviceReference: device.deviceReference }, correlationId: challenge.challengeId }, this.now);
      return { deviceReference: device.deviceReference, customerReference: device.customerReference, status: device.status };
    });
  }

  async beginLogin({ customerReference, deviceReference }) {
    requireOpaque(customerReference, "INVALID_CUSTOMER_REFERENCE"); requireOpaque(deviceReference, "INVALID_DEVICE_REFERENCE");
    return this.repository.transaction((state) => {
      const device = this.#activeDevice(state, deviceReference, customerReference);
      const challengeId = opaqueId("login"); const nonce = randomToken(32);
      const expiresAt = iso(new Date(this.now().getTime() + this.challengeTtlMs));
      const material = canonicalFields("LOGIN_V1", challengeId, customerReference, deviceReference, nonce, expiresAt);
      state.challenges[challengeId] = { challengeId, type: "LOGIN", customerReference, deviceReference, nonce, expiresAt, material, consumedAt: null };
      device.lastSeenAt = iso(this.now());
      return { challengeId, nonce, expiresAt, material };
    });
  }

  async completeLogin({ challengeId, signature, codeChallenge = null }) {
    return this.repository.transaction((state) => {
      const challenge = this.#activeChallenge(state, requireOpaque(challengeId, "INVALID_CHALLENGE_ID"), "LOGIN");
      const device = this.#activeDevice(state, challenge.deviceReference, challenge.customerReference);
      if (!verifyDevice(device.publicKeySpki, challenge.material, signature)) throw new BankError("INVALID_DEVICE_SIGNATURE", 403);
      challenge.consumedAt = iso(this.now());
      const authorizationCode = randomToken(32); const codeHash = sha256(authorizationCode);
      state.sessions[codeHash] = {
        type: "AUTHORIZATION_CODE", customerReference: challenge.customerReference, deviceReference: challenge.deviceReference,
        codeChallenge, expiresAt: iso(new Date(this.now().getTime() + 60_000)), consumedAt: null,
      };
      addAudit(state, { type: "LOGIN_AUTHORIZED", subjectReference: challenge.deviceReference, actorReference: challenge.customerReference, outcome: "SUCCESS" }, this.now);
      return { authorizationCode, expiresInSeconds: 60 };
    });
  }

  async exchangeAuthorizationCode({ authorizationCode, codeVerifier = null }) {
    return this.repository.transaction((state) => {
      const code = state.sessions[sha256(authorizationCode ?? "")];
      if (!code || code.type !== "AUTHORIZATION_CODE" || code.consumedAt || new Date(code.expiresAt) <= this.now()) throw new BankError("INVALID_AUTHORIZATION_CODE", 401);
      if (code.codeChallenge && sha256(codeVerifier ?? "") !== code.codeChallenge) throw new BankError("INVALID_PKCE_VERIFIER", 401);
      code.consumedAt = iso(this.now());
      return this.#issueTokenPair(state, code.customerReference, code.deviceReference);
    });
  }

  async refresh({ refreshToken }) {
    const result = await this.repository.transaction((state) => {
      const hash = sha256(refreshToken ?? ""); const record = state.refreshTokens[hash];
      if (!record) throw new BankError("INVALID_REFRESH_TOKEN", 401);
      if (record.rotatedAt) {
        this.#revokeSession(state, record.sessionId, "REFRESH_REUSE_DETECTED");
        return { terminalError: "REFRESH_REUSE_DETECTED" };
      }
      if (record.revokedAt || new Date(record.expiresAt) <= this.now()) throw new BankError("REFRESH_TOKEN_EXPIRED", 401);
      record.rotatedAt = iso(this.now());
      return this.#issueTokenPair(state, record.customerReference, record.deviceReference, record.sessionId);
    });
    if (result.terminalError) throw new BankError(result.terminalError, 401);
    return result;
  }

  authenticate(accessToken, requiredScope = null) {
    const payload = this.tokenService.verifyAccess(accessToken);
    const state = this.repository.snapshot();
    const device = state.devices[payload.device]; const session = state.sessions[payload.sid];
    if (!device || device.status !== ACTIVE || !session || session.revokedAt) throw new BankError("SESSION_REVOKED", 401);
    if (requiredScope && !String(payload.scope).split(" ").includes(requiredScope)) throw new BankError("FORBIDDEN", 403);
    return payload;
  }

  async changeDeviceStatus({ deviceReference, status, actorReference = "operations" }) {
    if (!DEVICE_STATES.has(status)) throw new BankError("INVALID_DEVICE_STATUS");
    return this.repository.transaction((state) => {
      const device = state.devices[requireOpaque(deviceReference, "INVALID_DEVICE_REFERENCE")];
      if (!device) throw new BankError("DEVICE_NOT_FOUND", 404);
      device.status = status; device.updatedAt = iso(this.now());
      if (status !== ACTIVE) for (const session of Object.values(state.sessions)) if (session.deviceReference === deviceReference) session.revokedAt = iso(this.now());
      addAudit(state, { type: "DEVICE_STATUS_CHANGED", subjectReference: deviceReference, actorReference, outcome: status }, this.now);
      addOutbox(state, { type: "DEVICE_STATUS_CHANGED", aggregateReference: device.customerReference, payload: { deviceReference, status }, correlationId: opaqueId("corr") }, this.now);
      return { deviceReference, status };
    });
  }

  async createScaChallenge({ customerReference, deviceReference, operation, accountReference, counterpartyReference, amountMinor, currency, operationReference, riskContext = "STANDARD", idempotencyKey }) {
    return this.repository.transaction((state) => {
      this.#activeDevice(state, requireOpaque(deviceReference), requireOpaque(customerReference));
      const challengeId = opaqueId("sca"); const nonce = randomToken(32);
      const expiresAt = iso(new Date(this.now().getTime() + this.challengeTtlMs));
      const material = canonicalFields("BNI_SCA_V1", challengeId, customerReference, deviceReference, operation, accountReference, counterpartyReference, amountMinor, currency, operationReference, nonce, expiresAt, riskContext, idempotencyKey);
      state.challenges[challengeId] = { challengeId, type: "SCA", customerReference, deviceReference, operation, accountReference, counterpartyReference, amountMinor, currency, operationReference, riskContext, idempotencyKey, nonce, expiresAt, material, consumedAt: null };
      addAudit(state, { type: "SCA_CHALLENGE_CREATED", subjectReference: operationReference, actorReference: customerReference, outcome: "ISSUED", details: { operation, amountMinor, currency, riskContext } }, this.now);
      return { challengeId, nonce, expiresAt, material, operation, amountMinor, currency, counterpartyReference };
    });
  }

  verifyScaInState(state, { challengeId, signature, expected }) {
    const challenge = this.#activeChallenge(state, requireOpaque(challengeId, "INVALID_CHALLENGE_ID"), "SCA");
    const device = this.#activeDevice(state, challenge.deviceReference, challenge.customerReference);
    for (const [key, value] of Object.entries(expected)) if (challenge[key] !== value) throw new BankError("SCA_DYNAMIC_LINK_MISMATCH", 403);
    if (!verifyDevice(device.publicKeySpki, challenge.material, signature)) throw new BankError("INVALID_DEVICE_SIGNATURE", 403);
    challenge.consumedAt = iso(this.now());
    addAudit(state, { type: "SCA_VERIFIED", subjectReference: challenge.operationReference, actorReference: challenge.customerReference, outcome: "SUCCESS", details: { operation: challenge.operation } }, this.now);
    return challenge;
  }

  #activeChallenge(state, challengeId, type) {
    const challenge = state.challenges[challengeId];
    if (!challenge || challenge.type !== type || challenge.consumedAt) throw new BankError("CHALLENGE_INVALID_OR_REPLAYED", 409);
    if (new Date(challenge.expiresAt) <= this.now()) throw new BankError("CHALLENGE_EXPIRED", 409);
    return challenge;
  }

  #activeDevice(state, deviceReference, customerReference) {
    const device = state.devices[deviceReference];
    const customer = state.customers[customerReference];
    if (!device || device.customerReference !== customerReference || device.status !== ACTIVE || !customer || customer.status !== ACTIVE) throw new BankError("DEVICE_BINDING_REJECTED", 403);
    return device;
  }

  #issueTokenPair(state, customerReference, deviceReference, existingSessionId = null) {
    const sessionId = existingSessionId ?? opaqueId("sid");
    const session = state.sessions[sessionId] ?? { type: "DEVICE_SESSION", sessionId, customerReference, deviceReference, createdAt: iso(this.now()), revokedAt: null };
    state.sessions[sessionId] = session;
    const access = this.tokenService.issueAccess({ customerReference, deviceReference, sessionId, scopes: ["banking:read", "banking:write"] });
    const refreshToken = randomToken(48); const expiresAt = iso(new Date(this.now().getTime() + this.tokenService.refreshTtlMs));
    state.refreshTokens[sha256(refreshToken)] = { sessionId, customerReference, deviceReference, expiresAt, rotatedAt: null, revokedAt: null };
    return { tokenType: "Bearer", accessToken: access.token, accessExpiresAt: access.expiresAt, refreshToken, refreshExpiresAt: expiresAt, sessionId };
  }

  #revokeSession(state, sessionId, reason) {
    const session = state.sessions[sessionId]; if (session) session.revokedAt = iso(this.now());
    for (const token of Object.values(state.refreshTokens)) if (token.sessionId === sessionId) token.revokedAt = iso(this.now());
    addAudit(state, { type: "SESSION_REVOKED", subjectReference: sessionId, outcome: reason }, this.now);
  }
}

export function generateDevelopmentDeviceKeyPair() {
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  return {
    publicKeySpki: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    sign: (material) => cryptoSign("sha256", Buffer.from(material), pair.privateKey).toString("base64url"),
  };
}
