import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";

export class BankError extends Error {
  constructor(code, httpStatus = 400, retryable = false) {
    super(code);
    this.name = "BankError";
    this.code = code;
    this.httpStatus = httpStatus;
    this.retryable = retryable;
  }
}

export const clone = (value) => structuredClone(value);
export const iso = (value = new Date()) => {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new BankError("INVALID_TIMESTAMP");
  return date.toISOString();
};
export const opaqueId = (prefix = "ref") => `${prefix}_${randomUUID().replaceAll("-", "")}`;
export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const sha256 = (value) => createHash("sha256").update(value).digest("hex");
export const hmac = (key, value) => createHmac("sha256", key).update(value).digest("base64url");
export const base64url = (value) => Buffer.from(value).toString("base64url");
export const fromBase64url = (value) => Buffer.from(value, "base64url");

export function safeEqual(left, right) {
  const a = Buffer.from(left ?? "", "utf8");
  const b = Buffer.from(right ?? "", "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export function requireOpaque(value, code = "INVALID_REFERENCE") {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{8,128}$/.test(value) || /^\d{13,19}$/.test(value)) {
    throw new BankError(code);
  }
  return value;
}

export function requireText(value, code = "INVALID_TEXT", max = 140) {
  if (typeof value !== "string" || value.length < 1 || value.length > max || /[\u0000-\u001f]/u.test(value)) {
    throw new BankError(code);
  }
  return value.normalize("NFC");
}

export function requireMoney(amountMinor, currency = "EUR", { allowZero = false } = {}) {
  if (!Number.isSafeInteger(amountMinor) || amountMinor < (allowZero ? 0 : 1) || amountMinor > 100_000_000_000) {
    throw new BankError("INVALID_AMOUNT");
  }
  if (typeof currency !== "string" || !/^[A-Z]{3}$/.test(currency)) throw new BankError("INVALID_CURRENCY");
  return Object.freeze({ amountMinor, currency });
}

export function canonicalFields(...fields) {
  return fields.map((field) => {
    const value = field == null ? "" : String(field).normalize("NFC");
    return `${Buffer.byteLength(value, "utf8")}:${value}`;
  }).join("|");
}

export function canonicalJson(value) {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonicalJson(item) ?? "null").join(",")}]`;
  if (value && typeof value === "object") {
    const fields = Object.keys(value).sort().flatMap((key) => {
      const encoded = canonicalJson(value[key]);
      return encoded === undefined ? [] : [`${JSON.stringify(key)}:${encoded}`];
    });
    return `{${fields.join(",")}}`;
  }
  return undefined;
}

export class AsyncMutex {
  #tail = Promise.resolve();

  async runExclusive(operation) {
    const previous = this.#tail;
    let release;
    this.#tail = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }
}

export function publicHash(reference) {
  return sha256(String(reference)).slice(0, 24);
}
