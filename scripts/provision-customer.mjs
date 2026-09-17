import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const apiBaseUrl = httpsOrigin(process.env.BNI_PUBLIC_BASE_URL);
const adminToken = required("BNI_ADMIN_TOKEN", 32);
const customerReference = process.env.BNI_CUSTOMER_REFERENCE ?? reference("customer");
const accountReference = process.env.BNI_ACCOUNT_REFERENCE ?? reference("account");
const activationCode = process.env.BNI_ACTIVATION_CODE ?? `BNI-${randomBytes(12).toString("hex").toUpperCase()}`;
const outputPath = resolve(process.argv[2] ?? `activation-credentials-${customerReference}.json`);

const response = await fetch(`${apiBaseUrl}/v2/admin/provision-customer`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-BNI-Admin-Token": adminToken,
    "X-Correlation-ID": reference("provision"),
  },
  body: JSON.stringify({
    customerReference,
    activationCode,
    accountReference,
    accountDisplayName: process.env.BNI_ACCOUNT_DISPLAY_NAME ?? "Conto BNI",
    currency: process.env.BNI_ACCOUNT_CURRENCY ?? "EUR",
  }),
  redirect: "error",
});

const envelope = await response.json().catch(() => ({}));
if (!response.ok) {
  throw new Error(`Provisioning rejected (${response.status}/${envelope.error?.code ?? "UNEXPECTED_RESPONSE"})`);
}

const credential = {
  apiBaseUrl,
  customerReference,
  activationCode,
  accountReference,
  issuedAt: new Date().toISOString(),
  activationType: "one-time-device-enrollment",
};
await writeFile(outputPath, `${JSON.stringify(credential, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
process.stdout.write(`Activation credentials written with mode 0600: ${outputPath}\n`);

function required(name, min) {
  const value = process.env[name];
  if (typeof value !== "string" || Buffer.byteLength(value) < min) throw new Error(`${name} is required and must contain at least ${min} bytes`);
  return value;
}

function httpsOrigin(value) {
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error("BNI_PUBLIC_BASE_URL must be a valid HTTPS origin"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) throw new Error("BNI_PUBLIC_BASE_URL must be a valid HTTPS origin");
  return parsed.origin;
}

function reference(prefix) {
  return `${prefix}_${randomBytes(12).toString("hex")}`;
}
