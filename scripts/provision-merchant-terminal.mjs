import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const apiBaseUrl = httpsOrigin(process.env.BNI_PUBLIC_BASE_URL);
const adminToken = required("BNI_ADMIN_TOKEN", 32);
const merchantId = process.env.BNI_MERCHANT_ID ?? reference("merchant");
const terminalId = process.env.BNI_TERMINAL_ID ?? reference("terminal");
const settlementAccountReference = process.env.BNI_MERCHANT_ACCOUNT_REFERENCE ?? reference("merchant_account");
const deviceReference = process.env.BNI_TERMINAL_DEVICE_REFERENCE ?? reference("pos_device");
const enrollmentCode = process.env.BNI_TERMINAL_ENROLLMENT_CODE ?? `POS-${randomBytes(12).toString("hex").toUpperCase()}`;
const displayName = required("BNI_MERCHANT_DISPLAY_NAME", 2);
const outputPath = resolve(process.argv[2] ?? `terminal-activation-${terminalId}.json`);

const response = await fetch(`${apiBaseUrl}/v2/admin/provision-merchant-terminal`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-BNI-Admin-Token": adminToken,
    "X-Correlation-ID": reference("provision"),
  },
  body: JSON.stringify({ merchantId, displayName, settlementAccountReference, terminalId, deviceReference, enrollmentCode, currency: "EUR" }),
  redirect: "error",
});
const envelope = await response.json().catch(() => ({}));
if (!response.ok) throw new Error(`Provisioning rejected (${response.status}/${envelope.error?.code ?? "UNEXPECTED_RESPONSE"})`);

const credential = { apiBaseUrl, merchantId, terminalId, settlementAccountReference, deviceReference, enrollmentCode, displayName, issuedAt: new Date().toISOString(), activationType: "one-time-terminal-enrollment" };
await writeFile(outputPath, `${JSON.stringify(credential, null, 2)}\n`, { encoding: "utf8", mode: 0o600, flag: "wx" });
process.stdout.write(`Terminal activation written with mode 0600: ${outputPath}\n`);

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

function reference(prefix) { return `${prefix}_${randomBytes(12).toString("hex")}`; }
