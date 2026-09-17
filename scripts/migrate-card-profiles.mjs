import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

const apiBaseUrl = httpsOrigin(process.env.BNI_PUBLIC_BASE_URL);
const adminToken = required("BNI_ADMIN_TOKEN", 32);
const inputPath = resolve(process.argv[2] ?? "operations/customer-card-profiles.json");
const payload = JSON.parse(await readFile(inputPath, "utf8"));

const response = await fetch(`${apiBaseUrl}/v2/admin/migrate-card-profiles`, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-BNI-Admin-Token": adminToken,
    "X-Correlation-ID": `cardmigration_${Date.now().toString(36)}`,
  },
  body: JSON.stringify(payload),
  redirect: "error",
});

const envelope = await response.json().catch(() => ({}));
if (!response.ok) throw new Error(`Card migration rejected (${response.status}/${envelope.error?.code ?? "UNEXPECTED_RESPONSE"})`);
process.stdout.write(`Card profiles migrated: ${envelope.data.cards.length}\n`);

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
