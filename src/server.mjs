import { createHash, createPrivateKey, createPublicKey, randomBytes } from "node:crypto";
import { resolve } from "node:path";
import { BankRepository } from "./shared/repository.mjs";
import { PostgresBankRepository } from "./shared/postgres-repository.mjs";
import { atomicJsonCommitter, loadSnapshot } from "./shared/file-store.mjs";
import { createPlatform } from "./platform.mjs";
import { createPlatformHttpServer } from "./http-server.mjs";

const mode = process.env.BNI_PLATFORM_MODE ?? "production";
const production = mode === "production";
if (!production && mode !== "integration") throw new Error("BNI_PLATFORM_MODE must be production or integration");

const tokenSigningKey = production ? deriveSecret("BNI_TOKEN_SIGNING_SECRET") : randomBytes(32);
const activationPepper = production ? requiredSecret("BNI_ACTIVATION_PEPPER") : process.env.BNI_ACTIVATION_PEPPER ?? "integration-only-pepper-change-me";
const adminToken = production ? requiredSecret("BNI_ADMIN_TOKEN") : process.env.BNI_ADMIN_TOKEN ?? null;
const backupEncryptionKey = production ? deriveSecret("BNI_BACKUP_ENCRYPTION_SECRET") : createHash("sha256").update(process.env.BNI_BACKUP_ENCRYPTION_SECRET ?? "integration-backup-key").digest();
const intentSigningKeyPair = production ? intentKeys(requiredSecret("BNI_INTENT_SIGNING_SECRET")) : undefined;
const publicBaseUrl = production ? publicOrigin() : "https://integration.bni.invalid";
const repository = production ? await productionRepository() : await integrationRepository();

const platform = createPlatform({
  repository,
  tokenSigningKey,
  tokenIssuer: `${publicBaseUrl}/identity`,
  tokenAudience: "bni-mobile-v2",
  activationPepper,
  backupEncryptionKey,
  ...(intentSigningKeyPair ? { intentSigningKeyPair } : {}),
});
const server = createPlatformHttpServer(platform, {
  adminToken,
  requireTlsForwarding: production ? process.env.BNI_REQUIRE_TLS_FORWARDING !== "false" : false,
});
const port = integerEnvironment("PORT", 8789);
const host = production ? "0.0.0.0" : "127.0.0.1";

server.listen(port, host, () => process.stdout.write(`BNI platform listening on ${host}:${port} (${mode})\n`));
server.on("error", (error) => {
  process.stderr.write(`BNI platform startup error: ${error.code ?? "UNKNOWN"}\n`);
  process.exitCode = 1;
});

for (const signal of ["SIGTERM", "SIGINT"]) {
  process.once(signal, () => {
    server.close(async () => {
      await repository.close?.();
      process.exit(0);
    });
  });
}

async function productionRepository() {
  const databaseUrl = process.env.DATABASE_URL;
  const databaseSsl = process.env.BNI_DATABASE_SSL ?? "connection-string";
  let ssl;
  if (databaseSsl === "disable") ssl = false;
  else if (databaseSsl === "require") ssl = { rejectUnauthorized: false };
  else if (databaseSsl === "verify-full") {
    const encodedCa = process.env.BNI_DATABASE_CA_BASE64;
    if (!encodedCa) throw new Error("BNI_DATABASE_CA_BASE64 is required for verify-full");
    ssl = { rejectUnauthorized: true, ca: Buffer.from(encodedCa, "base64").toString("utf8") };
  } else if (databaseSsl !== "connection-string") throw new Error("BNI_DATABASE_SSL must be connection-string, disable, require or verify-full");
  return new PostgresBankRepository({ connectionString: databaseUrl, ssl }).initialize();
}

async function integrationRepository() {
  const dataPath = resolve(process.env.BNI_PLATFORM_DATA_PATH ?? "runtime-data/integration-state.json");
  return new BankRepository({ snapshot: await loadSnapshot(dataPath), afterCommit: atomicJsonCommitter(dataPath) });
}

function requiredSecret(name) {
  const value = process.env[name];
  if (typeof value !== "string" || Buffer.byteLength(value) < 32) throw new Error(`${name} must contain at least 32 bytes`);
  return value;
}

function deriveSecret(name) {
  return createHash("sha256").update(requiredSecret(name)).digest();
}

function intentKeys(secret) {
  const seed = createHash("sha256").update(secret).digest();
  const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

function requiredHttpsUrl(name) {
  const value = process.env[name];
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${name} must be a valid HTTPS URL`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error(`${name} must be an HTTPS origin`);
  return parsed.origin;
}

function publicOrigin() {
  if (process.env.BNI_PUBLIC_BASE_URL) return requiredHttpsUrl("BNI_PUBLIC_BASE_URL");
  const renderHostname = process.env.RENDER_EXTERNAL_HOSTNAME;
  if (typeof renderHostname === "string" && /^[A-Za-z0-9.-]+$/.test(renderHostname)) return `https://${renderHostname}`;
  throw new Error("BNI_PUBLIC_BASE_URL is required outside Render");
}

function integerEnvironment(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) throw new Error(`${name} is invalid`);
  return value;
}
