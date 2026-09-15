import { readdir, readFile } from "node:fs/promises";
import pg from "pg";
import { AsyncMutex, BankError, clone } from "./kernel.mjs";
import { emptyState, isPristineState, validateState } from "./repository.mjs";

const { Pool } = pg;
const MIGRATION_LOCK = "bni-platform-migrations-v2";

export class PostgresBankRepository {
  #pool;
  #mutex = new AsyncMutex();
  #state = emptyState();
  #ready = false;

  constructor({ connectionString, ssl = undefined, pool = null } = {}) {
    if (!pool && (typeof connectionString !== "string" || connectionString.length < 12)) {
      throw new BankError("DATABASE_URL_REQUIRED", 500);
    }
    this.#pool = pool ?? new Pool({ connectionString, ssl, max: 10, idleTimeoutMillis: 30_000, connectionTimeoutMillis: 10_000 });
  }

  async initialize({ migrationsUrl = new URL("../../db/migration/", import.meta.url) } = {}) {
    await runMigrations(this.#pool, migrationsUrl);
    await this.#mutex.runExclusive(async () => {
      const client = await this.#pool.connect();
      try {
        await client.query("BEGIN");
        await client.query(
          "INSERT INTO platform_state_store(singleton, revision, state) VALUES (true, 0, $1::jsonb) ON CONFLICT (singleton) DO NOTHING",
          [JSON.stringify(emptyState())],
        );
        const result = await client.query("SELECT revision, state FROM platform_state_store WHERE singleton = true FOR UPDATE");
        if (result.rowCount !== 1) throw new BankError("DATABASE_STATE_UNAVAILABLE", 503, true);
        this.#state = normalizeState(result.rows[0]);
        validateState(this.#state);
        await client.query("COMMIT");
        this.#ready = true;
      } catch (error) {
        await rollbackQuietly(client);
        throw error;
      } finally {
        client.release();
      }
    });
    return this;
  }

  read(operation = (state) => state) {
    this.#assertReady();
    return clone(operation(this.#state));
  }

  snapshot() {
    this.#assertReady();
    return clone(this.#state);
  }

  async refresh() {
    this.#assertReady();
    return this.#mutex.runExclusive(async () => {
      const result = await this.#pool.query("SELECT revision, state FROM platform_state_store WHERE singleton = true");
      if (result.rowCount !== 1) throw new BankError("DATABASE_STATE_UNAVAILABLE", 503, true);
      const next = normalizeState(result.rows[0]);
      validateState(next);
      this.#state = next;
      return next.revision;
    });
  }

  async transaction(operation) {
    this.#assertReady();
    return this.#mutex.runExclusive(async () => {
      const client = await this.#pool.connect();
      try {
        await client.query("BEGIN");
        const locked = await client.query("SELECT revision, state FROM platform_state_store WHERE singleton = true FOR UPDATE");
        if (locked.rowCount !== 1) throw new BankError("DATABASE_STATE_UNAVAILABLE", 503, true);
        const current = normalizeState(locked.rows[0]);
        const draft = clone(current);
        const result = await operation(draft);
        validateState(draft);
        draft.revision = current.revision + 1;
        await client.query(
          "UPDATE platform_state_store SET revision = $1, state = $2::jsonb, updated_at = now() WHERE singleton = true",
          [draft.revision, JSON.stringify(draft)],
        );
        await client.query("COMMIT");
        this.#state = draft;
        return clone(result);
      } catch (error) {
        await rollbackQuietly(client);
        throw error;
      } finally {
        client.release();
      }
    });
  }

  async replaceSnapshot(snapshot, { requirePristine = true } = {}) {
    this.#assertReady();
    const next = { ...emptyState(), ...clone(snapshot) };
    validateState(next);
    if (!Number.isSafeInteger(next.revision) || next.revision < 0) throw new BankError("DATABASE_REVISION_INVALID", 500);
    return this.#mutex.runExclusive(async () => {
      const client = await this.#pool.connect();
      try {
        await client.query("BEGIN");
        const locked = await client.query("SELECT revision, state FROM platform_state_store WHERE singleton = true FOR UPDATE");
        if (locked.rowCount !== 1) throw new BankError("DATABASE_STATE_UNAVAILABLE", 503, true);
        const current = normalizeState(locked.rows[0]);
        if (requirePristine && !isPristineState(current)) throw new BankError("BACKUP_DESTINATION_NOT_EMPTY", 409);
        await client.query(
          "UPDATE platform_state_store SET revision = $1, state = $2::jsonb, updated_at = now() WHERE singleton = true",
          [next.revision, JSON.stringify(next)],
        );
        await client.query("COMMIT");
        this.#state = next;
        return { revision: next.revision };
      } catch (error) {
        await rollbackQuietly(client);
        throw error;
      } finally {
        client.release();
      }
    });
  }

  async ping() {
    await this.#pool.query("SELECT 1");
    return true;
  }

  async close() {
    await this.#pool.end();
  }

  #assertReady() {
    if (!this.#ready) throw new BankError("DATABASE_NOT_READY", 503, true);
  }
}

export async function runMigrations(pool, migrationsUrl = new URL("../../db/migration/", import.meta.url)) {
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock(hashtext($1))", [MIGRATION_LOCK]);
    const files = (await readdir(migrationsUrl)).filter((name) => /^V\d+__.+\.sql$/.test(name)).sort();
    const exists = await client.query("SELECT to_regclass('public.platform_schema_version') AS relation");
    const applied = new Set();
    if (exists.rows[0]?.relation) {
      const versions = await client.query("SELECT version FROM platform_schema_version");
      for (const row of versions.rows) applied.add(Number(row.version));
    }
    for (const file of files) {
      const version = Number(file.match(/^V(\d+)__/)[1]);
      if (applied.has(version)) continue;
      await client.query(await readFile(new URL(file, migrationsUrl), "utf8"));
      applied.add(version);
    }
  } catch (error) {
    await rollbackQuietly(client);
    throw error;
  } finally {
    try { await client.query("SELECT pg_advisory_unlock(hashtext($1))", [MIGRATION_LOCK]); } catch {}
    client.release();
  }
}

function normalizeState(row) {
  const stored = typeof row.state === "string" ? JSON.parse(row.state) : clone(row.state);
  const value = { ...emptyState(), ...stored };
  value.revision = Number(row.revision);
  if (!Number.isSafeInteger(value.revision) || value.revision < 0) throw new BankError("DATABASE_REVISION_INVALID", 500);
  return value;
}

async function rollbackQuietly(client) {
  try { await client.query("ROLLBACK"); } catch {}
}
