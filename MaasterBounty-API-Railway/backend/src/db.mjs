import { mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";

const configuredPath = process.env.DATABASE_PATH || "./data/itsmaaster-smp.sqlite";
const databasePath = configuredPath === ":memory:" ? ":memory:" : resolve(configuredPath);
if (databasePath !== ":memory:") mkdirSync(dirname(databasePath), { recursive: true });
export const db = new DatabaseSync(databasePath);
db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
const migrationPath = fileURLToPath(new URL("../../database/migrations/001_init.sql", import.meta.url));
db.exec(readFileSync(migrationPath, "utf8"));

export function transaction(callback) {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = callback();
    db.exec("COMMIT");
    return result;
  } catch (error) {
    try { db.exec("ROLLBACK"); } catch { /* A failed commit already ended the transaction. */ }
    throw error;
  }
}

export function run(sql, ...params) { return db.prepare(sql).run(...params); }
export function get(sql, ...params) { return db.prepare(sql).get(...params); }
export function all(sql, ...params) { return db.prepare(sql).all(...params); }
