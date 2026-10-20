// Synchronous SQLite adapter for Cloudflare's SQLite-backed Durable Objects.
// The API itself can keep its existing synchronous query helpers.
let durableStorage;

export function bindDurableStorage(storage) {
  durableStorage = storage;
}

function sql() {
  if (!durableStorage?.sql) throw new Error("Cloudflare SQLite storage is not ready.");
  return durableStorage.sql;
}

export const db = {
  exec(statement) {
    return sql().exec(statement);
  },
  close() {
    // Durable Object storage is managed by Cloudflare and must not be closed.
  }
};

export function transaction(callback) {
  return durableStorage.transactionSync(callback);
}

export function run(statement, ...params) {
  const cursor = sql().exec(statement, ...params);
  const changes = sql().exec("SELECT changes() AS changes").toArray()[0]?.changes ?? cursor.rowsWritten;
  return { changes, rowsWritten: cursor.rowsWritten };
}

export function get(statement, ...params) {
  return sql().exec(statement, ...params).toArray()[0] ?? null;
}

export function all(statement, ...params) {
  return sql().exec(statement, ...params).toArray();
}
