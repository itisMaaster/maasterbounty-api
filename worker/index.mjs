import { DurableObject } from "cloudflare:workers";
import { httpServerHandler } from "cloudflare:node";
import { server } from "../backend/src/server.mjs";
import { all, bindDurableStorage, run, transaction } from "../backend/src/db-cloudflare.mjs";
import { schemaSql } from "./schema.mjs";

const httpHandler = httpServerHandler(server);

export default {
  async fetch(request, env) {
    try {
      const id = env.API_DATABASE.idFromName("itsmaaster-bounty-api");
      return await env.API_DATABASE.get(id).fetch(request);
    } catch (error) {
      console.error("MaasterBounty API request failed", error);
      return new Response(JSON.stringify({ error: "internal_error" }), {
        status: 500,
        headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
      });
    }
  }
};

export class MaasterBountyApi extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ready = ctx.blockConcurrencyWhile(async () => {
      bindDurableStorage(ctx.storage);
      ctx.storage.sql.exec(schemaSql);
      // Additive-only community tables. Existing tables and records are left untouched.
      ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS smp_announcements (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
        active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
        author TEXT NOT NULL DEFAULT 'Maaster',
        created_at TEXT NOT NULL
      )`);
      ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS smp_chat_messages (
        id TEXT PRIMARY KEY,
        source_event_id TEXT UNIQUE,
        player_uuid TEXT,
        username TEXT NOT NULL,
        message TEXT NOT NULL CHECK (length(message) BETWEEN 1 AND 256),
        source TEXT NOT NULL CHECK (source IN ('minecraft', 'admin')),
        status TEXT NOT NULL DEFAULT 'delivered' CHECK (status IN ('pending', 'processing', 'delivered', 'failed')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        delivered_at TEXT
      )`);
      ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS idx_smp_announcements_active_created ON smp_announcements(active, pinned, created_at)");
      ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS idx_smp_chat_status_created ON smp_chat_messages(status, created_at)");
      ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS smp_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )`);
      ctx.storage.sql.exec("INSERT OR IGNORE INTO smp_settings (key, value, updated_at) VALUES ('mirror_chat_enabled', '1', datetime('now'))");
      ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS smp_hidden_players (
        player_uuid TEXT PRIMARY KEY,
        hidden_at TEXT NOT NULL,
        hidden_by TEXT NOT NULL DEFAULT 'admin'
      )`);
      ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS idx_smp_hidden_players_uuid ON smp_hidden_players(player_uuid)");
      if (await ctx.storage.getAlarm() === null) {
        await ctx.storage.setAlarm(Date.now() + 60_000);
      }
    });
  }

  async fetch(request) {
    await this.ready;
    bindDurableStorage(this.ctx.storage);
    // httpServerHandler returns a module handler object (with a fetch method)
    // in current Workers runtimes. Keep function support for older runtimes.
    if (typeof httpHandler === "function") return httpHandler(request, this.env, this.ctx);
    if (typeof httpHandler?.fetch === "function") return httpHandler.fetch(request, this.env, this.ctx);
    throw new TypeError("Cloudflare HTTP server handler does not expose a fetch handler.");
  }

  async alarm() {
    bindDurableStorage(this.ctx.storage);
    const now = new Date().toISOString();
    const expired = all("SELECT id FROM bounties WHERE status='active' AND expires_at IS NOT NULL AND expires_at<=?", now);
    transaction(() => {
      for (const bounty of expired) {
        run("UPDATE bounties SET status='expired', updated_at=?, version=version+1 WHERE id=? AND status='active'", now, bounty.id);
      }
      run("DELETE FROM plugin_nonces WHERE seen_at < ?", new Date(Date.now() - 10 * 60_000).toISOString());
    });
    await this.ctx.storage.setAlarm(Date.now() + 60_000);
  }
}
