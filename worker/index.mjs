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
