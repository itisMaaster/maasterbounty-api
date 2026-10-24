import { createServer } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";
import {
  claimEligible, constantTimeTextEqual, hash, kdRatio, pageArgs,
  publicPlayer, signature, validAmount, validUsername, validUuid
} from "./core.mjs";
import { all, db, get, run, transaction } from "./db-cloudflare.mjs";

const HOST = process.env.HOST || "127.0.0.1";
const PORT = Number(process.env.PORT || 8788);
const COOKIE = process.env.COOKIE_NAME || "maaster_smp_session";
const WEB_ORIGIN = process.env.PUBLIC_WEB_ORIGIN || "";
const SECURE_COOKIE = process.env.COOKIE_SECURE !== "false";
const CURRENCY = process.env.CURRENCY_NAME?.trim() || null;
const MAX_BOUNTY_ITEMS = positiveInt(process.env.MAX_BOUNTY_ITEMS, 2304);
const ITEM_CURRENCY_PREFIX = "ITEM:";
const MIN_BOUNTY = positiveInt(process.env.MIN_BOUNTY, 100);
const MAX_BOUNTY = positiveInt(process.env.MAX_BOUNTY, 100000);
const EXPIRY_HOURS = positiveInt(process.env.DEFAULT_EXPIRY_HOURS, 72);
const PAIR_COOLDOWN = positiveInt(process.env.SAME_PAIR_COOLDOWN_MINUTES, 30);
const KD_MIN = positiveInt(process.env.KD_MINIMUM_KILLS, 10);
const HEARTBEAT_STALE = positiveInt(process.env.HEARTBEAT_STALE_SECONDS, 90);
const PLUGIN_SECRET = process.env.PLUGIN_HMAC_SECRET || "";
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || "";
const SMP_ADMIN_TOKEN = process.env.SMP_ADMIN_TOKEN || "";
const BUILD_VERSION = "1.0.0";
const ISO_NOW = () => new Date().toISOString();
const SORTS = {
  kills: "p.kills", playtime: "p.playtime_seconds", killstreak: "p.best_streak",
  kd: "CASE WHEN p.deaths > 0 THEN CAST(p.kills AS REAL) / p.deaths END",
  mobKills: "p.mob_kills",
  bountyClaims: "coalesce(bc.value, 0)", bountyEarned: "coalesce(be.value, 0)",
  bountiesPlaced: "coalesce(bp.value, 0)", bountyPlacedValue: "coalesce(bv.value, 0)",
  largestClaim: "coalesce(lc.value, 0)", deaths: "p.deaths"
};
const LEADER_LABEL = {
  kills: "Most player kills", deaths: "Most player deaths", kd: "Best qualifying K/D",
  killstreak: "Highest killstreak", playtime: "Total playtime", mobKills: "Most mob kills", bountyClaims: "Bounties claimed",
  bountyEarned: "Bounty rewards earned", bountiesPlaced: "Bounties placed",
  bountyPlacedValue: "Bounty value placed", largestClaim: "Largest bounty claimed"
};
const rateBuckets = new Map();

function positiveInt(value, fallback) {
  const result = Number(value);
  return Number.isSafeInteger(result) && result > 0 ? result : fallback;
}
function storedItemMaterial(currency) {
  const value = String(currency || "");
  if (!value.startsWith(ITEM_CURRENCY_PREFIX)) return null;
  const material = value.slice(ITEM_CURRENCY_PREFIX.length);
  return /^[A-Z][A-Z0-9_]{0,63}$/.test(material) ? material : null;
}
function reply(res, status, data, extra = {}) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    ...extra
  };
  if (process.env.NODE_ENV === "production") headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
  res.writeHead(status, headers); res.end(JSON.stringify(data));
}
function fail(res, status, code, message) { reply(res, status, { error: { code, message } }); }
function safeJson(raw) {
  try { return JSON.parse(raw); } catch { return null; }
}
function readRaw(req, maximum = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const parts = []; let length = 0; let overflow = false;
    req.on("data", (chunk) => {
      if (overflow) return;
      length += chunk.length;
      if (length > maximum) { overflow = true; parts.length = 0; return; }
      parts.push(chunk);
    });
    req.on("end", () => overflow ? reject(Object.assign(new Error("Request body is too large."), { status: 413, code: "body_too_large" })) : resolve(Buffer.concat(parts).toString("utf8")));
    req.on("error", reject);
  });
}
async function readJson(req, maximum) {
  const raw = await readRaw(req, maximum);
  const parsed = safeJson(raw);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw Object.assign(new Error("Expected a JSON object."), { status: 400, code: "invalid_json" });
  return { raw, value: parsed };
}
function allowedOrigin(req, res) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (WEB_ORIGIN && origin === WEB_ORIGIN) {
    res.setHeader("Access-Control-Allow-Origin", WEB_ORIGIN);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, Idempotency-Key, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Vary", "Origin");
    return true;
  }
  return false;
}
function consumeRate(req, key, limit, periodMs = 60000) {
  const forwarded = process.env.TRUST_PROXY === "true" ? (req.headers["cf-connecting-ip"] || req.headers["x-forwarded-for"]?.split(",")[0]?.trim()) : null;
  const client = forwarded || req.socket.remoteAddress || "unknown";
  const id = `${client}:${key}`; const now = Date.now();
  let bucket = rateBuckets.get(id);
  if (!bucket || now >= bucket.resetAt) { bucket = { hits: 0, resetAt: now + periodMs }; rateBuckets.set(id, bucket); }
  bucket.hits++;
  return bucket.hits <= limit;
}

function parseCookies(req) {
  const raw = req.headers.cookie || ""; const values = {};
  for (const chunk of raw.split(";")) {
    const separator = chunk.indexOf("="); if (separator < 0) continue;
    const key = chunk.slice(0, separator).trim();
    try { values[key] = decodeURIComponent(chunk.slice(separator + 1).trim()); } catch { /* Ignore malformed cookies. */ }
  }
  return values;
}
function getSession(req) {
  const token = parseCookies(req)[COOKIE];
  if (!token || token.length > 160) return null;
  const session = get("SELECT s.*, p.username FROM sessions s JOIN players p ON p.uuid=s.player_uuid WHERE s.token_hash=? AND s.expires_at>?", hash(token), ISO_NOW());
  return session || null;
}
function requireSession(req, res) {
  const session = getSession(req);
  if (!session) { fail(res, 401, "authentication_required", "Link your Minecraft account in game first."); return null; }
  if (!constantTimeTextEqual(req.headers["x-csrf-token"] || "", session.csrf_token)) {
    fail(res, 403, "csrf_invalid", "This request could not be verified. Refresh the page and try again."); return null;
  }
  return session;
}
function requireAdmin(req, res) {
  const supplied = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 32 || !constantTimeTextEqual(supplied, ADMIN_TOKEN)) {
    fail(res, ADMIN_TOKEN ? 403 : 503, ADMIN_TOKEN ? "admin_forbidden" : "admin_unconfigured", "Administrative access is unavailable.");
    return false;
  }
  return true;
}
function requireSmpAdmin(req, res) {
  const supplied = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!SMP_ADMIN_TOKEN || SMP_ADMIN_TOKEN.length < 32 || !constantTimeTextEqual(supplied, SMP_ADMIN_TOKEN)) {
    fail(res, SMP_ADMIN_TOKEN ? 403 : 503, SMP_ADMIN_TOKEN ? "admin_forbidden" : "admin_unconfigured", "SMP administration is unavailable.");
    return false;
  }
  return true;
}

function validatePlayerIdentity(uuid, username) {
  return validUuid(uuid) && validUsername(username);
}
function ensurePlayer(uuid, username, now = ISO_NOW()) {
  const previous = get("SELECT username FROM players WHERE uuid=?", uuid);
  if (!previous) {
    run("INSERT INTO players (uuid, username, first_seen, last_seen, updated_at) VALUES (?, ?, ?, ?, ?)", uuid, username, now, now, now);
  } else if (previous.username !== username) {
    run("INSERT OR IGNORE INTO username_history (uuid, username, seen_at) VALUES (?, ?, ?)", uuid, previous.username, now);
    run("UPDATE players SET username=?, updated_at=? WHERE uuid=?", username, now, uuid);
    run("INSERT OR IGNORE INTO username_history (uuid, username, seen_at) VALUES (?, ?, ?)", uuid, username, now);
  }
}
function getPlayerByIdentity(identity) {
  if (validUuid(identity)) return get("SELECT * FROM players WHERE uuid=?", identity.toLowerCase());
  if (!validUsername(identity)) return null;
  return get("SELECT * FROM players WHERE username=? COLLATE NOCASE ORDER BY last_seen DESC LIMIT 1", identity);
}
function currentServer() {
  const heartbeat = get("SELECT * FROM server_heartbeat WHERE singleton=1");
  if (!heartbeat) return { status: "unavailable", name: process.env.SERVER_NAME || "itsMaaster SMP", edition: process.env.SERVER_EDITION || null, version: process.env.SERVER_VERSION || null, onlinePlayers: null, maxPlayers: null, lastHeartbeat: null, lastStatisticsUpdate: null, address: process.env.SERVER_ADDRESS || null, tps: null, mspt: null };
  const fresh = Date.now() - Date.parse(heartbeat.last_heartbeat) <= HEARTBEAT_STALE * 1000;
  return {
    status: fresh ? "online" : "unavailable", name: heartbeat.server_name || process.env.SERVER_NAME || "itsMaaster SMP",
    edition: heartbeat.edition || process.env.SERVER_EDITION || null, version: heartbeat.version || process.env.SERVER_VERSION || null,
    onlinePlayers: fresh ? heartbeat.online_players : null, maxPlayers: fresh ? heartbeat.max_players : null,
    lastHeartbeat: heartbeat.last_heartbeat, lastStatisticsUpdate: heartbeat.last_statistics_update,
    address: process.env.SERVER_ADDRESS || null, tps: fresh ? heartbeat.tps : null, mspt: fresh ? heartbeat.mspt : null
  };
}
function publicActivity(row) {
  if (!row) return null;
  const actor = row.actor_uuid ? get("SELECT uuid, username, skin_url FROM players WHERE uuid=?", row.actor_uuid) : null;
  const target = row.target_uuid ? get("SELECT uuid, username, skin_url FROM players WHERE uuid=?", row.target_uuid) : null;
  return { id: row.id, type: row.event_type, actor: actor ? { uuid: actor.uuid, username: actor.username, skinUrl: actor.skin_url || null } : null,
    target: target ? { uuid: target.uuid, username: target.username, skinUrl: target.skin_url || null } : null,
    bountyId: row.bounty_id, description: row.description || null, createdAt: row.created_at };
}
function publicBounty(row) {
  if (!row) return null;
  const target = get("SELECT uuid, username, skin_url FROM players WHERE uuid=?", row.target_uuid);
  const contributors = get("SELECT count(DISTINCT contributor_uuid) AS count FROM contributions WHERE bounty_id=?", row.id)?.count || 0;
  const itemMaterial = storedItemMaterial(row.currency);
  const itemAmount = itemMaterial ? row.total_value : null;
  return { id: row.id, target: target ? { uuid: target.uuid, username: target.username, skinUrl: target.skin_url || null } : null,
    totalValue: row.total_value, currency: itemMaterial || row.currency, bountyType: itemMaterial ? "item" : "currency",
    itemType: itemMaterial, itemMaterial, itemAmount,
    item: itemMaterial ? { material: itemMaterial, amount: itemAmount } : null,
    status: row.status, paymentStatus: row.payment_status,
    contributorCount: contributors, createdAt: row.created_at, updatedAt: row.updated_at,
    expiresAt: row.expires_at, claimedAt: row.claimed_at,
    hunter: row.claimed_by ? publicPlayer(get("SELECT * FROM players WHERE uuid=?", row.claimed_by)) : null };
}
function aggregatePlayer(uuid) {
  const bountyClaims = get("SELECT count(*) AS value FROM bounties WHERE claimed_by=?", uuid)?.value || 0;
  const bountyRewardsEarned = get("SELECT coalesce(sum(total_value), 0) AS value FROM bounties WHERE claimed_by=?", uuid)?.value || 0;
  const bountyValuePlaced = get("SELECT coalesce(sum(amount), 0) AS value FROM contributions WHERE contributor_uuid=?", uuid)?.value || 0;
  const bountiesPlaced = get("SELECT count(DISTINCT bounty_id) AS value FROM contributions WHERE contributor_uuid=?", uuid)?.value || 0;
  const largestClaim = get("SELECT max(total_value) AS value FROM bounties WHERE claimed_by=?", uuid)?.value || 0;
  const activeBounty = get("SELECT total_value, currency FROM bounties WHERE target_uuid=? AND status='active'", uuid);
  return { bountyClaims, bountyRewardsEarned, bountyValuePlaced, bountiesPlaced, largestClaim,
    activeBounty: activeBounty ? activeBounty.total_value : null, currency: activeBounty?.currency || CURRENCY };
}
function leaderboardQuery(category, limit, offset) {
  if (category.startsWith("weapon:")) {
    const slug = category.slice("weapon:".length);
    if (!/^[a-z0-9-]{1,64}$/.test(slug)) return null;
    return {
      sql: `SELECT p.*, wk.kills AS value FROM weapon_kills wk JOIN players p ON p.uuid=wk.player_uuid JOIN weapons w ON w.id=wk.weapon_id WHERE w.slug=? AND w.public=1 ORDER BY value DESC, p.uuid ASC LIMIT ? OFFSET ?`,
      params: [slug, limit, offset], countSql: "SELECT count(*) AS total FROM weapon_kills wk JOIN weapons w ON w.id=wk.weapon_id WHERE w.slug=? AND w.public=1", countParams: [slug]
    };
  }
  if (!Object.hasOwn(SORTS, category)) return null;
  const extraJoins = `LEFT JOIN (SELECT claimed_by AS uuid, count(*) AS value FROM bounties WHERE claimed_by IS NOT NULL GROUP BY claimed_by) bc ON bc.uuid=p.uuid
    LEFT JOIN (SELECT claimed_by AS uuid, sum(total_value) AS value FROM bounties WHERE claimed_by IS NOT NULL GROUP BY claimed_by) be ON be.uuid=p.uuid
    LEFT JOIN (SELECT c.contributor_uuid AS uuid, count(DISTINCT c.bounty_id) AS value FROM contributions c GROUP BY c.contributor_uuid) bp ON bp.uuid=p.uuid
    LEFT JOIN (SELECT contributor_uuid AS uuid, sum(amount) AS value FROM contributions GROUP BY contributor_uuid) bv ON bv.uuid=p.uuid
    LEFT JOIN (SELECT claimed_by AS uuid, max(total_value) AS value FROM bounties WHERE claimed_by IS NOT NULL GROUP BY claimed_by) lc ON lc.uuid=p.uuid`;
  const joins = ["bountyClaims", "bountyEarned", "bountiesPlaced", "bountyPlacedValue", "largestClaim"].includes(category) ? extraJoins : "";
  const minClause = category === "kd" ? "WHERE p.kills >= ? AND p.deaths > 0"
    : category === "mobKills" ? "WHERE p.mob_kills IS NOT NULL"
      : category === "playtime" ? "WHERE p.playtime_seconds IS NOT NULL"
        : category === "bountyClaims" || category === "bountyEarned" || category === "bountiesPlaced" || category === "bountyPlacedValue" || category === "largestClaim" ? `WHERE ${SORTS[category]} > 0` : "";
  const params = category === "kd" ? [KD_MIN, limit, offset] : [limit, offset];
  return {
    sql: `SELECT p.*, ${SORTS[category]} AS value FROM players p ${joins} ${minClause} ORDER BY value DESC, p.uuid ASC LIMIT ? OFFSET ?`,
    params,
    countSql: `SELECT count(*) AS total FROM players p ${joins} ${minClause}`,
    countParams: category === "kd" ? [KD_MIN] : []
  };
}
function leaderboardRows(category, limit, offset) {
  if (["bountyEarned", "bountyPlacedValue", "largestClaim"].includes(category) && !CURRENCY) return { items: [], total: 0 };
  const query = leaderboardQuery(category, limit, offset);
  if (!query) return null;
  const items = all(query.sql, ...query.params);
  const total = get(query.countSql, ...query.countParams)?.total || 0;
  return { items: items.map((row, index) => {
    const p = publicPlayer(row); const value = row.value ?? null;
    const displayValue = category === "playtime" ? (value == null ? "—" : `${Math.floor(value / 3600)}h`) : category === "kd" ? (value == null ? "—" : Number(value).toFixed(2)) : (value == null ? "—" : ["bountyEarned", "bountyPlacedValue", "largestClaim"].includes(category) ? `${value} ${CURRENCY}` : String(value));
    return { ...p, player: p, rank: offset + index + 1, value, currency: ["bountyEarned", "bountyPlacedValue", "largestClaim"].includes(category) ? CURRENCY : null, displayValue };
  }), total };
}
function addAudit(actor, action, entityType, entityId, result) {
  run("INSERT INTO audit_log (id, actor_uuid, action, entity_type, entity_id, result, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", randomUUID(), actor || null, action, entityType || null, entityId || null, result, ISO_NOW());
}
function addActivity(type, actor, target, bountyId, sourceEventId = null, description = null) {
  run("INSERT OR IGNORE INTO activity (id, source_event_id, event_type, actor_uuid, target_uuid, bounty_id, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", randomUUID(), sourceEventId, type, actor || null, target || null, bountyId || null, description, ISO_NOW());
}
function pageResponse(url, defaultLimit = 20, maxLimit = 100) { return pageArgs(url, defaultLimit, maxLimit); }

function authenticatePlugin(req, res, rawBody) {
  if (!PLUGIN_SECRET || PLUGIN_SECRET.length < 32) { fail(res, 503, "plugin_auth_unconfigured", "Trusted plugin authentication is not configured."); return false; }
  const timestamp = req.headers["x-smp-timestamp"];
  const requestId = req.headers["x-smp-request-id"];
  const supplied = req.headers["x-smp-signature"];
  if (!timestamp || !requestId || !supplied || !/^[A-Za-z0-9-]{8,80}$/.test(requestId)) { fail(res, 401, "plugin_auth_invalid", "Trusted plugin authentication failed."); return false; }
  const millis = Number(timestamp);
  if (!Number.isSafeInteger(millis) || Math.abs(Date.now() - millis) > 5 * 60_000) { fail(res, 401, "plugin_request_expired", "Trusted plugin request expired."); return false; }
  const path = new URL(req.url, "http://localhost").pathname + new URL(req.url, "http://localhost").search;
  const expected = signature(PLUGIN_SECRET, req.method, path, String(timestamp), requestId, rawBody);
  if (!constantTimeTextEqual(expected, supplied)) { fail(res, 401, "plugin_auth_invalid", "Trusted plugin authentication failed."); return false; }
  try {
    const inserted = run("INSERT OR IGNORE INTO plugin_nonces (request_id, seen_at) VALUES (?, ?)", requestId, ISO_NOW());
    if (inserted.changes !== 1) { fail(res, 409, "plugin_request_replayed", "This signed request was already received."); return false; }
  } catch { fail(res, 503, "plugin_auth_unavailable", "Trusted plugin authentication is temporarily unavailable."); return false; }
  return true;
}

async function apiHandler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  if (!allowedOrigin(req, res)) return fail(res, 403, "origin_not_allowed", "This origin is not allowed to access the API.");
  if (req.method === "OPTIONS") { res.writeHead(204, { "Content-Length": "0", "Cache-Control": "no-store" }); return res.end(); }
  if (!url.pathname.startsWith("/api/v1/")) return fail(res, 404, "not_found", "Endpoint not found.");
  const path = url.pathname.slice("/api/v1".length);

  // Public community endpoints. Chat is shown only after the server bridge confirms delivery.
  if (req.method === "GET" && path === "/announcements") {
    const limit = Math.min(50, Math.max(1, Number(url.searchParams.get("limit") || 20)));
    const items = all("SELECT id, title, body, pinned, author, created_at FROM smp_announcements WHERE active=1 ORDER BY pinned DESC, created_at DESC LIMIT ?", limit)
      .map((row) => ({ id: row.id, title: row.title, body: row.body, pinned: Boolean(row.pinned), author: row.author, createdAt: row.created_at }));
    return reply(res, 200, { items, total: get("SELECT count(*) AS total FROM smp_announcements WHERE active=1")?.total || 0 });
  }
  if (req.method === "GET" && path === "/chat") {
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") || 50)));
    const rows = all("SELECT id, username, message, source, created_at FROM smp_chat_messages WHERE status='delivered' ORDER BY created_at DESC LIMIT ?", limit).reverse();
    return reply(res, 200, { items: rows.map((row) => ({ id: row.id, username: row.username, message: row.message, source: row.source, createdAt: row.created_at })), total: get("SELECT count(*) AS total FROM smp_chat_messages WHERE status='delivered'")?.total || 0 });
  }

  if (path.startsWith("/plugin/")) {
    if (req.method !== "POST" && req.method !== "GET") return fail(res, 405, "method_not_allowed", "Method not allowed.");
    let raw = ""; let body = {};
    if (req.method === "POST") {
      const parsed = await readRaw(req, 1024 * 1024); raw = parsed;
      if (raw) { body = safeJson(raw); if (!body || typeof body !== "object" || Array.isArray(body)) return fail(res, 400, "invalid_json", "Expected a JSON object."); }
    }
    if (!authenticatePlugin(req, res, raw)) return;
    return pluginHandler(req, res, url, path, body);
  }

  if (path.startsWith("/auth/") && !consumeRate(req, "auth", 6)) return fail(res, 429, "rate_limited", "Too many authentication attempts. Try again shortly.");
  if (path === "/bounties" && req.method === "POST" && !consumeRate(req, "placement", 5)) return fail(res, 429, "rate_limited", "Too many bounty requests. Try again shortly.");
  if (path.startsWith("/players") && !consumeRate(req, "players", 120)) return fail(res, 429, "rate_limited", "Too many requests. Try again shortly.");

  if (req.method === "GET" && path === "/status") {
    let databaseStatus = "unavailable"; try { get("SELECT 1 AS healthy"); databaseStatus = "online"; } catch { /* Keep public status generic. */ }
    return reply(res, 200, { gameServer: currentServer(), backend: { status: "online", databaseStatus, checkedAt: ISO_NOW(), version: BUILD_VERSION } });
  }
  if (req.method === "GET" && path === "/overview") {
    const totals = get(`SELECT count(*) AS players, coalesce(sum(kills),0) AS playerKills,
      coalesce(sum(deaths),0) AS playerDeaths, coalesce(sum(mob_kills),0) AS mobKills,
      coalesce(sum(blocks_mined),0) AS blocksMined,
      (SELECT count(*) FROM bounties WHERE status='active') AS activeBounties,
      (SELECT coalesce(sum(total_value),0) FROM bounties WHERE status='active') AS activeBountyValue,
      (SELECT coalesce(sum(playtime_seconds),0) FROM players) AS playtimeSeconds,
      (SELECT count(*) FROM bounties WHERE status='claimed') AS bountyClaims FROM players`);
    const leaders = {};
    for (const [category, key] of [["kills", "kills"], ["killstreak", "killstreak"], ["kd", "kd"], ["bountyClaims", "bountyClaims"]]) {
      const board = leaderboardRows(category, 1, 0); const item = board?.items[0];
      leaders[key] = item ? { ...item.player, value: item.value, [category === "kd" ? "kd_ratio" : category === "kills" ? "player_kills" : category === "killstreak" ? "best_killstreak" : "bounties_claimed"]: item.value } : null;
    }
    const bounties = all("SELECT * FROM bounties WHERE status='active' ORDER BY total_value DESC, created_at DESC LIMIT 3").map(publicBounty);
    const activity = all("SELECT * FROM activity ORDER BY created_at DESC, id DESC LIMIT 5").map(publicActivity);
    return reply(res, 200, { generatedAt: ISO_NOW(), server: currentServer(), totals: { ...totals, currency: CURRENCY }, leaders, bounties, activity });
  }
  if (req.method === "GET" && path === "/players") {
    const { page, limit, offset } = pageResponse(url, 20, 100);
    const search = (url.searchParams.get("search") || "").slice(0, 32);
    const sort = url.searchParams.get("sort") || "kills";
    const sortExpression = ({ kills: "p.kills", playtime: "p.playtime_seconds", killstreak: "p.best_streak", kd: "CASE WHEN p.deaths>0 THEN CAST(p.kills AS REAL)/p.deaths END", bountyClaims: "(SELECT count(*) FROM bounties b WHERE b.claimed_by=p.uuid)" })[sort] || "p.kills";
    const onlineFilter = url.searchParams.get("online") || "all";
    if (!["all", "online", "offline"].includes(onlineFilter)) return fail(res, 400, "invalid_online_filter", "Online filter must be all, online, or offline.");
    const safeSearch = search.replace(/[\\%_]/g, "\\$&");
    const onlineAvailable = currentServer().status === "online";
    if (onlineFilter !== "all" && !onlineAvailable) return reply(res, 200, { items: [], total: 0, page, limit, hasMore: false, onlineFilterUnavailable: true });
    const onlineValue = onlineFilter === "online" ? 1 : onlineFilter === "offline" ? 0 : null;
    const kdClause = sort === "kd" ? ` AND p.kills>=${KD_MIN} AND p.deaths>0` : "";
    const onlineClause = onlineValue == null ? "" : " AND p.online=?";
    const sql = `SELECT p.*, (SELECT total_value FROM bounties b WHERE b.target_uuid=p.uuid AND b.status='active') AS active_bounty_value, (SELECT currency FROM bounties b WHERE b.target_uuid=p.uuid AND b.status='active') AS active_bounty_currency FROM players p WHERE (?='' OR p.username LIKE ? ESCAPE '\\' COLLATE NOCASE)${kdClause}${onlineClause} ORDER BY ${sortExpression} DESC, p.uuid ASC LIMIT ? OFFSET ?`;
    const items = onlineValue == null ? all(sql, search, `%${safeSearch}%`, limit, offset) : all(sql, search, `%${safeSearch}%`, onlineValue, limit, offset);
    const countSql = `SELECT count(*) AS total FROM players p WHERE (?='' OR p.username LIKE ? ESCAPE '\\' COLLATE NOCASE)${kdClause}${onlineClause}`;
    const total = (onlineValue == null ? get(countSql, search, `%${safeSearch}%`) : get(countSql, search, `%${safeSearch}%`, onlineValue))?.total || 0;
    return reply(res, 200, { items: items.map((row) => ({ ...publicPlayer(row), activeBountyValue: row.active_bounty_value ?? null, currency: row.active_bounty_currency || CURRENCY })), total, page, limit, hasMore: offset + items.length < total, onlineFilterUnavailable: false });
  }
  if (req.method === "GET" && path.startsWith("/players/")) {
    const identity = decodeURIComponent(path.slice("/players/".length));
    const row = getPlayerByIdentity(identity);
    if (!row) return fail(res, 404, "player_not_found", "No tracked player matches this profile.");
    const { page, limit, offset } = pageResponse(url, 20, 100);
    const profile = publicPlayer(row); const stats = aggregatePlayer(row.uuid);
    const historyRows = all("SELECT * FROM activity WHERE actor_uuid=? OR target_uuid=? ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", row.uuid, row.uuid, limit, offset);
    const historyTotal = get("SELECT count(*) AS total FROM activity WHERE actor_uuid=? OR target_uuid=?", row.uuid, row.uuid)?.total || 0;
    return reply(res, 200, { player: profile, statistics: { ...profile, playerKills: row.kills, playerDeaths: row.deaths, kd: kdRatio(row.kills, row.deaths), ...stats }, history: historyRows.map(publicActivity), historyPage: { total: historyTotal, page, limit, hasMore: offset + historyRows.length < historyTotal } });
  }
  if (req.method === "GET" && path === "/leaderboards") {
    const { page, limit, offset } = pageResponse(url, 25, 100);
    const category = url.searchParams.get("category") || "kills";
    const period = url.searchParams.get("period") || "all_time";
    if (period !== "all_time") return fail(res, 400, "period_unavailable", "Only all-time rankings are configured.");
    const board = leaderboardRows(category, limit, offset);
    if (!board) return fail(res, 400, "category_unavailable", "This leaderboard category is not configured.");
    const weaponCategories = all("SELECT slug, name FROM weapons WHERE public=1 ORDER BY name COLLATE NOCASE").map((weapon) => ({ category: `weapon:${weapon.slug}`, name: weapon.name }));
    return reply(res, 200, { category, period, title: LEADER_LABEL[category] || (category.startsWith("weapon:") ? "Custom weapon kills" : "Leaderboard"), minimumKills: category === "kd" ? KD_MIN : null, tieBreak: "Equal values are ordered by stable Minecraft UUID.", weaponCategories, ...board, page, limit, hasMore: offset + board.items.length < board.total });
  }
  if (req.method === "GET" && path === "/bounties") {
    const { page, limit, offset } = pageResponse(url, 24, 100);
    const sort = url.searchParams.get("sort") || "highest_reward";
    const order = ({ highest_reward: "total_value DESC, created_at DESC", newest: "created_at DESC", oldest: "created_at ASC", contributors: "contributor_count DESC, total_value DESC", expiring: "expires_at ASC" })[sort] || "total_value DESC, created_at DESC";
    const minValueRaw = url.searchParams.get("minValue") || ""; const minValue = minValueRaw ? Number(minValueRaw) : 0;
    const nearExpiry = url.searchParams.get("nearExpiry") || "";
    if (!Number.isSafeInteger(minValue) || minValue < 0 || (nearExpiry && !["24h", "72h"].includes(nearExpiry))) return fail(res, 400, "invalid_bounty_filter", "Reward and expiry filters are invalid.");
    const conditions = ["b.status='active'", "(b.expires_at IS NULL OR b.expires_at > ?)"]; const filterArgs = [ISO_NOW()];
    if (minValue > 0) { conditions.push("b.total_value>=?"); filterArgs.push(minValue); }
    if (nearExpiry) { conditions.push("b.expires_at IS NOT NULL AND b.expires_at<=?"); filterArgs.push(new Date(Date.now() + (nearExpiry === "24h" ? 24 : 72) * 3600_000).toISOString()); }
    const where = conditions.join(" AND ");
    const rows = all(`SELECT b.*, (SELECT count(DISTINCT contributor_uuid) FROM contributions c WHERE c.bounty_id=b.id) AS contributor_count FROM bounties b WHERE ${where} ORDER BY ${order} LIMIT ? OFFSET ?`, ...filterArgs, limit, offset);
    const total = get(`SELECT count(*) AS total FROM bounties b WHERE ${where}`, ...filterArgs)?.total || 0;
    const trackedPlayers = sort === "_unused" ? [] : all("SELECT uuid, username FROM players ORDER BY username COLLATE NOCASE LIMIT 200");
    return reply(res, 200, { items: rows.map(publicBounty), players: trackedPlayers, currency: CURRENCY, minimumAmount: MIN_BOUNTY, maximumAmount: MAX_BOUNTY, total, page, limit, hasMore: offset + rows.length < total });
  }
  if (req.method === "GET" && path === "/bounties/history") {
    const { page, limit, offset } = pageResponse(url, 20, 100);
    const status = url.searchParams.get("status") || "";
    const search = (url.searchParams.get("search") || "").slice(0, 32);
    const from = url.searchParams.get("from") || ""; const to = url.searchParams.get("to") || "";
    const allowedStatus = ["claimed", "expired", "cancelled", "under_review"];
    if (status && !allowedStatus.includes(status)) return fail(res, 400, "invalid_status", "This bounty status filter is not supported.");
    const validDate = (value) => { if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false; const parsed = new Date(`${value}T00:00:00.000Z`); return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value; };
    if ((from && !validDate(from)) || (to && !validDate(to))) return fail(res, 400, "invalid_date_range", "Dates must use valid YYYY-MM-DD calendar dates.");
    const conditions = ["status<>'active'"]; const args = [];
    if (status) { conditions.push("status=?"); args.push(status); }
    if (from) { conditions.push("created_at>=?"); args.push(`${from}T00:00:00.000Z`); }
    if (to) { conditions.push("created_at<=?"); args.push(`${to}T23:59:59.999Z`); }
    if (search) { const safe = search.replace(/[\\%_]/g, "\\$&"); conditions.push("(target_uuid IN (SELECT uuid FROM players WHERE username LIKE ? ESCAPE '\\' COLLATE NOCASE) OR claimed_by IN (SELECT uuid FROM players WHERE username LIKE ? ESCAPE '\\' COLLATE NOCASE))"); args.push(`%${safe}%`, `%${safe}%`); }
    const where = conditions.join(" AND ");
    const rows = all(`SELECT * FROM bounties WHERE ${where} ORDER BY coalesce(claimed_at, updated_at, created_at) DESC LIMIT ? OFFSET ?`, ...args, limit, offset);
    const total = get(`SELECT count(*) AS total FROM bounties WHERE ${where}`, ...args)?.total || 0;
    const items = rows.map((b) => ({ ...publicBounty(b), updatedAt: b.updated_at }));
    return reply(res, 200, { items, total, page, limit, hasMore: offset + rows.length < total });
  }
  if (req.method === "GET" && path.startsWith("/bounties/") && path !== "/bounties/history") {
    const id = decodeURIComponent(path.slice("/bounties/".length));
    const bounty = get("SELECT * FROM bounties WHERE id=?", id);
    if (!bounty) return fail(res, 404, "bounty_not_found", "No public bounty matches this record.");
    const contributions = all(`SELECT c.amount, c.created_at, p.uuid, p.username, p.skin_url FROM contributions c JOIN players p ON p.uuid=c.contributor_uuid WHERE c.bounty_id=? ORDER BY c.created_at ASC`, id).map((c) => ({ amount: c.amount, createdAt: c.created_at, player: { uuid: c.uuid, username: c.username, skinUrl: c.skin_url || null } }));
    return reply(res, 200, { bounty: publicBounty(bounty), contributions });
  }
  if (req.method === "GET" && path === "/weapons") {
    const { page, limit, offset } = pageResponse(url, 30, 100);
    const items = all(`SELECT w.*, sum(wk.kills) AS kills FROM weapons w LEFT JOIN weapon_kills wk ON wk.weapon_id=w.id WHERE w.public=1 GROUP BY w.id ORDER BY w.name COLLATE NOCASE LIMIT ? OFFSET ?`, limit, offset)
      .map((w) => ({ id: w.id, slug: w.slug, name: w.name, category: w.category, description: w.description, abilities: w.abilities ? safeJson(w.abilities) : [], cooldownSeconds: w.cooldown_seconds, kills: w.kills }));
    const total = get("SELECT count(*) AS total FROM weapons WHERE public=1")?.total || 0;
    return reply(res, 200, { items, total, page, limit, hasMore: offset + items.length < total });
  }
  if (req.method === "GET" && path === "/activity") {
    const { page, limit, offset } = pageResponse(url, 30, 100);
    const rows = all("SELECT * FROM activity ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?", limit, offset);
    const total = get("SELECT count(*) AS total FROM activity")?.total || 0;
    return reply(res, 200, { items: rows.map(publicActivity), total, page, limit, hasMore: offset + rows.length < total });
  }
  if (req.method === "GET" && path === "/me") {
    const session = getSession(req);
    if (!session) return reply(res, 200, { player: null });
    const player = publicPlayer(get("SELECT * FROM players WHERE uuid=?", session.player_uuid));
    return reply(res, 200, { player, csrfToken: session.csrf_token }, { "Cache-Control": "private, no-store" });
  }
  if (req.method === "GET" && path === "/me/transactions") {
    const session = getSession(req);
    if (!session) return fail(res, 401, "authentication_required", "Link your Minecraft account in game first.");
    const { page, limit, offset } = pageResponse(url, 20, 50);
    const rows = all("SELECT t.*, target.username AS target_username FROM transactions t LEFT JOIN players target ON target.uuid=t.target_uuid WHERE t.player_uuid=? ORDER BY t.created_at DESC LIMIT ? OFFSET ?", session.player_uuid, limit, offset);
    const total = get("SELECT count(*) AS total FROM transactions WHERE player_uuid=?", session.player_uuid)?.total || 0;
    const items = rows.map((row) => ({ ...transactionView(row), targetUsername: row.target_username || null }));
    return reply(res, 200, { items, total, page, limit, hasMore: offset + rows.length < total }, { "Cache-Control": "private, no-store" });
  }
  if (req.method === "POST" && path === "/auth/link") {
    if (!consumeRate(req, "link-code", 5, 5 * 60_000)) return fail(res, 429, "rate_limited", "Too many link attempts. Wait a few minutes before trying again.");
    const { value } = await readJson(req, 4096);
    const code = String(value.code || "").replace(/\s/g, "").toUpperCase();
    if (!/^[A-F0-9]{10}$/.test(code)) return fail(res, 400, "invalid_link_code", "Enter the 10-character code displayed in game.");
    const codeRow = get("SELECT * FROM link_codes WHERE code_hash=? AND used_at IS NULL AND expires_at>?", hash(code), ISO_NOW());
    if (!codeRow) return fail(res, 400, "link_code_invalid", "That code is invalid or expired. Generate a new one in game.");
    const token = randomBytes(32).toString("base64url"); const csrfToken = randomBytes(24).toString("base64url");
    const expires = new Date(Date.now() + 7 * 86400_000).toISOString();
    transaction(() => {
      const consumed = run("UPDATE link_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at>?", ISO_NOW(), hash(code), ISO_NOW());
      if (consumed.changes !== 1) throw Object.assign(new Error("That code was already used."), { status: 400, code: "link_code_invalid" });
      run("INSERT INTO sessions (token_hash, player_uuid, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)", hash(token), codeRow.player_uuid, csrfToken, expires, ISO_NOW());
    });
    const cookie = `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${7 * 86400}${SECURE_COOKIE ? "; Secure" : ""}`;
    return reply(res, 200, { player: publicPlayer(get("SELECT * FROM players WHERE uuid=?", codeRow.player_uuid)), csrfToken }, { "Set-Cookie": cookie, "Cache-Control": "private, no-store" });
  }
  if (req.method === "POST" && path === "/auth/logout") {
    const session = requireSession(req, res); if (!session) return;
    run("DELETE FROM sessions WHERE token_hash=?", session.token_hash);
    return reply(res, 200, { ok: true }, { "Set-Cookie": `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${SECURE_COOKIE ? "; Secure" : ""}` });
  }
  if (req.method === "POST" && path === "/bounties") {
    const session = requireSession(req, res); if (!session) return;
    const idempotency = String(req.headers["idempotency-key"] || "");
    if (!/^[A-Za-z0-9_-]{12,100}$/.test(idempotency)) return fail(res, 400, "idempotency_key_required", "A valid idempotency key is required.");
    const { value } = await readJson(req, 4096);
    const targetUuid = String(value.targetUuid || "").toLowerCase();
    const bountyType = String(value.bountyType || "item").toLowerCase();
    const nestedItem = value.item && typeof value.item === "object" && !Array.isArray(value.item) ? value.item : {};
    const itemMaterial = String(value.itemMaterial || value.itemType || nestedItem.material || "").trim().replace(/^minecraft:/i, "").toUpperCase();
    const rawItemAmount = value.itemAmount ?? nestedItem.amount;
    const itemAmount = typeof rawItemAmount === "number" ? rawItemAmount : Number(rawItemAmount);
    if (bountyType !== "item") return fail(res, 400, "invalid_bounty_type", "Only item bounties are supported.");
    if (!validUuid(targetUuid) || !/^[A-Z][A-Z0-9_]{0,63}$/.test(itemMaterial)
      || !Number.isSafeInteger(itemAmount) || itemAmount < 1 || itemAmount > MAX_BOUNTY_ITEMS) {
      return fail(res, 400, "invalid_bounty", `Choose a valid Minecraft item and a quantity from 1 to ${MAX_BOUNTY_ITEMS}.`);
    }
    if (targetUuid === session.player_uuid) return fail(res, 400, "self_bounty_forbidden", "You cannot place a bounty on yourself.");
    if (!get("SELECT 1 FROM players WHERE uuid=?", targetUuid)) return fail(res, 404, "target_not_found", "The target must be a tracked player.");
    const fullKey = `${session.player_uuid}:${idempotency}`;
    const existing = get("SELECT * FROM transactions WHERE idempotency_key=?", fullKey);
    if (existing) return reply(res, 202, { transaction: transactionView(existing) }, { "Cache-Control": "private, no-store" });

    const storedCurrency = `${ITEM_CURRENCY_PREFIX}${itemMaterial}`;
    const active = get("SELECT * FROM bounties WHERE target_uuid=? AND status='active'", targetUuid);
    if (active && storedItemMaterial(active.currency) !== itemMaterial) {
      return fail(res, 409, "active_bounty_item_mismatch", "This player already has an active bounty with a different item. Wait for it to be claimed or expire first.");
    }
    const pendingMismatch = get("SELECT id FROM transactions WHERE target_uuid=? AND type='placement' AND status IN ('requested','processing') AND currency<>? LIMIT 1", targetUuid, storedCurrency);
    if (pendingMismatch) {
      return fail(res, 409, "pending_bounty_item_mismatch", "A different item bounty request is already waiting for this target. Try again after it is processed.");
    }

    const now = ISO_NOW(); const txId = randomUUID();
    run("INSERT INTO transactions (id, type, player_uuid, target_uuid, bounty_id, amount, currency, status, idempotency_key, created_at, updated_at) VALUES (?, 'placement', ?, ?, ?, ?, ?, 'requested', ?, ?, ?)", txId, session.player_uuid, targetUuid, active?.id || null, itemAmount, storedCurrency, fullKey, now, now);
    addAudit(session.player_uuid, "item_bounty_placement_requested", "transaction", txId, "requested");
    return reply(res, 202, { transaction: transactionView(get("SELECT * FROM transactions WHERE id=?", txId)) }, { "Cache-Control": "private, no-store" });
  }

  if (path === "/admin/ping" && req.method === "GET") {
    if (!consumeRate(req, "smp-admin-ping", 15, 60_000)) return fail(res, 429, "rate_limited", "Too many admin authentication attempts. Try again shortly.");
    if (!requireSmpAdmin(req, res)) return;
    return reply(res, 200, { ok: true, role: "admin" }, { "Cache-Control": "no-store" });
  }
  if (path === "/admin/announcements" && req.method === "POST") {
    if (!requireSmpAdmin(req, res)) return;
    const { value } = await readJson(req, 8192);
    const title = String(value.title || "").trim();
    const body = String(value.body || "").trim();
    const pinned = value.pinned === true ? 1 : 0;
    if (!title || title.length > 100 || !body || body.length > 3000) return fail(res, 400, "invalid_announcement", "Enter a title (1–100 characters) and message (1–3000 characters).");
    const id = randomUUID(); const now = ISO_NOW();
    run("INSERT INTO smp_announcements (id, title, body, pinned, active, author, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)", id, title, body, pinned, "Maaster", now);
    addAudit("admin", "announcement_created", "announcement", id, "published");
    return reply(res, 201, { item: { id, title, body, pinned: Boolean(pinned), author: "Maaster", createdAt: now } });
  }
  const announcementDeleteMatch = path.match(/^\/admin\/announcements\/([0-9a-f-]{36})$/i);
  if (announcementDeleteMatch && req.method === "DELETE") {
    if (!requireSmpAdmin(req, res)) return;
    const id = announcementDeleteMatch[1].toLowerCase();
    const row = get("SELECT id FROM smp_announcements WHERE id=? AND active=1", id);
    if (!row) return fail(res, 404, "announcement_not_found", "Announcement not found.");
    run("UPDATE smp_announcements SET active=0 WHERE id=?", id);
    addAudit("admin", "announcement_hidden", "announcement", id, "hidden");
    return reply(res, 200, { ok: true });
  }
  if (path === "/admin/chat" && req.method === "POST") {
    if (!requireSmpAdmin(req, res)) return;
    const { value } = await readJson(req, 4096);
    const message = String(value.message || "").trim();
    if (!message || message.length > 256 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(message)) return fail(res, 400, "invalid_chat_message", "Enter a chat message between 1 and 256 characters.");
    const id = randomUUID(); const now = ISO_NOW();
    run("INSERT INTO smp_chat_messages (id, source_event_id, player_uuid, username, message, source, status, created_at, updated_at, delivered_at) VALUES (?, NULL, NULL, ?, ?, 'admin', 'pending', ?, ?, NULL)", id, "Maaster", message, now, now);
    addAudit("admin", "server_chat_queued", "chat_message", id, "pending_delivery");
    return reply(res, 202, { item: { id, username: "Maaster", message, source: "admin", status: "pending", createdAt: now } });
  }

  const adminMatch = path.match(/^\/admin\/transactions\/([0-9a-f-]{36})(?:\/(retry|reconcile))?$/i);
  if (adminMatch) {
    if (!requireAdmin(req, res)) return;
    const txId = adminMatch[1].toLowerCase(); const action = adminMatch[2] || "inspect";
    const tx = get("SELECT * FROM transactions WHERE id=?", txId);
    if (!tx) return fail(res, 404, "transaction_not_found", "Transaction not found.");
    if (action === "inspect" && req.method === "GET") {
      return reply(res, 200, { transaction: transactionView(tx), playerUuid: tx.player_uuid, targetUuid: tx.target_uuid, bountyId: tx.bounty_id, safeErrorCode: tx.safe_error_code || null });
    }
    if (action === "retry" && req.method === "POST") {
      const { value } = await readJson(req, 4096);
      if (tx.type !== "payout" || tx.status !== "failed" || value.confirmedNoPayment !== true) return fail(res, 409, "retry_not_allowed", "Only a failed payout verified as unpaid can be retried.");
      const bounty = tx.bounty_id ? get("SELECT * FROM bounties WHERE id=?", tx.bounty_id) : null;
      if (!bounty || !["claimed", "under_review"].includes(bounty.status)) return fail(res, 409, "bounty_not_recoverable", "The bounty is not in a recoverable payout state.");
      const retryId = randomUUID(); const retryKey = `admin-retry:${tx.id}:${retryId}`;
      transaction(() => {
        run("INSERT INTO transactions (id, type, player_uuid, target_uuid, bounty_id, amount, currency, status, idempotency_key, created_at, updated_at) VALUES (?, 'payout', ?, ?, ?, ?, ?, 'requested', ?, ?, ?)", retryId, tx.player_uuid, tx.target_uuid, tx.bounty_id, tx.amount, tx.currency, retryKey, ISO_NOW(), ISO_NOW());
        run("UPDATE bounties SET status='claimed', payment_status='pending', updated_at=?, version=version+1 WHERE id=?", ISO_NOW(), tx.bounty_id);
        addAudit("admin", "payout_retry_requested", "transaction", retryId, "requested_after_unpaid_verification");
      });
      return reply(res, 202, { transaction: transactionView(get("SELECT * FROM transactions WHERE id=?", retryId)) });
    }
    if (action === "reconcile" && req.method === "POST") {
      const { value } = await readJson(req, 4096); const outcome = value.outcome;
      if (tx.type !== "payout" || !["manual_review", "processing"].includes(tx.status) || !["completed", "failed"].includes(outcome)) return fail(res, 409, "reconciliation_not_allowed", "Only an unresolved payout can be reconciled as completed or failed.");
      transaction(() => {
        run("UPDATE transactions SET status=?, updated_at=?, completed_at=?, safe_error_code=? WHERE id=?", outcome, ISO_NOW(), outcome === "completed" ? ISO_NOW() : null, outcome === "failed" ? "admin_reconciled_failed" : null, tx.id);
        run("UPDATE bounties SET status='claimed', payment_status=?, updated_at=?, version=version+1 WHERE id=?", outcome, ISO_NOW(), tx.bounty_id);
        addAudit("admin", "payout_reconciled", "transaction", tx.id, outcome);
      });
      return reply(res, 200, { transaction: transactionView(get("SELECT * FROM transactions WHERE id=?", tx.id)), reconciled: true });
    }
    return fail(res, 405, "method_not_allowed", "Method not allowed.");
  }
  return fail(res, 404, "not_found", "Endpoint not found.");
}

function transactionView(row) {
  const itemMaterial = storedItemMaterial(row.currency);
  return { id: row.id, type: row.type, status: row.status, amount: row.amount,
    currency: itemMaterial || row.currency, bountyType: itemMaterial ? "item" : "currency",
    itemType: itemMaterial, itemMaterial, itemAmount: itemMaterial ? row.amount : null,
    item: itemMaterial ? { material: itemMaterial, amount: row.amount } : null,
    createdAt: row.created_at, updatedAt: row.updated_at };
}

function pluginHandler(req, res, url, path, body) {
  const now = ISO_NOW();
  if (req.method === "POST" && path === "/plugin/link-codes") {
    const uuid = String(body.uuid || "").toLowerCase(); const username = String(body.username || "");
    if (!validatePlayerIdentity(uuid, username)) return fail(res, 400, "invalid_player", "Player UUID or username is invalid.");
    ensurePlayer(uuid, username, now);
    const recentCodes = get("SELECT count(*) AS count FROM link_codes WHERE player_uuid=? AND created_at>?", uuid, new Date(Date.now() - 5 * 60_000).toISOString())?.count || 0;
    if (recentCodes >= 3) return fail(res, 429, "link_code_rate_limited", "Generate at most three account link codes every five minutes.");
    run("DELETE FROM link_codes WHERE expires_at<? OR used_at IS NOT NULL", now);
    let code = randomBytes(5).toString("hex").toUpperCase();
    for (let i = 0; i < 3 && get("SELECT 1 FROM link_codes WHERE code_hash=?", hash(code)); i++) code = randomBytes(5).toString("hex").toUpperCase();
    const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
    run("INSERT INTO link_codes (code_hash, player_uuid, expires_at, created_at) VALUES (?, ?, ?, ?)", hash(code), uuid, expiresAt, now);
    return reply(res, 201, { code, expiresAt });
  }
  if (req.method === "POST" && path === "/plugin/chat") {
    const eventId = String(body.eventId || "");
    const uuid = String(body.uuid || "").toLowerCase();
    const username = String(body.username || "");
    const message = String(body.message || "");
    if (!/^[A-Za-z0-9-]{8,100}$/.test(eventId) || !validatePlayerIdentity(uuid, username)
      || !message.trim() || message.length > 256 || /[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(message)) {
      return fail(res, 400, "invalid_chat_event", "Chat event details are invalid.");
    }
    if (get("SELECT 1 FROM smp_chat_messages WHERE source_event_id=?", eventId)) return reply(res, 200, { ok: true, duplicate: true });
    ensurePlayer(uuid, username, now);
    run("INSERT INTO smp_chat_messages (id, source_event_id, player_uuid, username, message, source, status, created_at, updated_at, delivered_at) VALUES (?, ?, ?, ?, ?, 'minecraft', 'delivered', ?, ?, ?)", randomUUID(), eventId, uuid, username, message, now, now, now);
    return reply(res, 201, { ok: true, receivedAt: now });
  }
  if (req.method === "GET" && path === "/plugin/chat-outbox") {
    const limit = Math.min(20, Math.max(1, Number(url.searchParams.get("limit") || 10)));
    const requeueBefore = new Date(Date.now() - 60_000).toISOString();
    const rows = all("SELECT id, username, message FROM smp_chat_messages WHERE source='admin' AND (status='pending' OR (status='processing' AND updated_at<?)) ORDER BY created_at ASC LIMIT ?", requeueBefore, limit);
    transaction(() => { for (const row of rows) run("UPDATE smp_chat_messages SET status='processing', updated_at=? WHERE id=? AND status IN ('pending','processing')", now, row.id); });
    return reply(res, 200, { items: rows });
  }
  const chatResultMatch = path.match(/^\/plugin\/chat-outbox\/([0-9a-f-]{36})\/result$/i);
  if (req.method === "POST" && chatResultMatch) {
    const id = chatResultMatch[1].toLowerCase();
    const outcome = String(body.outcome || "");
    if (!["delivered", "failed"].includes(outcome)) return fail(res, 400, "invalid_chat_outcome", "Chat delivery outcome is invalid.");
    const row = get("SELECT id, status FROM smp_chat_messages WHERE id=? AND source='admin'", id);
    if (!row) return fail(res, 404, "chat_message_not_found", "Queued chat message not found.");
    const deliveredAt = outcome === "delivered" ? now : null;
    run("UPDATE smp_chat_messages SET status=?, updated_at=?, delivered_at=? WHERE id=?", outcome, now, deliveredAt, id);
    return reply(res, 200, { ok: true, status: outcome });
  }
  if (req.method === "POST" && path === "/plugin/placement-requests") {
    // The installed Paper plugin places item bounties, not economy-currency bounties.
    // Keep the existing signed plugin authentication, but read the actual item fields.
    const playerUuid = String(body.playerUuid || "").toLowerCase();
    const playerUsername = String(body.playerUsername || "");
    const targetUuid = String(body.targetUuid || "").toLowerCase();
    const bountyType = String(body.bountyType || "item").toLowerCase();
    const nestedItem = body.item && typeof body.item === "object" && !Array.isArray(body.item) ? body.item : {};
    const itemMaterial = String(body.itemMaterial || body.itemType || nestedItem.material || "").trim().toUpperCase();
    const rawItemAmount = body.itemAmount ?? nestedItem.amount;
    const requestKey = String(body.requestKey || "");
    const itemAmount = typeof rawItemAmount === "number" ? rawItemAmount : Number(rawItemAmount);

    if (bountyType !== "item") return fail(res, 400, "invalid_bounty_type", "This endpoint accepts item bounties only.");
    if (!validUuid(playerUuid) || !validUuid(targetUuid) || !validUsername(playerUsername)
      || !/^[A-Z][A-Z0-9_]{0,63}$/.test(itemMaterial)
      || !Number.isSafeInteger(itemAmount) || itemAmount < 1 || itemAmount > MAX_BOUNTY_ITEMS
      || !/^[A-Za-z0-9_-]{12,100}$/.test(requestKey)) {
      return fail(res, 400, "invalid_bounty", `Choose a valid Minecraft item and a quantity from 1 to ${MAX_BOUNTY_ITEMS}.`);
    }
    if (playerUuid === targetUuid) return fail(res, 400, "self_bounty_forbidden", "You cannot place a bounty on yourself.");
    if (!get("SELECT 1 FROM players WHERE uuid=?", targetUuid)) return fail(res, 404, "player_not_found", "The target must be a tracked player.");

    ensurePlayer(playerUuid, playerUsername, now);
    const fullKey = `${playerUuid}:command:${requestKey}`;
    const existing = get("SELECT * FROM transactions WHERE idempotency_key=?", fullKey);
    if (existing) {
      const existingBounty = existing.bounty_id ? get("SELECT * FROM bounties WHERE id=?", existing.bounty_id) : null;
      return reply(res, 202, { transaction: transactionView(existing), bounty: existingBounty ? publicBounty(existingBounty) : null });
    }

    const storedCurrency = `${ITEM_CURRENCY_PREFIX}${itemMaterial}`;
    const active = get("SELECT * FROM bounties WHERE target_uuid=? AND status='active'", targetUuid);
    if (active && storedItemMaterial(active.currency) !== itemMaterial) {
      return fail(res, 409, "active_bounty_item_mismatch", "This player already has an active bounty with a different item. Wait for it to be claimed or expire first.");
    }

    const txId = randomUUID();
    let bounty;
    transaction(() => {
      if (active) {
        run("UPDATE bounties SET total_value=total_value+?, updated_at=?, version=version+1 WHERE id=? AND status='active'", itemAmount, now, active.id);
        bounty = get("SELECT * FROM bounties WHERE id=?", active.id);
      } else {
        const bountyId = randomUUID();
        const expires = new Date(Date.now() + EXPIRY_HOURS * 3600_000).toISOString();
        run("INSERT INTO bounties (id, target_uuid, total_value, currency, status, payment_status, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, 'active', 'not_due', ?, ?, ?)", bountyId, targetUuid, itemAmount, storedCurrency, now, now, expires);
        bounty = get("SELECT * FROM bounties WHERE id=?", bountyId);
      }
      run("INSERT INTO transactions (id, type, player_uuid, target_uuid, bounty_id, amount, currency, status, idempotency_key, created_at, updated_at, completed_at) VALUES (?, 'placement', ?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?)", txId, playerUuid, targetUuid, bounty.id, itemAmount, storedCurrency, fullKey, now, now, now);
      run("INSERT INTO contributions (id, bounty_id, contributor_uuid, amount, transaction_id, created_at) VALUES (?, ?, ?, ?, ?, ?)", randomUUID(), bounty.id, playerUuid, itemAmount, txId, now);
      addActivity("bounty_placed", playerUuid, targetUuid, bounty.id, null, `${itemAmount}x ${itemMaterial}`);
      addAudit(playerUuid, "bounty_placement_confirmed", "bounty", bounty.id, "completed_item_bounty");
    });
    const savedTx = get("SELECT * FROM transactions WHERE id=?", txId);
    return reply(res, 202, { transaction: transactionView(savedTx), bounty: publicBounty(get("SELECT * FROM bounties WHERE id=?", bounty.id)) });
  }
  if (req.method === "POST" && path === "/plugin/heartbeat") {
    const onlinePlayers = body.onlinePlayers == null ? null : Number(body.onlinePlayers);
    const maxPlayers = body.maxPlayers == null ? null : Number(body.maxPlayers);
    if ((onlinePlayers != null && (!Number.isSafeInteger(onlinePlayers) || onlinePlayers < 0)) || (maxPlayers != null && (!Number.isSafeInteger(maxPlayers) || maxPlayers < 0))) return fail(res, 400, "invalid_heartbeat", "Heartbeat player counts are invalid.");
    run(`INSERT INTO server_heartbeat (singleton, server_name, edition, version, online_players, max_players, tps, mspt, address, last_heartbeat)
      VALUES (1, ?, ?, ?, ?, ?, ?, ?, NULL, ?) ON CONFLICT(singleton) DO UPDATE SET server_name=excluded.server_name, edition=excluded.edition, version=excluded.version,
      online_players=excluded.online_players, max_players=excluded.max_players, tps=excluded.tps, mspt=excluded.mspt, last_heartbeat=excluded.last_heartbeat`,
      validText(body.serverName, 80), validText(body.edition, 40), validText(body.version, 40), onlinePlayers, maxPlayers,
      finiteOrNull(body.tps), finiteOrNull(body.mspt), now);
    return reply(res, 200, { ok: true, receivedAt: now });
  }
  if (req.method === "POST" && path === "/plugin/presence") {
    const eventId = String(body.eventId || "");
    const uuid = String(body.uuid || "").toLowerCase(); const username = String(body.username || "");
    const online = body.online;
    if (!/^[A-Za-z0-9-]{8,100}$/.test(eventId) || !validatePlayerIdentity(uuid, username) || typeof online !== "boolean") return fail(res, 400, "invalid_presence_event", "Presence event details are invalid.");
    if (get("SELECT 1 FROM activity WHERE source_event_id=?", eventId)) return reply(res, 200, { ok: true, duplicate: true });
    transaction(() => {
      ensurePlayer(uuid, username, now);
      run("UPDATE players SET online=?, last_seen=?, updated_at=? WHERE uuid=?", Number(online), now, now, uuid);
      addActivity(online ? "player_joined" : "player_left", uuid, null, null, eventId, null);
    });
    return reply(res, 200, { ok: true, receivedAt: now });
  }
  if (req.method === "POST" && path === "/plugin/stats") {
    if (!Array.isArray(body.players) || body.players.length > 500) return fail(res, 400, "invalid_stats", "Statistics payload must contain at most 500 players.");
    const updated = [];
    transaction(() => {
      if (body.completeOnlineSnapshot === true) run("UPDATE players SET online=0, updated_at=?", now);
      for (const p of body.players) {
        const uuid = String(p.uuid || "").toLowerCase(); const username = String(p.username || "");
        if (!validatePlayerIdentity(uuid, username)) continue;
        ensurePlayer(uuid, username, now);
        const values = ["kills", "deaths", "mobKills", "playtimeSeconds", "bestStreak", "currentStreak", "blocksMined"];
        if (values.some((key) => p[key] != null && (!Number.isSafeInteger(p[key]) || p[key] < 0))) continue;
        if (p.distanceTravelled != null && (!Number.isFinite(p.distanceTravelled) || p.distanceTravelled < 0)) continue;
        const online = typeof p.online === "boolean" ? Number(p.online) : null;
        run(`UPDATE players SET online=?, kills=coalesce(?, kills), deaths=coalesce(?, deaths), mob_kills=?, playtime_seconds=?, best_streak=coalesce(?, best_streak),
          current_streak=coalesce(?, current_streak), blocks_mined=?, distance_travelled=?, skin_url=?, last_seen=CASE WHEN ?=1 THEN ? ELSE last_seen END, updated_at=? WHERE uuid=?`,
          online, p.kills ?? null, p.deaths ?? null, p.mobKills ?? null, p.playtimeSeconds ?? null, p.bestStreak ?? null,
          p.currentStreak ?? null, p.blocksMined ?? null, p.distanceTravelled ?? null, validHttpUrl(p.skinUrl), online, now, now, uuid);
        updated.push(uuid);
      }
      run("UPDATE server_heartbeat SET last_statistics_update=? WHERE singleton=1", now);
    });
    return reply(res, 200, { ok: true, updated: updated.length, receivedAt: now });
  }
  if (req.method === "GET" && path === "/plugin/transactions") {
    const type = url.searchParams.get("type") || "";
    if (type && !["placement", "payout", "refund"].includes(type)) return fail(res, 400, "invalid_transaction_type", "Transaction type is invalid.");
    const limit = Math.min(100, Math.max(1, Number(url.searchParams.get("limit") || 30)));
    const candidates = type ? all("SELECT * FROM transactions WHERE type=? AND status IN ('requested','processing') ORDER BY created_at LIMIT ?", type, limit)
      : all("SELECT * FROM transactions WHERE status IN ('requested','processing') ORDER BY created_at LIMIT ?", limit);
    const rows = [];
    for (const row of candidates) {
      if (row.type === "placement" && storedItemMaterial(row.currency)) {
        const active = get("SELECT id, currency FROM bounties WHERE target_uuid=? AND status='active'", row.target_uuid);
        if (active && active.currency !== row.currency) {
          run("UPDATE transactions SET status='failed', updated_at=?, safe_error_code='active_bounty_item_mismatch' WHERE id=? AND status IN ('requested','processing')", now, row.id);
          addAudit(row.player_uuid, "item_bounty_placement_rejected", "transaction", row.id, "active_bounty_item_mismatch");
          continue;
        }
      }
      rows.push(row);
    }
    transaction(() => { for (const row of rows) run("UPDATE transactions SET status='processing', updated_at=? WHERE id=? AND status='requested'", now, row.id); });
    return reply(res, 200, { items: rows.map((row) => ({ ...transactionView({ ...row, status: "processing" }), playerUuid: row.player_uuid, targetUuid: row.target_uuid, bountyId: row.bounty_id })) });
  }
  const resultMatch = path.match(/^\/plugin\/transactions\/([0-9a-f-]{36})\/result$/i);
  if (req.method === "POST" && resultMatch) {
    const txId = resultMatch[1].toLowerCase(); const outcome = body.outcome;
    if (!["completed", "failed", "manual_review"].includes(outcome)) return fail(res, 400, "invalid_outcome", "Transaction outcome is invalid.");
    const tx = get("SELECT * FROM transactions WHERE id=?", txId);
    if (!tx) return fail(res, 404, "transaction_not_found", "Transaction not found.");
    if (tx.status === "completed" || tx.status === "failed" || tx.status === "manual_review") return reply(res, 200, { transaction: transactionView(tx), duplicate: true });
    transaction(() => {
      const completedAt = outcome === "completed" ? now : null;
      run("UPDATE transactions SET status=?, updated_at=?, completed_at=?, safe_error_code=? WHERE id=?", outcome, now, completedAt, validCode(body.errorCode), txId);
      if (outcome === "completed" && tx.type === "placement") {
        // The target is bound to the original browser request; do not accept a different target from the plugin result.
        const targetUuid = tx.target_uuid;
        if (!validUuid(targetUuid) || !get("SELECT 1 FROM players WHERE uuid=?", targetUuid)) throw Object.assign(new Error("Transaction target is no longer valid."), { status: 409, code: "target_invalid" });
        let bounty = get("SELECT * FROM bounties WHERE target_uuid=? AND status='active'", targetUuid);
        if (!bounty) {
          const bountyId = randomUUID(); const expires = new Date(Date.now() + EXPIRY_HOURS * 3600_000).toISOString();
          run("INSERT INTO bounties (id, target_uuid, total_value, currency, status, payment_status, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, 'active', 'not_due', ?, ?, ?)", bountyId, targetUuid, tx.amount, tx.currency, now, now, expires);
          bounty = get("SELECT * FROM bounties WHERE id=?", bountyId);
        } else {
          run("UPDATE bounties SET total_value=total_value+?, updated_at=?, version=version+1 WHERE id=? AND status='active'", tx.amount, now, bounty.id);
          bounty = get("SELECT * FROM bounties WHERE id=?", bounty.id);
        }
        run("UPDATE transactions SET bounty_id=? WHERE id=?", bounty.id, txId);
        run("INSERT INTO contributions (id, bounty_id, contributor_uuid, amount, transaction_id, created_at) VALUES (?, ?, ?, ?, ?, ?)", randomUUID(), bounty.id, tx.player_uuid, tx.amount, txId, now);
        addActivity("bounty_placed", tx.player_uuid, targetUuid, bounty.id, null, null);
        addAudit(tx.player_uuid, "bounty_placement_confirmed", "bounty", bounty.id, "completed");
      } else if (tx.type === "payout") {
        const bounty = get("SELECT * FROM bounties WHERE id=?", tx.bounty_id);
        if (bounty) {
          const payment = outcome === "completed" ? "completed" : outcome === "failed" ? "failed" : "manual_review";
          if (outcome === "manual_review") run("UPDATE bounties SET status='under_review', payment_status=?, updated_at=? WHERE id=?", payment, now, bounty.id);
          else run("UPDATE bounties SET payment_status=?, updated_at=? WHERE id=?", payment, now, bounty.id);
          addAudit(tx.player_uuid, "bounty_payout_result", "bounty", bounty.id, outcome);
        }
      } else if (outcome !== "completed") addAudit(tx.player_uuid, "transaction_result", tx.type, tx.id, outcome);
    });
    return reply(res, 200, { transaction: transactionView(get("SELECT * FROM transactions WHERE id=?", txId)), confirmed: outcome === "completed" });
  }
  if (req.method === "POST" && path === "/plugin/kills") {
    const eventId = String(body.eventId || "");
    const killerUuid = String(body.killerUuid || "").toLowerCase(); const victimUuid = String(body.victimUuid || "").toLowerCase();
    if (!/^[A-Za-z0-9-]{8,100}$/.test(eventId) || !validUuid(killerUuid) || !validUuid(victimUuid) || killerUuid === victimUuid) return fail(res, 400, "invalid_kill_event", "Kill event details are invalid.");
    const duplicate = get("SELECT bounty_id FROM activity WHERE source_event_id=?", eventId);
    if (duplicate) return reply(res, 200, { ok: true, duplicate: true, claimed: Boolean(duplicate.bounty_id) });
    const killerName = String(body.killerUsername || ""); const victimName = String(body.victimUsername || "");
    if (!validUsername(killerName) || !validUsername(victimName)) return fail(res, 400, "invalid_kill_event", "Player names are invalid.");
    let claim = null;
    transaction(() => {
      ensurePlayer(killerUuid, killerName, now); ensurePlayer(victimUuid, victimName, now);
      run("UPDATE players SET kills=kills+1, current_streak=current_streak+1, best_streak=max(best_streak, current_streak+1), last_seen=?, updated_at=? WHERE uuid=?", now, now, killerUuid);
      run("UPDATE players SET deaths=deaths+1, current_streak=0, last_seen=?, updated_at=? WHERE uuid=?", now, now, victimUuid);
      const weaponSlug = typeof body.weaponSlug === "string" && /^[a-z0-9-]{1,64}$/.test(body.weaponSlug) ? body.weaponSlug : "";
      if (weaponSlug) {
        const weapon = get("SELECT id FROM weapons WHERE slug=? AND public=1", weaponSlug);
        if (weapon) run("INSERT INTO weapon_kills (player_uuid, weapon_id, kills, best_streak) VALUES (?, ?, 1, 1) ON CONFLICT(player_uuid, weapon_id) DO UPDATE SET kills=kills+1, best_streak=best_streak+1", killerUuid, weapon.id);
      }
      addActivity("kill", killerUuid, victimUuid, null, eventId, null);
      let bounty = get("SELECT * FROM bounties WHERE target_uuid=? AND status='active'", victimUuid);
      if (bounty?.expires_at && Date.parse(bounty.expires_at) <= Date.now()) { run("UPDATE bounties SET status='expired', updated_at=? WHERE id=? AND status='active'", now, bounty.id); bounty = null; }
      if (bounty) {
        const contributed = Boolean(get("SELECT 1 FROM contributions WHERE bounty_id=? AND contributor_uuid=? LIMIT 1", bounty.id, killerUuid));
        const cutoff = new Date(Date.now() - PAIR_COOLDOWN * 60_000).toISOString();
        const recentlyClaimed = Boolean(get("SELECT 1 FROM bounties WHERE target_uuid=? AND claimed_by=? AND claimed_at>=? LIMIT 1", victimUuid, killerUuid, cutoff));
        if (claimEligible({ killerUuid, victimUuid, bounty, hasContributed: contributed, recentlyClaimed })) {
          const payoutId = randomUUID();
          run("UPDATE bounties SET status='claimed', payment_status='pending', claimed_at=?, claimed_by=?, claim_event_id=?, updated_at=?, version=version+1 WHERE id=? AND status='active'", now, killerUuid, eventId, now, bounty.id);
          run("INSERT INTO transactions (id, type, player_uuid, bounty_id, amount, currency, status, idempotency_key, created_at, updated_at) VALUES (?, 'payout', ?, ?, ?, ?, 'requested', ?, ?, ?)", payoutId, killerUuid, bounty.id, bounty.total_value, bounty.currency, `claim:${bounty.id}`, now, now);
          addActivity("bounty_claimed", killerUuid, victimUuid, bounty.id, `claim:${eventId}`, null);
          addAudit(killerUuid, "bounty_claim_recorded", "bounty", bounty.id, "payout_pending");
          claim = { bountyId: bounty.id, payoutTransactionId: payoutId, amount: bounty.total_value, currency: bounty.currency };
        }
      }
    });
    return reply(res, 200, { ok: true, claimed: Boolean(claim), claim });
  }
  if (req.method === "POST" && path === "/plugin/weapons") {
    if (!Array.isArray(body.weapons) || body.weapons.length > 100) return fail(res, 400, "invalid_weapons", "Weapons must be an array of at most 100 entries.");
    transaction(() => {
      for (const w of body.weapons) {
        if (typeof w.slug !== "string" || !/^[a-z0-9-]{1,64}$/.test(w.slug) || typeof w.name !== "string" || !w.name.trim() || w.name.length > 80) continue;
        const id = get("SELECT id FROM weapons WHERE slug=?", w.slug)?.id || randomUUID();
        run(`INSERT INTO weapons (id, slug, name, category, description, abilities, cooldown_seconds, public, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(slug) DO UPDATE SET name=excluded.name, category=excluded.category, description=excluded.description, abilities=excluded.abilities, cooldown_seconds=excluded.cooldown_seconds, public=excluded.public, updated_at=excluded.updated_at`,
          id, w.slug, w.name.trim(), validText(w.category, 40), validText(w.description, 240), JSON.stringify(Array.isArray(w.abilities) ? w.abilities.slice(0, 12) : []), finiteOrNull(w.cooldownSeconds), w.public === false ? 0 : 1, now);
      }
    });
    return reply(res, 200, { ok: true, receivedAt: now });
  }
  return fail(res, 404, "not_found", "Trusted plugin endpoint not found.");
}

function finiteOrNull(value) { return typeof value === "number" && Number.isFinite(value) ? value : null; }
function validText(value, max) { return typeof value === "string" && value.trim() && value.length <= max ? value.trim() : null; }
function validHttpUrl(value) { if (typeof value !== "string" || value.length > 500) return null; try { const url = new URL(value); return url.protocol === "https:" ? url.toString() : null; } catch { return null; } }
function validCode(value) { return typeof value === "string" && /^[a-z0-9_-]{1,48}$/.test(value) ? value : null; }

const server = createServer(async (req, res) => {
  try {
    await apiHandler(req, res);
  } catch (error) {
    if (res.headersSent) { res.destroy(); return; }
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status >= 500) console.error(JSON.stringify({ level: "error", message: "API request failed", code: error.code || "internal_error", method: req.method, path: new URL(req.url, "http://localhost").pathname }));
    fail(res, status, error.code || "internal_error", status >= 500 ? "The request could not be completed. No public data was changed unless it was confirmed." : error.message);
  }
});


export { apiHandler };
export { server };
