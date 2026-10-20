import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const USERNAME_RE = /^[A-Za-z0-9_]{1,16}$/;

export function validUuid(value) { return typeof value === "string" && UUID_RE.test(value); }
export function validUsername(value) { return typeof value === "string" && USERNAME_RE.test(value); }
export function validAmount(value, minimum = 1, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}
export function pageArgs(url, defaultLimit = 20, maxLimit = 100) {
  const rawPage = Number(url.searchParams.get("page") || 1);
  const rawLimit = Number(url.searchParams.get("limit") || defaultLimit);
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 ? rawPage : 1;
  const limit = Number.isSafeInteger(rawLimit) && rawLimit > 0 ? Math.min(rawLimit, maxLimit) : defaultLimit;
  return { page, limit, offset: (page - 1) * limit };
}
export function kdRatio(kills, deaths) {
  if (!Number.isFinite(kills) || !Number.isFinite(deaths) || deaths <= 0) return null;
  return kills / deaths;
}
export function hash(value) { return createHash("sha256").update(value).digest("hex"); }
export function constantTimeTextEqual(a, b) {
  const left = Buffer.from(String(a)); const right = Buffer.from(String(b));
  return left.length === right.length && timingSafeEqual(left, right);
}
export function signature(secret, method, path, timestamp, requestId, rawBody) {
  const digest = hash(rawBody);
  const canonical = `${method.toUpperCase()}\n${path}\n${timestamp}\n${requestId}\n${digest}`;
  return createHmac("sha256", secret).update(canonical).digest("hex");
}
export function claimEligible({ killerUuid, victimUuid, bounty, hasContributed, recentlyClaimed, now = Date.now() }) {
  if (!bounty || bounty.status !== "active") return false;
  if (killerUuid === victimUuid || bounty.target_uuid !== victimUuid) return false;
  if (bounty.expires_at && Date.parse(bounty.expires_at) <= now) return false;
  if (hasContributed || recentlyClaimed) return false;
  return true;
}
export function publicPlayer(row) {
  if (!row) return null;
  return {
    uuid: row.uuid, username: row.username, online: row.online == null ? null : Boolean(row.online),
    firstSeen: row.first_seen, lastSeen: row.last_seen, kills: row.kills, deaths: row.deaths,
    kd: kdRatio(row.kills, row.deaths), mobKills: row.mob_kills, playtimeSeconds: row.playtime_seconds,
    bestStreak: row.best_streak, currentStreak: row.current_streak, blocksMined: row.blocks_mined,
    distanceTravelled: row.distance_travelled, skinUrl: row.skin_url || null
  };
}
