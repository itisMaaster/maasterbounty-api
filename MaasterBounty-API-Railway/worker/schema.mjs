export const schemaSql = String.raw`CREATE TABLE IF NOT EXISTS players (
  uuid TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  online INTEGER CHECK (online IN (0, 1) OR online IS NULL),
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  kills INTEGER NOT NULL DEFAULT 0 CHECK (kills >= 0),
  deaths INTEGER NOT NULL DEFAULT 0 CHECK (deaths >= 0),
  mob_kills INTEGER CHECK (mob_kills >= 0 OR mob_kills IS NULL),
  playtime_seconds INTEGER CHECK (playtime_seconds >= 0 OR playtime_seconds IS NULL),
  best_streak INTEGER NOT NULL DEFAULT 0 CHECK (best_streak >= 0),
  current_streak INTEGER NOT NULL DEFAULT 0 CHECK (current_streak >= 0),
  blocks_mined INTEGER CHECK (blocks_mined >= 0 OR blocks_mined IS NULL),
  distance_travelled REAL CHECK (distance_travelled >= 0 OR distance_travelled IS NULL),
  skin_url TEXT,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS players_username_nocase ON players(username COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS players_kills ON players(kills DESC);
CREATE INDEX IF NOT EXISTS players_playtime ON players(playtime_seconds DESC);

CREATE TABLE IF NOT EXISTS username_history (
  uuid TEXT NOT NULL REFERENCES players(uuid),
  username TEXT NOT NULL,
  seen_at TEXT NOT NULL,
  PRIMARY KEY (uuid, username)
);

CREATE TABLE IF NOT EXISTS weapons (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  category TEXT,
  description TEXT,
  abilities TEXT,
  cooldown_seconds REAL,
  public INTEGER NOT NULL DEFAULT 1 CHECK (public IN (0, 1)),
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS weapon_kills (
  player_uuid TEXT NOT NULL REFERENCES players(uuid),
  weapon_id TEXT NOT NULL REFERENCES weapons(id),
  kills INTEGER NOT NULL DEFAULT 0 CHECK (kills >= 0),
  best_streak INTEGER NOT NULL DEFAULT 0 CHECK (best_streak >= 0),
  PRIMARY KEY (player_uuid, weapon_id)
);

CREATE TABLE IF NOT EXISTS bounties (
  id TEXT PRIMARY KEY,
  target_uuid TEXT NOT NULL REFERENCES players(uuid),
  total_value INTEGER NOT NULL DEFAULT 0 CHECK (total_value >= 0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'claimed', 'expired', 'cancelled', 'under_review')),
  payment_status TEXT NOT NULL DEFAULT 'not_due' CHECK (payment_status IN ('not_due', 'pending', 'processing', 'completed', 'failed', 'manual_review')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT,
  claimed_at TEXT,
  claimed_by TEXT REFERENCES players(uuid),
  claim_event_id TEXT UNIQUE,
  version INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_bounty_per_target ON bounties(target_uuid) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS bounties_public ON bounties(status, total_value DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS bounties_history ON bounties(status, claimed_at DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS transactions (
  id TEXT PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('placement', 'payout', 'refund')),
  player_uuid TEXT NOT NULL REFERENCES players(uuid),
  target_uuid TEXT REFERENCES players(uuid),
  bounty_id TEXT REFERENCES bounties(id),
  amount INTEGER NOT NULL CHECK (amount > 0),
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('requested', 'processing', 'completed', 'failed', 'manual_review')),
  idempotency_key TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  completed_at TEXT,
  safe_error_code TEXT
);
CREATE INDEX IF NOT EXISTS transactions_pending ON transactions(type, status, created_at);

CREATE TABLE IF NOT EXISTS contributions (
  id TEXT PRIMARY KEY,
  bounty_id TEXT NOT NULL REFERENCES bounties(id),
  contributor_uuid TEXT NOT NULL REFERENCES players(uuid),
  amount INTEGER NOT NULL CHECK (amount > 0),
  transaction_id TEXT NOT NULL UNIQUE REFERENCES transactions(id),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS contributions_bounty ON contributions(bounty_id, created_at);
CREATE INDEX IF NOT EXISTS contributions_player ON contributions(contributor_uuid, created_at);

CREATE TABLE IF NOT EXISTS activity (
  id TEXT PRIMARY KEY,
  source_event_id TEXT UNIQUE,
  event_type TEXT NOT NULL,
  actor_uuid TEXT REFERENCES players(uuid),
  target_uuid TEXT REFERENCES players(uuid),
  bounty_id TEXT REFERENCES bounties(id),
  weapon_id TEXT REFERENCES weapons(id),
  description TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS activity_latest ON activity(created_at DESC, id);
CREATE INDEX IF NOT EXISTS activity_players ON activity(actor_uuid, target_uuid, created_at DESC);

CREATE TABLE IF NOT EXISTS link_codes (
  code_hash TEXT PRIMARY KEY,
  player_uuid TEXT NOT NULL REFERENCES players(uuid),
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS link_codes_expiry ON link_codes(expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  player_uuid TEXT NOT NULL REFERENCES players(uuid),
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS plugin_nonces (
  request_id TEXT PRIMARY KEY,
  seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server_heartbeat (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  server_name TEXT,
  edition TEXT,
  version TEXT,
  online_players INTEGER CHECK (online_players >= 0 OR online_players IS NULL),
  max_players INTEGER CHECK (max_players >= 0 OR max_players IS NULL),
  tps REAL,
  mspt REAL,
  address TEXT,
  last_heartbeat TEXT NOT NULL,
  last_statistics_update TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  actor_uuid TEXT,
  action TEXT NOT NULL,
  entity_type TEXT,
  entity_id TEXT,
  result TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_latest ON audit_log(created_at DESC);
`;

