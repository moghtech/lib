CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL,
  username TEXT NOT NULL UNIQUE,
  -- bcrypt hash. Empty means the user can't log in with a password.
  password TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 0,
  admin INTEGER NOT NULL DEFAULT 0,
  -- JSON list of the groups assigned in the app.
  groups TEXT NOT NULL DEFAULT '[]',
  -- JSON webauthn passkey, encrypted.
  passkey TEXT NOT NULL DEFAULT '',
  -- Encrypted.
  totp_secret TEXT NOT NULL DEFAULT '',
  -- JSON list of bcrypt hashes.
  totp_recovery_codes TEXT NOT NULL DEFAULT '[]',
  external_skip_2fa INTEGER NOT NULL DEFAULT 0,
  -- JSON list of CIDR ranges / ips.
  cidr_whitelist TEXT NOT NULL DEFAULT '[]',
  -- Set on the users of workload identity rules.
  workload_issuer_id TEXT,
  workload_rule_id TEXT,
  workload_last_subject TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- One user per workload identity rule.
CREATE UNIQUE INDEX users_workload
  ON users (workload_issuer_id, workload_rule_id)
  WHERE workload_issuer_id IS NOT NULL;

CREATE TABLE external_logins (
  user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  external_id TEXT NOT NULL,
  avatar_url TEXT,
  -- JSON list of the groups synced from this provider.
  groups TEXT NOT NULL DEFAULT '[]',
  -- External ids are only unique per provider.
  PRIMARY KEY (provider_id, external_id),
  UNIQUE (user_id, provider_id)
);

CREATE TABLE api_keys (
  -- The key (V1) or the public key (V2).
  key TEXT PRIMARY KEY NOT NULL,
  kind TEXT NOT NULL,
  -- bcrypt hash (V1 only).
  secret TEXT NOT NULL DEFAULT '',
  user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  expires INTEGER NOT NULL DEFAULT 0,
  cidr_whitelist TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
);

CREATE INDEX api_keys_user ON api_keys (user_id);

-- External login providers managed by admins over the auth api.
CREATE TABLE login_providers (
  id TEXT PRIMARY KEY NOT NULL,
  -- JSON ExternalLoginProvider, encrypted (includes the client secret).
  data TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- Workload identity issuers managed by admins over the auth api.
CREATE TABLE trusted_issuers (
  id TEXT PRIMARY KEY NOT NULL,
  -- JSON TrustedIssuer, encrypted (may include a reviewer credential).
  data TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- TOTP steps which were already accepted, so a code only works once
-- across restarts and instances.
CREATE TABLE totp_steps (
  user_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  step INTEGER NOT NULL,
  PRIMARY KEY (user_id, step)
);

CREATE TABLE notes (
  id TEXT PRIMARY KEY NOT NULL,
  owner_id TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  -- Encrypted, bound to the note id.
  content TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE INDEX notes_owner ON notes (owner_id, updated_at);
