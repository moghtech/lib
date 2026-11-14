-- The logins the auth server completed (AuthImpl::record_login): the
-- example's audit trail, one row per login. Kept when the user is
-- deleted, as an audit trail is.
CREATE TABLE logins (
  id TEXT PRIMARY KEY NOT NULL,
  user_id TEXT NOT NULL,
  -- The username at the time of the login.
  username TEXT NOT NULL,
  ip TEXT NOT NULL,
  -- JSON LoginKind: "Local", {"Provider":{..}} or {"Workload":{..}}.
  kind TEXT NOT NULL,
  -- 'passkey', 'totp' or 'totp_recovery', empty for none.
  second_factor TEXT NOT NULL DEFAULT '',
  -- When the token the login issued expires, unix seconds.
  token_expires INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE INDEX logins_user ON logins (user_id, created_at);
