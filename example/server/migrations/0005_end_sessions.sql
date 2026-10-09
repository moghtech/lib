-- Ending the login sessions of a user (AuthImpl::credentials_changed):
-- the session tokens issued before `sessions_valid_after` (unix seconds)
-- are refused, except the one whose SHA-256 (hex) is `sessions_kept`, the
-- session which made the change.
ALTER TABLE users ADD COLUMN sessions_valid_after INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN sessions_kept TEXT NOT NULL DEFAULT '';
