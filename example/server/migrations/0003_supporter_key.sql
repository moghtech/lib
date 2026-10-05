-- The supporter key an admin set over the supporter api
-- (mogh_supporter), used over the config's. One row, encrypted: the
-- key holds the instance private key.
CREATE TABLE supporter_key (
  id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
