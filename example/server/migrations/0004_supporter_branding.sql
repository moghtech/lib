-- How the badge of an organization's supporter key is shown, as an
-- admin set it over the supporter api (mogh_supporter): one row of
-- JSON. Nothing in it is secret (every user's browser reads it), an
-- uploaded icon is in it as a data url.
CREATE TABLE supporter_branding (
  id INTEGER PRIMARY KEY NOT NULL CHECK (id = 1),
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
