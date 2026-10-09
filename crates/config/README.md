# Mogh Config

Module for comprehensive loading of strongly typed configuration files using `std::fs` and `serde`.

- Supports parsing JSON, YAML, TOML, and env files (`.env`, `*.env`).
- Supports merging final configuration from multiple supplied files / directories.
- Supports `${ENV_VAR}` and `$(command)` interpolation in values of
  local toml / yaml / json files (not in env files or in files loaded
  from Cicada, whose values are secrets taken verbatim). `$(command)` runs
  a single command word (letters, digits, `_`) without arguments, eg.
  `$(hostname)`; anything else, like `$(cat /run/secrets/db)` or
  `${VAR:-default}`, is kept as written, with a warning naming the key.
- Coerces string values into the field's type the way `envy` reads the
  process environment: numbers, booleans, comma separated lists into
  `Vec`s, `Option`, enum variants. Not inside `#[serde(flatten)]` fields
  or untagged / internally tagged enums, which serde buffers as-is.

Priority (later overrides earlier): `paths` in order given. Within a directory,
its own files (by wildcard, then name; a file matching several wildcards takes
the last one it matches), then each path in the include file in the order
listed, recursively, so includes override the directory's own files. A file
reached twice (listed as a path and found by a directory scan) is loaded once,
at its later position. A wildcard which doesn't compile is an error
(`Error::InvalidWildcard`), never a dropped filter.

Missing and broken files: a path which doesn't exist is skipped, so an app can
list optional paths. Every file which exists must load, whether listed, found
by a directory scan or named in an include file: one which can't be read or
doesn't parse is an error naming the file (and the line, never a value in it),
and so is a directory or include file which can't be read. Skipping it would
start the app without the settings in it. A file holding no settings (blank,
comments only, a yaml or json `null` document) is an empty source. A file a
directory scan finds which is no config file type (a `config.toml.bak` matching
`*config.*`) is skipped with a warning; listed, or named in an include file, it
is an error (`Error::UnsupportedFileType`).

```rust,no_run
use std::path::Path;

use mogh_config::ConfigLoader;

#[derive(serde::Deserialize)]
struct Config {
  title: String,
  aliases: Vec<String>,
  endpoint: String,
  use_option: bool,
}

let config = (ConfigLoader {
  // Read config files from a directory
  paths: &[Path::new("./configs")],
  match_wildcards: &["*config*.toml"],
  // It won't recurse into subdirectories unless they include '.configinclude' file
  include_file_name: ".configinclude",
  merge_nested: true,
  extend_array: true,
  debug_print: true,
})
.load::<Config>()
.expect("Failed to parse config from path");
```

Merging: each source merges over the ones before it, and is never dropped
over a type conflict. With `merge_nested`, two objects merge key by key; with
`extend_array`, an array extends the one before it. A `null` (a yaml section
with every line commented out) keeps the object or array before it. Any other
value replaces the one before it, as it does without those flags, and a value
the config type can't take fails the final deserialization with its path and
type (never the value). `mogh_config::merge_objects` keeps its stricter rules
(a type mismatch is an error) for callers merging anything else.

## The process environment

`ConfigLoader::load_with_env(&EnvSource)` reads the process environment as the
last source, over the config files: each variable of the `EnvSource`'s table
overrides one config field. An app declares its variables once, by config path,
instead of an `Env` struct mirroring its config and a line per field copying it
over:

```rust,no_run
use std::path::Path;

use mogh_config::{ConfigLoader, EnvSource};

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Database {
  address: String,
  password: String,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Config {
  host: String,
  port: u16,
  allowed_ips: Vec<String>,
  database: Database,
}

let env = EnvSource::new("APP_")
  // APP_HOST, APP_PORT, APP_ALLOWED_IPS, APP_DATABASE_ADDRESS,
  // APP_DATABASE_PASSWORD: a variable for every field.
  .fields_of(&Config::default())
  // Or by path: .fields(["host", "port", "database.address"])
  // A name of its own.
  .var("APP_MONGO_URI", "database.address")
  // An old name, still read.
  .alias("APP_LISTEN_PORT", "APP_PORT");
let config = (ConfigLoader {
  paths: &[Path::new("./config")],
  match_wildcards: &["*config.*"],
  include_file_name: ".configinclude",
  merge_nested: true,
  extend_array: false,
  debug_print: false,
})
.load_with_env::<Config>(&env)
.expect("Failed to load the config");
```

The rules:

| | |
| --- | --- |
| Names | The prefix, then the config path's segments uppercased and joined by `_`: `host` is `APP_HOST`, `database.address` is `APP_DATABASE_ADDRESS`. `nested_separator("__")` joins them with `__` instead (`APP_DATABASE__ADDRESS`). `fields_of(&config)` makes one for every value of the serialized config which is no object (`without([...])` leaves paths out), `fields([...])` one per path, `var(name, path)` gives one a name of its own. Names match in any case (`app_port`), as `envy` reads them. |
| Unknown variables | Ignored, also with the prefix (the `APP_CONFIG_PATHS` the app reads itself, a typo). |
| Values | Strings, parsed into the field's type as env file values are: numbers and booleans trimmed, lists split on commas (entries trimmed, empty ones dropped), a unit enum variant by name. A field which reads a string itself (its own `deserialize_with` going through `deserialize_any`) gets the whole value, eg. a list it splits on `;`. |
| Type errors | `Error::ParseEnv`, naming the variable as it was set (`APP_PORT`, `APP_PORT_FILE`) and the field, never the value. |
| Blank | A variable set to nothing but whitespace and commas counts as unset: the config file's value stays (compose templates optional variables as `${APP_X:-}`). A string or a list can't be emptied from the environment (for an allow list, empty can mean everyone), unless the variable is listed in `allow_empty([...])`: then a blank value sets the empty value (a security header left out when empty). |
| `_FILE` | Every variable `NAME` can be given as `NAME_FILE`, the path of a file holding the value (a docker secret): its contents, trimmed. It wins over `NAME`. A blank `NAME_FILE` counts as unset (`mogh_secret_file`'s rule), and so does a file holding nothing but whitespace and commas. A file which can't be read is `Error::EnvFile`, naming the variable and the path. `NAME_FILE` is a variable of its own when the table has one by that name (a field `health_file`). For the variables of `file_spec([...])` the file is not read: the field gets `file:<path>` (a key file the app reads, creates or rotates itself). |
| Aliases | `alias(old, name)` reads `old` (and `old_FILE`) for `name` when `name` (and `name_FILE`) is unset. Both set: `name` wins, `old` is ignored with a warning naming both, never the values. `fallback(other, name)` does the same for a variable of other programs (`TZ`), without the warning or a `_FILE`. |
| Overrides | A value replaces the field: a list too (`extend_array` doesn't extend it), a nested field only itself (the other fields of its object stay, whatever `merge_nested` says). A field the config type also takes under another key (`#[serde(alias = "mongo")] database`) is declared with `key_alias("database", "mongo")`: a file's value under the other key then moves to the field's own before the environment's values go in (else the field would be there twice, which serde refuses). |
| The table | Checked when it is read: a name twice, a path inside another's, an alias of no variable is `Error::InvalidEnvSource`, the app's mistake. `names()` lists the table's variables (eg. for docs, or a test that a renamed field kept its variable). |

## Env files

An env file is a flat configuration source: `NAME=value` lines, `#`
comments, optional `export`, values unquoted, single quoted (literal) or
double quoted with `\n` / `\r` / `\t` / `\"` / `\\` escapes. Names are lowercased
to match struct fields (`DB_PASSWORD=x` fills `db_password`) and dots
nest (`DATABASE.ADDRESS=x` fills `database.address`), values are strings
coerced into the field's type, so the same struct reads a toml file, an
env file, or both merged. A name with an empty segment cannot nest
(`.dockerconfigjson`, `A..B`, `A.`), so it is kept whole as one flat key,
lowercased (`.dockerconfigjson`, `a..b`; reach it with
`#[serde(rename = ".dockerconfigjson")]`). Nesting stops at 32 segments: a
longer name is one flat key too. A name that is both a value and
an object (`DATABASE=x` next to `DATABASE.ADDRESS=y`), or two names equal
once lowercased (`DB` and `db`), is an error naming the line and both
names. Values are never interpolated: they are secrets, not templates.
A parse error names the line (and entry) and what was expected, never
the value: not even the character after an unsupported escape.

```sh
# .env, listed in the paths after the defaults
PORT=8080
ALLOWED_HOSTS=a.example.com,b.example.com
DATABASE.ADDRESS=db.example.com:5432
DATABASE.USERNAME=app
DATABASE.PASSWORD="hunter2"
```

A comma separated value from an env file merged onto an array from an earlier
source extends it under `extend_array` (`HOSTS=b,c` onto `["a"]` gives
`["a", "b", "c"]`), and replaces it otherwise (the final deserialization
splits it into the list).

List an env file as a path, or match it with a directory wildcard
(`*.env`, `.env`): a directory scanned without wildcards skips env files,
so a compose `.env` next to the config files is not read by accident.
`.env` has no extension for `Path::extension`, and is recognized by name.

Both directions of the grammar live here. `mogh_config::parse_env_file` reads a
file into its entries: the line, the name, the value, and the description held
by the `#` comment lines directly above the entry (a blank line detaches them).
`mogh_config::serialize_env_file` writes entries back, each description as
comment lines above its entry, a value holding `$` single quoted when it can be
(Compose, systemd and dotenv libraries take it literally then), any other value
double quoted when it wouldn't survive unquoted. A serialized file parses back
to the same entries, each description as `mogh_config::normalize_env_description`
has it: every line break a `\n` (`\r\n`, and a lone `\r` or another character
some dotenv parser ends a line at, so no text of a description is an entry to
them), no line ending in whitespace (a comment line can't keep it). The parser
reads descriptions in that form too. An app storing descriptions normalizes
them with it when they are written, so an export / import round trip gives
them back unchanged. A name the syntax can't hold
(`mogh_config::representable_env_name`) or a name given twice is an error.
Cicada Core renders its exports with `serialize_env_file`, so a
`cicada://.env` source is read by the parser of the same grammar.

## Features

- `cicada` (off by default since 3.0): load config from [Cicada](https://github.com/moghtech/cicada)
  with `cicada:` paths, eg. `cicada://filesystem/config.yaml?env=prod` for a
  file interpolated with the `prod` environment, or `cicada://.env?env=base+prod`
  for the environments themselves as an env file. It pulls the Cicada client
  into the build, so it is opt in:
  `mogh_config = { version = "4", features = ["cicada"] }`.
  A `cicada:` line in an include file is a source like a `cicada:` path.
  Loading a `cicada:` source is blocking network I/O (reqwest's blocking
  client: the device's key check, onboarding or rotation, then the file), so
  call `ConfigLoader::load` outside an async runtime: before building the
  runtime (a plain `fn main` which loads the config, then starts tokio), or in
  `tokio::task::spawn_blocking`. On a runtime thread it panics in debug builds
  and blocks the worker in release builds.
  Without the feature a `cicada:` path is an error, not a skipped path. With
  it, a `cicada:` source which fails to load (`Error::CicadaLoad`: Core
  unreachable, the device not onboarded or not granted the environments, the
  file missing) or to parse is an error too, rather than starting the app with
  its defaults, like a local file which doesn't parse.

  The loader is not re-exported, so its API is no part of `mogh_config`'s: from
  4.0, a `cicada_loader` minor (`0.x`) bump ships as a `mogh_config` minor
  release (its notes name the loader's changes), and a loader patch bump as a
  patch release. An application using the loader's own API (starting its
  background with `cicada_loader::spawn()`, reacting to changes with
  `on_change` / `subscribe`, `load_env_as`) depends on `cicada_loader` itself,
  at the minor this `mogh_config` uses, and checks that it stays so (eg.
  `cargo tree --duplicates` listing no `cicada_loader`, in CI): two minors are
  two loaders in one process, each initializing a device from the same
  `CICADA_*` environment and key file. `CICADA_BACKGROUND=true` starts the
  background without the loader's API.
