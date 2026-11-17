# Mogh Env Parser

Parser for Env file (`.env`) syntax. Contains both serialization and deserialization functions.
`mogh_config` and `cicada_loader` read its env file sources with it.
Cicada Core renders its exports with `serialize_env_file`, so an export parses back unchanged.

```rust
#[derive(serde::Deserialize, Debug, PartialEq)]
struct Database {
  address: String,
  port: u16,
}

#[derive(serde::Deserialize, Debug, PartialEq)]
struct Config {
  debug: bool,
  hosts: Vec<String>,
  database: Database,
}

let config: Config = mogh_env_parser::from_str(
  "# The switches\n\
   DEBUG=True\n\
   HOSTS=a.example.com, b.example.com,\n\
   DATABASE.ADDRESS=db.example.com\n\
   DATABASE.PORT=\" 5432 \"\n",
)
.unwrap();

assert_eq!(
  config,
  Config {
    debug: true,
    hosts: vec!["a.example.com".into(), "b.example.com".into()],
    database: Database {
      address: "db.example.com".into(),
      port: 5432,
    },
  }
);
```

## The grammar

An env file is a flat set of `NAME=value` lines. 

- `#` lines are comments, and those directly above an entry are its description (an empty line detaches them).
- Empty lines are skipped.
- An `export ` prefix is accepted.
- A value is unquoted (taken literally to the end of the line minus whitespace), single quoted (literal), or double quoted with escapes:
  `\n`, `\r`, `\t`, `\"`, `\\` (a literal backslash), and `\uXXXX`: four hex digits (in any case) of a character, eg. `\u2028`.
  Any other escape is an error, and so is a `\u` not followed by four hex digits of a character (a surrogate, `\ud800`, is none):
  the error names the line and the entry, never the escaped text, which is part of the (secret) value.
- Nothing is substituted inside a value. `${VAR}` and `$(cmd)` are kept as written.
- A name given twice is an error.

`parse_env_file` reads a file into its entries. `serialize_env_file` writes entries back,
with values holding `$` single quoted, any other value double quoted when it wouldn't survive
unquoted. Other dotenv parsers end a line at more characters than `\n` and `\r`: VT, FF, FS, GS,
RS and NEL (Python's `str.splitlines`, which django-environ reads with), U+2028 and U+2029 (Node's
dotenv). Raw inside a value, the rest of the value would be an entry of its own to them (`x<U+2028>DATABASE_URL=...`):
`serialize_env_file` writes a value holding one double quoted, the character as its `\uXXXX`
escape (`\u2028`), so every parser reads the value on its line, and this parser reads it back
unchanged (another parser reads the escape by its own grammar: python-dotenv and Node's dotenv
keep the six characters). Descriptions turn them into line breaks of their comment lines
(`normalize_env_description`).

```rust
use mogh_env_parser::{EnvFileEntry, parse_env_file, serialize_env_file};

let entries = parse_env_file(
  "# The database password\nDB_PASSWORD=\"hunter2\"\nexport PORT=8080\n",
)
.unwrap();
assert_eq!(entries[0].name, "DB_PASSWORD");
assert_eq!(entries[0].value, "hunter2");
assert_eq!(entries[0].description, "The database password");
assert_eq!(entries[1].line, 3);

let file = serialize_env_file(&entries).unwrap();
assert_eq!(parse_env_file(&file).unwrap(), entries.iter().map(|e| EnvFileEntry {
  line: if e.name == "PORT" { 3 } else { 2 },
  ..e.clone()
}).collect::<Vec<_>>());
```

## As a configuration source

- `parse_env_file_object` reads a file into a `serde_json::Value`.
Names are lowercased to match struct fields (`DB_PASSWORD` fills `db_password`),
and using dots parses a nested struct (`DATABASE.ADDRESS` fills
`database.address`).

- A name with an empty segment cannot nest (`.dockerconfigjson`, `A..B`, `A.`),
so it is kept whole as one flat key, lowercased (reach it with `#[serde(rename = ".dockerconfigjson")]`).

- A name that is both a value and an object is an error (`DATABASE=x` next to
`DATABASE.ADDRESS=y`). Two names equal once lowercased (`DB` and
`db`) is also an error naming the line and both names.

- `deserialize` reads such an object into the specified type,
coercing string values into the fields' types similar to the way `envy` reads
the process environment.

- Booleans are not case sensitive (`TRUE`, `False`)

- A sequence splits a string on commas, with entries trimmed and empty ones dropped. `""` is an empty list; `Option<T>` is `Some`

- The deserializer itself is `Lenient`, for a `serde_path_to_error` or another wrapper of your own.

## Errors

Every error names a line (`line 2: expected NAME=value ...`), a name
(`DATABASE.ADDRESS conflicts with DATABASE (line 1)`) or a field (`at
'database.port': invalid value: string [redacted], expected u16`).
Values themselves are not logged. `redact_serde_error` (and `redact_serde_message`
for a message in hand) redacts the values serde writes into its
messages, for the errors of any other serde_json deserialization an app
logs.
