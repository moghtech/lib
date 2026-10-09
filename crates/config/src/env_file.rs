//! Env file (`.env`) syntax as a configuration source: a flat set
//! of `NAME=value` entries, the format Cicada renders a stack of
//! secret environments in and the one dotenv files use.
//!
//! The grammar is Cicada's, and both directions live here: Cicada
//! Core renders its secret exports with [serialize_env_file] and
//! reads imports with [parse_env_file], and every app reads the
//! export (`cicada://.env`) through the same parser, so a file
//! serialized here parses back unchanged. `#` lines are comments
//! (those directly above an entry are its description), blank lines
//! are skipped, an `export ` prefix is accepted, and a value is
//! unquoted (taken literally to the end of the line, trimmed),
//! single quoted (literal) or double quoted with `\n` / `\r` / `\t`
//! / `\"` / `\\` escapes. Nothing is substituted inside a value:
//! `${VAR}` and `$(cmd)` are kept as written, since env file values
//! are secrets and never templates.
//!
//! As a configuration source ([parse_env_file_object]) names are
//! lowercased to match struct fields, and dots nest:
//! `DATABASE.ADDRESS=x` fills `database.address`, so a flat set of
//! secrets can populate a structured config. A name with an empty
//! segment (`.dockerconfigjson`, `A..B`), or with more than 32
//! segments, stays one flat key.

/// The most `.` separated segments a name nests into. A name with
/// more stays one flat key: nesting without a bound lets one long
/// name (a cicada secret's, say) cost memory quadratic in its
/// length, and overflow the stack of whatever walks the object
/// next. yaml and json sources stop at 128 levels of their own.
const MAX_NESTED_SEGMENTS: usize = 32;

/// Where an env file failed to parse. The message never carries a
/// value, only what was expected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFileError {
  /// 1-based line number.
  pub line: usize,
  pub message: String,
}

impl std::fmt::Display for EnvFileError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "line {}: {}", self.line, self.message)
  }
}

impl std::error::Error for EnvFileError {}

fn error(line: usize, message: impl Into<String>) -> EnvFileError {
  EnvFileError {
    line,
    message: message.into(),
  }
}

/// One `NAME=value` entry of an env file, with the description held
/// by the `#` comment lines directly above it.
///
/// Its `Debug` leaves the value out: env file values are secrets.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct EnvFileEntry {
  /// The 1-based line of the `NAME=value` in the parsed file.
  /// [serialize_env_file] ignores it.
  pub line: usize,
  /// As written, trimmed and without an `export ` prefix.
  pub name: String,
  /// Unquoted and unescaped.
  pub value: String,
  /// The `#` comment lines directly above the entry (no blank line
  /// in between), one description line per comment line, each
  /// without the `#` and the one space after it. Empty when there
  /// are none. As [normalize_env_description] has it: a line break
  /// inside a comment line (a lone `\r`) breaks the description
  /// there too.
  pub description: String,
}

impl std::fmt::Debug for EnvFileEntry {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("EnvFileEntry")
      .field("line", &self.line)
      .field("name", &self.name)
      .field("value", &"[redacted]")
      .field("description", &self.description)
      .finish()
  }
}

/// Parses an env file into its entries in file order, names as
/// written, each with its line and description. A name given twice
/// is an error (which of the two the author meant is anyone's
/// guess). Names aren't checked further: an import creating
/// secrets from them holds them to [representable_env_name].
pub fn parse_env_file(
  content: &str,
) -> Result<Vec<EnvFileEntry>, EnvFileError> {
  // A byte order mark (hand written on Windows) is not part of the
  // first name.
  let content = content.strip_prefix('\u{FEFF}').unwrap_or(content);
  let mut entries: Vec<EnvFileEntry> = Vec::new();
  let mut names = std::collections::HashSet::<&str>::new();
  // The comment lines since the last entry or blank line.
  let mut comments = Vec::<&str>::new();
  for (idx, raw) in content.lines().enumerate() {
    let number = idx + 1;
    let line = raw.trim();
    // A blank line detaches the comments above it.
    if line.is_empty() {
      comments.clear();
      continue;
    }
    if let Some(comment) = line.strip_prefix('#') {
      // A serialized description line is `# <line>`: strip the
      // single separating space, keeping any further indentation.
      comments.push(comment.strip_prefix(' ').unwrap_or(comment));
      continue;
    }
    // Real env files often carry `export NAME=value`.
    let line = line
      .strip_prefix("export ")
      .map(str::trim_start)
      .unwrap_or(line);
    let Some((name, value)) = line.split_once('=') else {
      return Err(error(
        number,
        "expected `NAME=value`, a `#` comment, or a blank line",
      ));
    };
    let name = name.trim();
    if name.is_empty() {
      return Err(error(number, "missing name before `=`"));
    }
    if !names.insert(name) {
      return Err(error(
        number,
        format!("duplicate entry for `{name}`"),
      ));
    }
    // As serialize_env_file writes it, so a description imported
    // from a hand written file is exported unchanged.
    let description = if comments.is_empty() {
      String::new()
    } else {
      normalize_env_description(&comments.join("\n"))
    };
    entries.push(EnvFileEntry {
      line: number,
      name: name.to_string(),
      value: parse_value(value.trim(), name, number)?,
      description,
    });
    comments.clear();
  }
  Ok(entries)
}

/// Parses an env file into the configuration object it describes:
/// names lowercased (`DB_PASSWORD` is the field `db_password`),
/// dots nesting (`DATABASE.ADDRESS` is `database.address`), values
/// strings (the final deserialization coerces them).
///
/// A name with an empty segment cannot nest (`.dockerconfigjson`,
/// `A..B`, `A.`, `.`), so it is kept whole as one flat key,
/// lowercased (`.dockerconfigjson`, `a..b`): Cicada accepts such
/// secret names, and one of them must not fail the whole source.
/// So is a name with more than 32 `.` separated segments: nesting
/// stops there, so one long name can't cost memory quadratic in its
/// length or overflow the stack of what walks the object next.
///
/// Errors, with the line and both names involved: a name that is
/// both a value and an object (`DATABASE=x` next to
/// `DATABASE.ADDRESS=y`), and two spellings of one name (`Db` and
/// `DB`).
pub(crate) fn parse_env_file_object(
  content: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, EnvFileError>
{
  let mut object = serde_json::Map::new();
  // The entry which set each key (a value) or first nested under it
  // (an object), by its dotted path, to name both sides of a
  // conflict. A nested path never has an empty segment nor more
  // than MAX_NESTED_SEGMENTS segments, and a flat key always has
  // one or the other, so the two never share a path.
  let mut origins =
    std::collections::HashMap::<String, (String, usize)>::new();
  for entry in parse_env_file(content)? {
    let name = entry.name.to_lowercase();
    let segments = if name.split('.').any(str::is_empty)
      || name.split('.').nth(MAX_NESTED_SEGMENTS).is_some()
    {
      vec![name.as_str()]
    } else {
      name.split('.').collect::<Vec<_>>()
    };
    let (last, parents) =
      segments.split_last().expect("split yields one segment");
    let mut current = &mut object;
    for (depth, segment) in parents.iter().enumerate() {
      let path = segments[..=depth].join(".");
      let slot =
        current.entry(segment.to_string()).or_insert_with(|| {
          origins
            .insert(path.clone(), (entry.name.clone(), entry.line));
          serde_json::Value::Object(Default::default())
        });
      match slot {
        serde_json::Value::Object(map) => current = map,
        _ => {
          return Err(conflict(
            &entry,
            &origins[&path],
            format!("`{path}` is both a value and an object"),
          ));
        }
      }
    }
    if let Some(existing) = current.get(*last) {
      return Err(conflict(
        &entry,
        &origins[&name],
        if existing.is_object() {
          format!("`{name}` is both a value and an object")
        } else {
          // Exact duplicates were refused while parsing the entries.
          String::from("names are case insensitive")
        },
      ));
    }
    origins.insert(name.clone(), (entry.name.clone(), entry.line));
    current.insert(
      last.to_string(),
      serde_json::Value::String(entry.value),
    );
  }
  Ok(object)
}

/// A conflict between `entry` and the earlier entry `origin` (its
/// name and line), naming both.
fn conflict(
  entry: &EnvFileEntry,
  (origin, origin_line): &(String, usize),
  message: String,
) -> EnvFileError {
  error(
    entry.line,
    format!(
      "`{}` conflicts with `{origin}` (line {origin_line}): {message}",
      entry.name
    ),
  )
}

/// A value after `=`, already trimmed: unquoted (taken literally to
/// the end of the line), single quoted (literal), or double quoted
/// with escapes. `name` is the entry's, for the errors.
fn parse_value(
  value: &str,
  name: &str,
  line: usize,
) -> Result<String, EnvFileError> {
  let mut chars = value.chars();
  match chars.next() {
    Some('"') => {
      let mut out = String::new();
      loop {
        match chars.next() {
          Some('\\') => match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('t') => out.push('\t'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            // The escaped character is part of the (secret) value,
            // and so is where it sits, so the message names neither.
            Some(_) => {
              return Err(error(
                line,
                format!(
                  "unsupported escape in the value of `{name}`: \
                   a double quoted value takes `\\n`, `\\r`, `\\t`, \
                   `\\\"` and `\\\\` (a literal backslash)"
                ),
              ));
            }
            None => {
              return Err(error(
                line,
                "unterminated double quoted value",
              ));
            }
          },
          Some('"') => break,
          Some(c) => out.push(c),
          None => {
            return Err(error(
              line,
              "unterminated double quoted value",
            ));
          }
        }
      }
      if chars.next().is_some() {
        return Err(error(
          line,
          "unexpected content after closing quote",
        ));
      }
      Ok(out)
    }
    Some('\'') => {
      // Like Core: the value runs to the last quote, so `'it's'`
      // is `it's`.
      let rest = &value[1..];
      let Some(end) = rest.rfind('\'') else {
        return Err(error(line, "unterminated single quoted value"));
      };
      if !rest[end + 1..].is_empty() {
        return Err(error(
          line,
          "unexpected content after closing quote",
        ));
      }
      Ok(rest[..end].to_string())
    }
    _ => Ok(value.to_string()),
  }
}

/// Whether [serialize_env_file] can write a name such that
/// [parse_env_file] reads it back: not empty, without whitespace
/// around it (names are trimmed), not starting with `#` (a comment),
/// `export ` (a prefix, stripped once) or a byte order mark
/// (stripped at the start of a file), and without `=` (the first one
/// ends the name) or a line break.
pub fn representable_env_name(name: &str) -> bool {
  name.trim() == name
    && !name.is_empty()
    && !name.starts_with('#')
    && !name.starts_with("export ")
    && !name.starts_with('\u{FEFF}')
    && !name.contains(['=', '\n', '\r'])
}

/// An entry [serialize_env_file] can't write such that
/// [parse_env_file] reads it back. Names an entry, never a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EnvFileSerializeError {
  /// See [representable_env_name].
  #[error(
    "{name:?} can't be an env file name: it is empty, has whitespace around it, starts with '#', 'export ' or a byte order mark, or holds '=' or a line break"
  )]
  UnrepresentableName { name: String },
  /// [parse_env_file] refuses a name given twice.
  #[error("duplicate entry for `{name}`")]
  DuplicateName { name: String },
}

/// Writes entries as an env file, in the order given, which
/// [parse_env_file] reads back to the same names, values and
/// descriptions, each description as [normalize_env_description]
/// has it. The entries' `line` is ignored.
///
/// - An entry with a description gets its comment lines directly
///   above it (`# <line>`, a lone `#` for an empty line), separated
///   from the entry before by a blank line, so the comments attach
///   to it unambiguously. The description is written normalized:
///   a comment line keeps no whitespace at its end, and a line
///   break inside one (a lone `\r`, U+2028) would end the comment
///   for other dotenv parsers, which would read the rest of the
///   line as an entry.
/// - A value holding `$` is single quoted when it can be (no `'`,
///   no line break): Compose's `env_file:`, systemd and dotenv
///   libraries take a single quoted value literally, where they
///   would substitute `$NAME` / `${NAME}` in an unquoted or double
///   quoted one.
/// - Any other value is double quoted, with `\n` / `\r` / `\t` /
///   `\"` / `\\` escapes, when it wouldn't survive unquoted
///   (surrounding whitespace is trimmed, `#` starts a comment in
///   some dotenv dialects, a leading quote would be read as
///   quoting), else written as is.
///
/// Errors on a name the syntax can't hold, see
/// [representable_env_name], and on a name given twice.
pub fn serialize_env_file<E: std::borrow::Borrow<EnvFileEntry>>(
  entries: impl IntoIterator<Item = E>,
) -> Result<String, EnvFileSerializeError> {
  let mut out = String::new();
  let mut names = std::collections::HashSet::new();
  for entry in entries {
    let entry = entry.borrow();
    if !representable_env_name(&entry.name) {
      return Err(EnvFileSerializeError::UnrepresentableName {
        name: entry.name.clone(),
      });
    }
    if !names.insert(entry.name.clone()) {
      return Err(EnvFileSerializeError::DuplicateName {
        name: entry.name.clone(),
      });
    }
    let description = normalize_env_description(&entry.description);
    if !description.is_empty() {
      if !out.is_empty() {
        out.push('\n');
      }
      for line in description.split('\n') {
        if line.is_empty() {
          out.push_str("#\n");
        } else {
          out.push_str("# ");
          out.push_str(line);
          out.push('\n');
        }
      }
    }
    out.push_str(&entry.name);
    out.push('=');
    write_value(&mut out, &entry.value);
    out.push('\n');
  }
  Ok(out)
}

/// A description as [serialize_env_file] writes it, and so as
/// [parse_env_file] reads it back: every line break a `\n`, and no
/// line ending in whitespace (the parser trims comment lines).
/// `\r\n` is one line break, and so is each other character some
/// dotenv parser ends a line at: a lone `\r`, U+2028 and U+2029,
/// and VT, FF, FS, GS, RS and NEL (Python's `str.splitlines`).
/// Normalizing again changes nothing.
///
/// An app storing descriptions (Cicada's secrets) normalizes them
/// with this when it writes them: an export and import round trip
/// then gives back the stored description unchanged, and an import
/// comparing descriptions to tell what changed sees no change in a
/// file nobody edited.
pub fn normalize_env_description(description: &str) -> String {
  description
    .replace("\r\n", "\n")
    .split(is_line_break)
    .map(str::trim_end)
    .collect::<Vec<_>>()
    .join("\n")
}

/// Whether some dotenv parser ends a line at `c`: `\n`; a lone `\r`
/// (python-dotenv, PHP's dotenv and systemd, and Node's dotenv,
/// which turns `\r\n?` into `\n`); U+2028 / U+2029 (line terminators
/// to the multiline regex of Node's dotenv); and the other line
/// boundaries of Python's `str.splitlines` (django-environ splits
/// with it): VT, FF, FS, GS, RS and NEL.
fn is_line_break(c: char) -> bool {
  matches!(
    c,
    '\n'
      | '\r'
      | '\x0b'
      | '\x0c'
      | '\x1c'
      | '\x1d'
      | '\x1e'
      | '\u{85}'
      | '\u{2028}'
      | '\u{2029}'
  )
}

/// Writes a value, quoted as [serialize_env_file] describes.
fn write_value(out: &mut String, value: &str) {
  if value.contains('$') && !value.contains(['\'', '\n', '\r']) {
    out.push('\'');
    out.push_str(value);
    out.push('\'');
    return;
  }
  let needs_quoting = value.chars().any(|c| {
    c.is_whitespace() || matches!(c, '"' | '\'' | '#' | '\\')
  });
  if !needs_quoting {
    out.push_str(value);
    return;
  }
  out.push('"');
  for c in value.chars() {
    match c {
      '\n' => out.push_str("\\n"),
      '\r' => out.push_str("\\r"),
      '\t' => out.push_str("\\t"),
      '"' => out.push_str("\\\""),
      '\\' => out.push_str("\\\\"),
      c => out.push(c),
    }
  }
  out.push('"');
}

/// Whether a config path is an env file: named `.env`, or with the
/// `env` extension (`app.env`). `Path::extension` is `None` for
/// `.env`, hence the file name check.
pub(crate) fn is_env_file(path: &std::path::Path) -> bool {
  let name = path
    .file_name()
    .and_then(|name| name.to_str())
    .unwrap_or_default();
  name == ".env"
    || path
      .extension()
      .and_then(|ext| ext.to_str())
      .is_some_and(|ext| ext.eq_ignore_ascii_case("env"))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn entry(
    line: usize,
    name: &str,
    value: &str,
    description: &str,
  ) -> EnvFileEntry {
    EnvFileEntry {
      line,
      name: name.to_string(),
      value: value.to_string(),
      description: description.to_string(),
    }
  }

  /// The entries without their lines, compared with their values
  /// (an [EnvFileEntry]'s `Debug` leaves the value out).
  fn triples(entries: &[EnvFileEntry]) -> Vec<(&str, &str, &str)> {
    entries
      .iter()
      .map(|entry| {
        (
          entry.name.as_str(),
          entry.value.as_str(),
          entry.description.as_str(),
        )
      })
      .collect()
  }

  #[test]
  fn parses_the_cicada_grammar() {
    let file = "\
# A comment
export DB_PASSWORD=hunter2
PORT = 8080

# The description of B
B=\"escaped\\nnewline \\\"quoted\\\" \\\\ #tag\"
SINGLE='it's literal ${NOT_EXPANDED}'
EMPTY=
UNQUOTED=$(not run) ${NOT_EXPANDED} # not a comment
";
    let entries = parse_env_file(file).unwrap();
    assert_eq!(
      triples(&entries),
      [
        ("DB_PASSWORD", "hunter2", "A comment"),
        ("PORT", "8080", ""),
        (
          "B",
          "escaped\nnewline \"quoted\" \\ #tag",
          "The description of B"
        ),
        ("SINGLE", "it's literal ${NOT_EXPANDED}", ""),
        ("EMPTY", "", ""),
        (
          "UNQUOTED",
          "$(not run) ${NOT_EXPANDED} # not a comment",
          ""
        ),
      ]
    );
    assert_eq!(
      entries.iter().map(|entry| entry.line).collect::<Vec<_>>(),
      [2, 3, 6, 7, 8, 9]
    );
  }

  #[test]
  fn parses_comments_as_descriptions() {
    let parsed = parse_env_file(
      "KEY=value\n\
      \n\
      # Comments are one to one with\n\
      # the secret below's description\n\
      #\n\
      #   indented\n\
      I_HAVE=\"a description\"\n",
    )
    .unwrap();
    assert_eq!(
      parsed,
      [
        entry(1, "KEY", "value", ""),
        entry(
          7,
          "I_HAVE",
          "a description",
          "Comments are one to one with\n\
          the secret below's description\n\
          \n  indented"
        ),
      ]
    );
  }

  #[test]
  fn a_blank_line_detaches_comments() {
    let parsed =
      parse_env_file("# floating comment\n\nKEY=1\n# trailing\n")
        .unwrap();
    assert_eq!(parsed, [entry(3, "KEY", "1", "")]);
  }

  #[test]
  fn serializes_descriptions_above_their_entries() {
    let out = serialize_env_file([
      entry(0, "KEY", "value", ""),
      entry(0, "I_HAVE", "a description", "A described secret"),
      entry(0, "LINES", "x", "multi\n\nline"),
    ])
    .unwrap();
    assert_eq!(
      out,
      "KEY=value\n\
      \n\
      # A described secret\n\
      I_HAVE=\"a description\"\n\
      \n\
      # multi\n\
      #\n\
      # line\n\
      LINES=x\n"
    );
    // A first entry's description starts the file.
    assert_eq!(
      serialize_env_file([entry(0, "A", "1", "first")]).unwrap(),
      "# first\nA=1\n"
    );
    assert_eq!(
      serialize_env_file(Vec::<EnvFileEntry>::new()),
      Ok(String::new())
    );
  }

  #[test]
  fn single_quotes_dollar_values() {
    let out = serialize_env_file([
      entry(0, "A", "pa$$word", ""),
      entry(0, "B", "${HOME}/x y", ""),
      entry(0, "C", "a\\$b", ""),
      // Not representable single quoted: double quoted.
      entry(0, "D", "it's $5", ""),
      entry(0, "E", "$a\nb", ""),
      entry(0, "F", "$a\rb", ""),
      // No `$`: quoted only when it must be.
      entry(0, "G", "plain", ""),
      entry(0, "H", "has space", ""),
    ])
    .unwrap();
    assert_eq!(
      out,
      "A='pa$$word'\n\
      B='${HOME}/x y'\n\
      C='a\\$b'\n\
      D=\"it's $5\"\n\
      E=\"$a\\nb\"\n\
      F=\"$a\\rb\"\n\
      G=plain\n\
      H=\"has space\"\n"
    );
  }

  /// A serialized file parses back to the same entries: Cicada
  /// Core serializes its exports here, and every app reads them with
  /// this parser.
  #[test]
  fn serialized_entries_parse_back_unchanged() {
    let entries = vec![
      entry(0, "PLAIN", "value", ""),
      entry(0, "EMPTY", "", ""),
      entry(0, "SPACED", "  keeps  spaces  ", "multi\nline\n\ndesc"),
      entry(
        0,
        "ESCAPES",
        "line1\nline2\ttabbed \"quoted\" \\ #tag",
        "",
      ),
      entry(0, "SINGLE", "it's quoted", "described"),
      entry(0, "HASH", "not # a comment", ""),
      entry(0, "DOLLAR", "pa$$word", ""),
      entry(0, "DOLLAR_SPACED", " ${HOME} \\ #x\t$ ", ""),
      entry(0, "DOLLAR_QUOTE", "it's $5", ""),
      entry(0, "DOLLAR_LINES", "$a\n$b\r", ""),
      entry(0, "export\tTAB", "x", "  indented\n#hash"),
      entry(0, "export", "=", ""),
      entry(0, "a.b", "nested", ""),
    ];
    let serialized = serialize_env_file(&entries).unwrap();
    let parsed = parse_env_file(&serialized).unwrap();
    assert_eq!(triples(&parsed), triples(&entries), "{serialized}");

    // Every character, alone, doubled, between others, around
    // whitespace, next to quotes and `$`.
    let chars = (0..=0x7f_u8)
      .map(char::from)
      .chain(['\u{85}', '\u{a0}', '\u{2028}', '\u{3000}', '\u{feff}'])
      .chain(['é', '€', '😀']);
    let mut entries = Vec::new();
    for c in chars {
      for value in [
        format!("{c}"),
        format!("{c}{c}"),
        format!("a{c}b"),
        format!(" {c} "),
        format!("${c}"),
        format!("'{c}'"),
        format!("\"{c}\""),
        format!("{c}$'"),
      ] {
        entries.push(entry(
          0,
          &format!("N{}", entries.len()),
          &value,
          &format!("{c}x{c}"),
        ));
      }
    }
    let serialized = serialize_env_file(&entries).unwrap();
    // A value's CR is escaped, a description's is a line break.
    assert!(!serialized.contains('\r'));
    let parsed = parse_env_file(&serialized).unwrap();
    assert_eq!(parsed.len(), entries.len());
    for (parsed, entry) in parsed.iter().zip(&entries) {
      assert_eq!(parsed.name, entry.name);
      assert_eq!(parsed.value, entry.value, "{:?}", entry.value);
      assert_eq!(
        parsed.description,
        normalize_env_description(&entry.description),
        "{:?}",
        entry.description
      );
    }
    assert_eq!(serialize_env_file(&parsed).unwrap(), serialized);
  }

  /// A description is written as the one it parses back to: no line
  /// of it ends in whitespace (the parser trims lines), and no line
  /// break but `\n` is written. A lone CR ends the line for
  /// python-dotenv and Node's dotenv, U+2028 / U+2029 for Node's
  /// too: the text after one would be an entry to them.
  #[test]
  fn descriptions_parse_back_as_they_were_written() {
    for (description, written) in [
      ("Database password ", "Database password"),
      ("trailing\t \nlines  ", "trailing\nlines"),
      ("windows\r\nline endings\r\n", "windows\nline endings\n"),
      (
        "rotated monthly\rAPI_URL=https://evil.example",
        "rotated monthly\nAPI_URL=https://evil.example",
      ),
      ("old mac\r\rbreaks", "old mac\n\nbreaks"),
      ("space before \r a break", "space before\n a break"),
      (
        "unicode\u{2028}line\u{2029}breaks\u{85}too",
        "unicode\nline\nbreaks\ntoo",
      ),
      (
        "vertical\x0btab\x0cform feed\x1cand\x1dseparators\x1e",
        "vertical\ntab\nform feed\nand\nseparators\n",
      ),
      ("   ", ""),
      ("\r", "\n"),
      // Already as written: unchanged.
      ("  indented\n\n#hash\nkept", "  indented\n\n#hash\nkept"),
      ("", ""),
    ] {
      let serialized =
        serialize_env_file([entry(0, "KEY", "value", description)])
          .unwrap();
      for line in serialized.split('\n') {
        assert_eq!(line, line.trim_end(), "{serialized:?}");
        assert!(
          !line.contains([
            '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}',
            '\u{2028}', '\u{2029}'
          ]),
          "{serialized:?}"
        );
      }
      let parsed = parse_env_file(&serialized).unwrap();
      assert_eq!(
        triples(&parsed),
        [("KEY", "value", written)],
        "{description:?}"
      );
      // The export of an import is the same file: a round trip of
      // an unedited file changes nothing.
      assert_eq!(serialize_env_file(&parsed).unwrap(), serialized);
      assert_eq!(normalize_env_description(description), written);
      assert_eq!(normalize_env_description(written), written);
    }
  }

  /// A hand written file's comment holding a line break of another
  /// parser reads as the description the serializer writes for it,
  /// so its first export already parses back to the same.
  #[test]
  fn parsed_descriptions_are_normalized() {
    let parsed = parse_env_file(
      "# windows \r\n# old mac\rline\u{2028}break\n# kept \nKEY=value\n",
    )
    .unwrap();
    assert_eq!(
      triples(&parsed),
      [("KEY", "value", "windows\nold mac\nline\nbreak\nkept")]
    );
    let serialized = serialize_env_file(&parsed).unwrap();
    assert_eq!(
      triples(&parse_env_file(&serialized).unwrap()),
      triples(&parsed)
    );
  }

  /// The lines other dotenv parsers read: each line break of any of
  /// them inside a description stays inside a comment line, so no
  /// text of a description is an entry to them.
  #[test]
  fn descriptions_are_comments_to_other_parsers() {
    let serialized = serialize_env_file([
      entry(
        0,
        "KEY",
        "value",
        "rotated monthly\rAPI_URL=https://evil.example\r\n\
        B=2\u{2028}C=3\u{2029}D=4\u{85}E=5\x0bF=6\x0cG=7\x1cH=8",
      ),
      entry(0, "OTHER", "x", ""),
    ])
    .unwrap();
    let lines = serialized
      .split([
        '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}',
        '\u{2028}', '\u{2029}',
      ])
      .filter(|line| !line.is_empty())
      .collect::<Vec<_>>();
    assert_eq!(
      lines,
      [
        "# rotated monthly",
        "# API_URL=https://evil.example",
        "# B=2",
        "# C=3",
        "# D=4",
        "# E=5",
        "# F=6",
        "# G=7",
        "# H=8",
        "KEY=value",
        "OTHER=x",
      ]
    );
  }

  #[test]
  fn refuses_names_which_do_not_parse_back() {
    for name in [
      "",
      " PAD ",
      "PAD ",
      "#NAME",
      "A=B",
      "NEW\nLINE",
      "CR\rNAME",
      "export NAME",
      "\u{FEFF}NAME",
    ] {
      assert!(!representable_env_name(name), "{name:?}");
      let err =
        serialize_env_file([entry(0, name, "secretvalue", "")])
          .unwrap_err();
      assert_eq!(
        err,
        EnvFileSerializeError::UnrepresentableName {
          name: name.to_string()
        }
      );
      assert!(!err.to_string().contains("secretvalue"), "{err}");
    }
    for name in ["A", "a.b", "export", "exportA", "x#y", "é"] {
      assert!(representable_env_name(name), "{name:?}");
    }
    // The parser refuses a name given twice.
    let err = serialize_env_file([
      entry(0, "A", "1", ""),
      entry(0, "A", "2", ""),
    ])
    .unwrap_err();
    assert_eq!(err.to_string(), "duplicate entry for `A`");
  }

  #[test]
  fn debug_leaves_the_value_out() {
    let entry = entry(3, "DB_PASSWORD", "hunter2", "the database");
    let debug = format!("{entry:?}");
    assert!(!debug.contains("hunter2"), "{debug}");
    assert!(debug.contains("DB_PASSWORD"), "{debug}");
  }

  #[test]
  fn errors_name_the_line_and_never_the_value() {
    for (file, expected) in [
      ("A=1\nnot an entry", "line 2: expected `NAME=value`"),
      ("=1", "line 1: missing name"),
      ("A=1\nA=2", "line 2: duplicate entry for `A`"),
      (
        "A=\"bad \\x escape\"",
        "line 1: unsupported escape in the value of `A`",
      ),
      (
        "A=\"unterminated",
        "line 1: unterminated double quoted value",
      ),
      (
        "A='unterminated",
        "line 1: unterminated single quoted value",
      ),
      (
        "A=\"secret\" trailing",
        "line 1: unexpected content after closing quote",
      ),
      (
        "A='secret' trailing",
        "line 1: unexpected content after closing quote",
      ),
    ] {
      let err = parse_env_file(file).unwrap_err().to_string();
      assert!(err.starts_with(expected), "{file:?}: {err}");
      assert!(!err.contains("secret"), "{err}");
    }
  }

  /// The escaped character is a character of the (secret) value:
  /// the message is the same whichever it is, and wherever it sits.
  #[test]
  fn unsupported_escapes_never_name_the_escaped_character() {
    let expected = parse_env_file("DB_PASSWORD=\"\\q\"")
      .unwrap_err()
      .to_string();
    assert!(
      expected.starts_with(
        "line 1: unsupported escape in the value of `DB_PASSWORD`"
      ),
      "{expected}"
    );
    assert!(!expected.contains("\\q"), "{expected}");
    let escaped = ('!'..='~')
      .chain([' ', 'é', '€', '😀'])
      .filter(|c| !matches!(c, 'n' | 'r' | 't' | '"' | '\\'));
    for c in escaped {
      for file in [
        format!("DB_PASSWORD=\"\\{c}\""),
        format!("DB_PASSWORD=\"p4ss\\{c}w0rd\""),
        format!("DB_PASSWORD=\"{}\\{c}\"", "p".repeat(40)),
      ] {
        let err = parse_env_file(&file).unwrap_err();
        assert_eq!(err.line, 1);
        assert_eq!(err.to_string(), expected, "{file:?}");
      }
    }
  }

  #[test]
  fn a_byte_order_mark_is_not_part_of_the_first_name() {
    assert_eq!(
      parse_env_file("\u{FEFF}A=1\nB=2").unwrap(),
      [entry(1, "A", "1", ""), entry(2, "B", "2", "")]
    );
    // Before a description line, the comment still attaches.
    assert_eq!(
      parse_env_file("\u{FEFF}# described\nA=1\n").unwrap(),
      [entry(2, "A", "1", "described")]
    );
  }

  #[test]
  fn objects_lowercase_names_and_nest_on_dots() {
    let object = parse_env_file_object(
      "TITLE=app\nDATABASE.ADDRESS=db:5432\nDATABASE.CREDENTIALS.USERNAME=u\nDatabase.Credentials.Password=\"p\"\nPORT=8080\n",
    )
    .unwrap();
    assert_eq!(
      serde_json::Value::Object(object),
      serde_json::json!({
        "title": "app",
        "port": "8080",
        "database": {
          "address": "db:5432",
          "credentials": { "username": "u", "password": "p" },
        },
      })
    );
    assert_eq!(
      serde_json::Value::Object(parse_env_file_object("").unwrap()),
      serde_json::json!({})
    );
  }

  #[test]
  fn objects_refuse_conflicts_naming_the_line_and_both_names() {
    for (file, expected) in [
      (
        "DATABASE=x\nDATABASE.ADDRESS=y",
        "line 2: `DATABASE.ADDRESS` conflicts with `DATABASE` (line 1): `database` is both a value and an object",
      ),
      (
        "DATABASE.ADDRESS=y\nDATABASE=x",
        "line 2: `DATABASE` conflicts with `DATABASE.ADDRESS` (line 1): `database` is both a value and an object",
      ),
      (
        "A.B=1\nA.B.C=2",
        "line 2: `A.B.C` conflicts with `A.B` (line 1): `a.b` is both a value and an object",
      ),
      (
        "A.B.C=1\nA.X=2\nA.B=3",
        "line 3: `A.B` conflicts with `A.B.C` (line 1): `a.b` is both a value and an object",
      ),
      (
        "Db=1\nDB=2",
        "line 2: `DB` conflicts with `Db` (line 1): names are case insensitive",
      ),
      (
        "Database.Address=1\nDATABASE.ADDRESS=2",
        "line 2: `DATABASE.ADDRESS` conflicts with `Database.Address` (line 1): names are case insensitive",
      ),
      (
        ".DockerConfigJson=1\n.dockerconfigjson=2",
        "line 2: `.dockerconfigjson` conflicts with `.DockerConfigJson` (line 1): names are case insensitive",
      ),
    ] {
      let err = parse_env_file_object(file).unwrap_err().to_string();
      assert_eq!(err, expected, "{file:?}");
    }
    // Values never appear in the messages.
    let err = parse_env_file_object("A=secretvalue\nA.B=1")
      .unwrap_err()
      .to_string();
    assert!(!err.contains("secretvalue"), "{err}");
  }

  /// Cicada accepts secret names which cannot nest: each is one
  /// flat key, and the rest of the file still nests.
  #[test]
  fn names_with_an_empty_segment_stay_flat() {
    let object = parse_env_file_object(
      ".DockerConfigJson={\"auths\":{}}\nA..B=1\nX.=2\n.=3\nA.B=4\nDATABASE.ADDRESS=db:5432\n",
    )
    .unwrap();
    assert_eq!(
      serde_json::Value::Object(object),
      serde_json::json!({
        ".dockerconfigjson": "{\"auths\":{}}",
        "a..b": "1",
        "x.": "2",
        ".": "3",
        "a": { "b": "4" },
        "database": { "address": "db:5432" },
      })
    );
  }

  /// Nesting stops at [MAX_NESTED_SEGMENTS]: a longer name is one
  /// flat key, parsed in time and memory linear in its length.
  #[test]
  fn names_nest_up_to_the_segment_limit() {
    let nested = vec!["a"; MAX_NESTED_SEGMENTS].join(".");
    let object =
      parse_env_file_object(&format!("{nested}=1")).unwrap();
    let mut value = &serde_json::Value::Object(object);
    for _ in 0..MAX_NESTED_SEGMENTS {
      value = &value["a"];
    }
    assert_eq!(value, "1");

    let flat = vec!["a"; MAX_NESTED_SEGMENTS + 1].join(".");
    let object =
      parse_env_file_object(&format!("{flat}=1\nA.B=2")).unwrap();
    assert_eq!(
      serde_json::Value::Object(object),
      serde_json::json!({ flat.clone(): "1", "a": { "b": "2" } })
    );

    // 10k segments (20KB, 300MB of nesting before the limit): one
    // flat key, fast.
    let long = vec!["a"; 10_000].join(".");
    let started = std::time::Instant::now();
    let object = parse_env_file_object(&format!("{long}=1")).unwrap();
    assert!(object.contains_key(&long));
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
  }

  #[test]
  fn many_entries_parse_in_linear_time() {
    let file = (0..100_000)
      .map(|i| format!("NAME_{i}=value"))
      .collect::<Vec<_>>()
      .join("\n");
    let started = std::time::Instant::now();
    assert_eq!(parse_env_file(&file).unwrap().len(), 100_000);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    // Duplicates are still found.
    let err =
      parse_env_file(&format!("{file}\nNAME_7=x")).unwrap_err();
    assert_eq!(err.line, 100_001);
  }

  #[test]
  fn env_files_are_recognized_by_name_or_extension() {
    use std::path::Path;
    assert!(is_env_file(Path::new(".env")));
    assert!(is_env_file(Path::new("/etc/app/.env")));
    assert!(is_env_file(Path::new("app.env")));
    assert!(is_env_file(Path::new("APP.ENV")));
    assert!(!is_env_file(Path::new("config.toml")));
    assert!(!is_env_file(Path::new(".envrc")));
    assert!(!is_env_file(Path::new("env")));
  }
}
