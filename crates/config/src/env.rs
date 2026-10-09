//! The process environment as a config source, see [EnvSource].

use std::{collections::HashMap, ffi::OsString, path::Path};

use colored::Colorize;
use serde::Serialize;

use crate::{Error, Result};

/// The suffix of the variable which names a file holding the value
/// of another (`KOMODO_JWT_SECRET_FILE` for `KOMODO_JWT_SECRET`).
pub const FILE_SUFFIX: &str = "_FILE";

/// The process environment as the last source of a
/// [ConfigLoader][crate::ConfigLoader] (see
/// [load_with_env][crate::ConfigLoader::load_with_env]): each
/// variable of its table overrides one config field, whatever the
/// config files hold. The table maps names to config paths:
///
/// ```
/// # #[derive(serde::Deserialize, Default)]
/// # #[serde(default)]
/// # struct Database { address: String, password: String }
/// # #[derive(serde::Deserialize, Default)]
/// # #[serde(default)]
/// # struct Config { host: String, port: u16, database: Database }
/// let env = mogh_config::EnvSource::new("APP_")
///   // APP_HOST, APP_PORT, APP_DATABASE_ADDRESS, ...
///   .fields(["host", "port", "database.address", "database.password"])
///   // A name of its own.
///   .var("APP_DB_URI", "database.uri")
///   // A renamed variable, still read.
///   .alias("APP_PORT_NUMBER", "APP_PORT")
///   // Instead of the process environment (tests).
///   .with_vars([("APP_PORT", "8080"), ("APP_DATABASE_PASSWORD_FILE", "")]);
/// let config = mogh_config::ConfigLoader {
///   paths: &[],
///   match_wildcards: &[],
///   include_file_name: "",
///   merge_nested: true,
///   extend_array: false,
///   debug_print: false,
/// }
/// .load_with_env::<Config>(&env)?;
/// assert_eq!(config.port, 8080);
/// # Ok::<(), mogh_config::Error>(())
/// ```
///
/// The rules:
///
/// - **Names.** [Self::fields] (and [Self::fields_of]) name a
///   variable after its path: the prefix, then the path's segments
///   uppercased and joined by `_` (`database.address` is
///   `APP_DATABASE_ADDRESS`), or by the separator
///   [Self::nested_separator] sets (`__`: `APP_DATABASE__ADDRESS`).
///   [Self::var] gives a variable a name of its own. Names match in
///   any case, as `envy` reads them (`app_port` is `APP_PORT`).
///   Variables the table doesn't name are ignored, also with the
///   prefix (eg. the `APP_CONFIG_PATHS` an app reads itself).
/// - **Values** are strings, parsed into the field's type by the
///   final deserialization like the values of env files
///   ([deserialize_final][crate::deserialize_final]): numbers and
///   booleans from the trimmed string, a list split on commas
///   (entries trimmed, empty ones dropped), a unit enum variant by
///   name. A field which reads a string itself (its own
///   `deserialize_with` going through `deserialize_any`) gets the
///   whole value, eg. a list it splits on `;`. A value the field
///   can't take is an error naming the variable and the field
///   ([Error::ParseEnv]), never the value.
/// - **Blank is unset.** A variable set to nothing but whitespace
///   and commas counts as not set, so the config file's value stays:
///   compose files template optional variables as
///   `APP_X: ${APP_X:-}`, which sets them blank. A string field can't
///   be emptied this way, nor a list (for an allow list, empty can
///   mean everyone), unless the variable [allows it][Self::allow_empty]
///   (a security header which is left out when empty).
/// - **`_FILE`.** Every variable `NAME` can be given as `NAME_FILE`
///   instead, the path of a file holding the value (eg. a docker
///   secret): the file's contents, trimmed. It wins over `NAME`. A
///   blank `NAME_FILE`, or a file holding nothing but whitespace and
///   commas, counts as unset (`mogh_secret_file`'s rule for the
///   path), and a file which can't be read is an error naming the
///   variable and the path ([Error::EnvFile]). `NAME_FILE` is no
///   file variable when the table has a variable of that name itself
///   (a field `health_file`). For a variable of [Self::file_spec],
///   the file is not read: the field gets `file:<path>`.
/// - **Aliases.** [Self::alias] reads a variable under an older
///   name too (and its `_FILE`). It is read only when the variable
///   is unset under its own name (blank counts as unset): when both
///   are set, the own name wins, and the old one is ignored with a
///   warning naming both (never the values). [Self::fallback] is the
///   same for a variable of other programs (`TZ`), without the
///   warning or a `_FILE`.
/// - **Overrides.** Each value replaces the field it names, a list
///   included (`extend_array` doesn't extend it), and a nested field
///   only that field: `APP_DATABASE_ADDRESS` keeps the other
///   `database` fields of the files, whatever `merge_nested` says. A
///   field the config type also takes under another key (a serde
///   alias, eg. `mongo` for `database`) needs [Self::key_alias]: the
///   files' values under the other key then stay with the field.
///
/// The table is checked when it is read: two variables of one name,
/// a path inside another one's, an alias of no variable is an
/// [Error::InvalidEnvSource], a mistake of the app.
pub struct EnvSource {
  prefix: String,
  separator: String,
  /// In the order given.
  entries: Vec<Entry>,
  /// Paths left out of [Self::fields_of].
  without: Vec<Vec<String>>,
  /// The other names variables are read under, in their order.
  aliases: Vec<AliasEntry>,
  /// See [Self::file_spec], as given.
  file_specs: Vec<String>,
  /// See [Self::allow_empty], as given.
  allow_empty: Vec<String>,
  /// `(path of the field, its other key)`, see [Self::key_alias].
  key_aliases: Vec<(Vec<String>, String)>,
  /// Read instead of the process environment, see
  /// [Self::with_vars].
  values: Option<Vec<(OsString, OsString)>>,
}

/// An entry of an [EnvSource]'s table.
enum Entry {
  /// Named after its path, see [EnvSource::fields].
  Field(Vec<String>),
  /// A name of its own, see [EnvSource::var].
  Var { name: String, path: Vec<String> },
  /// Every leaf of a value, see [EnvSource::fields_of]. The error of
  /// serializing it, reported when the table is read.
  FieldsOf(std::result::Result<serde_json::Value, String>),
}

/// Another name a variable is read under.
#[derive(Debug)]
struct AliasEntry {
  other: String,
  name: String,
  /// A variable of other programs ([EnvSource::fallback]), rather
  /// than a renamed one ([EnvSource::alias]).
  fallback: bool,
}

/// The values stay out: they may be secrets.
impl std::fmt::Debug for EnvSource {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("EnvSource")
      .field("prefix", &self.prefix)
      .field("separator", &self.separator)
      .field("entries", &self.entries.len())
      .field("aliases", &self.aliases)
      .field("file_specs", &self.file_specs)
      .field("allow_empty", &self.allow_empty)
      .field("key_aliases", &self.key_aliases)
      .field(
        "values",
        &self.values.as_ref().map(|values| values.len()),
      )
      .finish()
  }
}

impl EnvSource {
  /// An empty table for the variables starting with `prefix` (eg.
  /// `APP_`, with its underscore), which names the variables of
  /// [Self::fields].
  pub fn new(prefix: impl Into<String>) -> EnvSource {
    EnvSource {
      prefix: prefix.into(),
      separator: String::from("_"),
      entries: Vec::new(),
      without: Vec::new(),
      aliases: Vec::new(),
      file_specs: Vec::new(),
      allow_empty: Vec::new(),
      key_aliases: Vec::new(),
      values: None,
    }
  }

  /// What joins the segments of a nested path in the names
  /// [Self::fields] and [Self::fields_of] make: `_` by default
  /// (`APP_DATABASE_ADDRESS`), `__` tells a nested field from a
  /// field with an underscore in its name (`APP_DATABASE__ADDRESS`).
  pub fn nested_separator(
    mut self,
    separator: impl Into<String>,
  ) -> EnvSource {
    self.separator = separator.into();
    self
  }

  /// A variable for each config path (dot separated: `port`,
  /// `database.address`), named the prefix and the path, see
  /// [EnvSource] ("Names").
  pub fn fields<'a>(
    mut self,
    paths: impl IntoIterator<Item = &'a str>,
  ) -> EnvSource {
    self.entries.extend(
      paths.into_iter().map(|path| Entry::Field(split(path))),
    );
    self
  }

  /// A variable for each field of `config` (eg. the config type's
  /// default), named as [Self::fields] names them: every value which
  /// is no object (a string, number, list, `null`) as `config`
  /// serializes. So a field added to the config gets its variable
  /// with it. Leave out the paths which shouldn't have one with
  /// [Self::without] (a list of objects). A field skipped when
  /// serializing (`skip_serializing_if`) has none: list it with
  /// [Self::fields].
  pub fn fields_of<T: Serialize>(mut self, config: &T) -> EnvSource {
    self.entries.push(Entry::FieldsOf(
      serde_json::to_value(config)
        .map_err(|e| crate::error::redact_serde_error(&e)),
    ));
    self
  }

  /// Leaves `path` (dot separated), and everything under it, out of
  /// [Self::fields_of].
  pub fn without<'a>(
    mut self,
    paths: impl IntoIterator<Item = &'a str>,
  ) -> EnvSource {
    self.without.extend(paths.into_iter().map(split));
    self
  }

  /// A variable with a name of its own (the full name, prefix
  /// included: `APP_DB_URI`) for the config path `path`.
  pub fn var(
    mut self,
    name: impl Into<String>,
    path: &str,
  ) -> EnvSource {
    self.entries.push(Entry::Var {
      name: name.into(),
      path: split(path),
    });
    self
  }

  /// Reads the variable `name` (a full name of the table) under the
  /// older name `alias` too, see [EnvSource] ("Aliases").
  pub fn alias(
    mut self,
    alias: impl Into<String>,
    name: impl Into<String>,
  ) -> EnvSource {
    self.aliases.push(AliasEntry {
      other: alias.into(),
      name: name.into(),
      fallback: false,
    });
    self
  }

  /// Reads `other`, a variable of other programs (eg. `TZ`), for the
  /// variable `name` (a full name of the table) when `name` is unset.
  /// Like an [alias][Self::alias], without the warning when both are
  /// set (the other programs still need it), and without a `_FILE`.
  pub fn fallback(
    mut self,
    other: impl Into<String>,
    name: impl Into<String>,
  ) -> EnvSource {
    self.aliases.push(AliasEntry {
      other: other.into(),
      name: name.into(),
      fallback: true,
    });
    self
  }

  /// The `_FILE` variant of these variables (full names of the
  /// table) names a file the field reads itself, rather than a file
  /// holding the value: the field gets `file:<path>`, the file isn't
  /// read. For a key spec (`mogh_pki`'s `file:/path`, an encryption
  /// key file), where the app reads the key, creates the file when
  /// there is none, or rotates the key in it.
  pub fn file_spec<'a>(
    mut self,
    names: impl IntoIterator<Item = &'a str>,
  ) -> EnvSource {
    self.file_specs.extend(names.into_iter().map(String::from));
    self
  }

  /// These variables (full names of the table) set the empty value
  /// when they are set blank (a `_FILE` holding nothing too), rather
  /// than counting as unset: for a field which means something when
  /// empty, which the environment must be able to empty (eg. a
  /// security header, left out when empty).
  pub fn allow_empty<'a>(
    mut self,
    names: impl IntoIterator<Item = &'a str>,
  ) -> EnvSource {
    self.allow_empty.extend(names.into_iter().map(String::from));
    self
  }

  /// The config type also takes the field at `path` (dot
  /// separated) under the key `alias` (a `#[serde(alias)]`), eg.
  /// `key_alias("database", "mongo")`. A config file's value under
  /// the other key is moved to the field's own before the
  /// environment's values go in: otherwise the field would be there
  /// twice, which serde refuses, or the file's nested values would
  /// be left out of the object the environment sets a field of.
  pub fn key_alias(
    mut self,
    path: &str,
    alias: impl Into<String>,
  ) -> EnvSource {
    self.key_aliases.push((split(path), alias.into()));
    self
  }

  /// Reads these variables instead of the process environment, eg.
  /// in tests.
  pub fn with_vars<K, V>(
    mut self,
    vars: impl IntoIterator<Item = (K, V)>,
  ) -> EnvSource
  where
    K: Into<OsString>,
    V: Into<OsString>,
  {
    self.values = Some(
      vars
        .into_iter()
        .map(|(name, value)| (name.into(), value.into()))
        .collect(),
    );
    self
  }

  /// The names of the table's variables, uppercase, in its order
  /// (aliases and `_FILE` variants left out). Eg. for an app's
  /// documentation, or a test that a renamed field kept its
  /// variable.
  pub fn names(&self) -> Result<Vec<String>> {
    Ok(self.table()?.vars.into_iter().map(|var| var.name).collect())
  }

  /// The table, checked.
  fn table(&self) -> Result<Table> {
    let invalid =
      |message: String| Error::InvalidEnvSource { message };
    let mut vars = Vec::<Var>::new();
    let mut push = |name: String, path: Vec<String>| {
      vars.push(Var {
        name: name.to_ascii_uppercase(),
        path,
        file_spec: false,
        allow_empty: false,
      })
    };
    for entry in &self.entries {
      match entry {
        Entry::Field(path) => push(self.name_of(path), path.clone()),
        Entry::Var { name, path } => push(name.clone(), path.clone()),
        Entry::FieldsOf(config) => {
          let config = config.as_ref().map_err(|message| {
            invalid(format!(
              "the config of fields_of doesn't serialize | {message}"
            ))
          })?;
          let mut paths = Vec::new();
          leaf_paths(config, &mut Vec::new(), &mut paths);
          if paths.is_empty() {
            return Err(invalid(String::from(
              "the config of fields_of has no fields (it serializes as no object, or an empty one)",
            )));
          }
          for path in paths {
            if self
              .without
              .iter()
              .any(|without| path.starts_with(without))
            {
              continue;
            }
            push(self.name_of(&path), path);
          }
        }
      }
    }
    for var in &vars {
      if var.name.is_empty() || has_empty_segment(&var.path) {
        return Err(invalid(format!(
          "the variable '{}' (config path '{}') has an empty name or path segment",
          var.name,
          var.path.join(".")
        )));
      }
    }
    // Names and paths, each once and none inside another.
    for (index, var) in vars.iter().enumerate() {
      for other in &vars[index + 1..] {
        if var.name == other.name {
          return Err(invalid(format!(
            "the variable '{}' is in the table twice",
            var.name
          )));
        }
        if var.path.starts_with(&other.path)
          || other.path.starts_with(&var.path)
        {
          return Err(invalid(format!(
            "'{}' sets '{}', which '{}' sets with '{}'",
            var.name,
            var.path.join("."),
            other.name,
            other.path.join(".")
          )));
        }
      }
    }
    let index_of = |vars: &[Var], name: &str, what: &str| {
      let name = name.to_ascii_uppercase();
      vars.iter().position(|var| var.name == name).ok_or_else(|| {
        invalid(format!(
          "{what} '{name}', which is no variable of the table"
        ))
      })
    };
    let mut aliases = Vec::<Alias>::new();
    for AliasEntry {
      other,
      name,
      fallback,
    } in &self.aliases
    {
      let other = other.to_ascii_uppercase();
      let index =
        index_of(&vars, name, &format!("the alias '{other}' is of"))?;
      if other.is_empty()
        || vars.iter().any(|var| var.name == other)
        || aliases.iter().any(|alias| alias.name == other)
      {
        return Err(invalid(format!(
          "the alias '{other}' (of '{name}') is empty, a variable of the table, or another alias"
        )));
      }
      aliases.push(Alias {
        name: other,
        index,
        fallback: *fallback,
      });
    }
    for name in &self.file_specs {
      let index = index_of(&vars, name, "file_spec names")?;
      vars[index].file_spec = true;
    }
    for name in &self.allow_empty {
      let index = index_of(&vars, name, "allow_empty names")?;
      vars[index].allow_empty = true;
    }
    for (path, alias) in &self.key_aliases {
      if alias.is_empty() || has_empty_segment(path) {
        return Err(invalid(format!(
          "the key alias '{alias}' of '{}' has an empty key or path segment",
          path.join(".")
        )));
      }
    }
    Ok(Table { vars, aliases })
  }

  /// The name [Self::fields] gives `path`.
  fn name_of(&self, path: &[String]) -> String {
    format!(
      "{}{}",
      self.prefix,
      path.join(&self.separator).to_ascii_uppercase()
    )
  }

  /// The values the environment sets, each with the config path it
  /// goes to and the variable it came from. See [EnvSource].
  pub(crate) fn read(&self, debug_print: bool) -> Result<EnvValues> {
    let table = self.table()?;
    // Every name read, uppercase: which variable, under which of its
    // names, and whether as its `_FILE` variant.
    let mut names = HashMap::<String, Read>::new();
    for (index, var) in table.vars.iter().enumerate() {
      names.insert(var.name.clone(), Read::plain(index, None));
    }
    for (position, alias) in table.aliases.iter().enumerate() {
      names.insert(
        alias.name.clone(),
        Read::plain(alias.index, Some(position)),
      );
    }
    let named = names.clone();
    for (name, read) in named {
      let fallback = read
        .alias
        .is_some_and(|position| table.aliases[position].fallback);
      if fallback {
        continue;
      }
      // Unless a variable of its own (a field `health_file`).
      names
        .entry(format!("{name}{FILE_SUFFIX}"))
        .or_insert(Read { file: true, ..read });
    }

    // The variables of the table set, by variable.
    let mut set = HashMap::<usize, Vec<SetVar>>::new();
    let environment = match &self.values {
      Some(values) => values.clone(),
      None => std::env::vars_os().collect(),
    };
    for (name, value) in environment {
      // A name which isn't utf-8 is none of the table's.
      let Some(name) = name.to_str() else {
        continue;
      };
      let Some(read) = names.get(&name.to_ascii_uppercase()) else {
        continue;
      };
      let value =
        value.into_string().map_err(|_| Error::EnvNotUnicode {
          variable: name.to_string(),
        })?;
      // Blank is unset: a blank `_FILE` is no file, and a blank
      // value no value, unless it may be empty.
      if is_blank(&value)
        && (read.file || !table.vars[read.index].allow_empty)
      {
        continue;
      }
      set.entry(read.index).or_default().push(SetVar {
        name: name.to_string(),
        read: *read,
        value,
      });
    }

    let mut values = Vec::new();
    for (index, var) in table.vars.iter().enumerate() {
      let Some(mut candidates) = set.remove(&index) else {
        continue;
      };
      // Its own name before the other names (in their order), a file
      // before the value.
      candidates.sort_by_key(|candidate| {
        (
          candidate.read.alias.is_some(),
          candidate.read.alias,
          !candidate.read.file,
        )
      });
      for (position, candidate) in candidates.iter().enumerate() {
        if let Some(other) = candidates[position + 1..]
          .iter()
          .find(|other| other.read == candidate.read)
        {
          // One name, set in two cases.
          return Err(Error::EnvVarSetTwice {
            variable: candidate.name.clone(),
            other: other.name.clone(),
          });
        }
      }
      // The first which holds a value: a file holding nothing but
      // whitespace and commas is unset too, unless the variable may
      // be empty (an error reading one is never passed over).
      let mut unset = Vec::new();
      let mut chosen = None;
      for (position, candidate) in candidates.iter().enumerate() {
        let value = match (candidate.read.file, var.file_spec) {
          (true, true) => format!("file:{}", candidate.value),
          (true, false) => {
            read_file(&candidate.name, Path::new(&candidate.value))?
          }
          (false, _) => candidate.value.clone(),
        };
        if !is_blank(&value) {
          chosen = Some((candidate, value));
          break;
        }
        if var.allow_empty {
          chosen = Some((candidate, String::new()));
          break;
        }
        unset.push(position);
      }
      let Some((chosen, value)) = chosen else {
        continue;
      };
      for (position, other) in candidates.iter().enumerate() {
        // Not for a value which gives way to the file of its own
        // name, nor for the variable of other programs.
        if unset.contains(&position)
          || other.read.alias == chosen.read.alias
          || other
            .read
            .alias
            .is_some_and(|alias| table.aliases[alias].fallback)
        {
          continue;
        }
        println!(
          "{}: {} is ignored, as {} is set too. Remove {}, an old name of {}.",
          "WARN".yellow(),
          other.name,
          chosen.name,
          other.name,
          var.name,
        );
      }
      values.push(EnvValue {
        path: var.path.clone(),
        variable: chosen.name.clone(),
        value,
      });
    }
    if debug_print {
      println!(
        "{}: {}: {:?}",
        "DEBUG".cyan(),
        "Environment overrides".dimmed(),
        values
          .iter()
          .map(|value| value.variable.as_str())
          .collect::<Vec<_>>()
      );
    }
    Ok(EnvValues {
      values,
      key_aliases: self.key_aliases.clone(),
    })
  }
}

/// A checked table, see [EnvSource::table].
struct Table {
  vars: Vec<Var>,
  aliases: Vec<Alias>,
}

struct Var {
  /// Uppercase.
  name: String,
  path: Vec<String>,
  /// See [EnvSource::file_spec].
  file_spec: bool,
  /// See [EnvSource::allow_empty].
  allow_empty: bool,
}

struct Alias {
  /// Uppercase.
  name: String,
  /// Of the variable.
  index: usize,
  /// See [EnvSource::fallback].
  fallback: bool,
}

/// How a name is read: as the variable at `index` of the table, by
/// its own name or another one (its position), as the value or the
/// `_FILE` variant.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Read {
  index: usize,
  alias: Option<usize>,
  file: bool,
}

impl Read {
  fn plain(index: usize, alias: Option<usize>) -> Read {
    Read {
      index,
      alias,
      file: false,
    }
  }
}

/// A variable of the table set in the environment.
struct SetVar {
  /// As set (in its case).
  name: String,
  read: Read,
  value: String,
}

/// The value of a variable, for [EnvValues].
struct EnvValue {
  path: Vec<String>,
  /// The name it was set under, as set (`app_port`,
  /// `APP_SECRET_FILE`), for the errors about it.
  variable: String,
  value: String,
}

/// What the environment sets, see [EnvSource::read].
pub(crate) struct EnvValues {
  values: Vec<EnvValue>,
  /// See [EnvSource::key_alias].
  key_aliases: Vec<(Vec<String>, String)>,
}

impl EnvValues {
  /// Sets each value at its path in `config`: replacing the value
  /// there (a list too), creating the objects on the way, and
  /// keeping the other fields of those which exist. A field's value
  /// under another key ([EnvSource::key_alias]) is moved to the
  /// field's own key first.
  pub(crate) fn apply(
    &self,
    config: &mut serde_json::Map<String, serde_json::Value>,
  ) {
    for EnvValue { path, value, .. } in &self.values {
      let mut object = &mut *config;
      for (depth, segment) in path.iter().enumerate() {
        let leaf = depth + 1 == path.len();
        for (alias_path, alias) in &self.key_aliases {
          if alias_path.len() != depth + 1
            || alias_path[..depth] != path[..depth]
            || alias_path[depth] != *segment
          {
            continue;
          }
          if !object.contains_key(segment) {
            if let Some(moved) = object.remove(alias) {
              object.insert(segment.clone(), moved);
            }
          } else if leaf {
            // Replaced: the other key would be the field twice.
            object.remove(alias);
          }
        }
        if leaf {
          object.insert(
            segment.clone(),
            serde_json::Value::String(value.clone()),
          );
          break;
        }
        let entry =
          object.entry(segment.clone()).or_insert_with(|| {
            serde_json::Value::Object(Default::default())
          });
        if !entry.is_object() {
          *entry = serde_json::Value::Object(Default::default());
        }
        object = entry.as_object_mut().expect("an object");
      }
    }
  }

  /// The variable which set the value at `path` (the segments of a
  /// final deserialization error), or one it is inside of (an entry
  /// of a list).
  pub(crate) fn variable_at(
    &self,
    path: &serde_path_to_error::Path,
  ) -> Option<&str> {
    use serde_path_to_error::Segment;
    let keys = path
      .iter()
      .map_while(|segment| match segment {
        Segment::Map { key } | Segment::Enum { variant: key } => {
          Some(key.as_str())
        }
        Segment::Seq { .. } | Segment::Unknown => None,
      })
      .collect::<Vec<_>>();
    self
      .values
      .iter()
      .find(|value| {
        keys.len() >= value.path.len()
          && value.path.iter().zip(&keys).all(|(a, b)| a == b)
      })
      .map(|value| value.variable.as_str())
  }
}

/// Whether a value counts as unset: nothing but whitespace and
/// commas, so no list entry either. An empty list is never set from
/// the environment (for an allow list, empty can mean everyone): a
/// blank `${APP_X:-}` must leave the config file's list as it is.
fn is_blank(value: &str) -> bool {
  value.chars().all(|c| c.is_whitespace() || c == ',')
}

/// The value in the file `path` a `_FILE` variable names, trimmed.
fn read_file(variable: &str, path: &Path) -> Result<String> {
  std::fs::read_to_string(path)
    .map(|contents| contents.trim().to_string())
    .map_err(|e| Error::EnvFile {
      variable: variable.to_string(),
      path: path.to_path_buf(),
      e,
    })
}

/// The segments of a dot separated config path.
fn split(path: &str) -> Vec<String> {
  path.split('.').map(str::to_string).collect()
}

fn has_empty_segment(path: &[String]) -> bool {
  path.is_empty() || path.iter().any(String::is_empty)
}

/// The paths of the values in `value` which are no object, see
/// [EnvSource::fields_of].
fn leaf_paths(
  value: &serde_json::Value,
  path: &mut Vec<String>,
  paths: &mut Vec<Vec<String>>,
) {
  match value {
    serde_json::Value::Object(object) => {
      for (key, value) in object {
        path.push(key.clone());
        leaf_paths(value, path, paths);
        path.pop();
      }
    }
    _ if !path.is_empty() => paths.push(path.clone()),
    _ => {}
  }
}
