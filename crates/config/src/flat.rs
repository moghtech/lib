//! The flat spellings of config tables, see
//! [EnvSource::flat_prefix][crate::EnvSource::flat_prefix].

use std::{collections::HashSet, path::Path};

use crate::{Error, Result};

/// The rules of [EnvSource::flat_prefix][crate::EnvSource::flat_prefix],
/// checked with the table
/// ([EnvSource::flat_prefixes][crate::EnvSource::flat_prefixes]).
#[derive(Debug, Default)]
pub(crate) struct FlatPrefixes {
  /// `(path of the table, prefix of its flat keys)`, the longest
  /// prefix first.
  rules: Vec<(Vec<String>, String)>,
  /// The top-level keys which are fields of the config (the first
  /// segment of a variable's path, or of a rule's path): never a
  /// flat spelling, however they start.
  fields: HashSet<String>,
}

impl FlatPrefixes {
  pub(crate) fn new(
    mut rules: Vec<(Vec<String>, String)>,
    fields: HashSet<String>,
  ) -> FlatPrefixes {
    // Stable: rules of one length keep their order.
    rules.sort_by_key(|(_, prefix)| std::cmp::Reverse(prefix.len()));
    FlatPrefixes { rules, fields }
  }

  /// Moves the flat keys of `source`, a parsed config file (named
  /// `file` in the error), into their tables. See
  /// [EnvSource::flat_prefix][crate::EnvSource::flat_prefix] for
  /// the rules.
  pub(crate) fn fold(
    &self,
    file: &Path,
    source: &mut serde_json::Map<String, serde_json::Value>,
  ) -> Result<()> {
    if self.rules.is_empty() {
      return Ok(());
    }
    let keys = source.keys().cloned().collect::<Vec<_>>();
    for key in keys {
      if self.fields.contains(&key) {
        continue;
      }
      let Some((path, prefix)) = self.rules.iter().find(|(_, prefix)| {
        key.len() > prefix.len() && key.starts_with(prefix.as_str())
      }) else {
        continue;
      };
      let field = key[prefix.len()..].to_string();
      let value = source.remove(&key).expect("a key of the source");
      let twice = |field: String| Error::FlatKeyTwice {
        path: file.to_path_buf(),
        key: key.clone(),
        field,
      };
      let mut object = &mut *source;
      for (depth, segment) in path.iter().enumerate() {
        let entry =
          object.entry(segment.clone()).or_insert_with(|| {
            serde_json::Value::Object(Default::default())
          });
        let Some(next) = entry.as_object_mut() else {
          // The table's key, holding no table.
          return Err(twice(path[..=depth].join(".")));
        };
        object = next;
      }
      if object.contains_key(&field) {
        return Err(twice(format!("{}.{field}", path.join("."))));
      }
      object.insert(field, value);
    }
    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use std::path::Path;

  use serde_json::json;

  use super::*;

  fn rules(rules: &[(&str, &str)], fields: &[&str]) -> FlatPrefixes {
    FlatPrefixes::new(
      rules
        .iter()
        .map(|(path, prefix)| {
          (
            path.split('.').map(String::from).collect(),
            prefix.to_string(),
          )
        })
        .collect(),
      fields.iter().map(|field| field.to_string()).collect(),
    )
  }

  fn fold(
    rules: &FlatPrefixes,
    source: serde_json::Value,
  ) -> Result<serde_json::Value> {
    let mut source = match source {
      serde_json::Value::Object(source) => source,
      _ => unreachable!(),
    };
    rules.fold(Path::new("app.toml"), &mut source)?;
    Ok(serde_json::Value::Object(source))
  }

  /// The longest prefix wins, a field of the config stays a field,
  /// the table's other fields stay, and a key which is no flat
  /// spelling stays as it is.
  #[test]
  fn folds_flat_keys_into_their_tables() {
    let rules = rules(
      &[
        ("oidc", "oidc_"),
        ("oidc_token_exchange", "oidc_token_exchange_"),
        ("auth.google", "google_"),
      ],
      &["oidc", "oidc_token_exchange", "auth", "host"],
    );
    let folded = fold(
      &rules,
      json!({
        "host": "h",
        "oidc_enabled": true,
        "oidc_client_id": "c",
        "oidc": { "provider": "p" },
        "oidc_token_exchange_enabled": true,
        "oidc_token_exchange": { "audiences": ["a"] },
        "google_id": "g",
        "oidc_": "kept",
        "other_key": 1
      }),
    )
    .unwrap();
    assert_eq!(
      folded,
      json!({
        "host": "h",
        "oidc": { "provider": "p", "enabled": true, "client_id": "c" },
        "oidc_token_exchange": { "audiences": ["a"], "enabled": true },
        "auth": { "google": { "id": "g" } },
        "oidc_": "kept",
        "other_key": 1
      })
    );
  }

  /// Both spellings of one field in one file, or the table's key
  /// holding no table, name the file and both keys.
  #[test]
  fn a_field_spelled_twice_is_an_error() {
    let rules = rules(&[("oidc", "oidc_")], &["oidc"]);
    let error = fold(
      &rules,
      json!({ "oidc_enabled": true, "oidc": { "enabled": false } }),
    )
    .unwrap_err();
    assert_eq!(
      error.to_string(),
      "Config file \"app.toml\" has both oidc_enabled and oidc.enabled: a field is spelled flat and in its table, keep one"
    );
    let error =
      fold(&rules, json!({ "oidc_enabled": true, "oidc": "x" }))
        .unwrap_err();
    assert!(
      error.to_string().contains("both oidc_enabled and oidc:"),
      "{error}"
    );
  }

  /// Without rules nothing moves, whatever the keys look like.
  #[test]
  fn no_rules_leave_the_source_alone() {
    let source = json!({ "oidc_enabled": true });
    assert_eq!(
      fold(&FlatPrefixes::default(), source.clone()).unwrap(),
      source
    );
  }
}
