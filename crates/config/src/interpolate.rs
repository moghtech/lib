use std::{path::PathBuf, sync::LazyLock};

use colored::Colorize as _;
use regex::{Captures, Regex};

/// Prefer bash, resolved once.
static SHELL: LazyLock<&'static str> = LazyLock::new(|| {
  if PathBuf::from("/bin/bash").exists() {
    "bash"
  } else {
    "sh"
  }
});

/// `${var_name}` syntax
static ENV_REGEX: LazyLock<Regex> =
  LazyLock::new(|| Regex::new(r"\$\{([A-Za-z0-9_]+)\}").unwrap());

/// Either syntax, for a single pass over the input.
static ENV_OR_SHELL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
  Regex::new(r"\$\{([A-Za-z0-9_]+)\}|\$\(([A-Za-z0-9_]+)\)").unwrap()
});

/// `$(...)` / `${...}` with anything inside, to find the ones
/// the interpolation leaves as written.
static ANY_INTERPOLATION_REGEX: LazyLock<Regex> =
  LazyLock::new(|| Regex::new(r"\$\([^)]*\)|\$\{[^}]*\}").unwrap());

/// Whether the string contains anything to interpolate.
pub(crate) fn needs_interpolation(input: &str) -> bool {
  input.contains("${") || input.contains("$(")
}

/// Whether the string has a `$(...)` / `${...}` which
/// [interpolate_env_and_shell] keeps as written: a command with
/// arguments (`$(cat /run/secrets/db)`), shell parameter syntax
/// (`${VAR:-default}`).
fn has_unsupported_interpolation(input: &str) -> bool {
  needs_interpolation(input)
    && ANY_INTERPOLATION_REGEX.find_iter(input).any(|found| {
      !ENV_OR_SHELL_REGEX.find(found.as_str()).is_some_and(
        |supported| {
          supported.start() == 0 && supported.end() == found.len()
        },
      )
    })
}

/// The paths (`database.password`, `hosts[1]`) of the string values
/// with a `$(...)` / `${...}` which [interpolate_env_and_shell]
/// keeps as written, so the loader can warn about them without
/// printing the values.
pub(crate) fn unsupported_interpolations(
  value: &serde_json::Value,
) -> Vec<String> {
  fn walk(
    value: &serde_json::Value,
    path: &str,
    found: &mut Vec<String>,
  ) {
    match value {
      serde_json::Value::String(s) => {
        if has_unsupported_interpolation(s) {
          found.push(if path.is_empty() {
            String::from(".")
          } else {
            path.to_string()
          });
        }
      }
      serde_json::Value::Array(items) => {
        for (index, item) in items.iter().enumerate() {
          walk(item, &format!("{path}[{index}]"), found);
        }
      }
      serde_json::Value::Object(map) => {
        for (key, value) in map {
          let path = if path.is_empty() {
            key.clone()
          } else {
            format!("{path}.{key}")
          };
          walk(value, &path, found);
        }
      }
      _ => {}
    }
  }
  let mut found = Vec::new();
  walk(value, "", &mut found);
  found
}

/// - Supports '${VAR}' -> Env var extended
/// - Supports '$(command)' -> the command's output, for a single
///   command word (letters, digits, '_') without arguments
///
/// Anything else (`$(cat /run/secrets/db)`, `${VAR:-default}`) is
/// kept as written.
///
/// Each `${VAR}` / `$(command)` in the input is substituted once,
/// in a single pass. Substituted text is never itself interpolated,
/// so `$(...)` inside an env var value is not executed and `${...}`
/// inside a command's output is kept verbatim. The one exception is
/// that env var values may reference other env vars (`${OTHER}`),
/// which are expanded one level.
pub fn interpolate_env_and_shell(input: &str) -> String {
  if !needs_interpolation(input) {
    return input.to_string();
  }
  ENV_OR_SHELL_REGEX
    .replace_all(input, |caps: &Captures| {
      if let Some(var_name) = caps.get(1) {
        let value = try_get_env_extended(var_name.as_str(), &SHELL);
        // Env vars may expand to other env vars.
        ENV_REGEX
          .replace_all(&value, |caps: &Captures| {
            try_get_env_extended(&caps[1], &SHELL)
          })
          .into_owned()
      } else {
        run_shell_command(&caps[2], &SHELL)
      }
    })
    .into_owned()
}

/// Applies [interpolate_env_and_shell] to every string in the
/// value, including object keys, in place. Objects are only
/// rebuilt when one of their keys needs interpolation.
pub(crate) fn interpolate_value(value: &mut serde_json::Value) {
  match value {
    serde_json::Value::String(s) => {
      if needs_interpolation(s) {
        *s = interpolate_env_and_shell(s);
      }
    }
    serde_json::Value::Array(items) => {
      items.iter_mut().for_each(interpolate_value);
    }
    serde_json::Value::Object(map) => {
      map.values_mut().for_each(interpolate_value);
      if map.keys().any(|key| needs_interpolation(key)) {
        let entries = std::mem::take(map);
        for (key, value) in entries {
          map.insert(interpolate_env_and_shell(&key), value);
        }
      }
    }
    _ => {}
  }
}

fn try_get_env_extended(var_name: &str, shell: &str) -> String {
  if let Ok(value) = std::env::var(var_name)
    && !value.is_empty()
  {
    return value;
  }
  let Ok(output) = std::process::Command::new(shell)
    .arg("-c")
    .arg(format!("echo ${var_name}"))
    .output()
  else {
    return String::new();
  };
  String::from_utf8(output.stdout)
    .map(|value| value.trim().to_string())
    .inspect_err(|e| println!("{}: Failed to parse shell stdout for ${var_name} as utf-8: {e}", "WARN".yellow()))
    .unwrap_or_default()
}

fn run_shell_command(command: &str, shell: &str) -> String {
  let Ok(output) = std::process::Command::new(shell)
    .arg("-c")
    .arg(command)
    .output()
    .inspect_err(|e| {
      println!(
        "{}: Failed to get output for $({command}): {e}",
        "WARN".yellow()
      )
    })
  else {
    return String::new();
  };
  String::from_utf8(output.stdout)
    .map(|value| value.trim().to_string())
    .inspect_err(|e| println!("{}: Failed to parse shell stdout for $({command}) as utf-8: {e}", "WARN".yellow()))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn finds_what_interpolation_keeps_as_written() {
    for supported in [
      "$(hostname)",
      "${HOME}",
      "a ${A_1} b $(true) c",
      "plain",
      "$",
    ] {
      assert!(
        !has_unsupported_interpolation(supported),
        "{supported}"
      );
    }
    for unsupported in [
      "$(cat /run/secrets/db)",
      "${VAR:-default}",
      "ok ${HOME} not $(echo hi)",
      "$(cat ${HOME})",
      "$()",
    ] {
      assert!(
        has_unsupported_interpolation(unsupported),
        "{unsupported}"
      );
    }
    let mut paths = unsupported_interpolations(&serde_json::json!({
      "password": "$(cat /run/secrets/db)",
      "port": "${PORT}",
      "database": { "uri": "${URI:-x}", "ok": "$(hostname)" },
      "hosts": ["a", "$(echo b)"],
    }));
    paths.sort();
    assert_eq!(paths, ["database.uri", "hosts[1]", "password"]);
  }
}
