use std::path::PathBuf;

use colored::Colorize as _;

/// - Supports '${VAR}' -> Env var extended
/// - Supports '$(shell command)' -> 'echo $(shell command)'
pub fn interpolate_env_and_shell(input: &str) -> String {
  // Prefer bash
  let shell = if PathBuf::from("/bin/bash").exists() {
    "bash"
  } else {
    "sh"
  };
  interpolate_shell(&interpolate_env(input, shell), shell)
}

/// - Supports '${VAR}' -> Env var extended
pub fn interpolate_env(input: &str, shell: &str) -> String {
  // ${var_name} syntax
  let env_regex =
    regex::Regex::new(r"\$\{([A-Za-z0-9_]+)\}").unwrap();
  let first_env_pass =
    env_regex.replace_all(input, |caps: &regex::Captures| {
      let var_name = &caps[1];
      try_get_env_extended(var_name, shell)
    });

  // Do it twice in case any env vars expand again to env vars
  env_regex
    .replace_all(&first_env_pass, |caps: &regex::Captures| {
      let var_name = &caps[1];
      try_get_env_extended(var_name, shell)
    })
    .into_owned()
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
    .inspect_err(|e| eprintln!("{}: Failed to parse shell stdout for ${var_name} as utf-8: {e}", "WARN".yellow()))
    .unwrap_or_default()
}

/// - Supports '$(shell command)' -> 'echo $(shell command)'
pub fn interpolate_shell(input: &str, shell: &str) -> String {
  // Interpolate $(shell command) syntax
  let shell_regex =
    regex::Regex::new(r"\$\(([A-Za-z0-9_]+)\)").unwrap();
  shell_regex
    .replace_all(input, |caps: &regex::Captures| {
      let command = &caps[1];
      let Ok(output) = std::process::Command::new(shell)
        .arg("-c")
        .arg(command)
        .output()
        .inspect_err(|e| eprintln!("{}: Failed to get output for $({command}): {e}", "WARN".yellow()))
      else {
        return String::new();
      };
      String::from_utf8(output.stdout)
        .map(|value| value.trim().to_string())
        .inspect_err(|e| eprintln!("{}: Failed to parse shell stdout for $({command}) as utf-8: {e}", "WARN".yellow()))
        .unwrap_or_default()
    })
    .into_owned()
}
