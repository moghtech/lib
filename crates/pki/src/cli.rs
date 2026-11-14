use anyhow::Context as _;
use colored::Colorize as _;

/// Private-Public key utilities. (alias: `k`)
///
/// The texts say nothing of what the keys are for, as [handle] takes
/// any [PkiKind][crate::PkiKind]: the app's own subcommand holding
/// this one says that.
#[derive(Debug, Clone, clap::Subcommand)]
pub enum KeyCommand {
  /// Generate a new private / public key pair, printed (not written
  /// to a file).
  /// (aliases: `gen`, `g`)
  #[clap(alias = "gen", alias = "g")]
  Generate {
    /// Specify the format of the output.
    #[arg(long, short = 'f', default_value_t = KeyOutputFormat::Standard)]
    format: KeyOutputFormat,
  },

  /// Compute the public key for a given private key.
  /// (aliases: `comp`, `c`)
  #[clap(alias = "comp", alias = "c")]
  Compute {
    /// Where to read the private key from: `-` (the default) reads it
    /// from stdin (type it, then Ctrl-D, or pipe it in),
    /// `file:/path/to/key` reads a key file (as
    /// `private_key = "file:..."` does). The key itself is refused:
    /// the process list and the shell history would show it.
    #[arg(default_value = "-")]
    private_key: String,
    /// Specify the format of the output.
    #[arg(long, short = 'f', default_value_t = KeyOutputFormat::Standard)]
    format: KeyOutputFormat,
  },
}

#[derive(
  Debug, Clone, Copy, Default, strum::Display, clap::ValueEnum,
)]
#[strum(serialize_all = "lowercase")]
pub enum KeyOutputFormat {
  /// Readable output format. Default. (alias: `s`)
  #[default]
  #[clap(alias = "s")]
  Standard,
  /// Json (single line) output format. (alias: `j`)
  #[clap(alias = "j")]
  Json,
  /// Json "pretty" (multi line) output format. (alias: `jp`)
  #[clap(alias = "jp")]
  JsonPretty,
}

#[derive(serde::Serialize)]
pub struct KeyPair<'a> {
  pub private_key: &'a str,
  pub public_key: &'a str,
}

pub async fn handle(
  command: &KeyCommand,
  pki_kind: crate::PkiKind,
) -> anyhow::Result<()> {
  match command {
    KeyCommand::Generate { format } => {
      let keys = crate::EncodedKeyPair::generate(pki_kind)
        .context("Failed to generate key pair")?;
      match format {
        KeyOutputFormat::Standard => {
          println!(
            "\nPrivate Key: {}",
            keys.private.as_str().red().bold()
          );
          println!("Public  Key: {}", keys.public.as_str().bold());
        }
        KeyOutputFormat::Json => {
          print_json(keys.private.as_str(), keys.public.as_str())?
        }
        KeyOutputFormat::JsonPretty => print_json_pretty(
          keys.private.as_str(),
          keys.public.as_str(),
        )?,
      }

      Ok(())
    }
    KeyCommand::Compute {
      private_key,
      format,
    } => {
      check_private_key_argument(private_key)?;
      let public_key = if private_key == "-" {
        let mut stdin = std::io::stdin();
        if std::io::IsTerminal::is_terminal(&stdin) {
          eprintln!(
            "Enter the private key, then Ctrl-D (or pass file:/path/to/key):"
          );
        }
        let mut input = zeroize::Zeroizing::new(String::new());
        std::io::Read::read_to_string(&mut stdin, &mut input)
          .context("Failed to read the private key from stdin")?;
        compute_public_key(pki_kind, strip_line_ending(&input))
      } else {
        compute_public_key(pki_kind, private_key)
      }
      .context("Failed to compute public key")?
      .into_inner();
      // The private key is not echoed back.
      match format {
        KeyOutputFormat::Standard => {
          println!("\nPublic Key: {}", public_key.bold());
        }
        KeyOutputFormat::Json => {
          let json = serde_json::to_string(&PublicKey {
            public_key: &public_key,
          })
          .context("Failed to serialize JSON")?;
          println!("{json}");
        }
        KeyOutputFormat::JsonPretty => {
          let json = serde_json::to_string_pretty(&PublicKey {
            public_key: &public_key,
          })
          .context("Failed to serialize JSON")?;
          println!("{json}");
        }
      }
      Ok(())
    }
  }
}

#[derive(serde::Serialize)]
struct PublicKey<'a> {
  public_key: &'a str,
}

/// The argument of `key compute` says where to read the private key
/// from: `-` (stdin) or a `file:` spec. Anything else is most likely
/// the key itself, which every local user sees in the process list
/// (`ps`, `/proc/<pid>/cmdline`) and the shell keeps in its history:
/// refused, without repeating it. Read from stdin, the key itself is
/// taken.
fn check_private_key_argument(argument: &str) -> anyhow::Result<()> {
  if argument == "-" || argument.trim().starts_with("file:") {
    return Ok(());
  }
  // The argument isn't in the error: it is most likely the key.
  anyhow::bail!(
    "The private key isn't taken on the command line, where the process list and the shell history show it. Pass `-` to type it or pipe it in, or `file:/path/to/key` to read a key file"
  )
}

/// The public key of a private key given as `file:/path` (the path
/// read like a `file:` private key spec, see
/// [crate::key_spec_path]), or as the key itself (read from stdin:
/// as the argument it is refused, see [check_private_key_argument]).
fn compute_public_key(
  pki_kind: crate::PkiKind,
  private_key: &str,
) -> anyhow::Result<crate::SpkiPublicKey> {
  if let Some(path) = crate::key_spec_path(private_key)? {
    return Ok(
      crate::EncodedKeyPair::from_file(pki_kind, path)?.public,
    );
  }
  let trimmed = private_key.trim();
  // The key of the path's bytes is not the key in the file.
  if crate::looks_like_a_path(private_key) {
    anyhow::bail!(
      "The private key looks like a file path, which would be taken for the key itself: pass `file:/path/to/key` to read a key file"
    );
  }
  if !trimmed.is_empty()
    && private_key.len() <= 32
    && !trimmed.starts_with("-----BEGIN")
  {
    eprintln!(
      "{}: the private key is not pkcs8 encoded, so it is used as the raw key bytes",
      "NOTE".yellow()
    );
    // What `from_private_key_spec` refuses (an onboarding or recovery
    // key is still read this way).
    if private_key.len() < 32 {
      eprintln!(
        "{}: shorter than 32 bytes, it can be guessed from its public key, and a node refuses it as its own private key: generate one",
        "WARN".yellow()
      );
    }
  }
  crate::SpkiPublicKey::from_private_key(pki_kind, private_key)
}

/// A line read from stdin, without its line ending (as `echo` adds).
fn strip_line_ending(input: &str) -> &str {
  input
    .strip_suffix('\n')
    .map(|input| input.strip_suffix('\r').unwrap_or(input))
    .unwrap_or(input)
}

fn print_json(
  private_key: &str,
  public_key: &str,
) -> anyhow::Result<()> {
  let json = serde_json::to_string(&KeyPair {
    private_key,
    public_key,
  })
  .context("Failed to serialize JSON")?;
  println!("{json}");
  Ok(())
}

fn print_json_pretty(
  private_key: &str,
  public_key: &str,
) -> anyhow::Result<()> {
  let json = serde_json::to_string_pretty(&KeyPair {
    private_key,
    public_key,
  })
  .context("Failed to serialize JSON")?;
  println!("{json}");
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::KeyCommand;
  use crate::{EncodedKeyPair, PkiKind};

  #[test]
  fn compute_reads_a_file_spec() {
    let dir = std::env::temp_dir().join(format!(
      "mogh_pki_cli_compute_{}_{}",
      std::process::id(),
      std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
    ));
    // A short path: once used as raw key bytes, silently.
    let path = dir.join("k");
    let keys =
      EncodedKeyPair::generate_write_sync(PkiKind::Mutual, &path)
        .unwrap();
    let spec = format!("file:{}", path.display());
    assert_eq!(
      super::compute_public_key(PkiKind::Mutual, &spec).unwrap(),
      keys.public
    );
    // Whitespace around the path is no part of it, as for a
    // `file:` private key spec.
    let spec = format!(" file: {} \r\n", path.display());
    assert_eq!(
      super::compute_public_key(PkiKind::Mutual, &spec).unwrap(),
      keys.public
    );
    let err = super::compute_public_key(PkiKind::Mutual, "file: ")
      .unwrap_err();
    assert!(format!("{err:#}").contains("names no key file"));
    assert_eq!(
      super::compute_public_key(
        PkiKind::Mutual,
        keys.private.as_str()
      )
      .unwrap(),
      keys.public
    );
    // A missing file is an error, not a key.
    let missing = format!("file:{}", dir.join("missing").display());
    assert!(
      super::compute_public_key(PkiKind::Mutual, &missing).is_err()
    );
    assert!(super::compute_public_key(PkiKind::Mutual, "").is_err());
    std::fs::remove_dir_all(dir).unwrap();
  }

  /// The aliases each format's help names are the ones clap takes,
  /// for both subcommands.
  #[test]
  fn format_help_names_the_real_aliases() {
    use clap::{Parser as _, ValueEnum as _};

    use super::KeyOutputFormat;

    #[derive(clap::Parser)]
    struct Cli {
      #[command(subcommand)]
      command: KeyCommand,
    }

    for format in KeyOutputFormat::value_variants() {
      let value = format.to_possible_value().unwrap();
      let help = value.get_help().unwrap().to_string();
      let documented = help
        .split_once("(alias: `")
        .and_then(|(_, alias)| alias.split_once('`'))
        .map(|(alias, _)| alias)
        .unwrap_or_else(|| panic!("no alias in {help:?}"));
      assert!(
        value
          .get_name_and_aliases()
          .any(|alias| alias == documented),
        "{help:?} names an alias clap doesn't take"
      );
      for args in [
        vec!["app", "generate", "-f", documented],
        vec!["app", "compute", "-", "--format", documented],
      ] {
        let parsed = match Cli::try_parse_from(&args).unwrap().command
        {
          KeyCommand::Generate { format }
          | KeyCommand::Compute { format, .. } => format,
        };
        assert_eq!(
          parsed.to_string(),
          format.to_string(),
          "{args:?}"
        );
      }
    }
  }

  /// The help is the lib's, for any app and either kind of key:
  /// what the keys are for is the app's to say.
  #[test]
  fn help_names_no_app() {
    use clap::Subcommand as _;

    let command =
      KeyCommand::augment_subcommands(clap::Command::new("app"));
    for sub in command.get_subcommands() {
      for help in [sub.get_about(), sub.get_long_about()]
        .into_iter()
        .flatten()
      {
        let help = help.to_string();
        for app in ["Core", "Periphery", "Komodo", "Cicada"] {
          assert!(
            !help.contains(app),
            "{}: {help:?}",
            sub.get_name()
          );
        }
      }
    }
  }

  /// The private key itself is refused as the argument of `key
  /// compute`, without the error repeating it: only `-` (stdin) and
  /// a `file:` spec are taken.
  #[tokio::test]
  async fn compute_refuses_an_inline_key() {
    use super::{
      KeyOutputFormat, check_private_key_argument, handle,
    };
    let keys = EncodedKeyPair::generate(PkiKind::Mutual).unwrap();
    let private_key = keys.private.as_str().to_string();
    let pem = format!(
      "-----BEGIN PRIVATE KEY-----\n{private_key}\n-----END PRIVATE KEY-----"
    );
    for inline in [
      private_key.as_str(),
      pem.as_str(),
      // Raw key bytes, and a path without its `file:`.
      "0123456789abcdef0123456789abcdef",
      "/config/keys/core.key",
      "",
    ] {
      let err = handle(
        &KeyCommand::Compute {
          private_key: inline.to_string(),
          format: KeyOutputFormat::Standard,
        },
        PkiKind::Mutual,
      )
      .await
      .unwrap_err();
      let message = format!("{err:#} {err:?}");
      assert!(
        message.contains("isn't taken on the command line"),
        "{message}"
      );
      if !inline.is_empty() {
        assert!(!message.contains(inline), "{message}");
      }
      assert!(!message.contains(&private_key), "{message}");
    }
    for taken in ["-", "file:/config/keys/core.key", " file: k "] {
      check_private_key_argument(taken).unwrap();
    }
  }

  #[test]
  fn stdin_line_ending_is_stripped() {
    assert_eq!(super::strip_line_ending("key\n"), "key");
    assert_eq!(super::strip_line_ending("key\r\n"), "key");
    assert_eq!(super::strip_line_ending("key"), "key");
    assert_eq!(super::strip_line_ending("key\n\n"), "key\n");
  }
}
