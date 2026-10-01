use anyhow::Context as _;
use colored::Colorize as _;

/// Private-Public key utilities. (alias: `k`)
#[derive(Debug, Clone, clap::Subcommand)]
pub enum KeyCommand {
  /// Generate a new public / private key pair
  /// for use with Core - Periphery authentication.
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
    /// The private key: `file:/path/to/key` reads a key file (as
    /// `private_key = "file:..."` does), `-` (the default) reads it
    /// from stdin. The key itself works too, but is then visible in
    /// the process list and the shell history.
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

/// The public key of a private key given as `file:/path` (loaded
/// like a `file:` private key spec), or as the key itself.
fn compute_public_key(
  pki_kind: crate::PkiKind,
  private_key: &str,
) -> anyhow::Result<crate::SpkiPublicKey> {
  if let Some(path) = private_key.strip_prefix("file:") {
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

    use super::{KeyCommand, KeyOutputFormat};

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
        vec!["km", "generate", "-f", documented],
        vec!["km", "compute", "-", "--format", documented],
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

  #[test]
  fn stdin_line_ending_is_stripped() {
    assert_eq!(super::strip_line_ending("key\n"), "key");
    assert_eq!(super::strip_line_ending("key\r\n"), "key");
    assert_eq!(super::strip_line_ending("key"), "key");
    assert_eq!(super::strip_line_ending("key\n\n"), "key\n");
  }
}
