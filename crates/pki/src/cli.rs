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
    /// Pass the private key
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
  /// Readable output format. Default. (alias: `t`)
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
      let public_key =
        crate::SpkiPublicKey::from_private_key_using_dh(
          pki_kind,
          private_key,
        )
        .context("Failed to compute public key")?
        .into_inner();
      match format {
        KeyOutputFormat::Standard => {
          println!("\nPublic Key: {}", public_key.bold());
        }
        KeyOutputFormat::Json => {
          print_json(private_key, &public_key)?
        }
        KeyOutputFormat::JsonPretty => {
          print_json_pretty(private_key, &public_key)?
        }
      }
      Ok(())
    }
  }
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
