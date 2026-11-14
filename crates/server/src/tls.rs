//! The https config of [crate::serve_app], built from the PEM cert /
//! key files, and kept up with them while the server runs: a renewed
//! pair is served to new connections without a restart.

use std::{
  sync::Arc,
  time::{Duration, SystemTime},
};

use anyhow::Context as _;
use axum_server::tls_rustls::RustlsConfig;
use rustls::{
  ServerConfig as TlsServerConfig,
  crypto::CryptoProvider,
  pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
};
use sha2::{Digest as _, Sha256};
use tracing::{info, warn};

/// The cert / key files, and the crypto provider every config of them
/// is built with.
pub(crate) struct TlsFiles {
  cert_file: String,
  key_file: String,
  provider: Arc<CryptoProvider>,
}

impl TlsFiles {
  /// `RustlsConfig::from_pem_file` lets rustls pick the crypto
  /// provider from its crate features, which panics when both `ring`
  /// and `aws-lc-rs` end up in the binary (eg together with
  /// mogh_auth_server). Instead use the provider the app installed
  /// as process default, else aws-lc-rs (what axum-server enables):
  /// chosen here once, so a reloaded pair is served with the
  /// provider of the first.
  pub(crate) fn new(cert_file: &str, key_file: &str) -> TlsFiles {
    let provider =
      CryptoProvider::get_default().cloned().unwrap_or_else(|| {
        Arc::new(rustls::crypto::aws_lc_rs::default_provider())
      });
    TlsFiles {
      cert_file: cert_file.to_string(),
      key_file: key_file.to_string(),
      provider,
    }
  }

  /// The config serving the pair as the files hold it now.
  pub(crate) fn server_config(
    &self,
  ) -> anyhow::Result<Arc<TlsServerConfig>> {
    let TlsFiles {
      cert_file,
      key_file,
      provider,
    } = self;
    let certs = CertificateDer::pem_file_iter(cert_file)
      .with_context(|| {
        format!("Failed to read ssl cert file at {cert_file}")
      })?
      .collect::<Result<Vec<_>, _>>()
      .with_context(|| {
        format!("Failed to parse ssl cert file at {cert_file}")
      })?;
    anyhow::ensure!(
      !certs.is_empty(),
      "No certificate in ssl cert file at {cert_file}"
    );
    let key =
      PrivateKeyDer::from_pem_file(key_file).with_context(|| {
        format!("Failed to read ssl key file at {key_file}")
      })?;
    let mut config =
      TlsServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("Unsupported TLS crypto provider")?
        .with_no_client_auth()
        // Refuses a key which isn't the certificate's.
        .with_single_cert(certs, key)
        .context("Failed to use ssl cert / key")?;
    // Same as axum-server's own configs.
    config.alpn_protocols =
      vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
  }

  /// What tells that the files changed: the modification time and
  /// size of each (following symlinks, so a link switched to a new
  /// pair counts), and the certificate's contents, which a renewal
  /// always changes (a pair copied over with its old times too). The
  /// key's contents are only read to build a config.
  ///
  /// An error names the file and the io error, never contents.
  fn state(&self) -> Observed {
    let failed =
      |path: &str, e: std::io::Error| format!("{path} | {e}");
    let file = |path: &str| {
      std::fs::metadata(path)
        .map(|metadata| FileState {
          modified: metadata.modified().ok(),
          len: metadata.len(),
        })
        .map_err(|e| failed(path, e))
    };
    let cert = std::fs::read(&self.cert_file)
      .map_err(|e| failed(&self.cert_file, e))?;
    Ok(FilesState {
      cert: file(&self.cert_file)?,
      key: file(&self.key_file)?,
      cert_digest: Sha256::digest(cert).into(),
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FilesState {
  cert: FileState,
  key: FileState,
  cert_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileState {
  modified: Option<SystemTime>,
  len: u64,
}

/// The files as one check found them: their state, or why it can't
/// be read (the io error, which names no contents).
type Observed = Result<FilesState, String>;

/// The https config of `files` for [crate::serve_app], and the task
/// keeping it up with the files every `reload_interval` (none with
/// `None`), which ends when the returned guard is dropped: with the
/// server.
pub(crate) fn serve_tls_files(
  files: TlsFiles,
  reload_interval: Option<Duration>,
) -> anyhow::Result<(RustlsConfig, Option<ReloadTask>)> {
  // Before the config: files changed while it is built are seen
  // changed by the first check.
  let served = files.state().ok();
  let config = RustlsConfig::from_config(files.server_config()?);
  let Some(interval) = reload_interval else {
    return Ok((config, None));
  };
  let mut reload = Reload {
    files,
    config: config.clone(),
    served,
    failed: None,
  };
  let task = tokio::spawn(async move {
    let mut ticks = tokio::time::interval_at(
      tokio::time::Instant::now() + interval,
      interval,
    );
    ticks.set_missed_tick_behavior(
      tokio::time::MissedTickBehavior::Delay,
    );
    loop {
      ticks.tick().await;
      // Two small files' metadata, and the certificate: short
      // blocking io, once a minute by default.
      reload.check();
    }
  });
  Ok((config, Some(ReloadTask(task))))
}

/// Ends the reload task when dropped.
pub(crate) struct ReloadTask(tokio::task::JoinHandle<()>);

impl Drop for ReloadTask {
  fn drop(&mut self) {
    self.0.abort();
  }
}

/// The state of the reload task.
struct Reload {
  files: TlsFiles,
  config: RustlsConfig,
  /// The state of the files the served config was built from, `None`
  /// when it couldn't be read then.
  served: Option<FilesState>,
  /// The last state which didn't load, warned about once.
  failed: Option<Observed>,
}

impl Reload {
  /// Serves the pair the files hold when they changed, and warns
  /// once about a pair which doesn't load (the served one stays).
  fn check(&mut self) {
    let observed = self.files.state();
    if let Ok(state) = &observed
      && self.served.as_ref() == Some(state)
    {
      // Unchanged, or back to the served pair after a bad one.
      self.failed = None;
      return;
    }
    if self.failed.as_ref() == Some(&observed) {
      // Warned about already.
      return;
    }
    let loaded = match &observed {
      Ok(_) => self.files.server_config(),
      Err(e) => Err(anyhow::anyhow!(
        "Failed to read the ssl cert / key files | {e}"
      )),
    };
    match loaded {
      Ok(config) => {
        self.config.reload_from_config(config);
        info!(
          "Reloaded the ssl cert / key: new connections are served the renewed certificate"
        );
        self.served = observed.ok();
        self.failed = None;
      }
      Err(e) => {
        warn!(
          "The ssl cert / key files changed but don't load: the previous certificate is served until they do | {e:#}"
        );
        self.failed = Some(observed);
      }
    }
  }
}
