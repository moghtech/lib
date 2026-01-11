use std::path::Path;

/// Writes data to path, setting permissions to 0600.
/// `std::fs` sync version.
///
/// Also ensures parent directory exists.
pub fn write(
  path: impl AsRef<Path>,
  contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
  use std::{io::Write, os::unix::fs::OpenOptionsExt};

  let path = path.as_ref();

  if let Some(parent) = path.parent() {
    std::fs::create_dir_all(parent)?;
  }

  let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    // Only sets mode if file is created.
    // This leaves existing permissions intact.
    .mode(0o600)
    .open(path)?;

  file.write_all(contents.as_ref())?;
  file.flush()?;

  Ok(())
}

/// Writes data to path, setting permissions to 0600.
/// `tokio::fs` async version.
///
/// Also ensures parent directory exists.
#[cfg(feature = "tokio")]
pub async fn write_async(
  path: impl AsRef<Path>,
  contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
  use tokio::io::AsyncWriteExt;

  let path = path.as_ref();

  if let Some(parent) = path.parent() {
    tokio::fs::create_dir_all(parent).await?;
  }

  let mut file = tokio::fs::OpenOptions::new()
    .write(true)
    .create(true)
    .truncate(true)
    // Only sets mode if file is created.
    // This leaves existing permissions intact.
    .mode(0o600)
    .open(path)
    .await?;

  file.write_all(contents.as_ref()).await?;
  file.flush().await?;

  Ok(())
}
