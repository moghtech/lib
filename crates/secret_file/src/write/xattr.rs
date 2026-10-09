//! The extended attributes which carry a file's access control on
//! Linux, carried over onto the new file replacing it.

use std::{
  ffi::{CStr, CString},
  fs::File,
  io::ErrorKind,
  os::{fd::AsRawFd, unix::ffi::OsStrExt},
  path::Path,
};

/// The extended attributes which decide who can access a file, next
/// to its owner, group and mode: the POSIX access ACL (`setfacl`),
/// and the SELinux / Smack security label.
const ACCESS_CONTROL: [&CStr; 3] = [
  c"system.posix_acl_access",
  c"security.selinux",
  c"security.SMACK64",
];

/// No extended attribute value is larger (Linux's `XATTR_SIZE_MAX`),
/// so a buffer this size reads any of them in one call.
const MAX_VALUE_SIZE: usize = 64 * 1024;

/// Gives the `temp` file the [ACCESS_CONTROL] extended attributes of
/// the file at `path`: sets the ones it has, and removes the ones it
/// doesn't have which `temp` got on creation (eg. an access ACL from
/// the directory's default ACL).
///
/// Before the mode is set: setting an access ACL sets the mode's
/// group bits to its mask, and the owning group's own entry may deny
/// what those bits allow, so the temp file (`0600` until now) never
/// grants more than the existing file does.
///
/// Fails with a [not permitted](super::is_not_permitted) error when an
/// attribute can't be set or removed, eg. without the permission to
/// relabel a file, or when the filesystem doesn't support it.
pub(super) fn copy_access_control(
  path: &Path,
  temp: &File,
) -> std::io::Result<()> {
  let c_path = CString::new(path.as_os_str().as_bytes())
    .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))?;
  let fd = temp.as_raw_fd();
  let mut buf = vec![0u8; MAX_VALUE_SIZE];
  for name in ACCESS_CONTROL {
    // The entry at the path, not following a symlink, like the
    // metadata the owner, group and mode are taken from.
    // SAFETY: c_path and name are nul terminated,
    // buf is valid for writes of buf.len() bytes.
    let existing = read(name, &mut buf, |buf| unsafe {
      libc::lgetxattr(
        c_path.as_ptr(),
        name.as_ptr(),
        buf.as_mut_ptr().cast(),
        buf.len(),
      )
    })?
    .map(<[u8]>::to_vec);
    // SAFETY: fd is open (borrowed from temp), name is nul
    // terminated, buf is valid for writes of buf.len() bytes.
    let current = read(name, &mut buf, |buf| unsafe {
      libc::fgetxattr(
        fd,
        name.as_ptr(),
        buf.as_mut_ptr().cast(),
        buf.len(),
      )
    })?;
    if existing.as_deref() == current {
      continue;
    }

    #[cfg(test)]
    super::tests::injected_access_control_failure(path)?;

    let res = match &existing {
      // SAFETY: fd is open (borrowed from temp), name is nul
      // terminated, value is valid for reads of value.len() bytes.
      Some(value) => unsafe {
        libc::fsetxattr(
          fd,
          name.as_ptr(),
          value.as_ptr().cast(),
          value.len(),
          0,
        )
      },
      // SAFETY: fd is open (borrowed from temp),
      // name is nul terminated.
      None => unsafe { libc::fremovexattr(fd, name.as_ptr()) },
    };
    if res != 0 {
      let action = if existing.is_some() { "set" } else { "remove" };
      return Err(error(
        action,
        name,
        std::io::Error::last_os_error(),
      ));
    }
  }
  Ok(())
}

/// Reads an extended attribute into `buf` with `get` (a getxattr
/// call). `None` when the file doesn't have it, or its filesystem
/// doesn't support it.
fn read<'a>(
  name: &CStr,
  buf: &'a mut [u8],
  get: impl FnOnce(&mut [u8]) -> libc::ssize_t,
) -> std::io::Result<Option<&'a [u8]>> {
  let len = get(buf);
  if let Ok(len) = usize::try_from(len) {
    return Ok(Some(&buf[..len]));
  }
  let e = std::io::Error::last_os_error();
  match e.raw_os_error() {
    Some(libc::ENODATA | libc::ENOTSUP) => Ok(None),
    _ => Err(error("read", name, e)),
  }
}

/// The OS error `e`, of the same kind, naming the attribute.
fn error(
  action: &str,
  name: &CStr,
  e: std::io::Error,
) -> std::io::Error {
  std::io::Error::new(
    e.kind(),
    format!("Failed to {action} {}: {e}", name.to_string_lossy()),
  )
}
