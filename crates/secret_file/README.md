# Mogh Secret File

Helpers for parsing secret values from file contents.

For example, used to parse secrets from the files specified in env variable ending in `_FILE`.
A blank `_FILE` variable (eg. `SECRET_FILE=` from a compose template) counts as unset.

Compatible with docker compose secrets,
see [https://docs.docker.com/compose/how-tos/use-secrets/](https://docs.docker.com/compose/how-tos/use-secrets/).

Also contains helpers for writing these files (`write` feature, plus `tokio` for `write_async` / `write_new_async`, which implies `write`):

- New files are created with `0600` permissions (on unix, other platforms use their default permissions).
- The contents are written to a temp file beside the path and renamed onto it,
  so readers never see a partial file and a failed write leaves the existing file untouched.
  The file and its directory are synced, so a completed write survives a crash.
- An existing file keeps its permissions, and on unix its owner and group.
  On Linux it also keeps its access ACL (`setfacl`) and its SELinux / Smack security label,
  and doesn't take on the directory's default ACL.
  If these can't be kept (eg. relabeling is not permitted), and the file can't be written in place either (see below), the write fails.
  Other extended attributes (eg. `user.*`, NFSv4 ACLs), and ACLs on other platforms, are not carried over when the file is replaced.
- A symlink at the path is **not followed**: it is replaced by a new `0600` file, and the file it points to is left untouched,
  so a planted link can't redirect the write. The same goes for anything else which is not a regular file (eg. a fifo).
  To write through a trusted link, resolve it first (eg. `std::fs::canonicalize`) and write the resolved path.
- Files which can't be replaced without changing what they are, are written in place instead, which is not atomic:
  - bind mounted files (eg. docker / kubernetes single file mounts),
  - files in directories which can't be written to,
  - files whose owner / group (or on Linux ACL / security label) can't be given to a new file
    (eg. a non-root process writing another user's file),
    except another user's file in a sticky directory (eg. `/tmp`), which fails like a rename would,
  - hard linked files, when only the directory's owner (root or the file's owner) can write to the directory.
    Otherwise, or if the file is read only, the link is split off.
- Don't write to paths in directories that untrusted users can write to, as they can plant the file which is written.
- `write_async` runs on the tokio blocking thread pool. A dropped future doesn't cut the write off halfway,
  it completes in the background.

Two stricter writers, for files like keys:

- `write_new` (`write_new_async`) creates a new file, and never touches an existing one: anything at the path
  is an `AlreadyExists` error. So two processes racing to create a key file end up with one key,
  the second reading the file the first created. The contents are written to a temp file beside the path,
  then hard linked into place (renamed after a check, where the filesystem has no hard links),
  and the directory (and any parent directories created) synced.
- `replace` writes like `write`, but never in place, so the file is never seen or left partially written:
  where `write` would write in place (a bind mount, a directory which can't be written to,
  an owner / ACL / label which can't be kept), it fails instead, and a hard linked file is split off from its other links.

For a file written beside another one and then renamed onto it (eg. a key rotation's `<key>.next`),
`copy_identity(from, &to)` gives the open file `to` what `write` keeps when it replaces a file:
the owner, group and mode of the file at `from`, and on Linux its access ACL and security label
(a symlink at `from` gives nothing). `is_not_permitted(&err)` tells a refusal (eg. not root) from an I/O error,
and `sync_parent_dir(path)` makes a rename onto `path` (or its removal) durable.
