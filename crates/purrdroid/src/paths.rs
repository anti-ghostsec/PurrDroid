//! Where PurrDroid keeps things: the encrypted files in its data folder, and
//! everything else (sockets, Tor's state, files on their way in or out) in
//! a folder in memory, which is refused if it isn't really in memory.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;

/// The data folder: `$PURRDROID_HOME`, else `$XDG_DATA_HOME/purrdroid`, else
/// `~/.local/share/purrdroid`. Made private (0700) if it's new.
pub fn data_dir() -> io::Result<PathBuf> {
    let dir = if let Some(d) = std::env::var_os("PURRDROID_HOME") {
        PathBuf::from(d)
    } else if let Some(d) = std::env::var_os("XDG_DATA_HOME").filter(|d| !d.is_empty()) {
        PathBuf::from(d).join("purrdroid")
    } else {
        let home = std::env::var_os("HOME").ok_or_else(|| io::Error::other("HOME isn't set"))?;
        PathBuf::from(home).join(".local/share/purrdroid")
    };
    private_dir(&dir)?;
    Ok(dir)
}

fn private_dir(dir: &PathBuf) -> io::Result<()> {
    match fs::DirBuilder::new().recursive(true).mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

pub struct Files {
    pub vault: PathBuf,
    pub android: PathBuf,
    pub media: PathBuf,
}

pub fn files() -> io::Result<Files> {
    let d = data_dir()?;
    Ok(Files { vault: d.join("purrdroid.vault"), android: d.join("android.disk"), media: d.join("media.disk") })
}

const TMPFS_MAGIC: i64 = 0x0102_1994;
const RAMFS_MAGIC: i64 = 0x8584_58f6;

/// True if `path` is on a filesystem in memory (tmpfs or ramfs).
pub fn in_memory(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return false;
    }
    let t = st.f_type as i64;
    t == TMPFS_MAGIC || t == RAMFS_MAGIC
}

/// `$XDG_RUNTIME_DIR/purrdroid`, private. An error if that isn't in memory:
/// nothing that isn't encrypted is ever put on a disk.
pub fn runtime_dir() -> io::Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("XDG_RUNTIME_DIR isn't set, so there's no private folder in memory to work in"))?;
    if !in_memory(&base) {
        return Err(io::Error::other(format!("{} isn't in memory (tmpfs), so PurrDroid won't use it", base.display())));
    }
    let dir = base.join("purrdroid");
    private_dir(&dir)?;
    Ok(dir)
}
