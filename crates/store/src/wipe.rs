//! Wiping a file: every part of it that holds anything is written over with
//! random bytes, the file is synced and then removed.
//!
//! On a hard disk that's the end of it. An SSD or flash drive may keep old
//! copies of what's overwritten elsewhere on the chip, out of reach of any
//! program, so there the real wipe is the vault's: the disks are sealed
//! under random keys that exist only in it, and once it's overwritten
//! nothing (not the password, not the keyfiles) can open them again. An old
//! copy of the vault left on the chip still needs the password and the
//! keyfiles, as the vault always did.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

const CHUNK: usize = 4 << 20;

/// The parts of the file that hold data: (start, end), holes left out (a
/// sparse disk's never-written space isn't written now either, which would
/// fill the drive for nothing).
fn data_ranges(f: &fs::File, len: u64) -> Vec<(u64, u64)> {
    let fd = f.as_raw_fd();
    let mut out = Vec::new();
    let mut at = 0u64;
    while at < len {
        // SAFETY: lseek only moves this descriptor's offset.
        let start = unsafe { libc::lseek(fd, at as libc::off_t, libc::SEEK_DATA) };
        if start < 0 {
            // ENXIO: no data after `at`. Anything else: no SEEK_DATA here, so all of it.
            if io::Error::last_os_error().raw_os_error() != Some(libc::ENXIO) && out.is_empty() && at == 0 {
                return vec![(0, len)];
            }
            break;
        }
        let end = unsafe { libc::lseek(fd, start, libc::SEEK_HOLE) };
        let end = if end < 0 { len as i64 } else { end };
        out.push((start as u64, (end as u64).min(len)));
        at = end as u64;
    }
    out
}

/// Overwrites what `path` holds with random bytes, syncs it and removes it.
/// `progress` is told how many bytes are done out of how many.
pub fn wipe_file(path: &Path, progress: &mut dyn FnMut(u64, u64)) -> io::Result<()> {
    let f = match OpenOptions::new().write(true).open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let len = f.metadata()?.len();
    let ranges = data_ranges(&f, len);
    let total: u64 = ranges.iter().map(|(a, b)| b - a).sum();
    let mut done = 0u64;
    let mut junk = vec![0u8; CHUNK];
    for (start, end) in ranges {
        let mut at = start;
        while at < end {
            let n = ((end - at) as usize).min(CHUNK);
            vaultkit::random_bytes(&mut junk[..n]).map_err(|_| io::Error::other("no random numbers"))?;
            f.write_all_at(&junk[..n], at)?;
            at += n as u64;
            done += n as u64;
            progress(done, total);
        }
    }
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)
}

/// Wipes every file in `dir` (not the folders in it), the vault first: once
/// it's gone the rest can't be opened even if the wipe is cut short.
pub fn wipe_dir(dir: &Path, first: &Path, progress: &mut dyn FnMut(u64, u64)) -> io::Result<()> {
    let mut files: Vec<_> = match fs::read_dir(dir) {
        Ok(rd) => rd.flatten().map(|e| e.path()).filter(|p| p.is_file() && p != first).collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    files.sort();
    wipe_file(first, &mut |_, _| {})?;
    let sizes: Vec<u64> = files.iter().map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0)).collect();
    let total: u64 = sizes.iter().sum::<u64>().max(1);
    let mut before = 0u64;
    for (p, size) in files.iter().zip(&sizes) {
        wipe_file(p, &mut |d, t| {
            let part = if t == 0 { 0 } else { (d as u128 * *size as u128 / t as u128) as u64 };
            progress(before + part, total)
        })?;
        before += size;
    }
    progress(total, total);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipes_data_and_leaves_nothing() {
        let mut r = [0u8; 8];
        vaultkit::random_bytes(&mut r).unwrap();
        let dir = std::env::temp_dir().join(format!("purrdroid-wipe-{}", r.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        fs::create_dir(&dir).unwrap();
        let vault = dir.join("purrdroid.vault");
        fs::write(&vault, vec![7u8; 1000]).unwrap();
        // Sparse: 64 MiB long, 8 KiB of it written.
        let disk = dir.join("android.disk");
        let f = fs::File::create(&disk).unwrap();
        f.set_len(64 << 20).unwrap();
        f.write_all_at(&[1u8; 8192], 32 << 20).unwrap();
        drop(f);
        // Only what was written is written over.
        let mut written = 0;
        wipe_file(&disk, &mut |_, total| written = total).unwrap();
        assert!(!disk.exists());
        assert!(written >= 8192 && written < 1 << 20, "wrote {written} bytes: holes were filled");
        fs::write(&disk, vec![1u8; 5000]).unwrap();
        let mut last = (0, 0);
        wipe_dir(&dir, &vault, &mut |d, t| last = (d, t)).unwrap();
        assert!(!vault.exists() && !disk.exists());
        assert_eq!(last.0, last.1);
        fs::remove_dir(&dir).unwrap();
    }
}
