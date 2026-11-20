//! Android's disk: one or more virtual disks inside one container from the
//! `deniable` crate (the same storage Enclave hides its vaults in). Without
//! the right key the container is random bytes all through; nothing in it
//! says how many disks it holds, where they are, or how full.
//!
//! Every new PurrDroid gets one of these, filled with random bytes when it's
//! made, with one disk in it, or two for a hidden Android. So a container
//! with one Android in it and one with two look the same, and so does the
//! vault slot that opens either: nothing there says whether there's a
//! second one.
//!
//! With two, the decoy disk is the lower volume and the real one is made
//! "above" it: opening the real one opens the decoy too, so the real
//! Android's writes never land on the decoy's blocks. Opening only the
//! decoy (its password, under pressure) shows one Android and nothing else;
//! but writing with only the decoy open can overwrite the real one's
//! blocks, which the decoy knows nothing about. Day to day, start the real
//! one.
//!
//! # Saving
//!
//! A save in `deniable` writes the volume's whole block map and two
//! superblocks, and adds cover writes. That's too much to do each time
//! Android asks for one (many times a second), so PurrDroid saves at most
//! every few seconds, and when Android stops. Each save is atomic: after a
//! power cut the disk is as it was at the last save, whole, as if the cut
//! had come a few seconds earlier; the last seconds of writes are lost.

use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

use deniable::{FileDevice, Kdf, Store, VolumeId, BLOCK};

use crate::dev::BlockDev;

pub type Container = Arc<Mutex<Store<FileDevice>>>;

/// Makes a container of `bytes` at `path` (which must not exist), every
/// block of it random (which takes as long as writing it all), with a disk
/// in it for each of `keys`, each made above the ones before it, each
/// `disk_len` bytes as Android sees it. They share the container's room.
/// `progress` is told how many bytes are written out of how many. On any
/// failure the file is removed.
pub fn create(path: &Path, bytes: u64, keys: &[&[u8; 32]], disk_len: u64, progress: &mut dyn FnMut(u64, u64)) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(path)?;
    let res = fill_and_make(f, path, bytes, keys, disk_len, progress);
    if res.is_err() {
        let _ = std::fs::remove_file(path);
    }
    res
}

fn fill_and_make(f: std::fs::File, path: &Path, bytes: u64, keys: &[&[u8; 32]], disk_len: u64, progress: &mut dyn FnMut(u64, u64)) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    let total = bytes / BLOCK as u64 * BLOCK as u64;
    // What `Store::format` does, with progress: every block random (the
    // first one's start is the container's salt), then opened as a container.
    let mut buf = vec![0u8; 4 << 20];
    let mut at = 0u64;
    while at < total {
        let n = ((total - at) as usize).min(buf.len());
        vaultkit::random_bytes(&mut buf[..n]).map_err(io::Error::from)?;
        f.write_all_at(&buf[..n], at)?;
        at += n as u64;
        progress(at, total);
    }
    f.sync_all()?;
    drop(f);
    let mut store = Store::open(FileDevice::open(path)?, Kdf::DEFAULT)?;
    let mut below = Vec::new();
    for key in keys {
        let id = store.create_key(key, &below)?;
        store.set_len(id, disk_len)?;
        below = vec![id];
    }
    store.flush()?;
    Ok(())
}

/// What Android may be given of a container this big: room for both disks'
/// maps and superblocks taken off, 90% of the rest.
pub fn disk_len_for(bytes: u64) -> u64 {
    let payload = (bytes / BLOCK as u64) * deniable::PAYLOAD as u64;
    (payload / 10 * 9) / 4096 * 4096
}

/// Opens the container and the disk `key` opens (with those below it).
pub fn open(path: &Path, key: &[u8; 32]) -> io::Result<(Container, VolumeId)> {
    let mut store = Store::open(FileDevice::open(path)?, Kdf::DEFAULT)?;
    let id = store.unlock_key(key).map_err(|e| match e {
        deniable::Error::NotFound => io::Error::other("the vault's key doesn't open any disk in the container"),
        other => other.into(),
    })?;
    Ok((Arc::new(Mutex::new(store)), id))
}

/// Every disk the container has open (the one opened, and those below it).
pub fn volumes(c: &Container) -> Vec<VolumeId> {
    c.lock().unwrap().volumes()
}

/// Saves every open disk of the container, if anything changed.
pub fn save(c: &Container) -> io::Result<()> {
    c.lock().unwrap().flush().map_err(Into::into)
}

/// One disk in a container, as the NBD server serves it.
pub struct Volume {
    pub container: Container,
    pub id: VolumeId,
    len: u64,
}

impl Volume {
    pub fn new(container: Container, id: VolumeId) -> io::Result<Volume> {
        let len = container.lock().unwrap().len(id)?;
        Ok(Volume { container, id, len })
    }
}

impl BlockDev for Volume {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_only(&self) -> bool {
        false
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if offset + buf.len() as u64 > self.len {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "beyond the end of the disk"));
        }
        let n = self.container.lock().unwrap().read(self.id, offset, buf)?;
        buf[n..].fill(0);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        if offset + data.len() as u64 > self.len {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "beyond the end of the disk"));
        }
        self.container.lock().unwrap().write(self.id, offset, data).map_err(|e| match e {
            deniable::Error::Full => io::Error::new(io::ErrorKind::StorageFull, "the container is full"),
            other => other.into(),
        })
    }

    /// Nothing: a block can't be given back without a save, and a trimmed
    /// block may read as anything.
    fn trim(&mut self, _offset: u64, _len: usize) -> io::Result<()> {
        Ok(())
    }

    fn write_zeroes(&mut self, offset: u64, len: usize) -> io::Result<()> {
        let zeros = vec![0u8; len.min(1 << 20)];
        let mut done = 0;
        while done < len {
            let n = (len - done).min(zeros.len());
            self.write_at(offset + done as u64, &zeros[..n])?;
            done += n;
        }
        Ok(())
    }

    /// Saves happen on a timer instead: see the module's notes.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoy_and_real() {
        let p = std::env::temp_dir().join(format!("pd-hidden-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let (dk, rk) = ([1u8; 32], [2u8; 32]);
        let bytes = 64 << 20;
        let len = disk_len_for(bytes);
        create(&p, bytes, &[&dk, &rk], len, &mut |_, _| {}).unwrap();

        // The real one, and what it writes.
        let (c, id) = open(&p, &rk).unwrap();
        let mut real = Volume::new(c.clone(), id).unwrap();
        assert_eq!(real.len(), len);
        real.write_at(4096 * 3 + 5, b"the real android").unwrap();
        save(&c).unwrap();
        drop((real, c));

        // The decoy alone sees its own disk only, and nothing of that.
        let (c, id) = open(&p, &dk).unwrap();
        let mut decoy = Volume::new(c.clone(), id).unwrap();
        let mut buf = vec![0u8; 16];
        decoy.read_at(4096 * 3 + 5, &mut buf).unwrap();
        assert_eq!(buf, vec![0u8; 16]);
        decoy.write_at(0, b"decoy").unwrap();
        save(&c).unwrap();
        drop((decoy, c));

        let (c, id) = open(&p, &rk).unwrap();
        let mut real = Volume::new(c, id).unwrap();
        real.read_at(4096 * 3 + 5, &mut buf).unwrap();
        assert_eq!(&buf, b"the real android");
        assert!(open(&p, &[3u8; 32]).is_err());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn one_disk_and_two_look_alike() {
        let dir = std::env::temp_dir();
        let (one, two) = (dir.join(format!("pd-one-{}", std::process::id())), dir.join(format!("pd-two-{}", std::process::id())));
        let _ = std::fs::remove_file(&one);
        let _ = std::fs::remove_file(&two);
        let bytes = 8 << 20;
        let len = disk_len_for(bytes);
        let mut last = (0, 0);
        create(&one, bytes, &[&[1u8; 32]], len, &mut |d, t| last = (d, t)).unwrap();
        assert_eq!(last, (bytes, bytes));
        create(&two, bytes, &[&[1u8; 32], &[2u8; 32]], len, &mut |_, _| {}).unwrap();
        // Same size, no holes, and the lower disk the same size in both.
        use std::os::unix::fs::MetadataExt;
        let (m1, m2) = (std::fs::metadata(&one).unwrap(), std::fs::metadata(&two).unwrap());
        assert_eq!(m1.len(), m2.len());
        assert!(m1.blocks() * 512 >= bytes && m2.blocks() * 512 >= bytes, "filled");
        for p in [&one, &two] {
            let (c, id) = open(p, &[1u8; 32]).unwrap();
            assert_eq!(Volume::new(c.clone(), id).unwrap().len(), len);
            assert_eq!(volumes(&c).len(), 1, "the lower key opens its own disk only");
        }
        let (c, _) = open(&two, &[2u8; 32]).unwrap();
        assert_eq!(volumes(&c).len(), 2);
        assert!(create(&one, bytes, &[&[3u8; 32]], len, &mut |_, _| {}).is_err(), "never over an existing file");
        assert!(one.exists());
        let _ = std::fs::remove_file(&one);
        let _ = std::fs::remove_file(&two);
    }
}
