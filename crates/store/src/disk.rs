//! An encrypted virtual disk: a file of 4 KiB sectors, each sealed on its
//! own with XChaCha20-Poly1305 under the disk's random 256-bit key.
//!
//! # Layout
//!
//! Block 0 holds the sealed header (the disk's size and a random id, so a
//! disk can't be passed off as another); the rest of that block is random.
//! After it come groups of 52 blocks: one block of seals, then the 51
//! sectors they belong to. Each sector has two seal slots (a nonce and a
//! tag, 40 bytes each) and is written like this:
//!
//! 1. the new seal goes into the slot that isn't the current one, its nonce
//!    marked one step newer (a marker that cycles 1, 2, 3: it never counts);
//! 2. then the sector itself is overwritten.
//!
//! A crash between the two leaves the newer slot not matching and the old
//! slot matching the old sector, which is what's read. A crash after both
//! leaves the new sector. Reading tries the newer slot first.
//!
//! Every seal covers the disk's id and the sector's number, so sectors
//! can't be swapped around or moved between disks without being noticed.
//!
//! # What it doesn't do
//!
//! * Rolling one sector back to an older copy of itself (with its old seal)
//!   isn't detected, as with LUKS. Nor is replacing the whole file.
//! * A sector never written is a hole of zeros, so the file shows how much
//!   of the disk has been used, and which parts (as LUKS does with
//!   discard on). `Disk::create(.., fill = true)` writes every sector once,
//!   so there are no holes; it takes as long as writing the whole disk.
//! * A second crash in the same sector, while it's being written again right
//!   after the first, can leave neither slot matching: that sector then
//!   reads as an error, not as old or new data.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::Path;

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// Bytes in a sector, as the virtual machine sees it.
pub const SECTOR: usize = 4096;
const NONCE: usize = 24;
const TAG: usize = 16;
const SLOT: usize = NONCE + TAG;
const PAIR: usize = 2 * SLOT;
/// Sectors whose seals share one block.
const PER_GROUP: u64 = (SECTOR / PAIR) as u64;
const GROUP_BLOCKS: u64 = PER_GROUP + 1;
const HEADER_AAD: &[u8] = b"purrdroid disk header v1";
const HEADER_PLAIN: usize = 8 + 16 + 24;

/// An open encrypted disk.
pub struct Disk {
    file: File,
    cipher: XChaCha20Poly1305,
    id: [u8; 16],
    sectors: u64,
    read_only: bool,
}

fn random(buf: &mut [u8]) -> io::Result<()> {
    vaultkit::random_bytes(buf).map_err(io::Error::from)
}

fn bad(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

/// Bytes a disk of `sectors` sectors takes on the disk, at most.
pub fn file_len(sectors: u64) -> u64 {
    let groups = sectors.div_ceil(PER_GROUP);
    (1 + groups * GROUP_BLOCKS) * SECTOR as u64
}

fn meta_offset(sector: u64) -> u64 {
    let (g, i) = (sector / PER_GROUP, sector % PER_GROUP);
    (1 + g * GROUP_BLOCKS) * SECTOR as u64 + i * PAIR as u64
}

fn data_offset(sector: u64) -> u64 {
    let (g, i) = (sector / PER_GROUP, sector % PER_GROUP);
    (1 + g * GROUP_BLOCKS + 1 + i) * SECTOR as u64
}

fn marker(slot: &[u8]) -> u8 {
    slot[0] & 3
}

fn is_empty(slot: &[u8]) -> bool {
    slot.iter().all(|&b| b == 0)
}

fn next_marker(m: u8) -> u8 {
    m % 3 + 1
}

/// Which slot of a pair is current (`None` if neither was ever written), and
/// which is the other one.
fn current_slot(pair: &[u8]) -> Option<(usize, usize)> {
    let (a, b) = (&pair[..SLOT], &pair[SLOT..]);
    match (is_empty(a), is_empty(b)) {
        (true, true) => None,
        (false, true) => Some((0, 1)),
        (true, false) => Some((1, 0)),
        (false, false) => {
            if marker(b) == next_marker(marker(a)) {
                Some((1, 0))
            } else {
                Some((0, 1))
            }
        }
    }
}

impl Disk {
    /// Makes a new disk of `sectors` sectors at `path`, which must not exist.
    /// The file is readable by its owner only. With `fill`, every sector is
    /// written once (as zeros), so the file has no holes.
    pub fn create(path: &Path, key: &[u8; 32], sectors: u64, fill: bool) -> io::Result<Disk> {
        if sectors == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a disk needs at least one sector"));
        }
        let file = OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(path)?;
        file.set_len(file_len(sectors))?;
        let mut id = [0u8; 16];
        random(&mut id)?;
        let mut plain = Zeroizing::new([0u8; HEADER_PLAIN]);
        plain[..8].copy_from_slice(&sectors.to_le_bytes());
        plain[8..24].copy_from_slice(&id);
        let sealed = vaultkit::seal(key, HEADER_AAD, &plain[..]).map_err(io::Error::from)?;
        let mut block = vec![0u8; SECTOR];
        random(&mut block)?;
        block[..sealed.len()].copy_from_slice(&sealed);
        file.write_all_at(&block, 0)?;
        let mut disk = Disk { file, cipher: XChaCha20Poly1305::new(key.into()), id, sectors, read_only: false };
        if fill {
            let zeros = vec![0u8; SECTOR * PER_GROUP as usize];
            let mut s = 0;
            while s < sectors {
                let n = (sectors - s).min(PER_GROUP);
                disk.write_sectors(s, &zeros[..n as usize * SECTOR])?;
                s += n;
            }
        }
        disk.file.sync_all()?;
        Ok(disk)
    }

    /// Opens the disk at `path` with its key. Fails, without saying which,
    /// when the key is wrong or the header was changed.
    pub fn open(path: &Path, key: &[u8; 32], read_only: bool) -> io::Result<Disk> {
        let file = OpenOptions::new().read(true).write(!read_only).open(path)?;
        let mut sealed = [0u8; NONCE + HEADER_PLAIN + TAG];
        file.read_exact_at(&mut sealed, 0)?;
        let plain = vaultkit::open(key, HEADER_AAD, &sealed).map_err(|_| bad("this disk doesn't belong to this vault, or it's damaged"))?;
        let sectors = u64::from_le_bytes(plain[..8].try_into().unwrap());
        let id: [u8; 16] = plain[8..24].try_into().unwrap();
        if file.metadata()?.len() < file_len(sectors) {
            return Err(bad("the disk file has been cut short"));
        }
        Ok(Disk { file, cipher: XChaCha20Poly1305::new(key.into()), id, sectors, read_only })
    }

    /// Size in bytes, as the virtual machine sees it.
    pub fn len(&self) -> u64 {
        self.sectors * SECTOR as u64
    }

    pub fn is_empty(&self) -> bool {
        self.sectors == 0
    }

    pub fn read_only(&self) -> bool {
        self.read_only
    }

    fn aad(&self, sector: u64) -> [u8; 24] {
        let mut aad = [0u8; 24];
        aad[..16].copy_from_slice(&self.id);
        aad[16..].copy_from_slice(&sector.to_le_bytes());
        aad
    }

    fn check_range(&self, offset: u64, len: usize) -> io::Result<()> {
        match offset.checked_add(len as u64) {
            Some(end) if end <= self.len() => Ok(()),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "beyond the end of the disk")),
        }
    }

    /// Reads whole sectors from `first` on (all in one group).
    fn read_group(&self, first: u64, buf: &mut [u8]) -> io::Result<()> {
        let n = buf.len() / SECTOR;
        let mut pairs = vec![0u8; n * PAIR];
        self.file.read_exact_at(&mut pairs, meta_offset(first))?;
        self.file.read_exact_at(buf, data_offset(first))?;
        for i in 0..n {
            let sector = first + i as u64;
            let pair = &pairs[i * PAIR..(i + 1) * PAIR];
            let out = &mut buf[i * SECTOR..(i + 1) * SECTOR];
            let Some((cur, old)) = current_slot(pair) else {
                out.fill(0);
                continue;
            };
            let aad = self.aad(sector);
            let mut tried = Zeroizing::new([0u8; SECTOR]);
            let mut ok = false;
            for slot in [cur, old] {
                let s = &pair[slot * SLOT..(slot + 1) * SLOT];
                if is_empty(s) {
                    continue;
                }
                tried.copy_from_slice(out);
                let (nonce, tag) = s.split_at(NONCE);
                if self.cipher.decrypt_in_place_detached(XNonce::from_slice(nonce), &aad, &mut tried[..], Tag::from_slice(tag)).is_ok() {
                    out.copy_from_slice(&tried[..]);
                    ok = true;
                    break;
                }
            }
            if !ok {
                return Err(bad(format!("sector {sector} doesn't match its seal: it was changed or damaged")));
            }
        }
        Ok(())
    }

    /// Writes whole sectors from `first` on (all in one group).
    fn write_sectors(&mut self, first: u64, data: &[u8]) -> io::Result<()> {
        let n = data.len() / SECTOR;
        let mut pairs = vec![0u8; n * PAIR];
        self.file.read_exact_at(&mut pairs, meta_offset(first))?;
        let mut out = data.to_vec();
        for i in 0..n {
            let pair = &mut pairs[i * PAIR..(i + 1) * PAIR];
            let (target, m) = match current_slot(pair) {
                None => (0, 1),
                Some((cur, old)) => (old, next_marker(marker(&pair[cur * SLOT..]))),
            };
            let mut nonce = [0u8; NONCE];
            random(&mut nonce)?;
            nonce[0] = (nonce[0] & !3) | m;
            let tag = self
                .cipher
                .encrypt_in_place_detached(XNonce::from_slice(&nonce), &self.aad(first + i as u64), &mut out[i * SECTOR..(i + 1) * SECTOR])
                .map_err(|_| bad("encryption failed"))?;
            let s = &mut pair[target * SLOT..(target + 1) * SLOT];
            s[..NONCE].copy_from_slice(&nonce);
            s[NONCE..].copy_from_slice(&tag);
        }
        // The seals first, then the sectors: see the module's notes.
        self.file.write_all_at(&pairs, meta_offset(first))?;
        self.file.write_all_at(&out, data_offset(first))?;
        Ok(())
    }

    /// Splits `[offset, offset+len)` into runs of whole sectors within one
    /// group, and the partial sectors at either end.
    fn runs(offset: u64, len: usize) -> Vec<(u64, usize, usize, usize)> {
        // (sector, start in sector, bytes, start in buffer)
        let mut out = Vec::new();
        let mut pos = 0usize;
        while pos < len {
            let at = offset + pos as u64;
            let sector = at / SECTOR as u64;
            let within = (at % SECTOR as u64) as usize;
            if within != 0 || len - pos < SECTOR {
                let n = (SECTOR - within).min(len - pos);
                out.push((sector, within, n, pos));
                pos += n;
            } else {
                let room = (PER_GROUP - sector % PER_GROUP) as usize;
                let whole = ((len - pos) / SECTOR).min(room);
                out.push((sector, 0, whole * SECTOR, pos));
                pos += whole * SECTOR;
            }
        }
        out
    }

    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.check_range(offset, buf.len())?;
        for (sector, within, n, pos) in Self::runs(offset, buf.len()) {
            if within == 0 && n % SECTOR == 0 {
                self.read_group(sector, &mut buf[pos..pos + n])?;
            } else {
                let mut tmp = Zeroizing::new([0u8; SECTOR]);
                self.read_group(sector, &mut tmp[..])?;
                buf[pos..pos + n].copy_from_slice(&tmp[within..within + n]);
            }
        }
        Ok(())
    }

    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "this disk is read-only"));
        }
        self.check_range(offset, data.len())?;
        for (sector, within, n, pos) in Self::runs(offset, data.len()) {
            if within == 0 && n % SECTOR == 0 {
                self.write_sectors(sector, &data[pos..pos + n])?;
            } else {
                let mut tmp = Zeroizing::new([0u8; SECTOR]);
                self.read_group(sector, &mut tmp[..])?;
                tmp[within..within + n].copy_from_slice(&data[pos..pos + n]);
                self.write_sectors(sector, &tmp[..])?;
            }
        }
        Ok(())
    }

    /// Forgets the contents of the whole sectors in the range: they read as
    /// zeros afterwards. Partial sectors at the ends are zeroed instead.
    pub fn discard(&mut self, offset: u64, len: usize) -> io::Result<()> {
        if self.read_only {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "this disk is read-only"));
        }
        self.check_range(offset, len)?;
        for (sector, within, n, _) in Self::runs(offset, len) {
            if within == 0 && n % SECTOR == 0 {
                let count = n / SECTOR;
                self.file.write_all_at(&vec![0u8; count * PAIR], meta_offset(sector))?;
            } else {
                self.write_at(sector * SECTOR as u64 + within as u64, &vec![0u8; n])?;
            }
        }
        Ok(())
    }

    pub fn flush(&self) -> io::Result<()> {
        if self.read_only {
            return Ok(());
        }
        self.file.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut r = [0u8; 8];
        random(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("purrdroid-test-{name}-{}", r.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        let _ = std::fs::remove_file(&p);
        p
    }

    fn pattern(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    #[test]
    fn round_trip_and_unaligned() {
        let p = tmp("rt");
        let key = [7u8; 32];
        let mut d = Disk::create(&p, &key, 200, false).unwrap();
        let mut buf = vec![1u8; 9000];
        d.read_at(1000, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0), "unwritten reads as zeros");

        let data = pattern(300_000, 3);
        d.write_at(4096 * 40 + 123, &data).unwrap();
        let mut back = vec![0u8; data.len()];
        d.read_at(4096 * 40 + 123, &mut back).unwrap();
        assert_eq!(back, data);
        // Overwrite part again, several times (both slots in use).
        for round in 0..5u8 {
            let more = pattern(10_000, round);
            d.write_at(4096 * 50 + 7, &more).unwrap();
            let mut b2 = vec![0u8; more.len()];
            d.read_at(4096 * 50 + 7, &mut b2).unwrap();
            assert_eq!(b2, more);
        }
        d.flush().unwrap();
        drop(d);

        let d = Disk::open(&p, &key, true).unwrap();
        assert_eq!(d.len(), 200 * 4096);
        let mut b3 = vec![0u8; 4096];
        d.read_at(4096 * 40 + 123, &mut b3).unwrap();
        assert_eq!(&b3[..], &data[..4096]);
        assert!(Disk::open(&p, &[8u8; 32], true).is_err(), "wrong key refused");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn crash_between_seal_and_sector_reads_old_data() {
        let p = tmp("crash");
        let key = [9u8; 32];
        let mut d = Disk::create(&p, &key, 60, false).unwrap();
        let old = pattern(SECTOR, 1);
        d.write_at(5 * 4096, &old).unwrap();
        // Simulate: the new seal reached the disk, the sector didn't.
        let saved = {
            let mut s = vec![0u8; SECTOR];
            d.file.read_exact_at(&mut s, data_offset(5)).unwrap();
            s
        };
        d.write_at(5 * 4096, &pattern(SECTOR, 2)).unwrap();
        d.file.write_all_at(&saved, data_offset(5)).unwrap();
        let mut back = vec![0u8; SECTOR];
        d.read_at(5 * 4096, &mut back).unwrap();
        assert_eq!(back, old);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn tampering_and_moving_sectors_detected() {
        let p = tmp("tamper");
        let key = [1u8; 32];
        let mut d = Disk::create(&p, &key, 60, false).unwrap();
        d.write_at(0, &pattern(SECTOR * 3, 5)).unwrap();
        // Copy sector 1's ciphertext and seals over sector 2's.
        let mut s = vec![0u8; SECTOR];
        d.file.read_exact_at(&mut s, data_offset(1)).unwrap();
        d.file.write_all_at(&s, data_offset(2)).unwrap();
        let mut m = vec![0u8; PAIR];
        d.file.read_exact_at(&mut m, meta_offset(1)).unwrap();
        d.file.write_all_at(&m, meta_offset(2)).unwrap();
        let mut back = vec![0u8; SECTOR];
        assert!(d.read_at(2 * 4096, &mut back).is_err());
        // A flipped bit.
        d.file.write_all_at(&[s[10] ^ 1], data_offset(0) + 10).unwrap();
        assert!(d.read_at(0, &mut back).is_err());
        d.read_at(4096, &mut back).unwrap();
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn discard_and_fill() {
        let p = tmp("fill");
        let key = [2u8; 32];
        let mut d = Disk::create(&p, &key, 120, true).unwrap();
        let mut back = vec![1u8; SECTOR * 2];
        d.read_at(4096 * 100, &mut back).unwrap();
        assert!(back.iter().all(|&b| b == 0));
        d.write_at(0, &pattern(SECTOR * 4, 9)).unwrap();
        d.discard(4096, 4096 * 2).unwrap();
        let mut all = vec![0u8; SECTOR * 4];
        d.read_at(0, &mut all).unwrap();
        assert_eq!(&all[..SECTOR], &pattern(SECTOR * 4, 9)[..SECTOR]);
        assert!(all[SECTOR..3 * SECTOR].iter().all(|&b| b == 0));
        let _ = std::fs::remove_file(&p);
    }
}
