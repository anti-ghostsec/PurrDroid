//! The vault: the one file sealed with the password (and keyfiles). It holds
//! the disks' keys and PurrDroid's settings, as `name=value` lines.
//!
//! # Layout
//!
//! `salt (32) | duress check (32) | 4 slots`, each slot
//! `nonce (24) | sealed settings (8 KiB) | tag (16)`. The password and the
//! keyfiles go through Argon2id once (the keyfiles as its secret input,
//! see [`crate::keyfile`]); the key that comes out is tried on every slot.
//! Slots nobody uses are random bytes, as is the duress check when there's
//! no duress password: there's no magic number, and nothing shows how many
//! slots are in use. So with a hidden Android set up, the decoy password
//! opens its slot and nothing in the file shows that another slot opens
//! with another password.
//!
//! Each slot is sealed with the salt and its own number as associated data,
//! so slots can't be swapped around or the salt changed without that
//! failing like a wrong password.
//!
//! # Saving
//!
//! The vault is always the same size, so it's rewritten in place, never
//! replaced by a new file: a new file would leave the old one's blocks
//! behind, free but readable, and an old copy opens with an old password
//! (one changed away from, or after the duress password was used). To
//! survive a crash part-way, the new contents go first to a file beside it
//! (`purrdroid.vault.new`), synced; then the vault is overwritten and
//! synced; then that file is written over with random bytes, synced and
//! removed. If PurrDroid finds it at the next unlock it finishes the job
//! (or drops it, if the vault was already written). Nothing is written when
//! nothing changed. On a copy-on-write filesystem (btrfs, ZFS) or an SSD,
//! overwriting may still leave old copies where no program can reach them.
//!
//! # Duress password
//!
//! A password (with keyfiles or not) that, given instead of a real one,
//! destroys the vault: the file is overwritten with random bytes and
//! removed, and the answer is "wrong password" as for any other. Without the
//! vault's keys every disk is random bytes. Telling a duress password from a
//! wrong one costs the same single Argon2id run, so it takes no longer.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::Blake2bMac;
use zeroize::Zeroizing;

use crate::keyfile::Secret;

const SALT: usize = 32;
const CHECK: usize = 32;
const HEAD: usize = SALT + CHECK;
/// Slots in every vault, used or not.
pub const SLOTS: usize = 4;
const BODY: usize = 8192;
const SLOT_LEN: usize = 24 + BODY + 16;
const FILE_LEN: usize = HEAD + SLOTS * SLOT_LEN;

/// The vault's Argon2id cost: 192 MiB, 3 passes, about a second per guess.
pub const KDF_MEMORY_KIB: u32 = 192 * 1024;
pub const KDF_PASSES: u32 = 3;

#[derive(Debug)]
pub enum Error {
    /// Wrong password or keyfiles, or the file was changed. Also what a
    /// duress password gets.
    WrongPassword,
    /// The vault already exists (on create) or doesn't (on unlock).
    Exists,
    Missing,
    /// That password (with those keyfiles) is already another one's: the
    /// duress password, or another slot's.
    SamePassword,
    /// The settings don't fit in a slot.
    TooBig,
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::WrongPassword => f.write_str("wrong password or keyfiles"),
            Error::Exists => f.write_str("there's already a vault there"),
            Error::Missing => f.write_str("there's no vault there yet (run `purrdroid init`)"),
            Error::SamePassword => f.write_str("that password (with those keyfiles) is already used for something else"),
            Error::TooBig => f.write_str("the settings are too big for the vault"),
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<vaultkit::Error> for Error {
    fn from(e: vaultkit::Error) -> Self {
        match e {
            vaultkit::Error::Decrypt => Error::WrongPassword,
            other => Error::Io(other.into()),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// What a slot holds, decrypted. Every value is wiped when dropped.
#[derive(Default)]
pub struct Settings {
    entries: BTreeMap<String, Zeroizing<String>>,
}

impl Settings {
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|v| v.as_str())
    }

    pub fn set(&mut self, name: &str, value: &str) {
        assert!(!name.contains(['=', '\n', '\0']) && !value.contains(['\n', '\0']), "settings are single lines");
        self.entries.insert(name.to_string(), Zeroizing::new(value.to_string()));
    }

    pub fn remove(&mut self, name: &str) {
        self.entries.remove(name);
    }

    /// A 256-bit key kept under `name`, in hex.
    pub fn key(&self, name: &str) -> Option<Zeroizing<[u8; 32]>> {
        let hex = self.get(name)?;
        let mut key = Zeroizing::new([0u8; 32]);
        if hex.len() != 64 {
            return None;
        }
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(key)
    }

    /// Keeps `key` under `name`.
    pub fn set_key(&mut self, name: &str, key: &[u8; 32]) {
        let hex = Zeroizing::new(key.iter().map(|b| format!("{b:02x}")).collect::<String>());
        self.set(name, &hex);
    }

    /// Makes a fresh random key, keeps it under `name` and returns it.
    pub fn new_key(&mut self, name: &str) -> Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0u8; 32]);
        vaultkit::random_bytes(&mut key[..])?;
        self.set_key(name, &key);
        Ok(key)
    }

    fn serialize(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(b"purrdroid-vault=2\n");
        for (k, v) in &self.entries {
            out.extend_from_slice(k.as_bytes());
            out.push(b'=');
            out.extend_from_slice(v.as_bytes());
            out.push(b'\n');
        }
        out.push(0);
        if out.len() > BODY {
            return Err(Error::TooBig);
        }
        out.resize(BODY, 0);
        Ok(out)
    }

    fn parse(bytes: &[u8]) -> Result<Settings> {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let text = std::str::from_utf8(&bytes[..end]).map_err(|_| Error::WrongPassword)?;
        let mut lines = text.lines();
        if lines.next() != Some("purrdroid-vault=2") {
            return Err(Error::WrongPassword);
        }
        let mut s = Settings::default();
        for line in lines {
            if let Some((k, v)) = line.split_once('=') {
                s.entries.insert(k.to_string(), Zeroizing::new(v.to_string()));
            }
        }
        Ok(s)
    }
}

/// An unlocked slot of the vault.
pub struct Vault {
    path: PathBuf,
    salt: [u8; SALT],
    slot: usize,
    key: Zeroizing<[u8; 32]>,
    pub settings: Settings,
    /// The settings as last saved (or read), to save only when they change.
    saved: Zeroizing<Vec<u8>>,
}

fn duress_check(key: &[u8; 32]) -> [u8; CHECK] {
    let mut mac = <Blake2bMac<U32> as Mac>::new_from_slice(key).expect("32-byte key");
    mac.update(b"purrdroid duress check");
    mac.finalize().into_bytes().into()
}

/// Argon2id of the password, with the keyfiles' secret as its secret input.
pub fn derive(password: &[u8], keyfiles: Option<&Secret>, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_PASSES, 1, Some(32)).map_err(|e| Error::Io(io::Error::other(e.to_string())))?;
    let secret: &[u8] = keyfiles.map(|s| &s[..]).unwrap_or(&[]);
    let argon =
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params).map_err(|e| Error::Io(io::Error::other(e.to_string())))?;
    let mut key = Zeroizing::new([0u8; 32]);
    argon.hash_password_into(password, salt, &mut key[..]).map_err(|e| Error::Io(io::Error::other(e.to_string())))?;
    Ok(key)
}

fn slot_aad(salt: &[u8], slot: usize) -> Vec<u8> {
    let mut aad = salt.to_vec();
    aad.extend_from_slice(b"purrdroid vault slot");
    aad.push(slot as u8);
    aad
}

fn slot_range(slot: usize) -> std::ops::Range<usize> {
    HEAD + slot * SLOT_LEN..HEAD + (slot + 1) * SLOT_LEN
}

fn try_open(bytes: &[u8], salt: &[u8], key: &[u8; 32], slot: usize) -> Option<Zeroizing<Vec<u8>>> {
    vaultkit::open(key, &slot_aad(salt, slot), &bytes[slot_range(slot)]).ok()
}

/// Overwrites the file with random bytes, flushes it and removes it.
fn scrub_file(path: &Path) {
    if let Ok(f) = fs::OpenOptions::new().write(true).custom_flags(libc::O_NOFOLLOW).open(path) {
        let len = f.metadata().map(|m| m.len()).unwrap_or(0) as usize;
        let mut junk = vec![0u8; len.max(FILE_LEN)];
        let _ = vaultkit::random_bytes(&mut junk);
        let _ = f.write_all_at(&junk, 0);
        let _ = f.sync_all();
    }
    let _ = fs::remove_file(path);
}

/// The vault, and the new contents waiting beside it while it's being
/// rewritten (see "Saving" above), both written over and removed.
fn destroy_file(path: &Path) {
    scrub_file(path);
    scrub_file(&pending_path(path));
}

/// Where the new contents wait while the vault is rewritten.
fn pending_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".new");
    path.with_file_name(name)
}

fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    fs::File::open(dir)?.sync_all()
}

/// Writes `bytes` over the start of the file at `path` and syncs it,
/// making it (owner only) if `create`; never through a link.
fn write_synced(path: &Path, bytes: &[u8], create: bool) -> io::Result<()> {
    let mut o = fs::OpenOptions::new();
    o.write(true).custom_flags(libc::O_NOFOLLOW).mode(0o600);
    if create {
        o.create(true);
    }
    let f = o.open(path)?;
    if f.metadata()?.len() > bytes.len() as u64 {
        f.set_len(bytes.len() as u64)?;
    }
    f.write_all_at(bytes, 0)?;
    f.sync_all()
}

/// Saves the whole vault in place, crash-safe (see "Saving" above).
fn write_vault(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let pending = pending_path(path);
    write_synced(&pending, bytes, true)?;
    sync_dir(path)?;
    write_synced(path, bytes, false)?;
    scrub_file(&pending);
    sync_dir(path)
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) if b.len() == FILE_LEN => Ok(Zeroizing::new(b)),
        Ok(_) => Err(Error::WrongPassword),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::Missing),
        Err(e) => Err(e.into()),
    }
}

impl Vault {
    /// Makes a new vault at `path`: every slot random but one, which this
    /// password and these keyfiles open.
    pub fn create(path: &Path, password: &[u8], keyfiles: Option<&Secret>) -> Result<Vault> {
        if path.exists() {
            return Err(Error::Exists);
        }
        let mut bytes = Zeroizing::new(vec![0u8; FILE_LEN]);
        vaultkit::random_bytes(&mut bytes)?;
        let salt: [u8; SALT] = bytes[..SALT].try_into().unwrap();
        let key = derive(password, keyfiles, &salt)?;
        let mut r = [0u8; 1];
        vaultkit::random_bytes(&mut r)?;
        let mut v = Vault {
            path: path.to_path_buf(),
            salt,
            slot: r[0] as usize % SLOTS,
            key,
            settings: Settings::default(),
            saved: Zeroizing::new(Vec::new()),
        };
        v.write_slot(&mut bytes)?;
        // A new file, never one that's there (or a link).
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        write_synced(path, &bytes, false)?;
        sync_dir(path)?;
        v.saved = v.settings.serialize()?;
        Ok(v)
    }

    /// Opens the slot this password and these keyfiles open. A duress
    /// password destroys the vault, and gets [`Error::WrongPassword`] like
    /// any wrong one.
    pub fn unlock(path: &Path, password: &[u8], keyfiles: Option<&Secret>) -> Result<Vault> {
        let bytes = read_file(path)?;
        let pending = pending_path(path);
        let salt: [u8; SALT] = bytes[..SALT].try_into().unwrap();
        let key = derive(password, keyfiles, &salt)?;
        // A save cut short: the new contents were written and synced beside
        // the vault before the vault itself was touched, and are removed
        // only once it's whole, so when they're there they are the newest.
        // They come first: a half-written vault can still open this slot
        // with the old contents when the slot is in the half not yet
        // rewritten, and the save would be lost.
        if let Ok(new) = read_file(&pending) {
            let new_salt: [u8; SALT] = new[..SALT].try_into().unwrap();
            let new_key = if new_salt == salt { key.clone() } else { derive(password, keyfiles, &new_salt)? };
            if let Some(v) = Self::open_slot(path, &new, new_key)? {
                write_vault(path, &new)?;
                return Ok(v);
            }
        }
        if let Some(v) = Self::open_slot(path, &bytes, key.clone())? {
            // Whatever waited beside it (cut short while being written, or
            // while being wiped) isn't needed.
            if pending.exists() {
                scrub_file(&pending);
            }
            return Ok(v);
        }
        if constant_eq(&duress_check(&key), &bytes[SALT..HEAD]) {
            destroy_file(path);
            return Err(Error::WrongPassword);
        }
        Err(Error::WrongPassword)
    }

    /// The slot of `bytes` that `key` opens, if any.
    fn open_slot(path: &Path, bytes: &[u8], key: Zeroizing<[u8; 32]>) -> Result<Option<Vault>> {
        let salt: [u8; SALT] = bytes[..SALT].try_into().unwrap();
        for slot in 0..SLOTS {
            if let Some(plain) = try_open(bytes, &salt, &key, slot) {
                let settings = Settings::parse(&plain)?;
                let saved = settings.serialize()?;
                return Ok(Some(Vault { path: path.to_path_buf(), salt, slot, key, settings, saved }));
            }
        }
        Ok(None)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn write_slot(&self, bytes: &mut [u8]) -> Result<()> {
        let sealed = vaultkit::seal(&self.key, &slot_aad(&self.salt, self.slot), &self.settings.serialize()?)?;
        bytes[slot_range(self.slot)].copy_from_slice(&sealed);
        Ok(())
    }

    /// Seals the settings back into this slot, leaving the other slots as
    /// they are (a crash leaves the old vault or the new one), if they've
    /// changed since they were read or last saved.
    pub fn save(&mut self) -> Result<()> {
        if self.settings.serialize()?[..] == self.saved[..] {
            return Ok(());
        }
        self.save_now()
    }

    fn save_now(&mut self) -> Result<()> {
        let mut bytes = read_file(&self.path)?;
        self.write_slot(&mut bytes)?;
        write_vault(&self.path, &bytes)?;
        self.saved = self.settings.serialize()?;
        Ok(())
    }

    /// True if `key` opens a slot other than this one, or is the duress
    /// password's.
    fn taken(&self, bytes: &[u8], key: &[u8; 32]) -> bool {
        (0..SLOTS).any(|s| s != self.slot && try_open(bytes, &self.salt, key, s).is_some()) || constant_eq(&duress_check(key), &bytes[SALT..HEAD])
    }

    /// Changes this slot's password and keyfiles.
    pub fn set_password(&mut self, password: &[u8], keyfiles: Option<&Secret>) -> Result<()> {
        let bytes = read_file(&self.path)?;
        let key = derive(password, keyfiles, &self.salt)?;
        if self.taken(&bytes, &key) {
            return Err(Error::SamePassword);
        }
        self.key = key;
        self.save_now()
    }

    /// Fills another slot, for a second Android opened by another password
    /// (and keyfiles). Only safe while it's known which slots are in use:
    /// right after [`Vault::create`], when the only one is this.
    pub fn add_slot(&self, password: &[u8], keyfiles: Option<&Secret>) -> Result<Vault> {
        let mut bytes = read_file(&self.path)?;
        let key = derive(password, keyfiles, &self.salt)?;
        if constant_eq(&key[..], &self.key[..]) || self.taken(&bytes, &key) {
            return Err(Error::SamePassword);
        }
        let mut r = [0u8; 1];
        vaultkit::random_bytes(&mut r)?;
        let free: Vec<usize> = (0..SLOTS).filter(|&s| s != self.slot).collect();
        let slot = free[r[0] as usize % free.len()];
        let mut v = Vault { path: self.path.clone(), salt: self.salt, slot, key, settings: Settings::default(), saved: Zeroizing::new(Vec::new()) };
        v.write_slot(&mut bytes)?;
        write_vault(&self.path, &bytes)?;
        v.saved = v.settings.serialize()?;
        Ok(v)
    }

    /// Sets the duress password (and keyfiles), or with `None` forgets it
    /// (the check goes back to random bytes).
    pub fn set_duress(&mut self, duress: Option<(&[u8], Option<&Secret>)>) -> Result<()> {
        let mut bytes = read_file(&self.path)?;
        let check = match duress {
            Some((pw, kf)) => {
                let key = derive(pw, kf, &self.salt)?;
                if constant_eq(&key[..], &self.key[..]) || (0..SLOTS).any(|s| try_open(&bytes, &self.salt, &key, s).is_some()) {
                    return Err(Error::SamePassword);
                }
                duress_check(&key)
            }
            None => {
                let mut c = [0u8; CHECK];
                vaultkit::random_bytes(&mut c)?;
                c
            }
        };
        bytes[SALT..HEAD].copy_from_slice(&check);
        self.write_slot(&mut bytes)?;
        write_vault(&self.path, &bytes)?;
        self.saved = self.settings.serialize()?;
        Ok(())
    }

    /// Destroys the whole vault on purpose (every slot).
    pub fn destroy(self) {
        destroy_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut r = [0u8; 8];
        vaultkit::random_bytes(&mut r).unwrap();
        std::env::temp_dir().join(format!("purrdroid-vault-{name}-{}", r.iter().map(|b| format!("{b:02x}")).collect::<String>()))
    }

    fn kf(b: u8) -> Secret {
        Zeroizing::new([b; 64])
    }

    #[test]
    fn create_unlock_change_duress() {
        let p = tmp("v");
        let mut v = Vault::create(&p, b"correct horse", None).unwrap();
        let k = v.settings.new_key("data_key").unwrap();
        v.settings.set("net", "tor");
        v.save().unwrap();
        assert_eq!(fs::read(&p).unwrap().len(), FILE_LEN);
        drop(v);

        assert!(matches!(Vault::unlock(&p, b"wrong", None), Err(Error::WrongPassword)));
        let mut v = Vault::unlock(&p, b"correct horse", None).unwrap();
        assert_eq!(v.settings.get("net"), Some("tor"));
        assert_eq!(*v.settings.key("data_key").unwrap(), *k);

        v.set_password(b"battery staple", None).unwrap();
        assert!(matches!(v.set_duress(Some((b"battery staple", None))), Err(Error::SamePassword)));
        v.set_duress(Some((b"panic", None))).unwrap();
        drop(v);
        assert!(Vault::unlock(&p, b"correct horse", None).is_err());
        assert!(Vault::unlock(&p, b"battery staple", None).is_ok());

        assert!(matches!(Vault::unlock(&p, b"panic", None), Err(Error::WrongPassword)));
        assert!(!p.exists(), "duress destroyed the vault");
    }

    #[test]
    fn saved_in_place_and_only_when_changed() {
        use std::os::unix::fs::MetadataExt;
        let p = tmp("inplace");
        let mut v = Vault::create(&p, b"pw", None).unwrap();
        let ino = fs::metadata(&p).unwrap().ino();
        v.settings.set("a", "1");
        v.save().unwrap();
        assert_eq!(fs::metadata(&p).unwrap().ino(), ino, "the same file, rewritten");
        let before = fs::read(&p).unwrap();
        v.save().unwrap();
        assert_eq!(fs::read(&p).unwrap(), before, "nothing changed, nothing written");
        v.set_password(b"pw2", None).unwrap();
        assert_ne!(fs::read(&p).unwrap(), before, "a new password is written even with the same settings");
        assert_eq!(fs::metadata(&p).unwrap().ino(), ino);
        assert!(!pending_path(&p).exists());
        drop(v);

        // Cut short with the new contents beside it and the vault not yet
        // written, or written only up to some point: the new password opens
        // it, and the save is finished, wherever this password's slot is
        // (in the part already rewritten or not).
        let mut v = Vault::unlock(&p, b"pw2", None).unwrap();
        let old = fs::read(&p).unwrap();
        v.settings.set("b", "2");
        v.save().unwrap();
        let new = fs::read(&p).unwrap();
        drop(v);
        for cut in [0, HEAD + SLOT_LEN, HEAD + 2 * SLOT_LEN, HEAD + 3 * SLOT_LEN, FILE_LEN - 1] {
            fs::write(pending_path(&p), &new).unwrap();
            let mut torn = old.clone();
            torn[..cut].copy_from_slice(&new[..cut]);
            let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
            f.write_all_at(&torn, 0).unwrap();
            drop(f);
            let v = Vault::unlock(&p, b"pw2", None).unwrap();
            assert_eq!(v.settings.get("b"), Some("2"), "cut at {cut}");
            assert_eq!(fs::read(&p).unwrap(), new);
            assert!(!pending_path(&p).exists(), "finished and wiped");
        }
        // Cut short after the vault was written: what's beside it is the
        // same, and is dropped.
        fs::write(pending_path(&p), &new).unwrap();
        assert_eq!(Vault::unlock(&p, b"pw2", None).unwrap().settings.get("b"), Some("2"));
        assert!(!pending_path(&p).exists());
        // Cut short while what's beside it was being wiped: it no longer
        // opens, and the vault is used.
        let mut half_wiped = new.clone();
        half_wiped[..FILE_LEN - 1].fill(0x5a);
        fs::write(pending_path(&p), &half_wiped).unwrap();
        assert_eq!(Vault::unlock(&p, b"pw2", None).unwrap().settings.get("b"), Some("2"));
        assert!(!pending_path(&p).exists());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn keyfiles_are_needed() {
        let p = tmp("kf");
        let mut v = Vault::create(&p, b"pw", Some(&kf(1))).unwrap();
        v.settings.set("x", "1");
        v.save().unwrap();
        assert!(Vault::unlock(&p, b"pw", None).is_err(), "password alone");
        assert!(Vault::unlock(&p, b"pw", Some(&kf(2))).is_err(), "wrong keyfile");
        assert!(Vault::unlock(&p, b"other", Some(&kf(1))).is_err(), "keyfile alone");
        let mut v = Vault::unlock(&p, b"pw", Some(&kf(1))).unwrap();
        // Dropping the keyfile is a password change too.
        v.set_password(b"pw", None).unwrap();
        assert!(Vault::unlock(&p, b"pw", None).is_ok());
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn two_slots_unseen_by_each_other() {
        let p = tmp("slots");
        let mut decoy = Vault::create(&p, b"decoy", None).unwrap();
        decoy.settings.set("who", "decoy");
        decoy.save().unwrap();
        let mut real = decoy.add_slot(b"real", Some(&kf(7))).unwrap();
        real.settings.set("who", "real");
        real.save().unwrap();
        assert_ne!(decoy.slot, real.slot);
        assert!(matches!(decoy.add_slot(b"real", Some(&kf(7))), Err(Error::SamePassword)));
        // Each saves without disturbing the other.
        decoy.settings.set("more", "x");
        decoy.save().unwrap();
        drop((decoy, real));
        assert_eq!(Vault::unlock(&p, b"decoy", None).unwrap().settings.get("who"), Some("decoy"));
        let mut real = Vault::unlock(&p, b"real", Some(&kf(7))).unwrap();
        assert_eq!(real.settings.get("who"), Some("real"));
        // A duress password can't be a slot's password.
        assert!(matches!(real.set_duress(Some((b"decoy", None))), Err(Error::SamePassword)));
        real.set_duress(Some((b"panic", Some(&kf(9))))).unwrap();
        assert!(Vault::unlock(&p, b"decoy", None).is_ok(), "setting duress kept the decoy's slot");
        assert!(Vault::unlock(&p, b"panic", Some(&kf(9))).is_err());
        assert!(!p.exists());
    }
}
