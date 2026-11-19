//! PurrDroid's storage. These files, and nothing else, are ever written:
//!
//! * [`vault`]: one small file sealed with the password and any keyfiles
//!   (Argon2id, then XChaCha20-Poly1305). It holds the random keys of the
//!   disks, the key Android's debugging bridge knows PurrDroid by, and the
//!   settings, in one of four slots (one per Android: see [`hidden`]).
//! * [`disk`]: the virtual disks Android runs on (and the imported ISO),
//!   every 4 KiB sector sealed on its own with XChaCha20-Poly1305 under a
//!   random 256-bit key that only the vault holds.
//! * [`hidden`]: instead of a plain disk, a container from the `deniable`
//!   crate holding a decoy Android's disk and, hidden above it, the real
//!   one's.
//!
//! None of them has a magic number, a version or anything else in the clear:
//! without the password the vault is random bytes, and without the vault a
//! disk is random bytes too (and, until it's filled, holes of zeros).
//!
//! # Against a quantum computer
//!
//! Nothing here uses public-key cryptography, which is what a quantum
//! computer breaks (Shor). What's left is a symmetric cipher with 256-bit
//! keys and a password hash, where the best known quantum attack (Grover)
//! only halves the key's strength: 256 bits still leave 128, out of reach.
//! The password is the weak point, quantum or not: Argon2id makes each guess
//! cost 192 MiB and about a second, and keyfiles add 512 bits nobody can
//! guess.

pub mod dev;
pub mod disk;
pub mod hidden;
pub mod keyfile;
pub mod vault;
pub mod wipe;

pub use dev::BlockDev;
pub use disk::Disk;
pub use vault::{Settings, Vault};

/// Turns on the protections a process holding keys should have: no core
/// dumps, and no other program of the same user may read its memory
/// (ptrace). Linux only; elsewhere it does nothing.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &none);
    }
}

/// Keeps `len` bytes at `ptr` out of swap, as far as the memory-lock limit
/// allows. Failing is not an error: FerroOS has no disk swap at all.
pub fn lock_memory(ptr: *const u8, len: usize) {
    #[cfg(unix)]
    unsafe {
        libc::mlock(ptr as *const libc::c_void, len);
    }
}
