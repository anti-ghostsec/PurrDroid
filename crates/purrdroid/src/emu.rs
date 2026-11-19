//! The emulator engine: Android system images made for Google's Android
//! Emulator (the SDK's `system-images/android-35/default/x86_64`, say),
//! which boot on its own board rather than on a PC's. Those are the images
//! with AOSP's test key and a userdebug build, which apps signed with that
//! key get their system permissions on.
//!
//! Google's emulator keeps an AVD as plain files, so PurrDroid never lets it
//! near the disk:
//!
//! * A throwaway AVD is made in memory (a private folder on a tmpfs:
//!   `$XDG_RUNTIME_DIR`, `/dev/shm` or `/tmp`, whichever has room), and every
//!   folder the emulator writes to (`HOME`, `ANDROID_*`, `TMPDIR`) points
//!   into it, so nothing lands in `~/.android`.
//! * Android's state from last time (its data, its file-encryption key image,
//!   the rest of the AVD) is decrypted from the encrypted store into it.
//! * When Android stops, the AVD is sealed back into the store (an encrypted
//!   disk under a fresh key; two files take turns, so a crash part-way keeps
//!   the last good one), and the folder in memory is removed.
//!
//! The emulator runs with its usage metrics off and no snapshots, no camera,
//! microphone or location, and PurrDroid's adb key is the one it trusts.
//!
//! What it costs: Android's data is in memory while it runs (a few GiB once
//! apps are in), and if PurrDroid is killed outright the session's changes
//! are lost (the state from the time before stays). The emulator's own
//! window is used, not PurrDroid's; it takes dropped APKs and files itself.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use purrdroid_store::disk::SECTOR;
use purrdroid_store::Disk;

/// The bytes at the start of a sealed state that list its files.
const INDEX: u64 = 1 << 20;

pub struct Config {
    pub sdk: PathBuf,
    /// Relative to the SDK, ending in '/'.
    pub image: String,
    pub ram_mb: u32,
    pub cpus: u32,
    pub width: u32,
    pub height: u32,
    pub density: u32,
    pub data_gb: u32,
    pub window: bool,
    /// The emulator's renderer: "host" (this PC's GPU) or "swiftshader_indirect".
    pub gpu: String,
    /// Where its control service listens (127.0.0.1).
    pub grpc_port: u16,
}

/// The folder in memory a session works in. Removed when dropped.
pub struct RamDir(pub PathBuf);

impl Drop for RamDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn free_bytes(dir: &Path) -> u64 {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else { return 0 };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return 0;
    }
    (st.f_bavail as u64).saturating_mul(st.f_frsize as u64)
}

fn mkdir_private(p: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(p)
}

/// Removes folders a session killed outright left behind (its data,
/// decrypted, would otherwise stay in memory until the PC is turned off).
pub fn clean_leftovers() {
    let uid = unsafe { libc::getuid() };
    for base in candidates() {
        let Ok(rd) = fs::read_dir(&base) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with(&format!("purrdroid-emu-{uid}-")) {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
}

fn candidates() -> Vec<PathBuf> {
    let mut c = Vec::new();
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        c.push(PathBuf::from(rt));
    }
    c.push("/dev/shm".into());
    c.push("/tmp".into());
    c
}

/// A private folder on a filesystem in memory with at least `need` bytes
/// free.
pub fn ram_dir(need: u64) -> io::Result<RamDir> {
    let uid = unsafe { libc::getuid() };
    for base in candidates() {
        if !crate::paths::in_memory(&base) || free_bytes(&base) < need {
            continue;
        }
        let mut r = [0u8; 8];
        vaultkit::random_bytes(&mut r).map_err(io::Error::from)?;
        let dir = base.join(format!("purrdroid-emu-{uid}-{}", r.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
        return Ok(RamDir(dir));
    }
    Err(io::Error::other(format!(
        "no filesystem in memory has {} GiB free for Android's data (tried $XDG_RUNTIME_DIR, /dev/shm and /tmp)",
        need.div_ceil(1 << 30)
    )))
}

pub fn avd_dir(ram: &Path) -> PathBuf {
    ram.join("avd/purrdroid.avd")
}

/// The locks a stopped emulator leaves, which would keep the next from starting.
pub fn clear_locks(ram: &Path) {
    if let Ok(dir) = fs::read_dir(avd_dir(ram)) {
        for e in dir.flatten() {
            if e.file_name().to_string_lossy().ends_with(".lock") {
                let p = e.path();
                let _ = if p.is_dir() { fs::remove_dir_all(&p) } else { fs::remove_file(&p) };
            }
        }
    }
}

/// Writes the AVD's description.
pub fn write_avd(ram: &Path, c: &Config) -> io::Result<()> {
    let avd = avd_dir(ram);
    mkdir_private(&avd)?;
    for d in ["home/.android", "home/.config", "tmp"] {
        mkdir_private(&ram.join(d))?;
    }
    let api = c.image.split('/').find(|p| p.starts_with("android-")).unwrap_or("android-35");
    fs::write(ram.join("avd/purrdroid.ini"), format!("avd.ini.encoding=UTF-8\npath={}\npath.rel=avd/purrdroid.avd\ntarget={api}\n", avd.display()))?;
    let config = format!(
        "avd.ini.encoding=UTF-8\nAvdId=purrdroid\navd.name=purrdroid\nPlayStore.enabled=no\nabi.type=x86_64\nhw.cpu.arch=x86_64\n\
         hw.cpu.ncore={cpus}\nhw.ramSize={ram}M\nimage.sysdir.1={image}\ntag.id=default\ntarget={api}\n\
         disk.dataPartition.size={data}G\nhw.lcd.width={w}\nhw.lcd.height={h}\nhw.lcd.density={d}\nhw.keyboard=yes\n\
         hw.gpu.enabled=yes\nhw.gpu.mode={gpu}\nhw.camera.back=none\nhw.camera.front=none\nhw.audioInput=no\nhw.audioOutput=yes\n\
         hw.gps=no\nhw.sdCard=no\nshowDeviceFrame=no\nfastboot.forceColdBoot=yes\nfastboot.forceFastBoot=no\n\
         firstboot.bootFromDownloadableSnapshot=no\nfirstboot.bootFromLocalSnapshot=no\nfirstboot.saveToLocalSnapshot=no\n",
        cpus = c.cpus,
        ram = c.ram_mb,
        image = c.image,
        data = c.data_gb,
        w = c.width,
        h = c.height,
        d = c.density,
        gpu = c.gpu
    );
    fs::write(avd.join("config.ini"), config)?;
    // Usage statistics: no, and never asked.
    fs::write(ram.join("home/.android/analytics.settings"), "{\"userId\":\"\",\"hasOptedIn\":false,\"debugDisablePublishing\":true}")?;
    Ok(())
}

/// Makes Android's data image for a first start, as the emulator would:
/// an empty ext4 filesystem the size of the data partition, in a qcow2 file
/// (which takes a few MiB). Left to the emulator, it first insists on 1.2
/// times the partition's size free in memory, as if none of it were sparse.
pub fn empty_data(ram: &Path, c: &Config) -> io::Result<()> {
    let tool = |names: &[&str]| names.iter().map(PathBuf::from).find(|p| p.exists());
    let mke2fs = tool(&["/usr/sbin/mke2fs", "/sbin/mke2fs"]).ok_or_else(|| io::Error::other("mke2fs isn't installed (e2fsprogs)"))?;
    let raw = ram.join("tmp/userdata.raw");
    let qcow = avd_dir(ram).join("userdata-qemu.img");
    let run = |cmd: &mut Command| -> io::Result<()> {
        let out = cmd.stdin(Stdio::null()).output()?;
        if out.status.success() {
            Ok(())
        } else {
            Err(io::Error::other(String::from_utf8_lossy(&out.stderr).trim().to_string()))
        }
    };
    run(Command::new(&mke2fs).args(["-q", "-F", "-t", "ext4", "-b", "4096", "-m", "0", "-L", "data"]).arg(&raw).arg(format!("{}G", c.data_gb)))?;
    let res = run(Command::new("qemu-img").args(["convert", "-q", "-f", "raw", "-O", "qcow2"]).arg(&raw).arg(&qcow));
    let _ = fs::remove_file(&raw);
    res
}

/// Puts PurrDroid's adb key where the emulator gives it to Android, so
/// Android trusts it from the first boot.
pub fn trust_key(ram: &Path, public: &str) -> io::Result<()> {
    for p in ["home/.android/adbkey.pub", "home/adbkey.pub"] {
        fs::write(ram.join(p), format!("{public}\n"))?;
    }
    Ok(())
}

pub fn command(ram: &Path, c: &Config, console: u16) -> Command {
    let mut q = Command::new(c.sdk.join("emulator/emulator"));
    q.args(["-avd", "purrdroid", "-no-snapshot", "-no-metrics", "-netfast", "-no-passive-gps"]);
    // Its own window stays shut: Android is shown in PurrDroid's, from
    // frames the emulator renders off-screen (on this PC's GPU with "host";
    // nothing goes through the screen gate, so nothing is grey).
    q.arg("-gpu").arg(&c.gpu);
    q.arg("-grpc").arg(c.grpc_port.to_string()).arg("-grpc-use-token");
    q.args(["-camera-back", "none", "-camera-front", "none"]);
    // No crash reports: its handler would send Google a dump of the
    // emulator's memory, which holds Android's decrypted data.
    q.args(["-crash-report-mode", "disabled"]);
    q.arg("-ports").arg(format!("{},{}", console, console + 1));
    q.arg("-memory").arg(c.ram_mb.to_string()).arg("-cores").arg(c.cpus.to_string());
    if !c.window {
        q.arg("-no-window");
    }
    // The emulator raises Android's memory to 2.5 GiB whatever it's asked
    // for, and Android fills it with cache that the PC never gets back. Its
    // QEMU takes the last size it's given, so this, last of all, is the size
    // asked for.
    q.arg("-qemu").arg("-m").arg(format!("{}M", c.ram_mb));

    let home = ram.join("home");
    q.env("ANDROID_SDK_ROOT", &c.sdk)
        .env("ANDROID_HOME", &c.sdk)
        .env("ANDROID_AVD_HOME", ram.join("avd"))
        .env("ANDROID_EMULATOR_HOME", home.join(".android"))
        .env("ANDROID_USER_HOME", home.join(".android"))
        .env("ANDROID_SDK_HOME", &home)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", ram.join("tmp"))
        .env("TMPDIR", ram.join("tmp"))
        .env("ANDROID_TMP", ram.join("tmp"))
        // Where it advertises its control service (with its token): in
        // PurrDroid's private folder, not the session's shared one.
        .env("XDG_RUNTIME_DIR", ram.join("tmp"))
        .env("ANDROID_EMU_ENABLE_CRASH_REPORTING", "0")
        // Where crash dumps would go, were any made: memory, gone at the end.
        .env("ANDROID_EMU_CRASH_REPORTING_DATABASE", ram.join("tmp/no-crash-reports"));
    // The emulator says a lot; it goes to a log in memory, for when it fails.
    q.stdin(Stdio::null());
    if let Ok(log) = OpenOptions::new().create(true).append(true).mode(0o600).open(ram.join("tmp/emulator.log")) {
        if let Ok(log2) = log.try_clone() {
            q.stdout(log).stderr(log2);
        }
    }
    unsafe {
        q.pre_exec(|| {
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
    q
}

pub fn start(ram: &Path, c: &Config, console: u16) -> io::Result<Child> {
    let exe = c.sdk.join("emulator/emulator");
    if !exe.exists() {
        return Err(io::Error::other(format!("there's no emulator at {} (install it with the SDK's sdkmanager \"emulator\")", exe.display())));
    }
    if !c.sdk.join(&c.image).join("system.img").exists() {
        return Err(io::Error::other(format!("there's no system image at {}", c.sdk.join(&c.image).display())));
    }
    command(ram, c, console).spawn()
}

/// A free pair of ports for the console and adb (the emulator wants an even
/// console port from 5554 up, with adb on the next one).
/// The emulator's last lines, for saying why it stopped.
pub fn log_tail(ram: &Path) -> String {
    let text = fs::read_to_string(ram.join("tmp/emulator.log")).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| l.contains("FATAL") || l.contains("ERROR")).collect();
    lines[lines.len().saturating_sub(4)..].join("\n")
}

/// The control service's token, which the emulator makes itself and writes
/// in its discovery file (in the session's folder in memory).
pub fn grpc_token(ram: &Path) -> Option<String> {
    let dir = ram.join("tmp/avd/running");
    for e in fs::read_dir(dir).ok()?.flatten() {
        let text = fs::read_to_string(e.path()).ok()?;
        if let Some(t) = text.lines().find_map(|l| l.strip_prefix("grpc.token=")) {
            return Some(t.trim().to_string());
        }
    }
    None
}

pub fn free_ports() -> io::Result<u16> {
    for p in (5554..5682).step_by(2) {
        let ok = std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() && std::net::TcpListener::bind(("127.0.0.1", p + 1)).is_ok();
        if ok {
            return Ok(p);
        }
    }
    Err(io::Error::other("no free emulator ports between 5554 and 5682"))
}

// ---- Sealed state ----
//
// An encrypted disk (crate::store's format): the first MiB lists the files,
// as `size<TAB>offset<TAB>path` lines; each file follows at a 4 KiB boundary.
// Blocks of zeros aren't written (an unwritten sector reads as zeros), so the
// sparse data image stays small.

fn walk(dir: &Path, base: &Path, out: &mut Vec<(PathBuf, u64)>) -> io::Result<()> {
    for e in fs::read_dir(dir)? {
        let e = e?;
        let t = e.file_type()?;
        let p = e.path();
        if t.is_dir() {
            walk(&p, base, out)?;
        } else if t.is_file() {
            let name = e.file_name();
            let n = name.to_string_lossy();
            if n.ends_with(".lock") || n == "hardware-qemu.ini.lock" {
                continue;
            }
            out.push((p.strip_prefix(base).unwrap().to_path_buf(), e.metadata()?.len()));
        }
    }
    Ok(())
}

/// Seals everything in `dir` into a new encrypted disk at `path` under
/// `key`.
pub fn seal(dir: &Path, path: &Path, key: &[u8; 32]) -> io::Result<()> {
    let mut files = Vec::new();
    walk(dir, dir, &mut files)?;
    let mut index = String::from("purrdroid-emu-state=1\n");
    let mut at = INDEX;
    for (p, len) in &files {
        index.push_str(&format!("{len}\t{at}\t{}\n", p.display()));
        at += len.div_ceil(SECTOR as u64) * SECTOR as u64;
    }
    if index.len() as u64 >= INDEX {
        return Err(io::Error::other("too many files in the AVD"));
    }
    let _ = fs::remove_file(path);
    let mut disk = Disk::create(path, key, at.div_ceil(SECTOR as u64).max(1), false)?;
    disk.write_at(0, index.as_bytes())?;
    let mut buf = vec![0u8; 1 << 20];
    let mut at = INDEX;
    for (p, len) in &files {
        let mut f = File::open(dir.join(p))?;
        let mut done = 0u64;
        while done < *len {
            let want = ((*len - done) as usize).min(buf.len());
            f.read_exact(&mut buf[..want])?;
            // Whole sectors of zeros stay holes.
            let mut s = 0;
            while s < want {
                let e = (s + SECTOR).min(want);
                if buf[s..e].iter().any(|&b| b != 0) {
                    disk.write_at(at + done + s as u64, &buf[s..e])?;
                }
                s = e;
            }
            done += want as u64;
        }
        at += len.div_ceil(SECTOR as u64) * SECTOR as u64;
    }
    disk.flush()
}

/// Bytes the state at `path` will take once unsealed (its files' sizes).
pub fn sealed_size(path: &Path, key: &[u8; 32]) -> io::Result<u64> {
    Ok(read_index(&Disk::open(path, key, true)?)?.iter().map(|(len, _, _)| len).sum())
}

fn read_index(disk: &Disk) -> io::Result<Vec<(u64, u64, PathBuf)>> {
    let mut raw = vec![0u8; INDEX.min(disk.len()) as usize];
    disk.read_at(0, &mut raw)?;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    let text = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = text.lines();
    if lines.next() != Some("purrdroid-emu-state=1") {
        return Err(io::Error::other("the emulator's saved state is damaged"));
    }
    let mut out = Vec::new();
    for l in lines {
        let mut parts = l.splitn(3, '\t');
        let (Some(len), Some(at), Some(p)) = (parts.next(), parts.next(), parts.next()) else { continue };
        let p = PathBuf::from(p);
        if p.is_absolute() || p.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            return Err(io::Error::other("the emulator's saved state is damaged"));
        }
        out.push((len.parse().map_err(io::Error::other)?, at.parse().map_err(io::Error::other)?, p));
    }
    Ok(out)
}

/// Unseals the state at `path` into `dir`.
pub fn unseal(path: &Path, key: &[u8; 32], dir: &Path) -> io::Result<()> {
    let disk = Disk::open(path, key, true)?;
    let mut buf = vec![0u8; 1 << 20];
    for (len, at, p) in read_index(&disk)? {
        let target = dir.join(&p);
        if let Some(parent) = target.parent() {
            mkdir_private(parent)?;
        }
        let mut f = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&target)?;
        f.set_len(len)?;
        let mut done = 0u64;
        while done < len {
            let want = ((len - done) as usize).min(buf.len());
            disk.read_at(at + done, &mut buf[..want])?;
            if buf[..want].iter().any(|&b| b != 0) {
                use std::os::unix::fs::FileExt;
                f.write_all_at(&buf[..want], done)?;
            }
            done += want as u64;
        }
        f.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_and_unseal_a_folder() {
        let base = std::env::temp_dir().join(format!("pd-emu-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let (src, dst) = (base.join("src"), base.join("dst"));
        fs::create_dir_all(src.join("data/misc")).unwrap();
        fs::write(src.join("config.ini"), b"hw.ramSize=2048M\n").unwrap();
        fs::write(src.join("data/misc/x"), vec![7u8; 10_000]).unwrap();
        // A big sparse file with a little data in the middle.
        let f = File::create(src.join("userdata-qemu.img")).unwrap();
        f.set_len(64 << 20).unwrap();
        use std::os::unix::fs::FileExt;
        f.write_all_at(b"android data", 30 << 20).unwrap();
        fs::write(src.join("multiinstance.lock"), b"").unwrap();

        let sealed = base.join("state.disk");
        let key = [5u8; 32];
        seal(&src, &sealed, &key).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert!(fs::metadata(&sealed).unwrap().blocks() * 512 < 4 << 20, "zeros stay holes");
        assert_eq!(sealed_size(&sealed, &key).unwrap(), 17 + 10_000 + (64 << 20));
        unseal(&sealed, &key, &dst).unwrap();
        assert_eq!(fs::read(dst.join("config.ini")).unwrap(), b"hw.ramSize=2048M\n");
        assert_eq!(fs::read(dst.join("data/misc/x")).unwrap(), vec![7u8; 10_000]);
        let img = fs::read(dst.join("userdata-qemu.img")).unwrap();
        assert_eq!(img.len(), 64 << 20);
        assert_eq!(&img[30 << 20..(30 << 20) + 12], b"android data");
        assert!(!dst.join("multiinstance.lock").exists());
        assert!(unseal(&sealed, &[6u8; 32], &base.join("x")).is_err());
        let _ = fs::remove_dir_all(&base);
    }
}
