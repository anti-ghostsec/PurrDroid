//! PurrDroid: Android apps on FerroOS, in a virtual machine.
//!
//!   purrdroid init [--size GiB] [--fill]   make the vault and Android's disk
//!   purrdroid init --hidden [--size GiB]   the same, with a decoy Android and,
//!                                          hidden behind it, the real one
//!   purrdroid init --emulator [--sdk PATH] [--image system-images/...]
//!                                          use an Android Emulator system image
//!                                          from the SDK instead (kept encrypted)
//!   purrdroid import FILE.iso [--remove]   copy an Android-x86 ISO in (encrypted)
//!   purrdroid install                      start from the ISO, to install Android
//!   purrdroid [run]                        start Android
//!       --net off|direct|tor   --ram MB   --cpus N   --screen WxH
//!       --no-gpu   --no-sound              (remembered in the vault)
//!       --no-window                        no window (Ctrl+C shuts Android down)
//!   purrdroid send FILE... | --text TEXT | --url URL
//!                                          send to the running Android
//!   purrdroid apk FILE.apk...              install APKs on the running Android
//!   purrdroid shell COMMAND                run a command in its shell (as adb shell)
//!   purrdroid passwd [--new-keyfile PATH]...
//!                                          change the password and keyfiles
//!   purrdroid duress [--duress-keyfile PATH]... | --off
//!                                          set (or forget) a duress password
//!   purrdroid keyfile PATH                 make a new keyfile of random bytes
//!   purrdroid destroy                      wipe everything (no password needed)
//!   purrdroid status                       what's there, and whether it's running
//!
//!   --keyfile PATH (any number, with any command): files or folders whose
//!   contents are needed as well as the password. With `init` they're the
//!   new vault's (with `init --hidden`, the real Android's; the decoy's are
//!   given with --decoy-keyfile). In the password box they can also be
//!   dropped on it.
//!   --password-stdin (with any command) reads the password from a line on
//!   stdin, for scripts.

mod bridge;
mod emu;
mod emugrpc;
mod gui;
mod panel;
mod paths;
mod tor;
mod viewer;
mod vm;
mod xdnd;

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use purrdroid_store::keyfile::{self, Secret};
use purrdroid_store::{hidden, Disk, Vault};
use zeroize::Zeroizing;

use bridge::Net;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn interactive() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

/// Says something went wrong: on the terminal, or in a message box when
/// started from the Start menu.
static GUI: AtomicBool = AtomicBool::new(false);

fn fail(msg: &str) {
    eprintln!("purrdroid: {msg}");
    // A box when there's no terminal to read it in; never for scripts.
    let scripted = PASSWORD_STDIN.load(Ordering::Relaxed);
    if (GUI.load(Ordering::Relaxed) || !interactive()) && !scripted && std::env::var_os("DISPLAY").is_some() {
        let _ = gui::message("PurrDroid", msg);
    }
}

/// Reads a line from the terminal without showing it.
fn read_hidden(prompt: &str) -> io::Result<Zeroizing<String>> {
    let tty = fs::OpenOptions::new().read(true).write(true).open("/dev/tty")?;
    let fd = tty.as_raw_fd();
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut old) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut quiet = old;
    quiet.c_lflag &= !libc::ECHO;
    quiet.c_lflag |= libc::ECHONL;
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    (&tty).write_all(prompt.as_bytes())?;
    let mut line = Zeroizing::new(Vec::new());
    let mut b = [0u8; 1];
    let res = loop {
        match (&tty).read(&mut b) {
            Ok(0) => break Ok(()),
            Ok(_) if b[0] == b'\n' => break Ok(()),
            Ok(_) => line.push(b[0]),
            Err(e) => break Err(e),
        }
    };
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
    res?;
    Ok(Zeroizing::new(String::from_utf8_lossy(&line).into_owned()))
}

static PASSWORD_STDIN: AtomicBool = AtomicBool::new(false);
/// The password box offers "Reset PurrDroid" (unlocking from the Start menu).
static OFFER_RESET: AtomicBool = AtomicBool::new(false);
/// What `ask` says when the person chose Reset and everything was wiped.
const WIPED: &str = "wiped";
pub(crate) static STOP: AtomicBool = AtomicBool::new(false);
/// Android was shut down because the PC was nearly out of memory.
static LOW_MEMORY: AtomicBool = AtomicBool::new(false);

/// Memory the PC could still hand out, in MiB (what's free plus caches it
/// can drop).
fn mem_available_mb() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| l.strip_prefix("MemAvailable:").and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok()))
        })
        .map_or(u64::MAX, |kb| kb / 1024)
}

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

/// Every `--NAME PATH` given, in order.
fn flag_paths(args: &[String], name: &str) -> Vec<PathBuf> {
    args.windows(2).filter(|w| w[0] == name).map(|w| PathBuf::from(&w[1])).collect()
}

/// Asks for a password. In the password box, keyfiles can be dropped too:
/// they come back with it, added to `keyfiles`.
fn ask(prompt: &str, keyfiles: &mut Vec<PathBuf>) -> Res<Zeroizing<String>> {
    if PASSWORD_STDIN.load(Ordering::Relaxed) {
        let mut line = Zeroizing::new(String::new());
        if io::stdin().read_line(&mut line)? == 0 {
            return Err("--password-stdin: no password on stdin".into());
        }
        let trimmed = Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string());
        return Ok(trimmed);
    }
    if interactive() && !GUI.load(Ordering::Relaxed) {
        Ok(read_hidden(&format!("{prompt}: "))?)
    } else {
        match gui::ask_password("PurrDroid", prompt, keyfiles, OFFER_RESET.load(Ordering::Relaxed))? {
            gui::Answer::Ok(pw, dropped) => {
                keyfiles.extend(dropped);
                Ok(pw)
            }
            gui::Answer::Cancel => Err("cancelled".into()),
            gui::Answer::Reset => {
                gui::working("PurrDroid", "Wiping PurrDroid: writing over everything...", |p| wipe_all(p).map_err(|e| e.to_string()))??;
                gui::message("PurrDroid", "PurrDroid is wiped: nothing of it is left.\nYou can set up a new one now.")?;
                Err(WIPED.into())
            }
        }
    }
}

/// The secret of these keyfiles, saying how many there were.
fn secret_of(keyfiles: &[PathBuf]) -> Res<Option<Secret>> {
    let s = keyfile::secret(keyfiles)?;
    if s.is_some() {
        eprintln!("purrdroid: using {} keyfile(s)", keyfile::expand(keyfiles)?.len());
    }
    Ok(s)
}

/// A new password, twice, and the keyfiles to go with it (those given,
/// plus any dropped on the box).
fn ask_new(what: &str, mut keyfiles: Vec<PathBuf>) -> Res<(Zeroizing<String>, Option<Secret>)> {
    loop {
        let a = ask(&format!("New {what}"), &mut keyfiles)?;
        // A script gives it once (and can't be asked again: it would read
        // nothing, and around it would go).
        if PASSWORD_STDIN.load(Ordering::Relaxed) {
            if a.chars().count() < 8 && keyfiles.is_empty() {
                return Err(format!("the {what} needs at least 8 characters, or a keyfile as well").into());
            }
            return Ok((a, secret_of(&keyfiles)?));
        }
        if a.chars().count() < 8 && keyfiles.is_empty() {
            eprintln!("Use at least 8 characters (a few words is best), or a keyfile as well.");
            continue;
        }
        let b = ask(&format!("The {what} again"), &mut keyfiles)?;
        if *a == *b {
            return Ok((a, secret_of(&keyfiles)?));
        }
        eprintln!("Those didn't match; once more.");
    }
}

fn unlock(args: &[String]) -> Res<Vault> {
    let f = paths::files()?;
    if !f.vault.exists() {
        return Err("there's no PurrDroid here yet: run `purrdroid init` in a terminal first".into());
    }
    let mut keyfiles = flag_paths(args, "--keyfile");
    let pw = ask("PurrDroid password", &mut keyfiles)?;
    let secret = secret_of(&keyfiles)?;
    eprintln!("purrdroid: unlocking (this takes a second on purpose)...");
    Ok(Vault::unlock(&f.vault, pw.as_bytes(), secret.as_ref())?)
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

// ---- init / import ----

/// What every Android's slot gets: its own identity and adb key.
fn new_android(v: &mut Vault) -> Res<()> {
    let (mac, serial, uuid) = vm::random_identity()?;
    v.settings.set("mac", &mac);
    v.settings.set("serial", &serial);
    v.settings.set("uuid", &uuid);
    v.settings.set("net", "direct");
    let adb = purrdroid_adb::Key::generate()?;
    v.settings.set("adb_key", &hex(&adb.to_der()));
    Ok(())
}

fn cmd_init(args: &[String]) -> Res<()> {
    let f = paths::files()?;
    if f.vault.exists() || f.android.exists() {
        return Err(format!("there's already a PurrDroid in {} (see `purrdroid destroy`)", f.vault.parent().unwrap().display()).into());
    }
    let hidden_mode = args.iter().any(|a| a == "--hidden");
    let gib: u64 =
        flag_value(args, "--size").map(|s| s.trim_end_matches(['G', 'g']).parse()).transpose()?.unwrap_or(if hidden_mode { 64 } else { 32 });
    if !(8..=1024).contains(&gib) {
        return Err("--size is in GiB, from 8 to 1024".into());
    }
    let fill = args.iter().any(|a| a == "--fill");
    println!("PurrDroid keeps Android's disk encrypted with a password and any keyfiles");
    println!("(Argon2id, XChaCha20-Poly1305). There's no way back in without them:");
    println!("write the password down somewhere safe, and keep copies of keyfiles.");

    if args.iter().any(|a| a == "--emulator") {
        let sdk = find_sdk(args)?;
        let image = flag_value(args, "--image").map(|i| if i.ends_with('/') { i } else { i + "/" }).unwrap_or_else(|| DEFAULT_IMAGE.to_string());
        let build = fs::read_to_string(sdk.join(&image).join("build.prop"))
            .map_err(|_| format!("there's no system image at {}", sdk.join(&image).display()))?;
        let prop = |k: &str| build.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).unwrap_or("?").to_string();
        println!(
            "Emulator engine: {} (Android {}, {}, {})",
            sdk.join(&image).display(),
            prop("ro.build.version.release"),
            prop("ro.build.type"),
            prop("ro.build.tags")
        );
        let (pw, secret) = ask_new("password", flag_paths(args, "--keyfile"))?;
        let mut v = Vault::create(&f.vault, pw.as_bytes(), secret.as_ref())?;
        v.settings.set("engine", "emulator");
        v.settings.set("sdk", &sdk.display().to_string());
        v.settings.set("image", &image);
        new_android(&mut v)?;
        v.save()?;
        println!("Ready: `purrdroid` starts it (the first start makes Android's data, a minute or two).");
        return Ok(());
    }

    if !hidden_mode {
        let (pw, secret) = ask_new("password", flag_paths(args, "--keyfile"))?;
        let mut v = Vault::create(&f.vault, pw.as_bytes(), secret.as_ref())?;
        let key = v.settings.new_key("android_key")?;
        v.settings.set("disk", "plain");
        new_android(&mut v)?;
        v.save()?;
        let sectors = gib * (1 << 30) / purrdroid_store::disk::SECTOR as u64;
        if fill {
            println!("Writing all {gib} GiB once, so the disk has no holes...");
        }
        Disk::create(&f.android, &key, sectors, fill)?;
        println!("Made a {gib} GiB disk for Android ({}).", f.android.display());
        println!("Next: `purrdroid import android.iso`, then `purrdroid install`.");
        return Ok(());
    }

    println!();
    println!("Hidden mode: two Androids in one container. The DECOY password opens an");
    println!("ordinary-looking Android you can show; the REAL one opens the other, and");
    println!("nothing shows that it exists. Use the real one day to day: while only the");
    println!("decoy is open, it can overwrite the real one's data without knowing.");
    println!();
    let (decoy_pw, decoy_secret) = ask_new("DECOY password", flag_paths(args, "--decoy-keyfile"))?;
    let (real_pw, real_secret) = ask_new("REAL password", flag_paths(args, "--keyfile"))?;
    let mut decoy = Vault::create(&f.vault, decoy_pw.as_bytes(), decoy_secret.as_ref())?;
    let mut real = match decoy.add_slot(real_pw.as_bytes(), real_secret.as_ref()) {
        Ok(r) => r,
        Err(e) => {
            decoy.destroy();
            return Err(e.into());
        }
    };
    let bytes = gib << 30;
    let disk_len = hidden::disk_len_for(bytes);
    for v in [&mut decoy, &mut real] {
        v.settings.new_key("android_key")?;
        v.settings.set("disk", "hidden");
        new_android(v)?;
    }
    println!("Filling {gib} GiB with random bytes (this takes a few minutes)...");
    hidden::create(&f.android, bytes, &decoy.settings.key("android_key").unwrap(), &real.settings.key("android_key").unwrap(), disk_len)?;
    decoy.save()?;
    real.save()?;
    println!("Made the container ({}): each Android sees a {} GiB disk, and they share", f.android.display(), disk_len >> 30);
    println!("the room. Install each one: `purrdroid import android.iso` and");
    println!("`purrdroid install`, once with the decoy password and once with the real one.");
    Ok(())
}

fn hex(b: &[u8]) -> Zeroizing<String> {
    Zeroizing::new(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn unhex(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(s.get(i..i + 2)?, 16).ok()?);
    }
    Some(out)
}

fn cmd_import(args: &[String]) -> Res<()> {
    let iso = args.iter().find(|a| !a.starts_with("--")).ok_or("which ISO? `purrdroid import FILE.iso`")?;
    let iso = PathBuf::from(iso);
    let src = File::open(&iso)?;
    let len = src.metadata()?.len();
    if len < 1 << 20 {
        return Err("that's too small to be an Android ISO".into());
    }
    drop(src);
    let mut v = unlock(args)?;
    let f = paths::files()?;
    let start = Instant::now();
    let progress = std::sync::atomic::AtomicU64::new(0);
    std::thread::scope(|s| -> Res<()> {
        let job = s.spawn(|| import_iso(&mut v, &iso, &progress).map_err(|e| e.to_string()));
        while !job.is_finished() {
            print!("\rEncrypting the ISO: {}%   ", progress.load(Ordering::Relaxed) * 100 / len);
            io::stdout().flush()?;
            thread::sleep(Duration::from_millis(250));
        }
        job.join().map_err(|_| "the import stopped")??;
        Ok(())
    })?;
    println!("\rEncrypted the ISO in {:.0} s ({}).          ", start.elapsed().as_secs_f64(), f.media.display());
    if args.iter().any(|a| a == "--remove") {
        overwrite_and_remove(&iso)?;
        println!("Overwrote and removed {}.", iso.display());
    } else {
        println!("The original is still at {}; `purrdroid import` with --remove overwrites it.", iso.display());
    }
    println!("Next: `purrdroid install` and pick Installation in the ISO's boot menu.");
    Ok(())
}

/// Encrypts the ISO at `iso` into the store, as this slot's install media,
/// counting the bytes done into `progress`.
fn import_iso(v: &mut Vault, iso: &Path, progress: &std::sync::atomic::AtomicU64) -> Res<()> {
    let mut src = File::open(iso)?;
    let len = src.metadata()?.len();
    if len < 1 << 20 {
        return Err("that's too small to be an Android ISO".into());
    }
    let f = paths::files()?;
    if f.media.exists() {
        fs::remove_file(&f.media)?;
    }
    let key = v.settings.new_key("media_key")?;
    let sectors = len.div_ceil(purrdroid_store::disk::SECTOR as u64);
    let mut disk = Disk::create(&f.media, &key, sectors, false)?;
    let mut buf = vec![0u8; 4 << 20];
    let mut done = 0u64;
    while done < len {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        disk.write_at(done, &buf[..n])?;
        done += n as u64;
        progress.store(done, Ordering::Relaxed);
    }
    disk.flush()?;
    v.settings.set("media_len", &len.to_string());
    v.save()?;
    Ok(())
}

/// Overwrites a file with random bytes, then removes it. (On an SSD the
/// drive may keep old copies the system can't reach; it's still better
/// than leaving it as it was.)
fn overwrite_and_remove(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    let f = fs::OpenOptions::new().write(true).open(path)?;
    let len = f.metadata()?.len();
    let mut junk = vec![0u8; 1 << 20];
    let mut at = 0;
    while at < len {
        vaultkit::random_bytes(&mut junk).map_err(io::Error::from)?;
        let n = (len - at).min(junk.len() as u64) as usize;
        f.write_all_at(&junk[..n], at)?;
        at += n as u64;
    }
    f.sync_all()?;
    drop(f);
    fs::remove_file(path)
}

// ---- run ----

fn setting_u32(v: &mut Vault, args: &[String], flag: &str, name: &str, default: u32, range: std::ops::RangeInclusive<u32>) -> Res<u32> {
    if let Some(s) = flag_value(args, flag) {
        let n: u32 = s.parse().map_err(|_| format!("{flag} needs a number"))?;
        if !range.contains(&n) {
            return Err(format!("{flag} must be from {} to {}", range.start(), range.end()).into());
        }
        v.settings.set(name, &n.to_string());
    }
    Ok(v.settings.get(name).and_then(|s| s.parse().ok()).unwrap_or(default))
}

/// Only one PurrDroid at a time: held while it runs.
fn take_lock() -> Res<File> {
    let rt = paths::runtime_dir()?;
    let lock = File::create(rt.join("lock"))?;
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("PurrDroid is already running".into());
    }
    Ok(lock)
}

fn cmd_run(args: &[String], install: bool) -> Res<()> {
    purrdroid_store::harden_process();
    let _lock = take_lock()?;
    let mut v = unlock(args)?;
    run_unlocked(args, &mut v, install)
}

fn run_unlocked(args: &[String], v: &mut Vault, install: bool) -> Res<()> {
    let rt = paths::runtime_dir()?;
    let files = paths::files()?;

    let cpus_here = thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(2);
    let ram = setting_u32(v, args, "--ram", "ram_mb", 3072, 1536..=65536)?;
    let cpus = setting_u32(v, args, "--cpus", "cpus", cpus_here.clamp(1, 4), 1..=cpus_here.max(1))?;
    if let Some(s) = flag_value(args, "--net") {
        Net::parse(&s).ok_or("--net is off, direct or tor")?;
        v.settings.set("net", &s);
    }
    if let Some(s) = flag_value(args, "--screen") {
        let (w, h) = s.split_once('x').ok_or("--screen is WIDTHxHEIGHT, like 1280x800")?;
        let (w, h): (u32, u32) = (w.parse()?, h.parse()?);
        if !(480..=3840).contains(&w) || !(480..=3840).contains(&h) {
            return Err("--screen is from 480x480 to 3840x3840".into());
        }
        v.settings.set("screen", &format!("{w}x{h}"));
    }
    if args.iter().any(|a| a == "--no-gpu") {
        v.settings.set("gpu", "off");
    }
    if args.iter().any(|a| a == "--gpu") {
        v.settings.set("gpu", "on");
    }
    if args.iter().any(|a| a == "--no-sound") {
        v.settings.set("sound", "off");
    }
    if args.iter().any(|a| a == "--sound") {
        v.settings.set("sound", "on");
    }
    v.save()?;
    let net = v.settings.get("net").and_then(Net::parse).unwrap_or(Net::Direct);
    let (width, height) =
        v.settings.get("screen").and_then(|s| s.split_once('x')).and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?))).unwrap_or((1280, 800));

    if v.settings.get("engine") == Some("emulator") {
        if install {
            return Err("there's nothing to install with the emulator engine: its Android comes ready-made in the SDK's system image".into());
        }
        return run_emulator(args, v, &files, ram, cpus, net);
    }

    // The disks, served to QEMU from memory.
    let android_key = v.settings.key("android_key").ok_or("the vault has no key for Android's disk")?;
    let mut exports: HashMap<String, purrdroid_nbd::Export> = HashMap::new();
    let mut container = None;
    if v.settings.get("disk") == Some("hidden") {
        let (c, id) = hidden::open(&files.android, &android_key)?;
        exports.insert("android".to_string(), Arc::new(Mutex::new(hidden::Volume::new(c.clone(), id)?)));
        // Saved every few seconds, and at the end (see hidden.rs).
        let saver = c.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(5));
            if let Err(e) = hidden::save(&saver) {
                eprintln!("purrdroid: couldn't save the container: {e}");
            }
        });
        container = Some(c);
    } else {
        exports.insert("android".to_string(), Arc::new(Mutex::new(Disk::open(&files.android, &android_key, false)?)));
    }
    if install {
        let key = v.settings.key("media_key").ok_or("no ISO for this password yet: `purrdroid import FILE.iso` first")?;
        let media =
            Disk::open(&files.media, &key, true).map_err(|_| "the ISO was imported with the other password: import it again with this one")?;
        exports.insert("media".to_string(), Arc::new(Mutex::new(media)));
        // An installer has run on this disk: from now on it may hold Android.
        if v.settings.get("install_ran") != Some("yes") {
            v.settings.set("install_ran", "yes");
            v.save()?;
        }
    }
    drop(android_key);
    let socks = vm::sockets(&rt);
    let _ = fs::remove_file(&socks.disk);
    let listener = UnixListener::bind(&socks.disk)?;
    let exports = Arc::new(exports);
    {
        let exports = exports.clone();
        thread::spawn(move || purrdroid_nbd::serve(listener, exports));
    }

    let tor = if net == Net::Tor { Some(tor::start(&rt)?) } else { None };
    let adb_key = purrdroid_adb::Key::from_der(&unhex(v.settings.get("adb_key").ok_or("the vault has no adb key")?).ok_or("bad adb key")?)?;
    let mut cfg = vm::Config {
        ram_mb: ram,
        cpus,
        width,
        height,
        gpu: v.settings.get("gpu") != Some("off"),
        sound: v.settings.get("sound") != Some("off"),
        net,
        adb_port: vm::free_port()?,
        install,
        mac: v.settings.get("mac").unwrap_or("02:00:00:00:00:01").to_string(),
        serial: v.settings.get("serial").unwrap_or("0").to_string(),
        uuid: v.settings.get("uuid").unwrap_or("00000000-0000-4000-8000-000000000000").to_string(),
        rt: rt.clone(),
        exe: std::env::current_exe()?,
        tor_socks: tor.as_ref().map(|t| t.socks.clone()),
    };

    eprintln!("purrdroid: starting Android ({} MiB, {} CPUs, network {})...", cfg.ram_mb, cfg.cpus, net.name());
    let child = Arc::new(Mutex::new(vm::start(&mut cfg)?));
    let vm_done = Arc::new(AtomicBool::new(false));
    let (wake_r, wake_w) = UnixStream::pair()?;
    wake_w.set_nonblocking(true)?;
    let waker = {
        let w = Arc::new(wake_w);
        move || {
            let _ = (&*w).write(&[1]);
        }
    };
    {
        let (child, done, waker) = (child.clone(), vm_done.clone(), waker.clone());
        thread::spawn(move || loop {
            if !matches!(child.lock().unwrap().try_wait(), Ok(None)) {
                done.store(true, Ordering::Relaxed);
                waker();
                return;
            }
            thread::sleep(Duration::from_millis(200));
        });
    }

    let mut screen = None;
    for _ in 0..100 {
        if let Ok(s) = UnixStream::connect(&socks.screen) {
            screen = Some(s);
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let screen = screen.ok_or("QEMU's screen never came up")?;
    let windowless = args.iter().any(|a| a == "--no-window");
    let outbox = rt.join("outbox");
    let (notes_tx, notes_rx) = mpsc::channel();
    let bridge_tx = bridge::start(cfg.adb_port, adb_key, net, outbox.clone(), notes_tx, waker.clone());
    bridge::serve_control(rt.join("control.sock"), bridge_tx.clone())?;

    let end = if windowless {
        // No window: until Android stops or Ctrl+C (or a TERM) asks it to.
        drop(screen);
        unsafe {
            libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
            libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
            libc::signal(libc::SIGHUP, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        }
        eprintln!("purrdroid: running without a window; Ctrl+C shuts Android down.");
        loop {
            if vm_done.load(Ordering::Relaxed) {
                break viewer::End::Stopped;
            }
            if STOP.load(Ordering::Relaxed) {
                break viewer::End::Closed;
            }
            for n in notes_rx.try_iter() {
                if let bridge::Note::Status(s) = n {
                    eprintln!("purrdroid: {s}");
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
    } else {
        let (frame, reader, input) = purrdroid_rfb::connect(screen)?;
        {
            let (frame, waker) = (frame.clone(), waker.clone());
            thread::spawn(move || {
                let _ = reader.run(frame, waker);
            });
        }
        let title = if install { "PurrDroid (installing)" } else { "PurrDroid" };
        viewer::Viewer {
            frame,
            input: Box::new(input),
            android_pointer: true,
            net,
            wake: wake_r,
            notes: notes_rx,
            bridge: bridge_tx.clone(),
            vm_done: vm_done.clone(),
            title: title.into(),
            width,
            height,
        }
        .run()?
    };

    if let viewer::End::Closed = end {
        eprintln!("purrdroid: shutting Android down...");
        let (tx, rx) = mpsc::channel();
        let _ = bridge_tx.send(bridge::Request::PowerOff(tx));
        let asked = rx.recv_timeout(Duration::from_secs(5)).unwrap_or(false);
        if !asked {
            let _ = vm::qmp(&socks.qmp, "system_powerdown");
        }
        let deadline = Instant::now() + Duration::from_secs(45);
        while !vm_done.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
        }
        if !vm_done.load(Ordering::Relaxed) {
            eprintln!("purrdroid: Android didn't shut down; stopping it.");
            let _ = vm::qmp(&socks.qmp, "quit");
            thread::sleep(Duration::from_secs(2));
            let _ = child.lock().unwrap().kill();
        }
    }
    let _ = child.lock().unwrap().wait();
    for d in exports.values() {
        let _ = d.lock().unwrap().flush();
    }
    if let Some(c) = &container {
        if let Err(e) = hidden::save(c) {
            eprintln!("purrdroid: couldn't save the container: {e}");
        }
    }
    drop(tor);
    for p in [&socks.disk, &socks.screen, &socks.qmp, &rt.join("control.sock")] {
        let _ = fs::remove_file(p);
    }
    let _ = fs::remove_dir_all(&outbox);
    eprintln!("purrdroid: Android is off.");
    Ok(())
}

// ---- the emulator engine ----

const DEFAULT_IMAGE: &str = "system-images/android-35/default/x86_64/";

/// The Android SDK: --sdk, else $ANDROID_HOME, else the usual places.
fn find_sdk(args: &[String]) -> Res<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let mut tries: Vec<PathBuf> = flag_value(args, "--sdk").map(PathBuf::from).into_iter().collect();
    if tries.is_empty() {
        tries.extend(["ANDROID_HOME", "ANDROID_SDK_ROOT"].iter().filter_map(std::env::var_os).map(PathBuf::from));
        tries.push(home.join(".local/opt/android-sdk"));
        tries.push(home.join("Android/Sdk"));
    }
    tries
        .into_iter()
        .find(|p| p.join("emulator/emulator").exists())
        .ok_or_else(|| "no Android SDK with the emulator in it: give it with --sdk PATH".into())
}

fn run_emulator(args: &[String], v: &mut Vault, files: &paths::Files, ram: u32, cpus: u32, net: Net) -> Res<()> {
    if net == Net::Tor {
        return Err("Tor mode isn't ready for the emulator engine yet (Android's name lookups would go around Tor): use --net direct or off".into());
    }
    let dir = files.vault.parent().unwrap().to_path_buf();
    let sdk = PathBuf::from(v.settings.get("sdk").ok_or("the vault doesn't say where the Android SDK is")?);
    let image = v.settings.get("image").unwrap_or(DEFAULT_IMAGE).to_string();
    let (width, height) =
        v.settings.get("screen").and_then(|s| s.split_once('x')).and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?))).unwrap_or((1080, 2400));
    let density = setting_u32(v, args, "--density", "density", 420, 120..=640)?;
    // The emulator wants room for 1.2 times the whole data partition in
    // memory before it starts, though it only uses what Android writes.
    let data_gb = setting_u32(v, args, "--data", "data_gb", 4, 2..=64)?;
    v.save()?;
    if args.iter().any(|a| a == "--software-gpu") {
        v.settings.set("emu_gpu", "swiftshader_indirect");
    }
    if args.iter().any(|a| a == "--gpu") {
        v.settings.set("emu_gpu", "host");
    }
    // Memory: Android's own, about 2 GiB more for the emulator and its
    // folder in memory (measured with /e/OS), and some left for the rest of
    // the PC, which has nothing to fall back on without swap. 2 GiB is
    // plenty for Android unless asked for more.
    const EMU_EXTRA_MB: u64 = 2048;
    const PC_KEEP_MB: u64 = 1536;
    let asked = flag_value(args, "--ram").is_some() || v.settings.get("ram_mb").is_some();
    let mut ram = if asked { ram } else { 2048 };
    let free = mem_available_mb();
    let fits = |r: u32| u64::from(r) + EMU_EXTRA_MB + PC_KEEP_MB <= free;
    if !fits(ram) {
        if !asked && fits(1536) {
            ram = 1536;
        } else {
            return Err(format!(
                "there isn't enough free memory to start Android without slowing the whole PC down: {free} MiB is free, and it needs about {} MiB ({ram} MiB for Android, {EMU_EXTRA_MB} for the emulator, {PC_KEEP_MB} kept for everything else). Close some programs and try again{}.",
                u64::from(ram) + EMU_EXTRA_MB + PC_KEEP_MB,
                if asked { ", or give Android less with --ram" } else { "" }
            )
            .into());
        }
    }
    let mut cfg = emu::Config {
        sdk,
        image,
        ram_mb: ram,
        cpus,
        width,
        height,
        density,
        data_gb,
        window: args.iter().any(|a| a == "--emulator-window"),
        gpu: v.settings.get("emu_gpu").unwrap_or("host").to_string(),
        grpc_port: vm::free_port()?,
    };
    v.save()?;

    emu::clean_leftovers();
    let current = v.settings.get("emu_state").map(str::to_string);
    let state_key = v.settings.key("emu_key");
    let state_path = |name: &str| dir.join(format!("emulator-{name}.disk"));
    let need = match (&current, &state_key) {
        (Some(name), Some(k)) => emu::sealed_size(&state_path(name), k)?.max(data_gb as u64 * 1229 << 20) + (256 << 20),
        _ => (data_gb as u64 * 1229 << 20) + (256 << 20),
    };
    let ramdir = emu::ram_dir(need)?;
    let avd = emu::avd_dir(&ramdir.0);
    if let (Some(name), Some(k)) = (&current, &state_key) {
        eprintln!("purrdroid: decrypting Android's state into memory...");
        emu::unseal(&state_path(name), k, &avd)?;
    }
    emu::write_avd(&ramdir.0, &cfg)?;
    if current.is_none() {
        emu::empty_data(&ramdir.0, &cfg)?;
    }
    let adb_key = purrdroid_adb::Key::from_der(&unhex(v.settings.get("adb_key").ok_or("the vault has no adb key")?).ok_or("bad adb key")?)?;
    emu::trust_key(&ramdir.0, &adb_key.public_string())?;
    let console = emu::free_ports()?;

    eprintln!("purrdroid: starting Android in the emulator ({} MiB, {} CPUs, network {})...", cfg.ram_mb, cfg.cpus, net.name());
    // Something on screen until Android's own window opens.
    let windowed = !(cfg.window || args.iter().any(|a| a == "--no-window")) && std::env::var_os("DISPLAY").is_some();
    let mut splash = windowed.then(|| gui::Splash::show("PurrDroid", "Starting Android... (a minute or two the first time)"));
    let mut first = emu::start(&ramdir.0, &cfg, console)?;
    // This PC's GPU first; if the emulator won't start with it, software.
    // Without its renderer it either quits or, as often, carries on with no
    // screen at all and Android never finishes starting: its log says which.
    if cfg.gpu == "host" {
        let log = ramdir.0.join("tmp/emulator.log");
        let mut failed = false;
        for _ in 0..80 {
            thread::sleep(Duration::from_millis(250));
            let said = fs::read_to_string(&log).unwrap_or_default();
            if first.try_wait()?.is_some() || said.contains("Could not start renderer") {
                failed = true;
                break;
            }
            if said.contains("Graphics Adapter") {
                break;
            }
        }
        if failed {
            eprintln!("purrdroid: the emulator wouldn't use this PC's GPU ({}); drawing in software instead", emu::log_tail(&ramdir.0));
            let _ = first.kill();
            let _ = first.wait();
            emu::clear_locks(&ramdir.0);
            cfg.gpu = "swiftshader_indirect".into();
            emu::write_avd(&ramdir.0, &cfg)?;
            first = emu::start(&ramdir.0, &cfg, console)?;
        }
    }
    let child = Arc::new(Mutex::new(first));
    let vm_done = Arc::new(AtomicBool::new(false));
    {
        let (child, done) = (child.clone(), vm_done.clone());
        thread::spawn(move || loop {
            if !matches!(child.lock().unwrap().try_wait(), Ok(None)) {
                done.store(true, Ordering::Relaxed);
                return;
            }
            // If the PC runs out of memory anyway, the kernel stops the
            // emulator rather than the desktop. (Set from here: the
            // emulator resets what it's started with.)
            if let Ok(pid) = child.lock().map(|c| c.id()) {
                let adj = format!("/proc/{pid}/oom_score_adj");
                if fs::read_to_string(&adj).is_ok_and(|v| v.trim() != "800") {
                    let _ = fs::write(&adj, "800");
                }
            }
            // Nearly out of memory (no swap here to slow down into): Android
            // is shut down before the PC freezes.
            if mem_available_mb() < 400 && !LOW_MEMORY.swap(true, Ordering::Relaxed) {
                STOP.store(true, Ordering::Relaxed);
            }
            thread::sleep(Duration::from_millis(200));
        });
    }
    let rt = paths::runtime_dir()?;
    let outbox = rt.join("outbox");
    let (notes_tx, notes_rx) = mpsc::channel();
    let mut notes_rx = Some(notes_rx);
    let bridge_tx = bridge::start(console + 1, adb_key, net, outbox.clone(), notes_tx, || {});
    bridge::serve_control(rt.join("control.sock"), bridge_tx.clone())?;
    unsafe {
        libc::signal(libc::SIGINT, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        // Closing the terminal it was started from shuts Android down
        // properly too, instead of losing the session.
        libc::signal(libc::SIGHUP, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
    }
    let net = net;
    if cfg.window || args.iter().any(|a| a == "--no-window") {
        eprintln!("purrdroid: Ctrl+C here shuts Android down.");
        // For testing the frame stream without a window: PURRDROID_FRAME_TEST=FILE.ppm
        if let Some(out) = std::env::var_os("PURRDROID_FRAME_TEST").map(PathBuf::from) {
            let (port, ram, shm, (w, h)) = (cfg.grpc_port, ramdir.0.clone(), emugrpc::shm_path(&ramdir.0), (cfg.width / 2, cfg.height / 2));
            thread::spawn(move || {
                let client = loop {
                    if let Some(token) = emu::grpc_token(&ram) {
                        if let Ok(c) = emugrpc::Client::connect(port, &token) {
                            break c;
                        }
                    }
                    thread::sleep(Duration::from_millis(200));
                };
                let frame = Arc::new(Mutex::new(purrdroid_rfb::Frame { width: 0, height: 0, pixels: vec![], dirty: None, resized: false }));
                let count = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let c2 = count.clone();
                if let Err(e) = emugrpc::stream_screen(&client, &shm, w, h, frame.clone(), move || {
                    c2.fetch_add(1, Ordering::Relaxed);
                }) {
                    eprintln!("purrdroid: frame test: {e}");
                    return;
                }
                let input = emugrpc::Input::new(client, (w * 2, h * 2), frame.clone());
                let mut last = 0;
                for round in 0.. {
                    thread::sleep(Duration::from_secs(5));
                    let n = count.load(Ordering::Relaxed);
                    let f = frame.lock().unwrap();
                    eprintln!("purrdroid: frame test: {} frames in 5 s, {}x{}", n - last, f.width, f.height);
                    last = n;
                    let mut ppm = format!("P6\n{} {}\n255\n", f.width, f.height).into_bytes();
                    for p in &f.pixels {
                        ppm.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, *p as u8]);
                    }
                    let _ = fs::write(&out, ppm);
                    drop(f);
                    // Move the pointer, to make frames.
                    let _ = input.pointer(0, (100 + round * 37 % 300) as u16, 300);
                }
            });
        }
    } else {
        // Android in PurrDroid's own window: frames and input through the
        // emulator's control service.
        let mut client = None;
        for _ in 0..300 {
            if vm_done.load(Ordering::Relaxed) {
                break;
            }
            if let Some(token) = emu::grpc_token(&ramdir.0) {
                if let Ok(c) = emugrpc::Client::connect(cfg.grpc_port, &token) {
                    client = Some(c);
                    break;
                }
            }
            thread::sleep(Duration::from_millis(200));
        }
        if let Some(client) = client {
            let (sw, sh) = if cfg.width >= 1000 { (cfg.width / 2, cfg.height / 2) } else { (cfg.width, cfg.height) };
            let frame = Arc::new(Mutex::new(purrdroid_rfb::Frame {
                width: sw as usize,
                height: sh as usize,
                pixels: vec![0; (sw * sh) as usize],
                dirty: None,
                resized: true,
            }));
            let (wake_r, wake_w) = UnixStream::pair()?;
            wake_w.set_nonblocking(true)?;
            let wake_w = Arc::new(wake_w);
            let waker = move || {
                let _ = (&*wake_w).write(&[1]);
            };
            emugrpc::stream_screen(&client, &emugrpc::shm_path(&ramdir.0), sw, sh, frame.clone(), waker)?;
            splash.take();
            let input = emugrpc::Input::new(client, (cfg.width, cfg.height), frame.clone());
            let end = viewer::Viewer {
                frame,
                input: Box::new(input),
                android_pointer: false,
                net,
                wake: wake_r,
                notes: notes_rx.take().unwrap(),
                bridge: bridge_tx.clone(),
                vm_done: vm_done.clone(),
                title: "PurrDroid".into(),
                width: sw,
                height: sh,
            }
            .run();
            match end {
                Ok(viewer::End::Closed) => STOP.store(true, Ordering::Relaxed),
                Ok(viewer::End::Stopped) => {}
                Err(e) => {
                    fail(&format!("PurrDroid's window failed ({e}); shutting Android down."));
                    STOP.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    loop {
        if vm_done.load(Ordering::Relaxed) {
            break;
        }
        if STOP.load(Ordering::Relaxed) {
            eprintln!("purrdroid: shutting Android down...");
            let (tx, rx) = mpsc::channel();
            let _ = bridge_tx.send(bridge::Request::PowerOff(tx));
            let _ = rx.recv_timeout(Duration::from_secs(5));
            let wait = if LOW_MEMORY.load(Ordering::Relaxed) { 15 } else { 60 };
            let deadline = Instant::now() + Duration::from_secs(wait);
            while !vm_done.load(Ordering::Relaxed) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(200));
            }
            if !vm_done.load(Ordering::Relaxed) {
                let _ = child.lock().unwrap().kill();
            }
            break;
        }
        for n in notes_rx.iter().flat_map(|r| r.try_iter()) {
            if let bridge::Note::Status(s) = n {
                eprintln!("purrdroid: {s}");
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    splash.take();
    let status = child.lock().unwrap().wait();
    if LOW_MEMORY.load(Ordering::Relaxed) {
        fail("PurrDroid shut Android down: the PC was nearly out of memory. Close some programs before starting it again.");
    }
    let _ = fs::remove_file(rt.join("control.sock"));
    let _ = fs::remove_dir_all(&outbox);
    let why = emu::log_tail(&ramdir.0);
    if !why.is_empty() && status.map(|s| !s.success()).unwrap_or(true) && !STOP.load(Ordering::Relaxed) {
        fail(&format!("The emulator stopped:\n{why}"));
    }

    // Seal the state into the other file, then point the vault at it.
    let next = if current.as_deref() == Some("a") { "b" } else { "a" };
    let mut key = Zeroizing::new([0u8; 32]);
    vaultkit::random_bytes(&mut key[..])?;
    eprintln!("purrdroid: sealing Android's state into the encrypted store...");
    if let Err(e) = emu::seal(&avd, &state_path(next), &key) {
        // Kept in memory, so nothing is lost before the PC is turned off.
        let kept = ramdir.0.clone();
        std::mem::forget(ramdir);
        return Err(format!("couldn't seal Android's state ({e}); it's still in memory at {}", kept.display()).into());
    }
    v.settings.set_key("emu_key", &key);
    v.settings.set("emu_state", next);
    v.settings.set("net", net.name());
    v.save()?;
    if let Some(old) = &current {
        if old != next {
            let _ = fs::remove_file(state_path(old));
        }
    }
    drop(ramdir);
    eprintln!("purrdroid: Android is off, and its state is sealed.");
    Ok(())
}

fn cmd_shell(args: &[String]) -> Res<()> {
    let command = args.join(" ");
    if command.trim().is_empty() {
        return Err("which command? `purrdroid shell 'pm list packages'`".into());
    }
    let rt = paths::runtime_dir()?;
    print!("{}", bridge::shell_on_running(&rt.join("control.sock"), &command)?);
    Ok(())
}

// ---- the GUI: everything from the Start menu, no terminal ----

/// A `key=value` file's value for `key`.
fn prop(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix('=')).map(|v| v.trim().to_string())
}

/// The x86_64 Androids in the SDK the emulator can run, the most private
/// first: /e/OS (no Google: microG instead), then the rest.
fn sdk_images(sdk: &Path) -> Vec<panel::Image> {
    let mut found: Vec<(u8, std::cmp::Reverse<u32>, panel::Image)> = Vec::new();
    let Ok(apis) = fs::read_dir(sdk.join("system-images")) else { return Vec::new() };
    for api in apis.flatten() {
        let Ok(tags) = fs::read_dir(api.path()) else { continue };
        for tag in tags.flatten() {
            let dir = tag.path().join("x86_64");
            if !dir.join("system.img").exists() {
                continue;
            }
            let rel = format!("system-images/{}/{}/x86_64/", api.file_name().to_string_lossy(), tag.file_name().to_string_lossy());
            let build = fs::read_to_string(dir.join("build.prop")).unwrap_or_default();
            let source = fs::read_to_string(dir.join("source.properties")).unwrap_or_default();
            let release = prop(&build, "ro.build.version.release").unwrap_or_else(|| api.file_name().to_string_lossy().into_owned());
            let all = format!("{build}\n{source}");
            // /e/OS is built on LineageOS, and says so by its legal page and product name.
            let eos = prop(&all, "ro.elegal.url").is_some_and(|u| u.contains("e.foundation"))
                || prop(&all, "ro.build.display.id").is_some_and(|d| d.starts_with("e_"));
            let google = tag.file_name().to_string_lossy().starts_with("google");
            let (rank, label, note) = if eos {
                let ver = prop(&build, "ro.lineage.build.version").unwrap_or_default();
                let patch = prop(&build, "ro.build.version.security_patch").unwrap_or_default();
                (
                    0,
                    format!("/e/OS {ver}, Android {release}: no Google, the most private"),
                    format!("Security patches of {patch}. Test keys: for your own apps, no real accounts."),
                )
            } else if google {
                (2, format!("Android {release} with Google's apps"), "Google services: the least private choice.".to_string())
            } else {
                (
                    1,
                    format!("Android {release} (AOSP): for testing your apps"),
                    "Signed with AOSP's test key: its system apps get full rights.".to_string(),
                )
            };
            found.push((rank, std::cmp::Reverse(release.parse::<u32>().unwrap_or(0)), panel::Image { path: rel, label, note }));
        }
    }
    found.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    found.into_iter().map(|(_, _, i)| i).collect()
}

fn gui_main() -> Res<()> {
    GUI.store(true, Ordering::Relaxed);
    purrdroid_store::harden_process();
    let _lock = take_lock()?;
    let f = paths::files()?;
    OFFER_RESET.store(true, Ordering::Relaxed);
    let mut v = loop {
        if f.vault.exists() {
            match unlock(&[]) {
                Ok(v) => break v,
                Err(e) if e.to_string() == "cancelled" => return Ok(()),
                // Wiped: on to setting up a new one.
                Err(e) if e.to_string() == WIPED => continue,
                Err(e) => return Err(e),
            }
        }
        let sdk = find_sdk(&[]).ok();
        let images = sdk.as_deref().map(sdk_images).unwrap_or_default();
        let Some(choice) = panel::setup(&images)? else { return Ok(()) };
        let secret = secret_of(&choice.keyfiles)?;
        let mut v = Vault::create(&f.vault, choice.password.as_bytes(), secret.as_ref())?;
        new_android(&mut v)?;
        match choice.engine {
            panel::Engine::Emulator(image) => {
                v.settings.set("engine", "emulator");
                v.settings.set("sdk", &sdk.ok_or("no Android SDK")?.display().to_string());
                v.settings.set("image", &image);
            }
            panel::Engine::Iso => {
                let key = v.settings.new_key("android_key")?;
                v.settings.set("disk", "plain");
                Disk::create(&f.android, &key, 32 * (1 << 30) / purrdroid_store::disk::SECTOR as u64, false)?;
            }
        }
        v.save()?;
        break v;
    };
    // Ready only once something could have installed it: "It's installed"
    // pressed with no ISO and no installer run left a blank disk that
    // booted to "No bootable device" every time.
    let could_be_installed = |v: &Vault| v.settings.get("install_ran") == Some("yes");
    if v.settings.get("engine") != Some("emulator") && (v.settings.get("android_ready") != Some("yes") || !could_be_installed(&v)) {
        loop {
            let has_iso = v.settings.get("media_key").is_some() && f.media.exists();
            let installed = could_be_installed(&v);
            let mut import = |iso: &Path, progress: &std::sync::atomic::AtomicU64| -> Res<()> {
                import_iso(&mut v, iso, progress).map_err(|e| e.to_string().into())
            };
            match panel::get_android(has_iso, installed, &mut import)? {
                panel::Next::Quit => return Ok(()),
                panel::Next::Install => {
                    // Back here afterwards, to start it once it's installed.
                    run_unlocked(&[], &mut v, true)?;
                }
                panel::Next::Start => {
                    v.settings.set("android_ready", "yes");
                    v.save()?;
                    break;
                }
            }
        }
    }
    run_unlocked(&[], &mut v, false)
}

fn cmd_apk(args: &[String]) -> Res<()> {
    let apks: Vec<PathBuf> = args.iter().filter(|a| !a.starts_with("--")).map(PathBuf::from).collect();
    if apks.is_empty() {
        return Err("which APKs? `purrdroid apk FILE.apk...`".into());
    }
    let rt = paths::runtime_dir()?;
    print!("{}", bridge::install_on_running(&rt.join("control.sock"), &apks)?);
    Ok(())
}

// ---- the rest ----

fn cmd_send(args: &[String]) -> Res<()> {
    let rt = paths::runtime_dir()?;
    let mut files = Vec::new();
    let mut texts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--text" | "--url" => {
                let t = args.get(i + 1).ok_or("--text needs the text")?;
                if t == "-" {
                    let mut s = String::new();
                    io::stdin().read_to_string(&mut s)?;
                    texts.push(s);
                } else {
                    texts.push(t.clone());
                }
                i += 1;
            }
            "--" => {}
            a => files.push(PathBuf::from(a.strip_prefix("file://").map(xdnd::percent_decode).unwrap_or_else(|| a.to_string()))),
        }
        i += 1;
    }
    if files.is_empty() && texts.is_empty() {
        return Err("send what? `purrdroid send FILE...` or `--text TEXT`".into());
    }
    bridge::send_to_running(&rt.join("control.sock"), &files, &texts)?;
    Ok(())
}

fn cmd_passwd(args: &[String]) -> Res<()> {
    let mut v = unlock(args)?;
    println!("The new password; the new keyfiles are those given with --new-keyfile (none: no keyfiles).");
    let (pw, secret) = ask_new("password", flag_paths(args, "--new-keyfile"))?;
    v.set_password(pw.as_bytes(), secret.as_ref())?;
    println!("Changed.");
    Ok(())
}

fn cmd_keyfile(args: &[String]) -> Res<()> {
    let path = args.iter().find(|a| !a.starts_with("--")).ok_or("where? `purrdroid keyfile PATH`")?;
    let p = Path::new(path);
    if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty() && !d.is_dir()) {
        return Err(format!("the folder {} doesn't exist: make it first (mkdir -m 700 {})", dir.display(), dir.display()).into());
    }
    keyfile::generate(p).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => format!("{path} already exists; PurrDroid never overwrites a keyfile"),
        _ => format!("couldn't make {path}: {e}"),
    })?;
    println!("Made {path}: 64 random bytes. Keep copies somewhere safe; without it there's no way in.");
    Ok(())
}

fn cmd_duress(args: &[String]) -> Res<()> {
    let mut v = unlock(args)?;
    if args.iter().any(|a| a == "--off") {
        v.set_duress(None)?;
        println!("There's no duress password now.");
        return Ok(());
    }
    println!("Typed instead of the real password, the duress password destroys the vault");
    println!("at once, and PurrDroid answers \"wrong password\" as for any other.");
    let (pw, secret) = ask_new("duress password", flag_paths(args, "--duress-keyfile"))?;
    v.set_duress(Some((pw.as_bytes(), secret.as_ref())))?;
    println!("Set.");
    Ok(())
}

fn cmd_destroy() -> Res<()> {
    let f = paths::files()?;
    if !f.vault.exists() {
        return Err("there's nothing to destroy".into());
    }
    let _lock = take_lock().map_err(|_| "PurrDroid is running: close it first")?;
    println!("This wipes PurrDroid: Android, its apps and everything in them, and the vault");
    println!("with the keys to it all. It can't be undone; no password or keyfile opens it again.");
    let typed = read_hidden("Type DESTROY to go ahead (it won't show): ")?;
    if typed.trim() != "DESTROY" {
        return Err("left as it was".into());
    }
    let mut shown = 0;
    wipe_all(&mut |d, t| {
        let pc = if t == 0 { 100 } else { d * 100 / t };
        if pc >= shown + 10 {
            shown = pc;
            eprintln!("purrdroid: wiping... {pc}%");
        }
    })?;
    println!("Wiped: every file was written over with random bytes and removed.");
    Ok(())
}

/// Wipes everything PurrDroid keeps: the vault first (without its keys the
/// rest can never be opened, even if this is cut short), then every disk
/// written over with random bytes and removed, and what a crash left in
/// memory. The caller holds the lock, so nothing of it is in use.
fn wipe_all(progress: &mut dyn FnMut(u64, u64)) -> Res<()> {
    let f = paths::files()?;
    emu::clean_leftovers();
    purrdroid_store::wipe::wipe_dir(f.vault.parent().unwrap(), &f.vault, progress)?;
    Ok(())
}

fn cmd_status() -> Res<()> {
    let f = paths::files()?;
    let size = |p: &Path| {
        fs::metadata(p).ok().map(|m| {
            use std::os::unix::fs::MetadataExt;
            format!("{:.1} GiB used on disk", (m.blocks() * 512) as f64 / (1u64 << 30) as f64)
        })
    };
    println!("Folder:  {}", f.vault.parent().unwrap().display());
    println!("Vault:   {}", if f.vault.exists() { "there" } else { "none yet (`purrdroid init`)" });
    println!("Android: {}", size(&f.android).unwrap_or_else(|| "no disk".into()));
    println!("ISO:     {}", size(&f.media).unwrap_or_else(|| "none imported".into()));
    let running = paths::runtime_dir().ok().is_some_and(|rt| {
        File::open(rt.join("lock")).ok().is_some_and(|l| unsafe { libc::flock(l.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0)
    });
    println!("Running: {}", if running { "yes" } else { "no" });
    Ok(())
}

fn usage() {
    let text = include_str!("main.rs").lines().skip(2).take_while(|l| l.starts_with("//!")).map(|l| l.trim_start_matches("//!")).collect::<Vec<_>>();
    println!("PurrDroid {}", env!("CARGO_PKG_VERSION"));
    for l in text {
        println!("{l}");
    }
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(i) = args.iter().position(|a| a == "--password-stdin") {
        args.remove(i);
        PASSWORD_STDIN.store(true, Ordering::Relaxed);
    }
    let (cmd, rest) = match args.first().map(String::as_str) {
        // From the Start menu (no terminal): the windows.
        None if !interactive() => ("gui", &args[..]),
        None => ("run", &args[..]),
        Some(c) if c.starts_with("--") && c != "--help" => ("run", &args[..]),
        Some(c) => (c, &args[1..]),
    };
    let res = match cmd {
        "init" => cmd_init(rest),
        "import" => cmd_import(rest),
        "install" => cmd_run(rest, true),
        "run" => cmd_run(rest, false),
        "send" => cmd_send(rest),
        "passwd" => cmd_passwd(rest),
        "keyfile" => cmd_keyfile(rest),
        "apk" => cmd_apk(rest),
        "gui" => gui_main(),
        "shell" => cmd_shell(rest),
        "duress" => cmd_duress(rest),
        "destroy" => cmd_destroy(),
        "status" => cmd_status(),
        "relay" => match rest.first() {
            Some(s) => tor::relay(Path::new(s)).map_err(Into::into),
            None => Err("relay SOCKET".into()),
        },
        "help" | "--help" | "-h" => {
            usage();
            Ok(())
        }
        other => Err(format!("there's no `{other}` command (see `purrdroid help`)").into()),
    };
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            fail(&e.to_string());
            ExitCode::FAILURE
        }
    }
}
