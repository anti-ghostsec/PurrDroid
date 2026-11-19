//! The bridge between FerroOS and Android, over adb inside the virtual
//! machine (reached on 127.0.0.1 only, and only with PurrDroid's own key):
//!
//! * In: files and text sent from FerroOS (dropped on the window, or from
//!   Share / `purrdroid send`) are copied to Android's
//!   `Download/From FerroOS` folder and Android's share sheet opens, so the
//!   person picks the app that gets them.
//! * Out: a file put in Android's `Download/To FerroOS` folder (any app's
//!   Save or Share to Files can) is moved out of Android into memory, and
//!   shows in the window's tray: drag it onto a FerroOS window, or click it
//!   for FerroOS's Share box.
//!
//! Nothing goes either way that the person didn't send. There's no shared
//! clipboard and no shared folder that both sides can see at once.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use purrdroid_adb::{quote, Adb, Key};

pub const FROM_DIR: &str = "/sdcard/Download/From FerroOS";
pub const TO_DIR: &str = "/sdcard/Download/To FerroOS";
/// Memory left for the rest of the PC when a file comes out of Android.
const OUT_KEEP: u64 = 600 << 20;

/// Where files too big for the outbox's own filesystem go instead: in
/// /dev/shm (memory too, and up to half of it), named after the outbox so
/// a second PurrDroid has its own. Removed with the outbox at the end.
pub fn big_outbox(outbox: &Path) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    outbox.hash(&mut h);
    PathBuf::from(format!("/dev/shm/purrdroid-out-{}-{:016x}", unsafe { libc::getuid() }, h.finish()))
}

pub enum Item {
    File { name: String, file: File },
    Text(String),
}

pub enum Request {
    Send(Vec<Item>),
    /// Installs these APKs (`pm install`), answering with what Android said.
    InstallApks(Vec<Item>, Sender<String>),
    /// Runs a command in Android's shell, answering with what it printed.
    Shell(String, Sender<String>),
    /// Asks Android to shut down; answers whether it could be asked.
    PowerOff(Sender<bool>),
    /// Types this text into what has the focus in Android (pasting, where
    /// PurrDroid can't reach Android's clipboard).
    Type(String),
}

pub enum Note {
    Status(String),
    Outbox(PathBuf),
    /// Something was copied in Android: its text.
    Clipboard(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Net {
    Off,
    Direct,
    Tor,
}

impl Net {
    pub fn parse(s: &str) -> Option<Net> {
        match s {
            "off" => Some(Net::Off),
            "direct" | "on" => Some(Net::Direct),
            "tor" => Some(Net::Tor),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Net::Off => "off",
            Net::Direct => "direct",
            Net::Tor => "tor",
        }
    }
}

/// Where Android's apps are told the proxy is, in Tor mode (QEMU hands
/// connections to it to `purrdroid relay`, which hands them to Tor).
pub const TOR_PROXY: &str = "10.0.2.100:8118";

pub fn start(port: u16, key: Key, net: Net, outbox: PathBuf, notes: Sender<Note>, wake: impl Fn() + Send + 'static) -> Sender<Request> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || run(port, key, net, outbox, rx, notes, wake));
    tx
}

fn run(port: u16, key: Key, net: Net, outbox: PathBuf, rx: Receiver<Request>, notes: Sender<Note>, wake: impl Fn()) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let note = |n: Note| {
        let _ = notes.send(n);
        wake();
    };
    let mut adb: Option<Adb> = None;
    let mut last_try = Instant::now() - Duration::from_secs(60);
    let mut pending: Vec<Vec<Item>> = Vec::new();
    let mut sizes: HashMap<String, u64> = HashMap::new();
    let mut told_waiting = false;
    let mut warned = std::collections::HashSet::new();
    loop {
        if adb.is_none() && last_try.elapsed() >= Duration::from_secs(3) {
            last_try = Instant::now();
            // A short wait for the Allow tap, then again on the next round:
            // requests in the meantime aren't held up for long.
            match Adb::connect(addr, &key, Duration::from_secs(10)) {
                Ok(mut a) => match setup(&mut a, net) {
                    Ok(()) => {
                        note(Note::Status("Connected to Android".into()));
                        adb = Some(a);
                    }
                    Err(e) => note(Note::Status(format!("Android's bridge: {e}"))),
                },
                Err(purrdroid_adb::Error::NotAllowed) => note(Note::Status("Tap Allow on Android's \"Allow USB debugging?\" screen".into())),
                Err(_) if !told_waiting => {
                    told_waiting = true;
                    note(Note::Status(
                        "Waiting for Android (turn on USB debugging in Android once: Settings > About, tap Build number 7 times)".into(),
                    ));
                }
                Err(_) => {}
            }
        }
        if let Some(a) = adb.as_mut() {
            for items in pending.drain(..) {
                if let Err(e) = send(a, items) {
                    note(Note::Status(format!("Couldn't send: {e}")));
                }
            }
        }
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(Request::Send(items)) => match adb.as_mut() {
                Some(a) => {
                    note(Note::Status("Sending to Android...".into()));
                    match send(a, items) {
                        Ok(()) => note(Note::Status("Sent: pick the app in Android's share sheet".into())),
                        Err(e) => {
                            note(Note::Status(format!("Couldn't send: {e}")));
                            adb = None;
                        }
                    }
                }
                None => {
                    pending.push(items);
                    note(Note::Status(format!("{HOW_TO_CONNECT} What you dropped is sent once it is.")));
                }
            },
            Ok(Request::InstallApks(items, reply)) => match adb.as_mut() {
                Some(a) => {
                    let (text, broken) = install_apks(a, items);
                    if broken {
                        adb = None;
                    }
                    let _ = reply.send(text);
                }
                None => {
                    let _ = reply.send(format!("{HOW_TO_CONNECT} Then drop it again."));
                }
            },
            Ok(Request::Shell(command, reply)) => match adb.as_mut() {
                Some(a) => match a.shell(&command) {
                    Ok(out) => {
                        let _ = reply.send(out);
                    }
                    Err(e) => {
                        let _ = reply.send(format!("{e}\n"));
                        adb = None;
                    }
                },
                None => {
                    let _ = reply.send("Android isn't connected yet: wait until it has started, and try again\n".into());
                }
            },
            Ok(Request::Type(text)) => match adb.as_mut() {
                Some(a) => {
                    // `input text` types what a keyboard could: letters, digits
                    // and the like (a space is written %s); a line break is Enter.
                    let skipped = text.chars().any(|c| !(c.is_ascii_graphic() || c == ' ' || c == '\n'));
                    let mut failed = false;
                    for (i, line) in text.lines().enumerate() {
                        if i > 0 && a.shell("input keyevent 66").is_err() {
                            failed = true;
                        }
                        let typed: String = line.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect::<String>().replace(' ', "%s");
                        if !typed.is_empty() && a.shell(&format!("input text {}", quote(&typed))).is_err() {
                            failed = true;
                        }
                    }
                    note(Note::Status(if failed {
                        "Couldn't paste into Android".into()
                    } else if skipped {
                        "Pasted (this Android takes only plain letters, digits and signs typed in: the rest was left out)".into()
                    } else {
                        "Pasted into Android".into()
                    }));
                }
                None => note(Note::Status(format!("{HOW_TO_CONNECT} Then paste again."))),
            },
            Ok(Request::PowerOff(reply)) => {
                let ok = adb.as_mut().is_some_and(|a| a.shell("sync; svc power shutdown || reboot -p").is_ok());
                let _ = reply.send(ok);
            }
            Err(RecvTimeoutError::Timeout) => {
                if let Some(a) = adb.as_mut() {
                    match poll_outbox(a, &outbox, &mut sizes, &mut warned) {
                        Ok(files) => files.into_iter().for_each(|p| note(Note::Outbox(p))),
                        Err(purrdroid_adb::Error::Failed(msg)) => note(Note::Status(format!("Couldn't take a file out: {msg}"))),
                        Err(_) => adb = None,
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

/// Installs each APK; returns what Android said about each, and whether
/// the connection broke.
/// The apps installed on top of Android's own: their package names.
fn added_apps(a: &mut Adb) -> Vec<String> {
    let said = a.shell("pm list packages -3").unwrap_or_default();
    said.lines().filter_map(|l| l.trim().strip_prefix("package:")).map(str::to_string).collect()
}

fn install_apks(a: &mut Adb, items: Vec<Item>) -> (String, bool) {
    let mut out = String::new();
    for item in items {
        let Item::File { name, mut file } = item else { continue };
        let remote = format!("/data/local/tmp/purrdroid-{}.apk", safe_name(&name).replace(' ', "_"));
        let before = added_apps(a);
        let res = a.push(&mut file, &remote, 0o100644).and_then(|()| {
            let said = a.shell(&format!("pm install -r -g {}; rm -f {}", quote(&remote), quote(&remote)))?;
            Ok(said)
        });
        // A browser that wasn't there before (Wisp, say) is the one the
        // person wants links to open in: it becomes Android's browser.
        // Android itself turns down any app that isn't a browser.
        if matches!(&res, Ok(said) if said.contains("Success")) {
            for pkg in added_apps(a).into_iter().filter(|p| !before.contains(p)) {
                let cmd = format!("cmd role add-role-holder --user 0 android.app.role.BROWSER {} >/dev/null 2>&1 && echo browser", quote(&pkg));
                if a.shell(&cmd).is_ok_and(|s| s.trim() == "browser") {
                    out.push_str(&format!("{name}: {pkg} now opens web links\n"));
                }
                // AnonpheneOS's apps are opened from inside AnonpheneOS itself
                // (Settings, a dialer code), which another Android hasn't got.
                match pkg.as_str() {
                    // Opened from AnonpheneOS privacy (its Secure Folder entry);
                    // Android doesn't let anything else switch its icon on.
                    "app.anonphene.securefolder" => {
                        out.push_str(&format!("{name}: open it with PurrDroid's Privacy button, then Secure Folder\n"));
                    }
                    // No icon of its own: opened now, and from PurrDroid's Privacy button after.
                    "app.anonphene.privacy" => {
                        let _ = a.shell("am start -n app.anonphene.privacy/.PrivacyActivity >/dev/null 2>&1");
                        out.push_str(&format!("{name}: opened; PurrDroid's Privacy button opens it again\n"));
                    }
                    _ => {}
                }
            }
        }
        match res {
            Ok(said) => out.push_str(&format!("{name}: {}\n", explain_install(said.trim()))),
            Err(purrdroid_adb::Error::Failed(msg)) => out.push_str(&format!("{name}: Android said: {msg}\n")),
            Err(e) => {
                out.push_str(&format!("{name}: {e}\n"));
                return (out, true);
            }
        }
    }
    (out, false)
}

/// Android's answer to an install, with the usual failures said plainly
/// (Android's own words kept after them).
fn explain_install(said: &str) -> String {
    // Android's API levels, as Android versions.
    fn version(api: u32) -> String {
        match api {
            21 | 22 => "5".into(),
            23 => "6".into(),
            24 | 25 => "7".into(),
            26 | 27 => "8".into(),
            28 => "9".into(),
            29..=31 => (api - 19).to_string(),
            32 => "12L".into(),
            33..=36 => (api - 20).to_string(),
            _ => format!("API {api}"),
        }
    }
    let numbers =
        |after: &str| -> Option<u32> { said.split(after).nth(1)?.split(|c: char| !c.is_ascii_digit()).find(|s| !s.is_empty())?.parse().ok() };
    let plain = if said.contains("INSTALL_FAILED_OLDER_SDK") {
        match (numbers("newer sdk version #"), numbers("current version is #")) {
            (Some(need), Some(have)) => format!("needs Android {} or newer; this one is Android {}.", version(need), version(have)),
            _ => "needs a newer Android than this one.".into(),
        }
    } else if said.contains("INSTALL_FAILED_NO_MATCHING_ABIS") {
        "is built for another kind of processor only (ARM, say), and this Android can't run it.".into()
    } else if said.contains("INSTALL_FAILED_UPDATE_INCOMPATIBLE") || said.contains("INSTALL_FAILED_SHARED_USER_INCOMPATIBLE") {
        "is signed with another key than the copy already installed: uninstall that one first.".into()
    } else if said.contains("INSTALL_FAILED_VERSION_DOWNGRADE") {
        "is older than the copy already installed.".into()
    } else if said.contains("INSTALL_FAILED_INSUFFICIENT_STORAGE") {
        "doesn't fit: Android's storage is full.".into()
    } else {
        return said.to_string();
    };
    format!("not installed: it {plain} (Android said: {said})")
}

/// How to switch Android's side of the bridge on (an Android from an ISO;
/// the emulator's is on already).
pub const HOW_TO_CONNECT: &str = "Android isn't connected to PurrDroid yet. Switch it on once, in Android: Settings > About tablet, tap Build number 7 times; then Settings > System > Developer options, turn on USB debugging, and tap Allow when Android asks about PurrDroid's key.";

fn setup(a: &mut Adb, net: Net) -> purrdroid_adb::Result<()> {
    a.shell(&format!("mkdir -p {} {}", quote(FROM_DIR), quote(TO_DIR)))?;
    // A virtual PC has no battery, so Android on it reads one at 0%: told
    // it's plugged in and full instead (until Android restarts).
    a.shell("dumpsys battery | grep -qE 'present: false|level: 0$' && dumpsys battery set ac 1 && dumpsys battery set level 100; true")?;
    // In Tor mode every app is pointed at the proxy; the virtual machine
    // has no other way out, so an app that ignores it simply gets nowhere.
    let proxy = if net == Net::Tor { TOR_PROXY } else { ":0" };
    a.shell(&format!("settings put global http_proxy {proxy}"))?;
    if net == Net::Off {
        a.shell("cmd connectivity airplane-mode enable")?;
    }
    Ok(())
}

/// A file name that's safe in Android's shell and folders.
pub fn safe_name(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || " .,-_()+[]@".contains(c) { c } else { '_' })
        .collect::<String>()
        .trim_start_matches('.')
        .chars()
        .take(120)
        .collect();
    if s.trim().is_empty() {
        "file".into()
    } else {
        s
    }
}

pub fn mime_for(name: &str) -> &'static str {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "mp4" | "m4v" => "video/mp4",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        "mp3" => "audio/mpeg",
        "ogg" | "opus" => "audio/ogg",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "m4a" => "audio/mp4",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "html" | "htm" => "text/html",
        "zip" => "application/zip",
        "apk" => "application/vnd.android.package-archive",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "odt" => "application/vnd.oasis.opendocument.text",
        "epub" => "application/epub+zip",
        _ => "application/octet-stream",
    }
}

fn send(a: &mut Adb, items: Vec<Item>) -> purrdroid_adb::Result<()> {
    let mut pushed = Vec::new();
    for item in items {
        match item {
            Item::Text(t) => {
                a.shell(&format!("am start -a android.intent.action.SEND -t text/plain --es android.intent.extra.TEXT {}", quote(&t)))?;
            }
            Item::File { name, mut file } => {
                let name = safe_name(&name);
                // Share's text comes as "Shared text.txt": send it as text.
                if name.starts_with("Shared text") && name.ends_with(".txt") && file.metadata().map(|m| m.len() < 64 * 1024).unwrap_or(false) {
                    let mut t = String::new();
                    if io::Read::read_to_string(&mut file, &mut t).is_ok() {
                        a.shell(&format!("am start -a android.intent.action.SEND -t text/plain --es android.intent.extra.TEXT {}", quote(&t)))?;
                        continue;
                    }
                }
                let existing = a.shell(&format!("ls -1 {} 2>/dev/null", quote(FROM_DIR)))?;
                let taken: Vec<&str> = existing.lines().collect();
                let mut target = name.clone();
                let mut n = 2;
                while taken.contains(&target.as_str()) {
                    target = match name.rsplit_once('.') {
                        Some((stem, ext)) => format!("{stem} ({n}).{ext}"),
                        None => format!("{name} ({n})"),
                    };
                    n += 1;
                }
                let remote = format!("{FROM_DIR}/{target}");
                a.push(&mut file, &remote, 0o100644)?;
                pushed.push(remote);
            }
        }
    }
    match pushed.as_slice() {
        [] => {}
        [one] => share_file(a, one)?,
        _ => {
            // Several: open the folder in Android's Files.
            a.shell("am start -a android.intent.action.VIEW -t vnd.android.document/directory -d content://com.android.externalstorage.documents/document/primary%3ADownload%2FFrom%20FerroOS")?;
        }
    }
    Ok(())
}

/// Opens Android's share sheet for a file that was just copied in.
fn share_file(a: &mut Adb, remote: &str) -> purrdroid_adb::Result<()> {
    let mime = mime_for(remote);
    let path = remote.replacen("/sdcard/", "/storage/emulated/0/", 1);
    // Android's media store lists the file as it arrives; its content://
    // address is what apps can open.
    let mut uri = None;
    for _ in 0..10 {
        let q = a.shell(&format!(
            "content query --uri content://media/external/file --projection _id --where {}",
            quote(&format!("_data='{}'", path.replace('\'', "''")))
        ))?;
        if let Some(id) = q.split("_id=").nth(1).map(|s| s.trim().split(|c: char| !c.is_ascii_digit()).next().unwrap_or("").to_string()) {
            if !id.is_empty() {
                uri = Some(format!("content://media/external/file/{id}"));
                break;
            }
        }
        thread::sleep(Duration::from_millis(300));
    }
    let uri = uri.unwrap_or_else(|| format!("file://{path}"));
    if mime == "application/vnd.android.package-archive" {
        // An app: Android's installer, which asks before installing.
        a.shell(&format!("am start -a android.intent.action.VIEW -t {mime} -d {} --grant-read-uri-permission", quote(&uri)))?;
    } else {
        a.shell(&format!(
            "am start -a android.intent.action.SEND -t {mime} --eu android.intent.extra.STREAM {} --grant-read-uri-permission",
            quote(&uri)
        ))?;
    }
    Ok(())
}

/// Moves files that have finished arriving in `To FerroOS` into memory.
fn poll_outbox(
    a: &mut Adb,
    outbox: &Path,
    sizes: &mut HashMap<String, u64>,
    warned: &mut std::collections::HashSet<String>,
) -> purrdroid_adb::Result<Vec<PathBuf>> {
    let list = a.shell(&format!("cd {} 2>/dev/null && for f in *; do [ -f \"$f\" ] && echo \"$(stat -c %s \"$f\") $f\"; done", quote(TO_DIR)))?;
    let mut out = Vec::new();
    let mut seen = HashMap::new();
    for line in list.lines() {
        let Some((size, name)) = line.split_once(' ') else { continue };
        let Ok(size) = size.trim().parse::<u64>() else { continue };
        seen.insert(name.to_string(), size);
        // Taken once its size has stayed the same for one round: an app
        // still writing it would be caught half-way otherwise.
        if sizes.get(name) != Some(&size) {
            continue;
        }
        let remote = format!("{TO_DIR}/{name}");
        // In memory, wherever it fits: the outbox, or /dev/shm for a big one;
        // and only while the PC keeps some memory to spare.
        let _ = std::os::unix::fs::DirBuilderExt::mode(std::fs::DirBuilder::new().recursive(true), 0o700).create(outbox);
        let room = crate::mem_available_mb().saturating_mul(1 << 20).saturating_sub(OUT_KEEP);
        let fits = |dir: &Path| size + (64 << 20) <= free_memory(dir);
        let base = if fits(outbox) {
            Some(outbox.to_path_buf())
        } else if crate::paths::in_memory(Path::new("/dev/shm")) && fits(Path::new("/dev/shm")) {
            Some(big_outbox(outbox))
        } else {
            None
        };
        let Some(base) = base.filter(|_| size <= room) else {
            // Left where it is, and tried again each round; said once.
            if warned.insert(name.to_string()) {
                return Err(purrdroid_adb::Error::Failed(format!(
                    "{name} ({} MiB) is still in Android: holding it in memory now would leave the PC short ({} MiB free). Close some programs and it comes out by itself.",
                    size.div_ceil(1 << 20),
                    crate::mem_available_mb()
                )));
            }
            continue;
        };
        let dir = unique_dir(&base).map_err(purrdroid_adb::Error::Io)?;
        let path = dir.join(safe_name(name));
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(purrdroid_adb::Error::Io)?;
        if let Err(e) = a.pull(&remote, &mut f, size + (1 << 20)) {
            drop(f);
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        a.shell(&format!("rm -f {}", quote(&remote)))?;
        seen.remove(name);
        out.push(path);
    }
    *sizes = seen;
    Ok(out)
}

fn free_memory(dir: &Path) -> u64 {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else { return 0 };
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return 0;
    }
    (st.f_bavail as u64).saturating_mul(st.f_frsize as u64)
}

fn unique_dir(base: &Path) -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let mut r = [0u8; 8];
    vaultkit::random_bytes(&mut r).map_err(io::Error::from)?;
    let dir = base.join(r.iter().map(|b| format!("{b:02x}")).collect::<String>());
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    Ok(dir)
}

// ---- The control socket: `purrdroid send` talking to the running one ----
//
// A SOCK_SEQPACKET socket in PurrDroid's folder in memory (0700), so each
// message arrives whole. A file is sent as an open file descriptor
// (SCM_RIGHTS), never as a path: PurrDroid reads exactly the file `send`
// opened, even if it's been removed since (as Share's copies are).

fn seqpacket() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn sockaddr(path: &Path) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let b = path.as_os_str().as_bytes();
    if b.len() >= addr.sun_path.len() {
        return Err(io::Error::other("socket path too long"));
    }
    for (i, &c) in b.iter().enumerate() {
        addr.sun_path[i] = c as libc::c_char;
    }
    Ok((addr, std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t))
}

fn send_msg(fd: RawFd, data: &[u8], pass: Option<RawFd>) -> io::Result<()> {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
    let mut cbuf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(pfd) = pass {
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut i32, pfd);
        }
    }
    if unsafe { libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn recv_msg(fd: RawFd, buf: &mut [u8]) -> io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
    let mut cbuf = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cbuf.len() as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut passed = None;
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&msg);
        while !c.is_null() {
            if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS {
                let count = ((*c).cmsg_len as usize - libc::CMSG_LEN(0) as usize) / 4;
                for i in 0..count {
                    let f = std::ptr::read_unaligned((libc::CMSG_DATA(c) as *const i32).add(i));
                    let owned = OwnedFd::from_raw_fd(f);
                    if passed.is_none() {
                        passed = Some(owned);
                    }
                }
            }
            c = libc::CMSG_NXTHDR(&msg, c);
        }
    }
    Ok((n as usize, passed))
}

/// Listens for `purrdroid send` on `path`. Runs on its own thread.
pub fn serve_control(path: PathBuf, tx: Sender<Request>) -> io::Result<()> {
    let _ = std::fs::remove_file(&path);
    let sock = seqpacket()?;
    let (addr, len) = sockaddr(&path)?;
    if unsafe { libc::bind(sock.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, len) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::listen(sock.as_raw_fd(), 8) } != 0 {
        return Err(io::Error::last_os_error());
    }
    thread::spawn(move || loop {
        let c = unsafe { libc::accept4(sock.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if c < 0 {
            continue;
        }
        let conn = unsafe { OwnedFd::from_raw_fd(c) };
        let tx = tx.clone();
        // Each caller on its own thread: a slow answer holds up nobody else.
        thread::spawn(move || {
            // Only this same user (the folder is 0700 too).
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut clen = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            let ok = unsafe { libc::getsockopt(conn.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut _, &mut clen) }
                == 0
                && cred.uid == unsafe { libc::getuid() };
            if !ok {
                return;
            }
            let mut items = Vec::new();
            let mut apks = Vec::new();
            let mut shell = None;
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                match recv_msg(conn.as_raw_fd(), &mut buf) {
                    Ok((0, _)) | Err(_) => break,
                    Ok((n, fd)) => match (buf[0], fd) {
                        (b'F', Some(fd)) => items.push(Item::File { name: String::from_utf8_lossy(&buf[1..n]).into_owned(), file: File::from(fd) }),
                        (b'P', Some(fd)) => apks.push(Item::File { name: String::from_utf8_lossy(&buf[1..n]).into_owned(), file: File::from(fd) }),
                        (b'T', _) => items.push(Item::Text(String::from_utf8_lossy(&buf[1..n]).into_owned())),
                        (b'S', _) => shell = Some(String::from_utf8_lossy(&buf[1..n]).into_owned()),
                        (b'E', _) => {
                            let mut answer = "OK".to_string();
                            if let Some(command) = shell.take() {
                                let (rtx, rrx) = mpsc::channel();
                                let _ = tx.send(Request::Shell(command, rtx));
                                answer = rrx.recv_timeout(Duration::from_secs(300)).unwrap_or_else(|_| "no answer from Android".into());
                            }
                            if !apks.is_empty() {
                                let (rtx, rrx) = mpsc::channel();
                                let _ = tx.send(Request::InstallApks(std::mem::take(&mut apks), rtx));
                                answer = rrx.recv_timeout(Duration::from_secs(300)).unwrap_or_else(|_| "no answer from Android".into());
                            }
                            // In pieces (a message has a size limit); closing
                            // the connection ends it.
                            for piece in answer.as_bytes().chunks(32 * 1024) {
                                if send_msg(conn.as_raw_fd(), piece, None).is_err() {
                                    break;
                                }
                            }
                            break;
                        }
                        _ => {}
                    },
                }
            }
            if !items.is_empty() {
                let _ = tx.send(Request::Send(items));
            }
        });
    });
    Ok(())
}

/// `purrdroid send`: hands files and text to the running PurrDroid.
pub fn send_to_running(control: &Path, files: &[PathBuf], texts: &[String]) -> io::Result<()> {
    talk(control, b'F', files, texts).map(|_| ())
}

/// `purrdroid apk`: has the running PurrDroid install APKs; returns what
/// Android said.
pub fn install_on_running(control: &Path, apks: &[PathBuf]) -> io::Result<String> {
    talk(control, b'P', apks, &[])
}

/// `purrdroid shell`: runs a command in the running Android's shell.
pub fn shell_on_running(control: &Path, command: &str) -> io::Result<String> {
    talk(control, b'S', &[], &[command.to_string()])
}

fn talk(control: &Path, kind: u8, files: &[PathBuf], texts: &[String]) -> io::Result<String> {
    let sock = seqpacket()?;
    let (addr, len) = sockaddr(control)?;
    if unsafe { libc::connect(sock.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, len) } != 0 {
        return Err(io::Error::new(io::ErrorKind::NotConnected, "PurrDroid isn't running: start it first"));
    }
    for p in files {
        let f = File::open(p)?;
        if !f.metadata()?.is_file() {
            return Err(io::Error::other(format!("{} isn't a file", p.display())));
        }
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        let mut m = vec![kind];
        m.extend_from_slice(name.as_bytes());
        send_msg(sock.as_raw_fd(), &m, Some(f.as_raw_fd()))?;
    }
    for t in texts {
        if t.len() > 200 * 1024 {
            return Err(io::Error::other("that text is too long to send"));
        }
        let mut m = vec![if kind == b'S' { b'S' } else { b'T' }];
        m.extend_from_slice(t.as_bytes());
        send_msg(sock.as_raw_fd(), &m, None)?;
    }
    send_msg(sock.as_raw_fd(), b"E", None)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut answer = Vec::new();
    loop {
        let (n, _) = recv_msg(sock.as_raw_fd(), &mut buf)?;
        if n == 0 {
            break;
        }
        answer.extend_from_slice(&buf[..n]);
    }
    Ok(String::from_utf8_lossy(&answer).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_failures_said_plainly() {
        let said = "Failure [INSTALL_FAILED_OLDER_SDK: Failed parse during installPackageLI: /data/app/x.tmp/base.apk (at Binary XML file line #0): Requires newer sdk version #35 (current version is #30)]";
        assert!(explain_install(said).starts_with("not installed: it needs Android 15 or newer; this one is Android 11."));
        assert_eq!(explain_install("Success"), "Success");
    }

    #[test]
    fn names() {
        assert_eq!(safe_name("../../etc/passwd"), "_.._etc_passwd");
        assert_eq!(safe_name("My photo (1).JPG"), "My photo (1).JPG");
        assert_eq!(safe_name("a'b\"c$`d"), "a_b_c__d");
        assert_eq!(safe_name(""), "file");
        assert_eq!(mime_for("x.JPG"), "image/jpeg");
    }

    #[test]
    fn control_socket_passes_files_and_text() {
        let dir = std::env::temp_dir().join(format!("pd-ctl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("c.sock");
        let (tx, rx) = mpsc::channel();
        serve_control(sock.clone(), tx).unwrap();
        let f = dir.join("hello.txt");
        std::fs::write(&f, b"hi there").unwrap();
        send_to_running(&sock, &[f.clone()], &["some text".into()]).unwrap();
        std::fs::remove_file(&f).unwrap(); // the fd still reads it
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            Request::Send(items) => {
                assert_eq!(items.len(), 2);
                match &items[0] {
                    Item::File { name, file } => {
                        assert_eq!(name, "hello.txt");
                        let mut s = String::new();
                        io::Read::read_to_string(&mut &*file, &mut s).unwrap();
                        assert_eq!(s, "hi there");
                    }
                    _ => panic!(),
                }
                assert!(matches!(&items[1], Item::Text(t) if t == "some text"));
            }
            _ => panic!(),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
