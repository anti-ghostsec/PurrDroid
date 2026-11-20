//! Starting Android's virtual machine (QEMU with KVM) and talking to it.
//!
//! QEMU gets no files at all, and no socket anything else could connect to:
//! its disks (from PurrDroid's NBD server, decrypted in memory), its control
//! (QMP) and its screen (VNC) each come over a socket pair PurrDroid makes
//! and hands it already connected, with no name anywhere in the filesystem.
//! Another program of the same user has nothing to connect to: no disk, no
//! screen or keyboard, no control over the virtual machine. It runs with
//! QEMU's own seccomp sandbox, no guest core dumps, memory merging off
//! (which can leak between programs), and dies with PurrDroid.
//!
//! What the virtual machine is given: a disk, a screen (virtio GPU, with
//! 3D through virgl when there's a render node), a tablet-style pointer, a
//! keyboard, sound out (no microphone), a random number source, memory
//! ballooning (memory Android frees goes back to FerroOS) and, depending on
//! the network mode, a network card behind QEMU's user-mode NAT. Its serial
//! number, UUID and network card address are random, made once per vault:
//! nothing about this PC.

use std::io::{self, BufRead, BufReader};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::bridge::Net;

pub struct Config {
    pub ram_mb: u32,
    pub cpus: u32,
    pub width: u32,
    pub height: u32,
    pub gpu: bool,
    pub sound: bool,
    pub net: Net,
    pub adb_port: u16,
    pub install: bool,
    /// While installing: the disk before the ISO (see main's `disk_first`).
    pub disk_first: bool,
    pub mac: String,
    pub serial: String,
    pub uuid: String,
    /// `purrdroid` itself, for Tor mode's relay.
    pub exe: PathBuf,
    pub tor_socks: Option<PathBuf>,
}

/// QEMU's ends of the socket pairs it's started with, by descriptor
/// number (inherited across exec; everything else PurrDroid has open is
/// close-on-exec).
struct Passed {
    qmp: RawFd,
    android: RawFd,
    media: Option<RawFd>,
}

fn render_node() -> Option<PathBuf> {
    (128..136).map(|n| PathBuf::from(format!("/dev/dri/renderD{n}"))).find(|p| p.exists())
}

/// How sound gets out: PulseAudio's socket (PipeWire's PulseAudio service
/// has it too), PipeWire's own, or else ALSA's default device, which is how
/// FerroOS plays sound (through its enhancer and mixer, so Android's sound
/// is enhanced and mixed with the rest too).
fn audio_backend() -> Option<&'static str> {
    let rt = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    if rt.as_ref().is_some_and(|rt| rt.join("pulse/native").exists()) {
        Some("pa")
    } else if rt.as_ref().is_some_and(|rt| rt.join("pipewire-0").exists()) {
        Some("pipewire")
    } else if Path::new("/dev/snd").exists() {
        Some("alsa,out.dev=default")
    } else {
        None
    }
}

fn command(c: &Config, fds: &Passed) -> Command {
    let mut q = Command::new("qemu-system-x86_64");
    let a = |q: &mut Command, args: &[&str]| {
        q.args(args);
    };
    a(&mut q, &["-name", "PurrDroid,process=purrdroid-vm", "-nodefaults", "-no-user-config"]);
    a(&mut q, &["-machine", "q35,accel=kvm,dump-guest-core=off,mem-merge=off", "-cpu", "host"]);
    q.arg("-smp").arg(c.cpus.to_string()).arg("-m").arg(c.ram_mb.to_string());
    // Spawning is needed only for Tor mode's relay.
    let spawn = if c.net == Net::Tor { "allow" } else { "deny" };
    q.arg("-sandbox").arg(format!("on,obsolete=deny,elevateprivileges=deny,spawn={spawn},resourcecontrol=deny"));
    a(&mut q, &["-display", "none", "-monitor", "none", "-serial", "none", "-parallel", "none"]);
    // QMP on a socket already connected to PurrDroid: QEMU is the client
    // of a connection that's already there.
    q.arg("-chardev").arg(format!("socket,id=qmp,fd={}", fds.qmp));
    a(&mut q, &["-mon", "chardev=qmp,mode=control"]);
    q.arg("-smbios").arg(format!("type=1,manufacturer=PurrDroid,product=Virtual Android,serial={}", c.serial));
    q.arg("-uuid").arg(&c.uuid);
    a(&mut q, &["-rtc", "base=utc"]);

    // Disks, from PurrDroid's NBD server, each over its own connection.
    q.arg("-blockdev").arg(format!("driver=nbd,node-name=android,server.type=fd,server.str={},export=android,discard=unmap", fds.android));
    let (disk_at, iso_at) = if c.install && !c.disk_first { (1, 0) } else { (0, 1) };
    q.arg("-device").arg(format!("virtio-blk-pci,drive=android,bootindex={disk_at}"));
    if let Some(media) = fds.media {
        q.arg("-blockdev").arg(format!("driver=nbd,node-name=media,server.type=fd,server.str={media},export=media,read-only=on"));
        q.arg("-device").arg(format!("ide-cd,drive=media,bootindex={iso_at}"));
    }

    // Screen, pointer, keyboard.
    match (c.gpu, render_node()) {
        (true, Some(node)) => {
            q.arg("-device").arg(format!("virtio-vga-gl,xres={},yres={}", c.width, c.height));
            q.arg("-display").arg(format!("egl-headless,rendernode={}", node.display()));
        }
        _ => {
            q.arg("-device").arg(format!("virtio-vga,xres={},yres={}", c.width, c.height));
        }
    }
    // VNC with nowhere to listen: PurrDroid hands it the one connection
    // there is (QMP's add_client), see [`Vm::screen`].
    a(&mut q, &["-vnc", "none"]);
    a(&mut q, &["-device", "qemu-xhci", "-device", "usb-tablet", "-device", "usb-kbd"]);
    a(&mut q, &["-device", "virtio-rng-pci", "-device", "virtio-balloon-pci,free-page-reporting=on"]);

    // Sound out only: Android gets no microphone.
    if let Some(backend) = c.sound.then(audio_backend).flatten() {
        q.arg("-audiodev").arg(format!("{backend},id=snd"));
        a(&mut q, &["-device", "ich9-intel-hda", "-device", "hda-output,audiodev=snd"]);
    }

    // Network: adb's port (on 127.0.0.1 only) always; the internet in
    // direct mode; only Tor's relay in Tor mode; nothing more in off mode.
    let mut net = format!("user,id=net0,ipv6=off,hostfwd=tcp:127.0.0.1:{}-:5555", c.adb_port);
    match c.net {
        Net::Direct => {}
        Net::Off => net.push_str(",restrict=on"),
        Net::Tor => {
            let socks = c.tor_socks.as_ref().expect("Tor started");
            net.push_str(&format!(",restrict=on,guestfwd=tcp:{}-cmd:{} relay {}", crate::bridge::TOR_PROXY, c.exe.display(), socks.display()));
        }
    }
    q.arg("-netdev").arg(net);
    // romfile= : no network boot firmware, nothing to boot from there.
    q.arg("-device").arg(format!("virtio-net-pci,netdev=net0,mac={},romfile=", c.mac));

    q.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    let keep: Vec<RawFd> = [Some(fds.qmp), Some(fds.android), fds.media].into_iter().flatten().collect();
    unsafe {
        q.pre_exec(move || {
            // Gone with PurrDroid, whatever happens to it.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            // These, and only these, go across exec.
            for &fd in &keep {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    q
}

/// A running QEMU and PurrDroid's ends of its connections.
pub struct Vm {
    pub child: Child,
    pub qmp: Qmp,
}

/// Starts QEMU. If it quits at once (no sound server, or no 3D on this
/// PC), tries again without sound, then without 3D. `serve` is handed
/// PurrDroid's end of each disk connection as it's made, to serve it
/// straight away (QEMU waits for the disks before it carries on).
pub fn start(c: &mut Config, serve: &mut dyn FnMut(UnixStream)) -> io::Result<Vm> {
    let mut last = String::new();
    for attempt in 0..3 {
        if attempt == 1 {
            if !c.sound {
                c.gpu = false;
            }
            c.sound = false;
        }
        if attempt == 2 {
            c.gpu = false;
        }
        let (qmp_ours, qmp_theirs) = UnixStream::pair()?;
        let (disk_ours, disk_theirs) = UnixStream::pair()?;
        let media = if c.install { Some(UnixStream::pair()?) } else { None };
        let fds = Passed { qmp: qmp_theirs.as_raw_fd(), android: disk_theirs.as_raw_fd(), media: media.as_ref().map(|(_, t)| t.as_raw_fd()) };
        let spawned = command(c, &fds).spawn();
        // QEMU has its own copies now (or none, if it didn't start).
        drop((qmp_theirs, disk_theirs));
        let media = media.map(|(ours, _theirs)| ours);
        let mut child = spawned.map_err(|e| io::Error::other(format!("couldn't start qemu-system-x86_64 ({e}); is QEMU installed?")))?;
        serve(disk_ours);
        if let Some(m) = media {
            serve(m);
        }
        // Give it a moment to fail on its own options.
        for _ in 0..20 {
            std::thread::sleep(Duration::from_millis(100));
            if child.try_wait()?.is_some() {
                break;
            }
        }
        match child.try_wait()? {
            None => {
                let sound = c.sound && audio_backend().is_some();
                eprintln!(
                    "purrdroid: QEMU is running (3D {}, sound {})",
                    if c.gpu && render_node().is_some() { "on" } else { "off" },
                    if sound { "on" } else { "off" }
                );
                return Ok(Vm { child, qmp: Qmp::new(qmp_ours)? });
            }
            Some(_) => {
                let mut err = String::new();
                if let Some(e) = child.stderr.take() {
                    let _ = io::Read::read_to_string(&mut io::Read::take(e, 8192), &mut err);
                }
                last = err.trim().to_string();
                eprintln!("purrdroid: QEMU quit at once: {last}");
            }
        }
    }
    Err(io::Error::other(format!("QEMU wouldn't start: {last}")))
}

/// QEMU's control connection (QMP), PurrDroid's only. Everything QEMU
/// says is read as it comes (events included), so it never backs up.
pub struct Qmp {
    sock: UnixStream,
    lines: mpsc::Receiver<String>,
    ready: bool,
}

impl Qmp {
    fn new(sock: UnixStream) -> io::Result<Qmp> {
        let (tx, lines) = mpsc::channel();
        let r = BufReader::new(sock.try_clone()?);
        std::thread::spawn(move || {
            for line in r.lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Ok(Qmp { sock, lines, ready: false })
    }

    /// The next line that isn't an event, within `wait`.
    fn answer(&self, wait: Duration) -> io::Result<String> {
        let deadline = std::time::Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let line = self.lines.recv_timeout(left).map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QEMU didn't answer"))?;
            if !line.contains("\"event\"") {
                return Ok(line);
            }
        }
    }

    /// Sends one command (a JSON object), with a descriptor passed along it
    /// if `fd` is given; returns QEMU's answer, or its error as an error.
    pub fn execute(&mut self, json: &str, fd: Option<RawFd>) -> io::Result<String> {
        if !self.ready {
            // The greeting, then out of capabilities negotiation.
            let hello = self.answer(Duration::from_secs(10))?;
            if !hello.contains("QMP") {
                return Err(io::Error::other(format!("QEMU's control said: {hello}")));
            }
            send_with_fd(&self.sock, b"{\"execute\":\"qmp_capabilities\"}\n", None)?;
            self.answer(Duration::from_secs(5))?;
            self.ready = true;
        }
        let mut line = json.as_bytes().to_vec();
        line.push(b'\n');
        send_with_fd(&self.sock, &line, fd)?;
        let said = self.answer(Duration::from_secs(5))?;
        if said.contains("\"error\"") {
            return Err(io::Error::other(format!("QEMU said: {said}")));
        }
        Ok(said)
    }

    /// A command with no arguments, its answer ignored.
    pub fn command(&mut self, name: &str) -> io::Result<()> {
        self.execute(&format!("{{\"execute\":\"{name}\"}}"), None).map(|_| ())
    }

    /// The screen: a new connection handed to QEMU's VNC server, the only
    /// one it gets.
    pub fn screen(&mut self) -> io::Result<UnixStream> {
        let (ours, theirs) = UnixStream::pair()?;
        self.execute(r#"{"execute":"getfd","arguments":{"fdname":"screen"}}"#, Some(theirs.as_raw_fd()))?;
        self.execute(r#"{"execute":"add_client","arguments":{"protocol":"vnc","fdname":"screen","skipauth":true}}"#, None)?;
        Ok(ours)
    }
}

/// Writes all of `data` on `sock`, with `fd` passed along the first part
/// (SCM_RIGHTS), as QMP's getfd wants it.
fn send_with_fd(sock: &UnixStream, data: &[u8], fd: Option<RawFd>) -> io::Result<()> {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
    let mut cbuf = [0u64; 4];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if let Some(fd) = fd {
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            (*c).cmsg_level = libc::SOL_SOCKET;
            (*c).cmsg_type = libc::SCM_RIGHTS;
            (*c).cmsg_len = libc::CMSG_LEN(4) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut i32, fd);
        }
    }
    let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = n as usize;
    if n < data.len() {
        use std::io::Write;
        (&*sock).write_all(&data[n..])?;
    }
    Ok(())
}

/// A free TCP port on 127.0.0.1, for adb.
pub fn free_port() -> io::Result<u16> {
    let l = std::net::TcpListener::bind("127.0.0.1:0")?;
    Ok(l.local_addr()?.port())
}

/// Made once per vault: a random, locally administered network card
/// address, serial number and UUID.
pub fn random_identity() -> io::Result<(String, String, String)> {
    let mut b = [0u8; 32];
    vaultkit::random_bytes(&mut b).map_err(io::Error::from)?;
    let mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", (b[0] & 0xfc) | 0x02, b[1], b[2], b[3], b[4], b[5]);
    let serial: String = b[6..14].iter().map(|x| format!("{:02X}", x)).collect();
    let u = &b[14..30];
    let uuid = format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-4{:01x}{:02x}-{:01x}{:01x}{:02x}-{}",
        u[0],
        u[1],
        u[2],
        u[3],
        u[4],
        u[5],
        u[6] & 0xf,
        u[7],
        8 | (u[8] & 3),
        u[9] & 0xf,
        u[10],
        u[11..16].iter().map(|x| format!("{x:02x}")).collect::<String>() + &format!("{:02x}", b[30])
    );
    Ok((mac, serial, uuid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// What arrives on `s` next, and a descriptor passed with it.
    fn recv(s: &UnixStream) -> (String, Option<std::os::fd::OwnedFd>) {
        use std::os::fd::FromRawFd;
        let mut buf = [0u8; 4096];
        let mut iov = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: buf.len() };
        let mut cbuf = [0u64; 8];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut _;
        msg.msg_controllen = std::mem::size_of_val(&cbuf) as _;
        let n = unsafe { libc::recvmsg(s.as_raw_fd(), &mut msg, 0) };
        assert!(n > 0);
        let mut fd = None;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            if !c.is_null() && (*c).cmsg_type == libc::SCM_RIGHTS {
                fd = Some(std::os::fd::OwnedFd::from_raw_fd(std::ptr::read_unaligned(libc::CMSG_DATA(c) as *const i32)));
            }
        }
        (String::from_utf8_lossy(&buf[..n as usize]).into_owned(), fd)
    }

    #[test]
    fn qmp_hands_over_the_screen() {
        let (ours, qemu) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut w = qemu.try_clone().unwrap();
            w.write_all(b"{\"QMP\": {\"version\": {}, \"capabilities\": []}}\n").unwrap();
            assert!(recv(&qemu).0.contains("qmp_capabilities"));
            w.write_all(b"{\"timestamp\": {}, \"event\": \"RTC_CHANGE\"}\n{\"return\": {}}\n").unwrap();
            let (said, fd) = recv(&qemu);
            assert!(said.contains("getfd") && said.contains("screen"));
            let screen = UnixStream::from(fd.expect("the screen's descriptor came along"));
            w.write_all(b"{\"return\": {}}\n").unwrap();
            assert!(recv(&qemu).0.contains("add_client"));
            w.write_all(b"{\"return\": {}}\n").unwrap();
            (&screen).write_all(b"RFB 003.008\n").unwrap();
            assert!(recv(&qemu).0.contains("system_powerdown"));
            w.write_all(b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"no\"}}\n").unwrap();
        });
        let mut q = Qmp::new(ours).unwrap();
        let screen = q.screen().unwrap();
        let mut hello = String::new();
        BufReader::new(screen).read_line(&mut hello).unwrap();
        assert_eq!(hello, "RFB 003.008\n");
        assert!(q.command("system_powerdown").is_err(), "QEMU's errors are errors");
        fake.join().unwrap();
    }
}
