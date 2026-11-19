//! Starting Android's virtual machine (QEMU with KVM) and talking to it.
//!
//! QEMU gets no files at all: its disks come from PurrDroid's NBD server
//! (decrypted in memory), its screen goes to a VNC socket and its control
//! to a QMP socket, both in PurrDroid's private folder in memory. It runs
//! with QEMU's own seccomp sandbox, no guest core dumps, memory merging off
//! (which can leak between programs), and dies with PurrDroid.
//!
//! What the virtual machine is given: a disk, a screen (virtio GPU, with
//! 3D through virgl when there's a render node), a tablet-style pointer, a
//! keyboard, sound out (no microphone), a random number source, memory
//! ballooning (memory Android frees goes back to FerroOS) and, depending on
//! the network mode, a network card behind QEMU's user-mode NAT. Its serial
//! number, UUID and network card address are random, made once per vault:
//! nothing about this PC.

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
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
    pub rt: PathBuf,
    /// `purrdroid` itself, for Tor mode's relay.
    pub exe: PathBuf,
    pub tor_socks: Option<PathBuf>,
}

pub struct Sockets {
    pub disk: PathBuf,
    pub screen: PathBuf,
    pub qmp: PathBuf,
}

pub fn sockets(rt: &Path) -> Sockets {
    Sockets { disk: rt.join("disk.sock"), screen: rt.join("screen.sock"), qmp: rt.join("qmp.sock") }
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

pub fn command(c: &Config) -> Command {
    let s = sockets(&c.rt);
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
    q.arg("-qmp").arg(format!("unix:{},server=on,wait=off", s.qmp.display()));
    q.arg("-smbios").arg(format!("type=1,manufacturer=PurrDroid,product=Virtual Android,serial={}", c.serial));
    q.arg("-uuid").arg(&c.uuid);
    a(&mut q, &["-rtc", "base=utc"]);

    // Disks, from PurrDroid's NBD server.
    let disk = s.disk.display().to_string();
    q.arg("-blockdev").arg(format!("driver=nbd,node-name=android,server.type=unix,server.path={disk},export=android,discard=unmap"));
    let (disk_at, iso_at) = if c.install && !c.disk_first { (1, 0) } else { (0, 1) };
    q.arg("-device").arg(format!("virtio-blk-pci,drive=android,bootindex={disk_at}"));
    if c.install {
        q.arg("-blockdev").arg(format!("driver=nbd,node-name=media,server.type=unix,server.path={disk},export=media,read-only=on"));
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
    q.arg("-vnc").arg(format!("unix:{}", s.screen.display()));
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
    unsafe {
        q.pre_exec(|| {
            // Gone with PurrDroid, whatever happens to it.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL);
            Ok(())
        });
    }
    q
}

/// Starts QEMU. If it quits at once (no sound server, or no 3D on this
/// PC), tries again without sound, then without 3D. Returns the running
/// QEMU.
pub fn start(c: &mut Config) -> io::Result<Child> {
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
        let mut child = command(c).spawn().map_err(|e| io::Error::other(format!("couldn't start qemu-system-x86_64 ({e}); is QEMU installed?")))?;
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
                return Ok(child);
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

/// A QMP command (`{"execute": ...}`), its answer ignored.
pub fn qmp(path: &Path, command: &str) -> io::Result<()> {
    let s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut r = BufReader::new(s.try_clone()?);
    let mut w = s;
    let mut line = String::new();
    r.read_line(&mut line)?;
    w.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    line.clear();
    r.read_line(&mut line)?;
    w.write_all(format!("{{\"execute\":\"{command}\"}}\n").as_bytes())?;
    line.clear();
    let _ = r.read_line(&mut line);
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
