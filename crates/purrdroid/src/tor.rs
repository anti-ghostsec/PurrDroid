//! Tor mode. PurrDroid starts its own Tor, with all its state in memory
//! (nothing about which relays were used is left on the disk), listening
//! on a Unix socket in PurrDroid's private folder only.
//!
//! The virtual machine's network is cut off from everything (QEMU's
//! `restrict=on`) except one address, 10.0.2.100:8118, which Android is
//! told is its HTTP proxy. QEMU runs `purrdroid relay` for each connection
//! to it; the relay reads the proxy request (CONNECT host:port, or a plain
//! http:// request), has Tor open that connection (the name is looked up by
//! the exit relay, so no DNS leaves the machine) and passes bytes both ways.
//! An app that ignores the proxy has no way out at all.

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct Tor {
    child: Child,
    pub socks: PathBuf,
    dir: PathBuf,
}

impl Drop for Tor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Starts Tor in `rt/tor` (which is in memory) and waits until it has
/// built a circuit.
pub fn start(rt: &Path) -> io::Result<Tor> {
    use std::os::unix::fs::DirBuilderExt;
    let dir = rt.join("tor");
    let _ = fs::remove_dir_all(&dir);
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    fs::DirBuilder::new().mode(0o700).create(dir.join("data"))?;
    let socks = dir.join("socks.sock");
    let conf = format!(
        "DataDirectory {data}\nSocksPort unix:{socks} WorldWritable 0\nSocksPort 0\nClientOnly 1\nAvoidDiskWrites 1\n\
         Log notice stdout\nSafeLogging 1\nControlPort 0\n",
        data = dir.join("data").display(),
        socks = socks.display()
    );
    let torrc = dir.join("torrc");
    fs::write(&torrc, conf)?;
    let mut child = Command::new("tor")
        .arg("-f")
        .arg(&torrc)
        .arg("--defaults-torrc")
        .arg("/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| io::Error::other(format!("couldn't start tor ({e}); is it installed?")))?;
    let out = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if line.contains("Bootstrapped 100%") {
                let _ = tx.send(());
            }
        }
    });
    let tor = Tor { child, socks, dir };
    eprintln!("purrdroid: connecting to Tor...");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if rx.recv_timeout(Duration::from_millis(500)).is_ok() {
            return Ok(tor);
        }
        if Instant::now() > deadline {
            return Err(io::Error::other("Tor didn't connect within two minutes"));
        }
    }
}

/// `purrdroid relay SOCKS`: one proxied connection, on stdin and stdout
/// (QEMU's guestfwd hands each connection to a new relay).
pub fn relay(socks: &Path) -> io::Result<()> {
    let mut input = BufReader::new(io::stdin().lock());
    let mut head = Vec::new();
    // The request line and headers, at most 16 KiB.
    loop {
        let mut line = Vec::new();
        if input.by_ref().take(8192).read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        head.extend_from_slice(&line);
        if line == b"\r\n" || line == b"\n" || head.len() > 16 * 1024 {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let first = text.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let mut out = io::stdout().lock();
    let (host, port, forward) = if method.eq_ignore_ascii_case("CONNECT") {
        let (h, p) = split_host_port(target, 443);
        (h, p, None)
    } else if let Some(rest) = target.strip_prefix("http://") {
        let hostport = rest.split('/').next().unwrap_or("");
        let (h, p) = split_host_port(hostport, 80);
        (h, p, Some(head.clone()))
    } else {
        out.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")?;
        return Ok(());
    };
    let mut tor = match socks_connect(socks, &host, port) {
        Ok(s) => s,
        Err(_) => {
            out.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")?;
            return Ok(());
        }
    };
    match forward {
        None => out.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?,
        Some(h) => tor.write_all(&h)?,
    }
    out.flush()?;
    // Whatever the request reader already holds goes first.
    let buffered = input.buffer().to_vec();
    tor.write_all(&buffered)?;
    drop(input);
    let mut up = tor.try_clone()?;
    let t = thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut up);
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let mut down = tor;
    let _ = io::copy(&mut down, &mut out);
    let _ = out.flush();
    drop(t);
    Ok(())
}

fn split_host_port(s: &str, default: u16) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once(']') {
            return (h.to_string(), p.trim_start_matches(':').parse().unwrap_or(default));
        }
    }
    match s.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h.to_string(), p.parse().unwrap_or(default)),
        _ => (s.to_string(), default),
    }
}

/// Asks Tor (SOCKS5, by name, so Tor's exit looks the name up) for a
/// connection to `host:port`.
fn socks_connect(socks: &Path, host: &str, port: u16) -> io::Result<UnixStream> {
    if host.is_empty() || host.len() > 255 {
        return Err(io::Error::other("bad host"));
    }
    let mut s = UnixStream::connect(socks)?;
    s.write_all(&[5, 1, 0])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r != [5, 0] {
        return Err(io::Error::other("Tor refused"));
    }
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut rep = [0u8; 4];
    s.read_exact(&mut rep)?;
    if rep[1] != 0 {
        return Err(io::Error::other("Tor couldn't connect"));
    }
    let skip = match rep[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)?;
            l[0] as usize
        }
        _ => return Err(io::Error::other("bad SOCKS reply")),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest)?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_ports() {
        assert_eq!(split_host_port("example.org:8443", 443), ("example.org".into(), 8443));
        assert_eq!(split_host_port("example.org", 80), ("example.org".into(), 80));
        assert_eq!(split_host_port("[2001:db8::1]:443", 1), ("2001:db8::1".into(), 443));
    }
}
