//! A small adb client, so PurrDroid doesn't need Google's platform tools.
//! It connects to adbd inside the virtual machine, proves who it is with its
//! own RSA key (which only the vault holds), runs shell commands and moves
//! files with the sync protocol.
//!
//! adbd lets a key in only after the person allows it once, on Android's own
//! screen ("Allow USB debugging?"). A program that reaches adbd's port
//! without that key gets nothing.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use base64::Engine;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pkcs1v15Sign, RsaPrivateKey};
use zeroize::Zeroizing;

const A_CNXN: u32 = 0x4e58_4e43;
const A_AUTH: u32 = 0x4854_5541;
const A_OPEN: u32 = 0x4e45_504f;
const A_OKAY: u32 = 0x5941_4b4f;
const A_CLSE: u32 = 0x4553_4c43;
const A_WRTE: u32 = 0x4554_5257;
const VERSION: u32 = 0x0100_0001;
const MAX_DATA: u32 = 256 * 1024;
const AUTH_TOKEN: u32 = 1;
const AUTH_SIGNATURE: u32 = 2;
const AUTH_RSAPUBLICKEY: u32 = 3;
/// What adbd calls this key on its "Allow USB debugging?" screen. Nothing
/// about this computer or its user.
const KEY_NAME: &str = "PurrDroid";

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// adbd hasn't been told yet to let this key in: the person must tap
    /// Allow on Android's screen.
    NotAllowed,
    Protocol(String),
    /// A sync request came back with FAIL and this message.
    Failed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::NotAllowed => f.write_str("Android hasn't allowed PurrDroid's key yet: tap Allow on its \"Allow USB debugging?\" screen"),
            Error::Protocol(s) => write!(f, "adb: {s}"),
            Error::Failed(s) => write!(f, "Android said: {s}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// The RSA key PurrDroid is known to adbd by.
pub struct Key(RsaPrivateKey);

impl Key {
    pub fn generate() -> Result<Key> {
        let k = RsaPrivateKey::new(&mut rand_core::OsRng, 2048).map_err(|e| Error::Protocol(e.to_string()))?;
        Ok(Key(k))
    }

    /// The key as PKCS#8 DER, for the vault. Wiped when dropped.
    pub fn to_der(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_pkcs8_der().expect("encodable").as_bytes().to_vec())
    }

    pub fn from_der(der: &[u8]) -> Result<Key> {
        RsaPrivateKey::from_pkcs8_der(der).map(Key).map_err(|e| Error::Protocol(e.to_string()))
    }

    /// Signs adbd's 20-byte token, as adb does (PKCS#1 v1.5 with the SHA-1
    /// prefix, over the token itself).
    fn sign(&self, token: &[u8]) -> Result<Vec<u8>> {
        self.0.sign(Pkcs1v15Sign::new::<sha1::Sha1>(), token).map_err(|e| Error::Protocol(e.to_string()))
    }

    /// The public key in Android's own format, base64, then a name.
    pub fn public_string(&self) -> String {
        let n = self.0.n();
        let words = 2048 / 32;
        let n_bytes = le_bytes(n, 256);
        let n0 = u32::from_le_bytes(n_bytes[..4].try_into().unwrap());
        let mut inv: u32 = 1;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(n0.wrapping_mul(inv)));
        }
        let rr = (BigUint::from(1u8) << 4096usize) % n;
        let mut out = Vec::with_capacity(4 + 4 + 256 + 256 + 4);
        out.extend_from_slice(&(words as u32).to_le_bytes());
        out.extend_from_slice(&inv.wrapping_neg().to_le_bytes());
        out.extend_from_slice(&n_bytes);
        out.extend_from_slice(&le_bytes(&rr, 256));
        let e = le_bytes(self.0.e(), 4);
        out.extend_from_slice(&e);
        format!("{} {KEY_NAME}", base64::engine::general_purpose::STANDARD.encode(out))
    }
}

fn le_bytes(n: &BigUint, len: usize) -> Vec<u8> {
    let mut b = n.to_bytes_le();
    b.resize(len, 0);
    b
}

struct Msg {
    cmd: u32,
    arg0: u32,
    arg1: u32,
    data: Vec<u8>,
}

/// A connection to adbd.
pub struct Adb {
    stream: TcpStream,
    max_data: usize,
    next_id: u32,
}

impl Adb {
    /// Connects to adbd at `addr` and authenticates with `key`. When adbd
    /// doesn't know the key yet it's offered, and the person is asked on
    /// Android's screen; this waits up to `approval` for them.
    pub fn connect(addr: SocketAddr, key: &Key, approval: Duration) -> Result<Adb> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut adb = Adb { stream, max_data: 4096, next_id: 1 };
        adb.send(A_CNXN, VERSION, MAX_DATA, b"host::\0")?;
        let mut signed = false;
        let mut offered = false;
        loop {
            let m = match adb.recv() {
                Err(Error::NotAllowed) if !offered => return Err(Error::Protocol("adbd didn't answer".into())),
                other => other?,
            };
            match m.cmd {
                A_CNXN => {
                    adb.max_data = (m.arg1 as usize).clamp(4096, MAX_DATA as usize);
                    adb.stream.set_read_timeout(Some(Duration::from_secs(60)))?;
                    return Ok(adb);
                }
                A_AUTH if m.arg0 == AUTH_TOKEN => {
                    if !signed {
                        signed = true;
                        let sig = key.sign(&m.data)?;
                        adb.send(A_AUTH, AUTH_SIGNATURE, 0, &sig)?;
                    } else if !offered {
                        offered = true;
                        let mut pubkey = key.public_string().into_bytes();
                        pubkey.push(0);
                        adb.send(A_AUTH, AUTH_RSAPUBLICKEY, 0, &pubkey)?;
                        adb.stream.set_read_timeout(Some(approval.max(Duration::from_secs(1))))?;
                    } else {
                        return Err(Error::NotAllowed);
                    }
                }
                _ => return Err(Error::Protocol(format!("unexpected message {:08x} while connecting", m.cmd))),
            }
        }
    }

    fn send(&mut self, cmd: u32, arg0: u32, arg1: u32, data: &[u8]) -> Result<()> {
        let sum: u32 = data.iter().map(|&b| b as u32).sum();
        let mut head = [0u8; 24];
        for (i, v) in [cmd, arg0, arg1, data.len() as u32, sum, cmd ^ 0xffff_ffff].iter().enumerate() {
            head[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        self.stream.write_all(&head)?;
        self.stream.write_all(data)?;
        Ok(())
    }

    fn recv(&mut self) -> Result<Msg> {
        let mut head = [0u8; 24];
        self.stream.read_exact(&mut head).map_err(|e| if offered_timeout(&e) { Error::NotAllowed } else { Error::Io(e) })?;
        let w = |i: usize| u32::from_le_bytes(head[i * 4..i * 4 + 4].try_into().unwrap());
        let (cmd, arg0, arg1, len, magic) = (w(0), w(1), w(2), w(3) as usize, w(5));
        if magic != cmd ^ 0xffff_ffff || len > MAX_DATA as usize * 4 {
            return Err(Error::Protocol("damaged message".into()));
        }
        let mut data = vec![0u8; len];
        self.stream.read_exact(&mut data)?;
        Ok(Msg { cmd, arg0, arg1, data })
    }

    fn open(&mut self, service: &str) -> Result<Stream<'_>> {
        let local = self.next_id;
        self.next_id += 1;
        let mut s = service.as_bytes().to_vec();
        s.push(0);
        self.send(A_OPEN, local, 0, &s)?;
        loop {
            let m = self.recv()?;
            match m.cmd {
                A_OKAY if m.arg1 == local => return Ok(Stream { adb: self, local, remote: m.arg0, pending: Vec::new(), closed: false }),
                A_CLSE if m.arg1 == local => return Err(Error::Protocol(format!("Android refused \"{service}\""))),
                _ => {}
            }
        }
    }

    /// Runs `command` in Android's shell, returns what it printed.
    pub fn shell(&mut self, command: &str) -> Result<String> {
        let mut s = self.open(&format!("shell:{command}"))?;
        let mut out = Vec::new();
        s.read_to_end(&mut out)?;
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Copies `data` to `remote` (a path inside Android), with permissions
    /// `mode`.
    pub fn push(&mut self, data: &mut dyn Read, remote: &str, mode: u32) -> Result<()> {
        let mut s = self.open("sync:")?;
        let spec = format!("{remote},{mode}");
        let mut req = b"SEND".to_vec();
        req.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        req.extend_from_slice(spec.as_bytes());
        s.write(&req)?;
        let chunk = (s.adb.max_data - 8).min(64 * 1024);
        let mut buf = vec![0u8; chunk];
        loop {
            let n = data.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let mut pkt = b"DATA".to_vec();
            pkt.extend_from_slice(&(n as u32).to_le_bytes());
            pkt.extend_from_slice(&buf[..n]);
            s.write(&pkt)?;
        }
        let mut done = b"DONE".to_vec();
        done.extend_from_slice(&0u32.to_le_bytes());
        s.write(&done)?;
        let mut head = [0u8; 8];
        s.read_exact(&mut head)?;
        let len = u32::from_le_bytes(head[4..].try_into().unwrap()) as usize;
        if &head[..4] == b"FAIL" {
            let mut msg = vec![0u8; len.min(4096)];
            s.read_exact(&mut msg)?;
            return Err(Error::Failed(String::from_utf8_lossy(&msg).into_owned()));
        }
        if &head[..4] != b"OKAY" {
            return Err(Error::Protocol("unexpected sync reply".into()));
        }
        let mut quit = b"QUIT".to_vec();
        quit.extend_from_slice(&0u32.to_le_bytes());
        s.write(&quit)?;
        Ok(())
    }

    /// Copies `remote` (a file inside Android) into `out`, at most `limit`
    /// bytes.
    pub fn pull(&mut self, remote: &str, out: &mut dyn Write, limit: u64) -> Result<u64> {
        let mut s = self.open("sync:")?;
        let mut req = b"RECV".to_vec();
        req.extend_from_slice(&(remote.len() as u32).to_le_bytes());
        req.extend_from_slice(remote.as_bytes());
        s.write(&req)?;
        let mut total = 0u64;
        loop {
            let mut head = [0u8; 8];
            s.read_exact(&mut head)?;
            let len = u32::from_le_bytes(head[4..].try_into().unwrap()) as usize;
            match &head[..4] {
                b"DATA" => {
                    if len > 64 * 1024 {
                        return Err(Error::Protocol("sync chunk too large".into()));
                    }
                    total += len as u64;
                    if total > limit {
                        return Err(Error::Failed(format!("the file is bigger than {} MiB", limit >> 20)));
                    }
                    let mut buf = vec![0u8; len];
                    s.read_exact(&mut buf)?;
                    out.write_all(&buf)?;
                }
                b"DONE" => break,
                b"FAIL" => {
                    let mut msg = vec![0u8; len.min(4096)];
                    s.read_exact(&mut msg)?;
                    return Err(Error::Failed(String::from_utf8_lossy(&msg).into_owned()));
                }
                _ => return Err(Error::Protocol("unexpected sync reply".into())),
            }
        }
        let mut quit = b"QUIT".to_vec();
        quit.extend_from_slice(&0u32.to_le_bytes());
        s.write(&quit)?;
        Ok(total)
    }
}

fn offered_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}

/// One open service (a shell command, a sync session).
struct Stream<'a> {
    adb: &'a mut Adb,
    local: u32,
    remote: u32,
    pending: Vec<u8>,
    closed: bool,
}

impl Stream<'_> {
    fn write(&mut self, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(self.adb.max_data) {
            self.adb.send(A_WRTE, self.local, self.remote, chunk)?;
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                let m = self.adb.recv()?;
                match m.cmd {
                    A_OKAY if m.arg1 == self.local => break,
                    A_WRTE if m.arg1 == self.local => {
                        self.pending.extend_from_slice(&m.data);
                        self.adb.send(A_OKAY, self.local, self.remote, &[])?;
                    }
                    A_CLSE if m.arg1 == self.local => {
                        self.closed = true;
                        return Err(Error::Protocol("Android closed the connection".into()));
                    }
                    _ => {}
                }
                if Instant::now() > deadline {
                    return Err(Error::Protocol("Android stopped answering".into()));
                }
            }
        }
        Ok(())
    }

    /// More data, or false once Android has closed the stream.
    fn fill(&mut self) -> Result<bool> {
        if self.closed {
            return Ok(false);
        }
        loop {
            let m = self.adb.recv()?;
            match m.cmd {
                A_WRTE if m.arg1 == self.local => {
                    self.pending.extend_from_slice(&m.data);
                    self.adb.send(A_OKAY, self.local, self.remote, &[])?;
                    return Ok(true);
                }
                A_CLSE if m.arg1 == self.local => {
                    self.closed = true;
                    return Ok(false);
                }
                _ => {}
            }
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        while self.pending.len() < buf.len() {
            if !self.fill()? {
                return Err(Error::Protocol("Android closed the connection early".into()));
            }
        }
        buf.copy_from_slice(&self.pending[..buf.len()]);
        self.pending.drain(..buf.len());
        Ok(())
    }

    fn read_to_end(&mut self, out: &mut Vec<u8>) -> Result<()> {
        loop {
            out.append(&mut self.pending);
            if out.len() > 16 << 20 || !self.fill()? {
                out.append(&mut self.pending);
                return Ok(());
            }
        }
    }
}

impl Drop for Stream<'_> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.adb.send(A_CLSE, self.local, self.remote, &[]);
        }
    }
}

/// Quotes `s` for Android's shell (single quotes, any inside escaped).
pub fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_format() {
        let k = Key::generate().unwrap();
        let s = k.public_string();
        let (b64, name) = s.split_once(' ').unwrap();
        assert_eq!(name, KEY_NAME);
        let raw = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        assert_eq!(raw.len(), 4 + 4 + 256 + 256 + 4);
        assert_eq!(u32::from_le_bytes(raw[..4].try_into().unwrap()), 64);
        // n0inv * n0 == -1 (mod 2^32)
        let n0inv = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let n0 = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        assert_eq!(n0inv.wrapping_mul(n0), u32::MAX);
        assert_eq!(u32::from_le_bytes(raw[520..524].try_into().unwrap()), 65537);
        let back = Key::from_der(&k.to_der()).unwrap();
        assert_eq!(back.public_string(), s);
        assert_eq!(k.sign(&[5u8; 20]).unwrap().len(), 256);
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("it's"), "'it'\\''s'");
    }
}
