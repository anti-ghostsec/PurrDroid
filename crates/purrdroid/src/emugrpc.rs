//! Talking to Google's emulator through its own control service (gRPC, on
//! 127.0.0.1 only, with a token only PurrDroid knows), so Android shows in
//! PurrDroid's one window instead of the emulator's:
//!
//! * `streamScreenshot` with the frames written straight into shared memory
//!   (a file in PurrDroid's folder in memory): every new frame of Android's
//!   screen, without copying it through the connection;
//! * `streamInputEvent`: one long stream for the mouse, the wheel and keys.
//!
//! gRPC runs over HTTP/2. Rather than pull in an async runtime and a whole
//! HTTP/2 stack for two calls, this is the little of HTTP/2 they need:
//! plain-text ("prior knowledge") connection, headers sent as literals,
//! response headers skipped, flow control both ways.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use purrdroid_rfb::Frame;

const SERVICE: &str = "/android.emulation.control.EmulatorController/";
const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const END_STREAM: u8 = 1;
const END_HEADERS: u8 = 4;
const PADDED: u8 = 8;
const PRIORITY: u8 = 0x20;
const OUR_WINDOW: u32 = 16 << 20;

// ---- protobuf, the few fields used ----

fn varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn field_int(out: &mut Vec<u8>, field: u32, v: i64) {
    varint(out, (field as u64) << 3);
    varint(out, v as u64);
}

fn field_bytes(out: &mut Vec<u8>, field: u32, b: &[u8]) {
    varint(out, ((field as u64) << 3) | 2);
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn read_varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *b.get(*i)?;
        *i += 1;
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// The fields of a message: (number, varint value or bytes).
fn fields(b: &[u8]) -> Vec<(u32, u64, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let Some(tag) = read_varint(b, &mut i) else { break };
        let (num, wire) = ((tag >> 3) as u32, tag & 7);
        match wire {
            0 => match read_varint(b, &mut i) {
                Some(v) => out.push((num, v, &b[0..0])),
                None => break,
            },
            2 => {
                let Some(len) = read_varint(b, &mut i) else { break };
                let end = i + len as usize;
                if end > b.len() {
                    break;
                }
                out.push((num, 0, &b[i..end]));
                i = end;
            }
            1 => i += 8,
            5 => i += 4,
            _ => break,
        }
    }
    out
}

// ---- HTTP/2, the little needed ----

struct Stream {
    /// Bytes we may still send on it.
    send_window: i64,
    closed: bool,
}

struct State {
    conn_window: i64,
    initial_window: i64,
    streams: HashMap<u32, Stream>,
    next_id: u32,
    dead: bool,
}

#[derive(Clone)]
pub struct Client {
    w: Arc<Mutex<TcpStream>>,
    state: Arc<(Mutex<State>, Condvar)>,
    authority: String,
    token: String,
    /// What to do with the bytes of each stream that gets any.
    sinks: Arc<Mutex<HashMap<u32, Box<dyn FnMut(&[u8]) + Send>>>>,
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(9 + payload.len());
    let len = payload.len() as u32;
    f.extend_from_slice(&len.to_be_bytes()[1..]);
    f.push(kind);
    f.push(flags);
    f.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// An HPACK "literal header field without indexing, new name", no Huffman.
fn header(out: &mut Vec<u8>, name: &str, value: &str) {
    fn int7(out: &mut Vec<u8>, mut v: usize) {
        if v < 127 {
            out.push(v as u8);
            return;
        }
        out.push(127);
        v -= 127;
        while v >= 128 {
            out.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }
    out.push(0);
    int7(out, name.len());
    out.extend_from_slice(name.as_bytes());
    int7(out, value.len());
    out.extend_from_slice(value.as_bytes());
}

impl Client {
    pub fn connect(port: u16, token: &str) -> io::Result<Client> {
        let s = TcpStream::connect(("127.0.0.1", port))?;
        s.set_nodelay(true)?;
        let mut w = s.try_clone()?;
        w.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")?;
        // Our receive window (16 MiB) and frame size (1 MiB).
        let mut set = Vec::new();
        set.extend_from_slice(&4u16.to_be_bytes());
        set.extend_from_slice(&OUR_WINDOW.to_be_bytes());
        set.extend_from_slice(&5u16.to_be_bytes());
        set.extend_from_slice(&(1u32 << 20).to_be_bytes());
        set.extend_from_slice(&2u16.to_be_bytes()); // no server push
        set.extend_from_slice(&0u32.to_be_bytes());
        w.write_all(&frame(SETTINGS, 0, 0, &set))?;
        w.write_all(&frame(WINDOW_UPDATE, 0, 0, &(OUR_WINDOW - 65535).to_be_bytes()))?;
        let c = Client {
            w: Arc::new(Mutex::new(w)),
            state: Arc::new((
                Mutex::new(State { conn_window: 65535, initial_window: 65535, streams: HashMap::new(), next_id: 1, dead: false }),
                Condvar::new(),
            )),
            authority: format!("127.0.0.1:{port}"),
            token: token.to_string(),
            sinks: Arc::new(Mutex::new(HashMap::new())),
        };
        let reader = c.clone();
        thread::spawn(move || {
            let _ = reader.read_loop(s);
            let (m, cv) = &*reader.state;
            m.lock().unwrap().dead = true;
            cv.notify_all();
        });
        Ok(c)
    }

    fn send_raw(&self, bytes: &[u8]) -> io::Result<()> {
        self.w.lock().unwrap().write_all(bytes)
    }

    fn read_loop(&self, mut s: TcpStream) -> io::Result<()> {
        let mut head = [0u8; 9];
        let mut payload = Vec::new();
        loop {
            s.read_exact(&mut head)?;
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let (kind, flags) = (head[3], head[4]);
            let id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
            payload.resize(len, 0);
            s.read_exact(&mut payload)?;
            match kind {
                DATA => {
                    let mut body = &payload[..];
                    if flags & PADDED != 0 && !body.is_empty() {
                        let pad = body[0] as usize;
                        body = &body[1..body.len().saturating_sub(pad)];
                    }
                    if let Some(sink) = self.sinks.lock().unwrap().get_mut(&id) {
                        sink(body);
                    }
                    if len > 0 {
                        // Give the room back at once.
                        let inc = (len as u32).to_be_bytes();
                        let mut out = frame(WINDOW_UPDATE, 0, 0, &inc);
                        if flags & END_STREAM == 0 {
                            out.extend(frame(WINDOW_UPDATE, 0, id, &inc));
                        }
                        self.send_raw(&out)?;
                    }
                    if flags & END_STREAM != 0 {
                        self.close(id);
                    }
                }
                HEADERS => {
                    // Status and trailers aren't needed; a stream that ends
                    // with its headers has failed or finished.
                    let _ = flags & (PRIORITY | PADDED);
                    if flags & END_STREAM != 0 {
                        self.close(id);
                    }
                }
                RST_STREAM => self.close(id),
                SETTINGS if flags & 1 == 0 => {
                    for kv in payload.chunks_exact(6) {
                        let key = u16::from_be_bytes([kv[0], kv[1]]);
                        let val = u32::from_be_bytes([kv[2], kv[3], kv[4], kv[5]]) as i64;
                        if key == 4 {
                            let (m, cv) = &*self.state;
                            let mut st = m.lock().unwrap();
                            let delta = val - st.initial_window;
                            st.initial_window = val;
                            for stream in st.streams.values_mut() {
                                stream.send_window += delta;
                            }
                            cv.notify_all();
                        }
                    }
                    self.send_raw(&frame(SETTINGS, 1, 0, &[]))?;
                }
                PING if flags & 1 == 0 => self.send_raw(&frame(PING, 1, 0, &payload))?,
                GOAWAY => return Err(io::Error::other("the emulator closed its control connection")),
                WINDOW_UPDATE if payload.len() == 4 => {
                    let inc = (u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff) as i64;
                    let (m, cv) = &*self.state;
                    let mut st = m.lock().unwrap();
                    if id == 0 {
                        st.conn_window += inc;
                    } else if let Some(stream) = st.streams.get_mut(&id) {
                        stream.send_window += inc;
                    }
                    cv.notify_all();
                }
                _ => {}
            }
        }
    }

    fn close(&self, id: u32) {
        let (m, cv) = &*self.state;
        if let Some(s) = m.lock().unwrap().streams.get_mut(&id) {
            s.closed = true;
        }
        self.sinks.lock().unwrap().remove(&id);
        cv.notify_all();
    }

    /// Opens a call to `method`; `sink` gets the bytes the emulator sends back.
    fn open(&self, method: &str, sink: Option<Box<dyn FnMut(&[u8]) + Send>>) -> io::Result<u32> {
        let id = {
            let (m, _) = &*self.state;
            let mut st = m.lock().unwrap();
            if st.dead {
                return Err(io::Error::other("the emulator's control connection is gone"));
            }
            let id = st.next_id;
            st.next_id += 2;
            let w = st.initial_window;
            st.streams.insert(id, Stream { send_window: w, closed: false });
            id
        };
        if let Some(s) = sink {
            self.sinks.lock().unwrap().insert(id, s);
        }
        let mut h = Vec::new();
        header(&mut h, ":method", "POST");
        header(&mut h, ":scheme", "http");
        header(&mut h, ":path", &format!("{SERVICE}{method}"));
        header(&mut h, ":authority", &self.authority);
        header(&mut h, "content-type", "application/grpc");
        header(&mut h, "te", "trailers");
        header(&mut h, "authorization", &format!("Bearer {}", self.token));
        self.send_raw(&frame(HEADERS, END_HEADERS, id, &h))?;
        Ok(id)
    }

    /// Sends one gRPC message on stream `id`, waiting for room if needed.
    fn message(&self, id: u32, msg: &[u8], last: bool) -> io::Result<()> {
        let mut body = Vec::with_capacity(5 + msg.len());
        body.push(0);
        body.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        body.extend_from_slice(msg);
        let need = body.len() as i64;
        let (m, cv) = &*self.state;
        let mut st = m.lock().unwrap();
        loop {
            if st.dead {
                return Err(io::Error::other("the emulator's control connection is gone"));
            }
            let s = st.streams.get(&id).ok_or_else(|| io::Error::other("no such call"))?;
            if s.closed {
                return Err(io::Error::other("the emulator ended the call"));
            }
            if s.send_window >= need && st.conn_window >= need {
                break;
            }
            st = cv.wait_timeout(st, Duration::from_secs(5)).unwrap().0;
        }
        st.conn_window -= need;
        st.streams.get_mut(&id).unwrap().send_window -= need;
        drop(st);
        self.send_raw(&frame(DATA, if last { END_STREAM } else { 0 }, id, &body))
    }
}

// ---- The screen ----

/// Shared memory the emulator writes each frame into (RGBA, `w` x `h`).
struct Mapped {
    ptr: *mut u8,
    len: usize,
}

unsafe impl Send for Mapped {}

impl Mapped {
    fn bytes(&self, n: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, n.min(self.len)) }
    }
}

impl Drop for Mapped {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

fn map(path: &Path, len: usize) -> io::Result<Mapped> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(true).mode(0o600).open(path)?;
    f.set_len(len as u64)?;
    use std::os::fd::AsRawFd;
    let ptr = unsafe { libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_SHARED, f.as_raw_fd(), 0) };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(Mapped { ptr: ptr as *mut u8, len })
}

/// Streams Android's screen, `w` x `h` (the emulator scales to fit), into
/// `frame`, calling `changed` after each new frame. `shm` is the file in
/// memory the frames go through.
pub fn stream_screen(c: &Client, shm: &Path, w: u32, h: u32, frame: Arc<Mutex<Frame>>, changed: impl Fn() + Send + 'static) -> io::Result<()> {
    let len = (w * h * 4) as usize;
    let mapped = map(shm, len)?;
    let mut buf: Vec<u8> = Vec::new();
    let sink = move |bytes: &[u8]| {
        buf.extend_from_slice(bytes);
        // Whole gRPC messages: a flag byte and a length, then the message.
        while buf.len() >= 5 {
            let mlen = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if buf.len() < 5 + mlen {
                break;
            }
            let msg: Vec<u8> = buf[5..5 + mlen].to_vec();
            buf.drain(..5 + mlen);
            let (mut fw, mut fh) = (0usize, 0usize);
            let mut inline: Option<Vec<u8>> = None;
            for (num, _, bytes) in fields(&msg) {
                match num {
                    1 => {
                        for (n, v, _) in fields(bytes) {
                            match n {
                                3 => fw = v as usize,
                                4 => fh = v as usize,
                                _ => {}
                            }
                        }
                    }
                    4 if !bytes.is_empty() => inline = Some(bytes.to_vec()),
                    _ => {}
                }
            }
            if fw == 0 || fh == 0 || fw * fh * 4 > len {
                continue;
            }
            let src: &[u8] = match &inline {
                Some(b) if b.len() >= fw * fh * 4 => b,
                Some(_) => continue,
                None => mapped.bytes(fw * fh * 4),
            };
            let mut f = frame.lock().unwrap();
            if f.width != fw || f.height != fh {
                f.width = fw;
                f.height = fh;
                f.pixels = vec![0; fw * fh];
                f.resized = true;
            }
            for (px, rgba) in f.pixels.iter_mut().zip(src.chunks_exact(4)) {
                *px = (rgba[0] as u32) << 16 | (rgba[1] as u32) << 8 | rgba[2] as u32;
            }
            f.dirty = Some((0, 0, fw, fh));
            drop(f);
            changed();
        }
    };
    let id = c.open("streamScreenshot", Some(Box::new(sink)))?;
    let mut req = Vec::new();
    field_int(&mut req, 1, 1); // RGBA8888
    field_int(&mut req, 3, w as i64);
    field_int(&mut req, 4, h as i64);
    // Shared memory is the faster way, but this emulator (37.2) stops soon
    // after it writes the first frame there; inline frames are kept to.
    if std::env::var_os("PURRDROID_SHM_FRAMES").is_some() {
        let mut transport = Vec::new();
        field_int(&mut transport, 1, 1); // MMAP
        field_bytes(&mut transport, 2, format!("file://{}", shm.display()).as_bytes());
        field_bytes(&mut req, 6, &transport);
    }
    c.message(id, &req, true)
}

// ---- Input ----

/// Sends the mouse, the wheel and keys to Android, on one long stream.
pub struct Input {
    c: Client,
    id: Mutex<Option<u32>>,
    /// Android's screen as the emulator measures it, for scaling.
    pub device: (u32, u32),
    /// The frames' size, which pointer positions come in.
    pub shown: Arc<Mutex<Frame>>,
}

impl Input {
    pub fn new(c: Client, device: (u32, u32), shown: Arc<Mutex<Frame>>) -> Input {
        Input { c, id: Mutex::new(None), device, shown }
    }

    fn send(&self, event: Vec<u8>) -> io::Result<()> {
        let mut id = self.id.lock().unwrap();
        if id.is_none() {
            *id = Some(self.c.open("streamInputEvent", None)?);
        }
        let r = self.c.message(id.unwrap(), &event, false);
        if r.is_err() {
            *id = None;
        }
        r
    }

    /// A key, by its Linux (evdev) code.
    pub fn key(&self, down: bool, evdev: u32) -> io::Result<()> {
        let mut k = Vec::new();
        field_int(&mut k, 1, 1); // Evdev
        field_int(&mut k, 2, if down { 0 } else { 1 });
        field_int(&mut k, 3, evdev as i64);
        let mut ev = Vec::new();
        field_bytes(&mut ev, 1, &k);
        self.send(ev)
    }

    /// A key pressed and let go (Back, Home...).
    pub fn press(&self, evdev: u32) -> io::Result<()> {
        let mut k = Vec::new();
        field_int(&mut k, 1, 1);
        field_int(&mut k, 2, 2);
        field_int(&mut k, 3, evdev as i64);
        let mut ev = Vec::new();
        field_bytes(&mut ev, 1, &k);
        self.send(ev)
    }

    /// The pointer at (`x`, `y`) of the frames shown, buttons as VNC has
    /// them (bit 0 left, 2 right, 3/4 the wheel).
    pub fn pointer(&self, buttons: u8, x: u16, y: u16) -> io::Result<()> {
        let (fw, fh) = {
            let f = self.shown.lock().unwrap();
            (f.width.max(1) as i64, f.height.max(1) as i64)
        };
        let dx = x as i64 * self.device.0 as i64 / fw;
        let dy = y as i64 * self.device.1 as i64 / fh;
        if buttons & 0b11000 != 0 {
            // The emulator gives Android touchscreens but no mouse, so the
            // wheel goes nowhere as a wheel: each notch is a short slow drag
            // instead (up the screen to go down the page), slow enough not
            // to fling. Not while a button is held.
            if buttons & 0b101 != 0 {
                return Ok(());
            }
            let step = (self.device.1 as i64 / 7).max(80);
            let dir = if buttons & 8 != 0 { 1 } else { -1 };
            let drag = |m: i64, y: i64| {
                let mut e = Vec::new();
                field_int(&mut e, 1, dx);
                field_int(&mut e, 2, y.clamp(0, self.device.1 as i64 - 1));
                field_int(&mut e, 3, m);
                let mut ev = Vec::new();
                field_bytes(&mut ev, 3, &e);
                self.send(ev)
            };
            drag(1, dy)?;
            for i in 1..=10 {
                std::thread::sleep(std::time::Duration::from_millis(16));
                drag(1, dy + dir * step * i / 10)?;
            }
            // Held still a moment at the end: a drag, not a fling.
            std::thread::sleep(std::time::Duration::from_millis(60));
            drag(1, dy + dir * step)?;
            return drag(0, dy + dir * step);
        }
        let mut m = Vec::new();
        field_int(&mut m, 1, dx);
        field_int(&mut m, 2, dy);
        field_int(&mut m, 3, ((buttons & 1) | if buttons & 4 != 0 { 2 } else { 0 }) as i64);
        let mut ev = Vec::new();
        field_bytes(&mut ev, 3, &m);
        self.send(ev)
    }
}

/// Where the frames go: a file in the session's folder in memory.
pub fn shm_path(ram: &Path) -> PathBuf {
    ram.join("tmp/screen.rgba")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protobuf_round_trip() {
        let mut inner = Vec::new();
        field_int(&mut inner, 3, 540);
        field_int(&mut inner, 4, 1200);
        let mut msg = Vec::new();
        field_bytes(&mut msg, 1, &inner);
        field_int(&mut msg, 5, 7);
        let f = fields(&msg);
        assert_eq!(f[0].0, 1);
        assert_eq!(fields(f[0].2).iter().map(|x| x.1).collect::<Vec<_>>(), vec![540, 1200]);
        assert_eq!((f[1].0, f[1].1), (5, 7));
        // Negative int32: ten bytes, as protobuf has it.
        let mut neg = Vec::new();
        field_int(&mut neg, 2, -120);
        assert_eq!(neg.len(), 11);
        assert_eq!(fields(&neg)[0].1 as i64, -120);
    }

    #[test]
    fn hpack_literal() {
        let mut h = Vec::new();
        header(&mut h, "te", "trailers");
        assert_eq!(h, b"\x00\x02te\x08trailers");
    }
}
