//! A small VNC client for QEMU's own VNC server, reached over a Unix socket
//! in memory (`$XDG_RUNTIME_DIR`), never over the network. It asks for raw
//! 32-bit pixels (nothing to decode, which is fastest on one machine),
//! follows the screen's size as Android changes it, and sends keys as
//! scancodes (QEMU's extended key event) so every keyboard layout types
//! what its keys say. Clipboard text the server sends is ignored: nothing
//! crosses between Android and the desktop that the person didn't send.

use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const ENC_RAW: i32 = 0;
const ENC_COPYRECT: i32 = 1;
const ENC_DESKTOP_SIZE: i32 = -223;
const ENC_QEMU_EXT_KEY: i32 = -258;

/// The picture of Android's screen, `0x00RRGGBB` per pixel.
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub pixels: Vec<u32>,
    /// What changed since the window last drew (x, y, w, h), or the whole
    /// screen after a resize.
    pub dirty: Option<(usize, usize, usize, usize)>,
    pub resized: bool,
}

impl Frame {
    fn mark(&mut self, x: usize, y: usize, w: usize, h: usize) {
        self.dirty = Some(match self.dirty {
            None => (x, y, w, h),
            Some((dx, dy, dw, dh)) => {
                let (x0, y0) = (dx.min(x), dy.min(y));
                let (x1, y1) = ((dx + dw).max(x + w), (dy + dh).max(y + h));
                (x0, y0, x1 - x0, y1 - y0)
            }
        });
    }
}

/// Sends input to QEMU. Cheap to clone; usable from any thread.
#[derive(Clone)]
pub struct Input {
    stream: Arc<Mutex<UnixStream>>,
    ext_keys: Arc<AtomicBool>,
}

impl Input {
    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        self.stream.lock().unwrap().write_all(bytes)
    }

    /// A key: `keysym` (X11's) and its scancode (QEMU's numbering), used
    /// when QEMU takes scancodes.
    pub fn key(&self, down: bool, keysym: u32, qnum: u32) -> io::Result<()> {
        if self.ext_keys.load(Ordering::Relaxed) && qnum != 0 {
            let mut m = vec![255u8, 0];
            m.extend_from_slice(&(down as u16).to_be_bytes());
            m.extend_from_slice(&keysym.to_be_bytes());
            m.extend_from_slice(&qnum.to_be_bytes());
            self.send(&m)
        } else {
            let mut m = vec![4u8, down as u8, 0, 0];
            m.extend_from_slice(&keysym.to_be_bytes());
            self.send(&m)
        }
    }

    /// The pointer at (x, y) on Android's screen, with these buttons held
    /// (bit 0 left, 1 middle, 2 right, 3/4 wheel up/down).
    pub fn pointer(&self, buttons: u8, x: u16, y: u16) -> io::Result<()> {
        let mut m = vec![5u8, buttons];
        m.extend_from_slice(&x.to_be_bytes());
        m.extend_from_slice(&y.to_be_bytes());
        self.send(&m)
    }

    fn request(&self, incremental: bool, w: u16, h: u16) -> io::Result<()> {
        let mut m = vec![3u8, incremental as u8, 0, 0, 0, 0];
        m.extend_from_slice(&w.to_be_bytes());
        m.extend_from_slice(&h.to_be_bytes());
        self.send(&m)
    }
}

/// Reads from QEMU and keeps the [`Frame`] up to date.
pub struct Reader {
    r: BufReader<UnixStream>,
    input: Input,
}

fn u8_(r: &mut impl Read) -> io::Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}
fn u16_(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}
fn u32_(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}
fn skip(r: &mut impl Read, n: u64) -> io::Result<()> {
    io::copy(&mut r.take(n), &mut io::sink()).map(|_| ())
}
fn bad(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s.to_string())
}

/// Does the handshake (no password: the socket is reachable by its owner
/// only) and returns the screen, the reader and the input side.
pub fn connect(stream: UnixStream) -> io::Result<(Arc<Mutex<Frame>>, Reader, Input)> {
    let mut w = stream.try_clone()?;
    let mut r = BufReader::with_capacity(1 << 20, stream.try_clone()?);
    let mut ver = [0u8; 12];
    r.read_exact(&mut ver)?;
    if &ver[..4] != b"RFB " {
        return Err(bad("not a VNC server"));
    }
    w.write_all(b"RFB 003.008\n")?;
    let n = u8_(&mut r)?;
    if n == 0 {
        return Err(bad("the VNC server refused the connection"));
    }
    let mut types = vec![0u8; n as usize];
    r.read_exact(&mut types)?;
    if !types.contains(&1) {
        return Err(bad("the VNC server wants a password"));
    }
    w.write_all(&[1])?;
    if u32_(&mut r)? != 0 {
        return Err(bad("the VNC server refused the connection"));
    }
    w.write_all(&[1])?; // shared
    let width = u16_(&mut r)? as usize;
    let height = u16_(&mut r)? as usize;
    skip(&mut r, 16)?;
    let name_len = u32_(&mut r)?;
    skip(&mut r, name_len as u64)?;

    // 32 bits per pixel, little-endian, 0x00RRGGBB: what an X11 window
    // takes as it is.
    let mut pf = vec![0u8, 0, 0, 0, 32, 24, 0, 1];
    pf.extend_from_slice(&255u16.to_be_bytes());
    pf.extend_from_slice(&255u16.to_be_bytes());
    pf.extend_from_slice(&255u16.to_be_bytes());
    pf.extend_from_slice(&[16, 8, 0, 0, 0, 0]);
    w.write_all(&pf)?;
    let encs = [ENC_RAW, ENC_COPYRECT, ENC_DESKTOP_SIZE, ENC_QEMU_EXT_KEY];
    let mut se = vec![2u8, 0];
    se.extend_from_slice(&(encs.len() as u16).to_be_bytes());
    for e in encs {
        se.extend_from_slice(&e.to_be_bytes());
    }
    w.write_all(&se)?;

    let input = Input { stream: Arc::new(Mutex::new(w)), ext_keys: Arc::new(AtomicBool::new(false)) };
    input.request(false, width as u16, height as u16)?;
    let frame = Arc::new(Mutex::new(Frame { width, height, pixels: vec![0; width * height], dirty: None, resized: true }));
    Ok((frame, Reader { r, input: input.clone() }, input))
}

impl Reader {
    /// Reads until QEMU closes the connection. `changed` is called after
    /// each update, to wake the window.
    pub fn run(mut self, frame: Arc<Mutex<Frame>>, changed: impl Fn()) -> io::Result<()> {
        let r = &mut self.r;
        let mut row = Vec::new();
        loop {
            match u8_(r)? {
                0 => {
                    skip(r, 1)?;
                    let rects = u16_(r)?;
                    for _ in 0..rects {
                        let x = u16_(r)? as usize;
                        let y = u16_(r)? as usize;
                        let w = u16_(r)? as usize;
                        let h = u16_(r)? as usize;
                        let enc = u32_(r)? as i32;
                        match enc {
                            ENC_RAW => {
                                row.resize(w * 4, 0);
                                for yy in 0..h {
                                    r.read_exact(&mut row)?;
                                    let mut f = frame.lock().unwrap();
                                    if y + yy >= f.height || x + w > f.width {
                                        continue;
                                    }
                                    let start = (y + yy) * f.width + x;
                                    for (i, px) in row.chunks_exact(4).enumerate() {
                                        f.pixels[start + i] = u32::from_le_bytes([px[0], px[1], px[2], 0]);
                                    }
                                }
                                frame.lock().unwrap().mark(x, y, w, h);
                            }
                            ENC_COPYRECT => {
                                let sx = u16_(r)? as usize;
                                let sy = u16_(r)? as usize;
                                let mut f = frame.lock().unwrap();
                                if sx + w <= f.width && sy + h <= f.height && x + w <= f.width && y + h <= f.height {
                                    let fw = f.width;
                                    let copy: Vec<u32> = (0..h).flat_map(|yy| f.pixels[(sy + yy) * fw + sx..][..w].to_vec()).collect();
                                    for yy in 0..h {
                                        f.pixels[(y + yy) * fw + x..][..w].copy_from_slice(&copy[yy * w..(yy + 1) * w]);
                                    }
                                    f.mark(x, y, w, h);
                                }
                            }
                            ENC_DESKTOP_SIZE => {
                                let mut f = frame.lock().unwrap();
                                f.width = w;
                                f.height = h;
                                f.pixels = vec![0; w * h];
                                f.resized = true;
                                f.dirty = Some((0, 0, w, h));
                            }
                            ENC_QEMU_EXT_KEY => self.input.ext_keys.store(true, Ordering::Relaxed),
                            _ => return Err(bad("the VNC server sent an encoding it wasn't asked for")),
                        }
                    }
                    changed();
                    let (fw, fh) = {
                        let f = frame.lock().unwrap();
                        (f.width as u16, f.height as u16)
                    };
                    self.input.request(true, fw, fh)?;
                }
                1 => {
                    skip(r, 3)?;
                    let n = u16_(r)?;
                    skip(r, n as u64 * 6)?;
                }
                2 => {}
                3 => {
                    skip(r, 3)?;
                    let n = u32_(r)?;
                    skip(r, n as u64)?;
                }
                _ => return Err(bad("unknown message from the VNC server")),
            }
        }
    }
}

/// QEMU's scancode number for a Linux evdev key code (an X11 key code minus
/// 8), or 0 if there's none.
pub fn evdev_to_qnum(code: u32) -> u32 {
    match code {
        1..=83 => code,
        86 => 0x56,
        87 => 0x57,
        88 => 0x58,
        96 => 0x9c,  // keypad Enter
        97 => 0x9d,  // right Ctrl
        98 => 0xb5,  // keypad /
        99 => 0xb7,  // Print Screen
        100 => 0xb8, // right Alt
        102 => 0xc7, // Home
        103 => 0xc8, // Up
        104 => 0xc9, // Page Up
        105 => 0xcb, // Left
        106 => 0xcd, // Right
        107 => 0xcf, // End
        108 => 0xd0, // Down
        109 => 0xd1, // Page Down
        110 => 0xd2, // Insert
        111 => 0xd3, // Delete
        113 => 0xa0, // Mute
        114 => 0xae, // Volume Down
        115 => 0xb0, // Volume Up
        119 => 0xc6, // Pause
        125 => 0xdb, // left Super
        126 => 0xdc, // right Super
        127 => 0xdd, // Menu
        158 => 0xea, // Back (browser)
        172 => 0xb2, // Home page
        _ => 0,
    }
}
