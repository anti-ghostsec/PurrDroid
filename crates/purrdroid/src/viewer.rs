//! PurrDroid's window: Android's screen (scaled to the window), keyboard
//! and pointer going in, files and text dropped on it sent into Android,
//! and a tray along the bottom with the files Android sent out, to drag
//! onto another window or click to Share.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use purrdroid_rfb::{evdev_to_qnum, Frame};
use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::xproto::*;
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

use crate::bridge::{Item, Net, Note, Request};
use crate::gui::{self, Keymap, Pen, Res, BLACK, GREY, WHITE};
use crate::xdnd::{self, Dropped, Under};

const TRAY_H: u16 = 26;
const TOOL_H: u16 = 28;

/// Where keys and the pointer go: QEMU's VNC socket, or the emulator's
/// control service.
pub trait Sink: Send {
    /// A key: its X keysym and its Linux (evdev) code.
    fn key(&self, down: bool, keysym: u32, evdev: u32);
    /// The pointer at (x, y) of the frames shown; buttons as VNC has them.
    fn pointer(&self, buttons: u8, x: u16, y: u16);
    /// A key pressed and let go (the toolbar's Back, Home...).
    fn press(&self, evdev: u32) {
        self.key(true, 0, evdev);
        self.key(false, 0, evdev);
    }
}

impl Sink for purrdroid_rfb::Input {
    fn key(&self, down: bool, keysym: u32, evdev: u32) {
        let _ = purrdroid_rfb::Input::key(self, down, keysym, evdev_to_qnum(evdev));
    }
    fn pointer(&self, buttons: u8, x: u16, y: u16) {
        let _ = purrdroid_rfb::Input::pointer(self, buttons, x, y);
    }
}

impl Sink for crate::emugrpc::Input {
    fn key(&self, down: bool, _keysym: u32, evdev: u32) {
        let _ = crate::emugrpc::Input::key(self, down, evdev);
    }
    fn pointer(&self, buttons: u8, x: u16, y: u16) {
        let _ = crate::emugrpc::Input::pointer(self, buttons, x, y);
    }
    fn press(&self, evdev: u32) {
        // The emulator's keyboard has Home on KEY_HOME (102), as its own
        // Home button sends it; KEY_HOMEPAGE (172) does nothing there.
        let evdev = if evdev == 172 { 102 } else { evdev };
        let _ = crate::emugrpc::Input::press(self, evdev);
    }
}

/// The toolbar's buttons: label, width, and the Linux key code each sends
/// (0: the network switch).
const TOOLS: [(&str, u16, u32); 7] =
    [("Back", 52, 158), ("Home", 52, 172), ("Apps", 52, 580), ("Power", 56, 116), ("Vol -", 50, 114), ("Vol +", 50, 115), ("", 110, 0)];
const CHIP_W: u16 = 200;

pub struct Viewer {
    pub frame: Arc<Mutex<Frame>>,
    pub input: Box<dyn Sink>,
    /// The network now, for its switch: on (Direct or Tor) or off.
    pub net: Net,
    /// Android draws its own pointer (Android-x86 in QEMU): FerroOS's is
    /// hidden over the screen. The emulator's Android draws none, so there
    /// FerroOS's stays.
    pub android_pointer: bool,
    pub wake: UnixStream,
    pub notes: Receiver<Note>,
    pub bridge: Sender<Request>,
    pub vm_done: Arc<AtomicBool>,
    pub title: String,
    pub width: u32,
    pub height: u32,
}

struct Chip {
    path: PathBuf,
    name: String,
}

struct Drag {
    chip: usize,
    from: (i16, i16),
    moving: bool,
}

/// Why the window loop ended.
pub enum End {
    /// The person closed the window.
    Closed,
    /// The virtual machine stopped.
    Stopped,
}

fn set_title(conn: &RustConnection, win: Window, net_name: Atom, utf8: Atom, title: &str) -> Res<()> {
    conn.change_property8(PropMode::REPLACE, win, AtomEnum::WM_NAME, AtomEnum::STRING, title.as_bytes())?;
    conn.change_property8(PropMode::REPLACE, win, net_name, utf8, title.as_bytes())?;
    Ok(())
}

/// Copies the part of `frame` inside `dirty` (source pixels) into the
/// window, scaled to `vw` x `vh`.
fn draw_screen_at(
    conn: &RustConnection,
    win: Window,
    gc: Gcontext,
    depth: u8,
    f: &Frame,
    dirty: (usize, usize, usize, usize),
    vw: usize,
    vh: usize,
    top: i16,
) -> Res<()> {
    if f.width == 0 || f.height == 0 || vw == 0 || vh == 0 {
        return Ok(());
    }
    let (x, y, w, h) = dirty;
    let dx0 = x * vw / f.width;
    let dy0 = y * vh / f.height;
    let dx1 = ((x + w) * vw).div_ceil(f.width).min(vw);
    let dy1 = ((y + h) * vh).div_ceil(f.height).min(vh);
    if dx1 <= dx0 || dy1 <= dy0 {
        return Ok(());
    }
    let dw = dx1 - dx0;
    let max = conn.maximum_request_bytes().saturating_sub(64);
    let rows_per = (max / (dw * 4)).max(1);
    let xs: Vec<usize> = (dx0..dx1).map(|dx| (dx * f.width / vw).min(f.width - 1)).collect();
    let mut buf = Vec::with_capacity(dw * 4 * rows_per.min(dy1 - dy0));
    let mut band_start = dy0;
    while band_start < dy1 {
        let band_end = (band_start + rows_per).min(dy1);
        buf.clear();
        for dy in band_start..band_end {
            let sy = (dy * f.height / vh).min(f.height - 1);
            let row = &f.pixels[sy * f.width..(sy + 1) * f.width];
            for &sx in &xs {
                buf.extend_from_slice(&row[sx].to_le_bytes());
            }
        }
        conn.put_image(
            ImageFormat::Z_PIXMAP,
            win,
            gc,
            dw as u16,
            (band_end - band_start) as u16,
            dx0 as i16,
            band_start as i16 + top,
            0,
            depth,
            &buf,
        )?;
        band_start = band_end;
    }
    Ok(())
}

fn invisible_cursor(conn: &RustConnection, win: Window) -> Res<Cursor> {
    let pix = conn.generate_id()?;
    conn.create_pixmap(1, pix, win, 1, 1)?;
    let cur = conn.generate_id()?;
    conn.create_cursor(cur, pix, pix, 0, 0, 0, 0, 0, 0, 0, 0)?;
    conn.free_pixmap(pix)?;
    Ok(cur)
}

fn arrow_cursor(conn: &RustConnection) -> Res<Cursor> {
    let font = conn.generate_id()?;
    conn.open_font(font, b"cursor")?;
    let cur = conn.generate_id()?;
    // 68: the left-pointing arrow.
    conn.create_glyph_cursor(cur, font, font, 68, 69, 0, 0, 0, 0xffff, 0xffff, 0xffff)?;
    Ok(cur)
}

/// Fits `w` x `h` in 90% of the screen, keeping its shape.
fn fit(w: u32, h: u32, sw: u16, sh: u16) -> (u16, u16) {
    let (mw, mh) = (sw as f64 * 0.9, sh as f64 * 0.9 - 30.0);
    let s = (mw / w as f64).min(mh / h as f64).min(1.0);
    (((w as f64 * s) as u16).max(200), ((h as f64 * s) as u16).max(150))
}

impl Viewer {
    pub fn run(self) -> Res<End> {
        let (conn, screen_num) = x11rb::connect(None)?;
        let screen = conn.setup().roots[screen_num].clone();
        let keymap = Keymap::load(&conn)?;
        let atoms = xdnd::Atoms::new(&conn)?;
        let utf8 = gui::atom(&conn, "UTF8_STRING")?;
        let net_name = gui::atom(&conn, "_NET_WM_NAME")?;
        let (mut ww, mut wh) = fit(self.width, self.height, screen.width_in_pixels, screen.height_in_pixels.saturating_sub(TOOL_H));
        wh += TOOL_H;
        ww = ww.max(TOOLS.iter().map(|t| t.1 + 4).sum::<u16>() + 8);
        let mask = EventMask::EXPOSURE
            | EventMask::STRUCTURE_NOTIFY
            | EventMask::KEY_PRESS
            | EventMask::KEY_RELEASE
            | EventMask::BUTTON_PRESS
            | EventMask::BUTTON_RELEASE
            | EventMask::POINTER_MOTION
            | EventMask::FOCUS_CHANGE;
        let (win, delete) = gui::window(&conn, screen_num, ww, wh, &self.title, mask)?;
        let cursor = if self.android_pointer { invisible_cursor(&conn, win)? } else { arrow_cursor(&conn)? };
        conn.change_window_attributes(win, &ChangeWindowAttributesAux::new().background_pixel(BLACK).cursor(cursor))?;
        // Its own name for the window manager, which remembers window sizes
        // by name: older versions left the password box's size under
        // "purrdroid", which squeezed Android into it.
        conn.change_property8(PropMode::REPLACE, win, AtomEnum::WM_CLASS, AtomEnum::STRING, b"purrdroid-android\0PurrDroid\0")?;
        xdnd::make_aware(&conn, &atoms, win)?;
        let gc = conn.generate_id()?;
        conn.create_gc(gc, win, &CreateGCAux::new().graphics_exposures(0))?;

        let tray = conn.generate_id()?;
        conn.create_window(
            screen.root_depth,
            tray,
            win,
            0,
            (wh - TRAY_H) as i16,
            ww,
            TRAY_H,
            0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &CreateWindowAux::new()
                .background_pixel(GREY)
                .cursor(arrow_cursor(&conn)?)
                .event_mask(EventMask::EXPOSURE | EventMask::BUTTON_PRESS | EventMask::BUTTON_RELEASE | EventMask::BUTTON1_MOTION),
        )?;
        xdnd::make_aware(&conn, &atoms, tray)?;
        let toolbar = conn.generate_id()?;
        conn.create_window(
            screen.root_depth,
            toolbar,
            win,
            0,
            0,
            ww,
            TOOL_H,
            0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &CreateWindowAux::new().background_pixel(GREY).cursor(arrow_cursor(&conn)?).event_mask(EventMask::EXPOSURE | EventMask::BUTTON_PRESS),
        )?;
        xdnd::make_aware(&conn, &atoms, toolbar)?;
        conn.map_window(toolbar)?;
        let pen = Pen::new(&conn, tray)?;
        let mut net_on = self.net != Net::Off;
        conn.map_window(win)?;
        conn.flush()?;

        let mut chips: Vec<Chip> = Vec::new();
        let mut drag: Option<Drag> = None;
        let mut incoming = None;
        let mut buttons: u8 = 0;
        let mut held: Vec<u8> = Vec::new();
        let mut full_redraw = true;
        let mut last_pointer = (0u16, 0u16);
        let mut status = String::new();
        let mut installs: Vec<std::sync::mpsc::Receiver<String>> = Vec::new();
        self.wake.set_nonblocking(true)?;

        let view_h = |wh: u16, chips: &Vec<Chip>| if chips.is_empty() { wh } else { wh.saturating_sub(TRAY_H) };

        let draw_tray = |chips: &Vec<Chip>, ww: u16| -> Res<()> {
            pen.fill(&conn, tray, GREY, 0, 0, ww, TRAY_H)?;
            pen.fill(&conn, tray, WHITE, 0, 0, ww, 1)?;
            let mut x = 4i16;
            for c in chips {
                pen.bevel(&conn, tray, x, 3, CHIP_W, TRAY_H - 6, false)?;
                let name: String = c.name.chars().take(((CHIP_W - 30) / pen.char_w as u16) as usize).collect();
                pen.text(&conn, tray, BLACK, GREY, x + 6, 6, &name)?;
                pen.text(&conn, tray, BLACK, GREY, x + CHIP_W as i16 - 14, 6, "x")?;
                x += CHIP_W as i16 + 4;
            }
            if chips.len() == 1 {
                pen.text(&conn, tray, BLACK, GREY, x + 6, 6, "<- from Android: drag it to a window, or click it to Share")?;
            }
            Ok(())
        };

        let draw_toolbar = |ww: u16, net_on: bool, status: &str| -> Res<()> {
            pen.fill(&conn, toolbar, GREY, 0, 0, ww, TOOL_H)?;
            pen.fill(&conn, toolbar, gui::DARK, 0, TOOL_H as i16 - 1, ww, 1)?;
            let mut x = 4i16;
            for (label, w, _) in TOOLS {
                let label = if label.is_empty() {
                    if net_on {
                        "Network: on"
                    } else {
                        "Network: off"
                    }
                } else {
                    label
                };
                pen.bevel(&conn, toolbar, x, 3, w, TOOL_H - 6, false)?;
                pen.text(
                    &conn,
                    toolbar,
                    BLACK,
                    GREY,
                    x + (w as i16 - label.len() as i16 * pen.char_w) / 2,
                    3 + (TOOL_H as i16 - 6 - pen.line_h) / 2,
                    label,
                )?;
                x += w as i16 + 4;
            }
            let room = ((ww as i16 - x - 8) / pen.char_w).max(0) as usize;
            let shown: String = status.chars().take(room).collect();
            pen.text(&conn, toolbar, gui::DARK, GREY, x + 6, 3 + (TOOL_H as i16 - 6 - pen.line_h) / 2, &shown)?;
            Ok(())
        };

        loop {
            if self.vm_done.load(Ordering::Relaxed) {
                return Ok(End::Stopped);
            }
            // Ctrl+C or a TERM: as if the window were closed.
            if crate::STOP.load(Ordering::Relaxed) {
                return Ok(End::Closed);
            }
            // Wait for X, the screen or the bridge.
            let mut fds = [
                libc::pollfd { fd: conn.stream().as_raw_fd(), events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: self.wake.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            ];
            unsafe { libc::poll(fds.as_mut_ptr(), 2, 250) };
            let mut sink = [0u8; 256];
            while matches!((&self.wake).read(&mut sink), Ok(n) if n > 0) {}

            while let Some(ev) = conn.poll_for_event()? {
                let vh = view_h(wh, &chips).saturating_sub(TOOL_H);
                let to_guest = |x: i16, y: i16| -> (u16, u16) {
                    let f = self.frame.lock().unwrap();
                    let y = y - TOOL_H as i16;
                    let gx = (x.max(0) as usize * f.width / ww.max(1) as usize).min(f.width.saturating_sub(1));
                    let gy = (y.max(0) as usize * f.height / vh.max(1) as usize).min(f.height.saturating_sub(1));
                    (gx as u16, gy as u16)
                };
                match ev {
                    Event::Expose(e) if e.count == 0 => {
                        if e.window == tray {
                            draw_tray(&chips, ww)?;
                        } else if e.window == toolbar {
                            draw_toolbar(ww, net_on, &status)?;
                        } else {
                            full_redraw = true;
                        }
                    }
                    Event::ConfigureNotify(e) if e.window == win => {
                        if (e.width, e.height) != (ww, wh) {
                            ww = e.width;
                            wh = e.height;
                            conn.configure_window(tray, &ConfigureWindowAux::new().y((wh.saturating_sub(TRAY_H)) as i32).width(ww as u32))?;
                            conn.configure_window(toolbar, &ConfigureWindowAux::new().width(ww as u32))?;
                            draw_toolbar(ww, net_on, &status)?;
                            full_redraw = true;
                        }
                    }
                    Event::ButtonPress(b) if b.event == toolbar && b.detail == 1 => {
                        let mut x = 4i16;
                        for (_, w, code) in TOOLS {
                            if (x..x + w as i16).contains(&b.event_x) {
                                if code != 0 {
                                    self.input.press(code);
                                } else {
                                    net_on = !net_on;
                                    let (tx, _rx) = std::sync::mpsc::channel();
                                    let cmd = if net_on { "cmd connectivity airplane-mode disable" } else { "cmd connectivity airplane-mode enable" };
                                    let _ = self.bridge.send(Request::Shell(cmd.into(), tx));
                                    status = if net_on { "Network on".into() } else { "Network off (airplane mode)".into() };
                                }
                                draw_toolbar(ww, net_on, &status)?;
                                break;
                            }
                            x += w as i16 + 4;
                        }
                    }
                    Event::KeyPress(k) | Event::KeyRelease(k) if k.event == win => {
                        let down = matches!(ev, Event::KeyPress(_));
                        let shift = u16::from(k.state) & u16::from(KeyButMask::SHIFT) != 0;
                        let sym = keymap.keysym(k.detail, shift);
                        self.input.key(down, sym, k.detail.saturating_sub(8) as u32);
                        if down {
                            if !held.contains(&k.detail) {
                                held.push(k.detail);
                            }
                        } else {
                            held.retain(|&c| c != k.detail);
                        }
                    }
                    Event::FocusOut(_) => {
                        // Let go of every key, or Android would think one's
                        // still held after Alt+Tab.
                        for code in held.drain(..) {
                            self.input.key(false, keymap.keysym(code, false), code.saturating_sub(8) as u32);
                        }
                    }
                    Event::ButtonPress(b) if b.event == win => {
                        let (gx, gy) = to_guest(b.event_x, b.event_y);
                        match b.detail {
                            1..=3 => {
                                buttons |= 1 << (b.detail - 1);
                                self.input.pointer(buttons, gx, gy);
                            }
                            4..=7 => {
                                let bit = 1 << (b.detail - 1);
                                self.input.pointer(buttons | bit, gx, gy);
                                self.input.pointer(buttons, gx, gy);
                            }
                            _ => {}
                        }
                        last_pointer = (gx, gy);
                    }
                    Event::ButtonRelease(b) if b.event == win => {
                        if (1..=3).contains(&b.detail) {
                            buttons &= !(1 << (b.detail - 1));
                            let (gx, gy) = to_guest(b.event_x, b.event_y);
                            self.input.pointer(buttons, gx, gy);
                        }
                    }
                    Event::MotionNotify(m) if m.event == win => {
                        let p = to_guest(m.event_x, m.event_y);
                        if p != last_pointer {
                            last_pointer = p;
                            self.input.pointer(buttons, p.0, p.1);
                        }
                    }
                    Event::ButtonPress(b) if b.event == tray && b.detail == 1 => {
                        let i = (b.event_x - 4) / (CHIP_W as i16 + 4);
                        if b.event_x >= 4 && (i as usize) < chips.len() {
                            drag = Some(Drag { chip: i as usize, from: (b.root_x, b.root_y), moving: false });
                        }
                    }
                    Event::MotionNotify(m) if m.event == tray => {
                        if let Some(d) = drag.as_mut() {
                            if (m.root_x - d.from.0).abs() + (m.root_y - d.from.1).abs() > 6 {
                                d.moving = true;
                            }
                        }
                    }
                    Event::ButtonRelease(b) if b.event == tray && b.detail == 1 => {
                        let Some(d) = drag.take() else { continue };
                        let Some(chip) = chips.get(d.chip) else { continue };
                        let within_chip = (b.event_x - 4) % (CHIP_W as i16 + 4);
                        if d.moving {
                            match xdnd::under(&conn, screen.root, &atoms) {
                                Under::Taker(target, v) if target != win && target != tray => {
                                    let ok = xdnd::drop_files(
                                        &conn,
                                        &atoms,
                                        tray,
                                        (target, v),
                                        (b.root_x as i32, b.root_y as i32),
                                        b.time,
                                        &[chip.path.clone()],
                                    );
                                    status = if ok { format!("Gave {} to that window", chip.name) } else { "That window didn't take it".into() };
                                }
                                _ => status = "Drop it on a program's window, or click it to Share".into(),
                            }
                        } else if within_chip > CHIP_W as i16 - 20 {
                            // The x: forget it (it's only in memory).
                            let c = chips.remove(d.chip);
                            if let Some(dir) = c.path.parent() {
                                let _ = std::fs::remove_dir_all(dir);
                            }
                            if chips.is_empty() {
                                conn.unmap_window(tray)?;
                            }
                            full_redraw = true;
                        } else {
                            let ok = std::process::Command::new("ferro-share").arg("--").arg(&chip.path).spawn().is_ok();
                            if !ok {
                                status = "FerroOS's Share isn't installed: drag the file onto a window instead".into();
                            }
                        }
                        set_title(&conn, win, net_name, utf8, &format!("{} - {status}", self.title))?;
                        draw_toolbar(ww, net_on, &status)?;
                        draw_tray(&chips, ww)?;
                    }
                    Event::ClientMessage(c) => {
                        if c.type_ != atoms.enter
                            && c.type_ != atoms.position
                            && c.type_ != atoms.drop
                            && c.type_ != atoms.leave
                            && c.data.as_data32()[0] == delete
                        {
                            return Ok(End::Closed);
                        }
                        xdnd::on_message(&conn, &atoms, win, &mut incoming, &c)?;
                    }
                    Event::SelectionNotify(s) => {
                        if let Some(d) = xdnd::read_drop(&conn, &atoms, win, &mut incoming, &s) {
                            let items: Vec<Item> = match d {
                                Dropped::Text(t) => vec![Item::Text(t)],
                                Dropped::Files(all) => {
                                    // APKs are installed; the rest goes to Android's share sheet.
                                    let (apks, paths): (Vec<PathBuf>, Vec<PathBuf>) =
                                        all.into_iter().partition(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("apk")));
                                    let apk_items: Vec<Item> = apks
                                        .iter()
                                        .filter_map(|p| {
                                            Some(Item::File {
                                                name: p.file_name()?.to_string_lossy().into_owned(),
                                                file: std::fs::File::open(p).ok()?,
                                            })
                                        })
                                        .collect();
                                    if !apk_items.is_empty() {
                                        let (tx, rx) = std::sync::mpsc::channel();
                                        let _ = self.bridge.send(Request::InstallApks(apk_items, tx));
                                        installs.push(rx);
                                        status = "Installing...".into();
                                        set_title(&conn, win, net_name, utf8, &format!("{} - {status}", self.title))?;
                                        draw_toolbar(ww, net_on, &status)?;
                                    }
                                    paths
                                        .iter()
                                        .filter_map(|p| {
                                            let file = std::fs::File::open(p).ok()?;
                                            file.metadata().ok()?.is_file().then_some(())?;
                                            Some(Item::File { name: p.file_name()?.to_string_lossy().into_owned(), file })
                                        })
                                        .collect()
                                }
                            };
                            if items.is_empty() && !installs.is_empty() {
                                // Only APKs: nothing to share.
                            } else if items.is_empty() {
                                status = "Only files and text can go into Android (not folders)".into();
                                set_title(&conn, win, net_name, utf8, &format!("{} - {status}", self.title))?;
                                draw_toolbar(ww, net_on, &status)?;
                            } else {
                                let _ = self.bridge.send(Request::Send(items));
                            }
                        }
                    }
                    _ => {}
                }
            }

            let mut done_installs = Vec::new();
            installs.retain(|r| match r.try_recv() {
                Ok(t) => {
                    done_installs.push(t);
                    false
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => true,
                Err(_) => false,
            });
            for t in done_installs {
                // In a box too: the toolbar may be too narrow to show it.
                let said = t.clone();
                std::thread::spawn(move || {
                    let _ = gui::message("PurrDroid: install", said.trim());
                });
                status = t.lines().collect::<Vec<_>>().join("; ");
                set_title(&conn, win, net_name, utf8, &format!("{} - {status}", self.title))?;
                draw_toolbar(ww, net_on, &status)?;
            }
            for note in self.notes.try_iter() {
                match note {
                    Note::Status(s) => {
                        status = s;
                        set_title(&conn, win, net_name, utf8, &format!("{} - {status}", self.title))?;
                        draw_toolbar(ww, net_on, &status)?;
                    }
                    Note::Outbox(path) => {
                        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                        let was_empty = chips.is_empty();
                        chips.push(Chip { path, name });
                        if was_empty {
                            conn.configure_window(tray, &ConfigureWindowAux::new().y((wh.saturating_sub(TRAY_H)) as i32).width(ww as u32))?;
                            conn.map_window(tray)?;
                            full_redraw = true;
                        }
                        draw_tray(&chips, ww)?;
                    }
                }
            }

            let vh = view_h(wh, &chips) as usize;
            let mut f = self.frame.lock().unwrap();
            if f.resized {
                f.resized = false;
                full_redraw = true;
            }
            let dirty = if full_redraw { Some((0, 0, f.width, f.height)) } else { f.dirty };
            f.dirty = None;
            if let Some(d) = dirty {
                draw_screen_at(&conn, win, gc, screen.root_depth, &f, d, ww as usize, vh.saturating_sub(TOOL_H as usize), TOOL_H as i16)?;
            }
            drop(f);
            full_redraw = false;
            conn.flush()?;
        }
    }
}
