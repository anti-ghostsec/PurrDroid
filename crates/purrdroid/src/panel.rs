//! PurrDroid's own windows, in the Windows 95 look, for everything a
//! terminal would otherwise be needed for:
//!
//! * [`setup`]: the first start: which Android, the password (twice) and
//!   any keyfiles, dropped on the window;
//! * [`get_android`]: for an Android from an ISO: drop the ISO on it (it's
//!   encrypted into the store, with a progress bar), then install it;
//!
//! FerroOS has no file picker: files come in the way the File Manager hands
//! them to any program, by dragging them onto the window.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use std::time::Duration;

use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::CURRENT_TIME;
use zeroize::Zeroizing;

use crate::gui::{self, Keymap, Pen, Res, BLACK, DARK, GREY, WHITE};
use crate::xdnd::{self, Dropped};

const NAVY: u32 = 0x000080;
const RED: u32 = 0x800000;

enum Ev {
    Key {
        sym: u32,
        ch: Option<char>,
    },
    Click {
        x: i16,
        y: i16,
    },
    /// Right or middle click: paste there (the clipboard is asked for; it
    /// comes as `Paste`).
    PasteAt {
        x: i16,
        y: i16,
    },
    Paste(Zeroizing<String>),
    Drop(Dropped),
    Close,
    Redraw,
    Tick,
}

struct Ui {
    conn: RustConnection,
    win: Window,
    delete: Atom,
    pen: Pen,
    keymap: Keymap,
    atoms: xdnd::Atoms,
    incoming: Option<xdnd::Incoming>,
    clip: gui::Clipboard,
    w: u16,
    h: u16,
}

#[derive(Clone, Copy)]
struct R {
    x: i16,
    y: i16,
    w: u16,
    h: u16,
}

impl R {
    fn hit(&self, x: i16, y: i16) -> bool {
        x >= self.x && y >= self.y && x < self.x + self.w as i16 && y < self.y + self.h as i16
    }
}

impl Ui {
    fn new(title: &str, w: u16, h: u16) -> Res<Ui> {
        let (conn, screen) = x11rb::connect(None)?;
        let keymap = Keymap::load(&conn)?;
        let atoms = xdnd::Atoms::new(&conn)?;
        let mask = EventMask::EXPOSURE | EventMask::KEY_PRESS | EventMask::BUTTON_PRESS | EventMask::STRUCTURE_NOTIFY;
        let (win, delete) = gui::window(&conn, screen, w, h, title, mask)?;
        gui::fixed_size(&conn, win, w, h)?;
        let clip = gui::Clipboard::new(&conn)?;
        xdnd::make_aware(&conn, &atoms, win)?;
        let pen = Pen::new(&conn, win)?;
        conn.map_window(win)?;
        conn.flush()?;
        Ok(Ui { conn, win, delete, pen, keymap, atoms, incoming: None, clip, w, h })
    }

    fn clear(&self) -> Res<()> {
        self.pen.fill(&self.conn, self.win, GREY, 0, 0, self.w, self.h)
    }

    fn text(&self, x: i16, y: i16, s: &str) -> Res<()> {
        self.pen.text(&self.conn, self.win, BLACK, GREY, x, y, s)
    }

    fn text_color(&self, x: i16, y: i16, color: u32, s: &str) -> Res<()> {
        self.pen.text(&self.conn, self.win, color, GREY, x, y, s)
    }

    fn button(&self, r: R, label: &str, enabled: bool) -> Res<()> {
        self.pen.fill(&self.conn, self.win, GREY, r.x, r.y, r.w, r.h)?;
        self.pen.bevel(&self.conn, self.win, r.x, r.y, r.w, r.h, false)?;
        self.pen.bevel(&self.conn, self.win, r.x + 1, r.y + 1, r.w - 2, r.h - 2, false)?;
        let tx = r.x + (r.w as i16 - label.chars().count() as i16 * self.pen.char_w) / 2;
        self.pen.text(&self.conn, self.win, if enabled { BLACK } else { DARK }, GREY, tx, r.y + (r.h as i16 - self.pen.line_h) / 2, label)
    }

    fn field(&self, r: R, shown: &str, focused: bool) -> Res<()> {
        self.pen.fill(&self.conn, self.win, WHITE, r.x, r.y, r.w, r.h)?;
        self.pen.bevel(&self.conn, self.win, r.x, r.y, r.w, r.h, true)?;
        let max = ((r.w as i16 - 12) / self.pen.char_w).max(1) as usize;
        let s: String = shown.chars().take(max).collect();
        self.pen.text(&self.conn, self.win, BLACK, WHITE, r.x + 5, r.y + (r.h as i16 - self.pen.line_h) / 2, &s)?;
        if focused {
            let cx = r.x + 5 + s.chars().count() as i16 * self.pen.char_w;
            self.pen.fill(&self.conn, self.win, BLACK, cx, r.y + 4, 1, r.h - 8)?;
        }
        Ok(())
    }

    fn radio(&self, x: i16, y: i16, label: &str, on: bool, enabled: bool) -> Res<()> {
        self.pen.fill(&self.conn, self.win, WHITE, x, y, 12, 12)?;
        self.pen.bevel(&self.conn, self.win, x, y, 12, 12, true)?;
        if on {
            self.pen.fill(&self.conn, self.win, BLACK, x + 4, y + 4, 4, 4)?;
        }
        self.pen.text(&self.conn, self.win, if enabled { BLACK } else { DARK }, GREY, x + 18, y, label)
    }

    /// A sunken area that says what to drop on it.
    fn drop_area(&self, r: R, lines: &[&str]) -> Res<()> {
        self.pen.fill(&self.conn, self.win, WHITE, r.x, r.y, r.w, r.h)?;
        self.pen.bevel(&self.conn, self.win, r.x, r.y, r.w, r.h, true)?;
        let total = lines.len() as i16 * (self.pen.line_h + 3);
        for (i, l) in lines.iter().enumerate() {
            let tx = r.x + (r.w as i16 - l.chars().count() as i16 * self.pen.char_w) / 2;
            let ty = r.y + (r.h as i16 - total) / 2 + i as i16 * (self.pen.line_h + 3);
            self.pen.text(&self.conn, self.win, if i == 0 { BLACK } else { DARK }, WHITE, tx, ty, l)?;
        }
        Ok(())
    }

    fn progress(&self, r: R, part: f64) -> Res<()> {
        self.pen.fill(&self.conn, self.win, WHITE, r.x, r.y, r.w, r.h)?;
        self.pen.bevel(&self.conn, self.win, r.x, r.y, r.w, r.h, true)?;
        let inner = ((r.w - 4) as f64 * part.clamp(0.0, 1.0)) as u16;
        let mut x = r.x + 2;
        // Windows 95's blocks.
        while x + 8 <= r.x + 2 + inner as i16 {
            self.pen.fill(&self.conn, self.win, NAVY, x, r.y + 2, 7, r.h - 4)?;
            x += 9;
        }
        Ok(())
    }

    fn flush(&self) -> Res<()> {
        self.conn.flush()?;
        Ok(())
    }

    fn focus(&self) {
        let _ = self.conn.set_input_focus(InputFocus::PARENT, self.win, CURRENT_TIME);
        let _ = self.conn.flush();
    }

    /// The next thing that happened, or `Tick` after `wait` with nothing.
    fn next(&mut self, wait: Duration) -> Res<Ev> {
        loop {
            if let Some(ev) = self.conn.poll_for_event()? {
                match ev {
                    Event::Expose(e) if e.count == 0 => return Ok(Ev::Redraw),
                    Event::MapNotify(_) => {
                        self.focus();
                        return Ok(Ev::Redraw);
                    }
                    Event::KeyPress(k) => {
                        let shift = u16::from(k.state) & u16::from(KeyButMask::SHIFT) != 0;
                        let ctrl = u16::from(k.state) & u16::from(KeyButMask::CONTROL) != 0;
                        let sym = self.keymap.keysym(k.detail, shift);
                        // Ctrl+V and Shift+Insert paste; other Ctrl keys type nothing.
                        if (ctrl && (sym == 0x76 || sym == 0x56)) || (shift && sym == 0xff63) {
                            self.clip.ask(&self.conn, self.win)?;
                            continue;
                        }
                        if ctrl && sym < 0xff00 {
                            continue;
                        }
                        let ch = self.keymap.char(k.detail, u16::from(k.state));
                        return Ok(Ev::Key { sym, ch });
                    }
                    Event::ButtonPress(b) if b.detail == 1 => return Ok(Ev::Click { x: b.event_x, y: b.event_y }),
                    Event::ButtonPress(b) if b.detail == 2 || b.detail == 3 => return Ok(Ev::PasteAt { x: b.event_x, y: b.event_y }),
                    Event::ClientMessage(c) => {
                        let a = &self.atoms;
                        if c.type_ == a.enter || c.type_ == a.position || c.type_ == a.drop || c.type_ == a.leave {
                            xdnd::on_message(&self.conn, &self.atoms, self.win, &mut self.incoming, &c)?;
                        } else if c.data.as_data32()[0] == self.delete {
                            return Ok(Ev::Close);
                        }
                    }
                    Event::SelectionNotify(sn) => {
                        if let Some(text) = self.clip.read(&self.conn, self.win, &sn) {
                            return Ok(Ev::Paste(text));
                        }
                        if let Some(d) = xdnd::read_drop(&self.conn, &self.atoms, self.win, &mut self.incoming, &sn) {
                            return Ok(Ev::Drop(d));
                        }
                    }
                    _ => {}
                }
                continue;
            }
            let mut fds = [libc::pollfd { fd: self.conn.stream().as_raw_fd(), events: libc::POLLIN, revents: 0 }];
            let n = unsafe { libc::poll(fds.as_mut_ptr(), 1, wait.as_millis() as i32) };
            if n == 0 {
                return Ok(Ev::Tick);
            }
        }
    }
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut out = Vec::new();
    for para in s.lines() {
        let mut line = String::new();
        for word in para.split_whitespace() {
            if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > width {
                out.push(std::mem::take(&mut line));
            }
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
        out.push(line);
    }
    out
}

fn keyfile_label(n: usize) -> String {
    match n {
        0 => "Keyfiles: none. Drop files on this window to use them as keyfiles.".into(),
        1 => "Keyfiles: 1. Drop more on this window, or Clear.".into(),
        n => format!("Keyfiles: {n}. Drop more on this window, or Clear."),
    }
}

// ---- Setup ----

pub enum Engine {
    /// The emulator, with this system image (its path in the SDK).
    Emulator(String),
    Iso,
}

/// An Android the emulator can run, found in the SDK.
pub struct Image {
    pub path: String,
    pub label: String,
    pub note: String,
}

pub struct Setup {
    pub engine: Engine,
    pub password: Zeroizing<String>,
    pub keyfiles: Vec<PathBuf>,
}

/// The first start. `images` are the Androids found in the SDK for the
/// emulator, the first one chosen to begin with.
pub fn setup(images: &[Image]) -> Res<Option<Setup>> {
    // A row per image (one, saying the SDK's needed, if there are none), then the ISO.
    let rows = images.len().clamp(1, 4) as i16;
    let dy = (rows - 1) * 24;
    let (w, h) = (520u16, 400u16 + dy as u16);
    let mut ui = Ui::new("Set up PurrDroid", w, h)?;
    let iso = rows as usize;
    let mut choice = if images.is_empty() { iso } else { 0 };
    // Never grown past what they're made with: see gui::TYPED_ROOM.
    let mut fields = [Zeroizing::new(String::with_capacity(crate::gui::TYPED_ROOM)), Zeroizing::new(String::with_capacity(crate::gui::TYPED_ROOM))];
    let mut focus = 0usize;
    let mut keyfiles: Vec<PathBuf> = Vec::new();
    let mut error = String::new();
    let f1 = R { x: 150, y: 176 + dy, w: 350, h: 22 };
    let f2 = R { x: 150, y: 206 + dy, w: 350, h: 22 };
    let clear = R { x: 420, y: 238 + dy, w: 80, h: 22 };
    let ok = R { x: w as i16 - 190, y: h as i16 - 40, w: 80, h: 26 };
    let cancel = R { x: w as i16 - 100, y: h as i16 - 40, w: 80, h: 26 };
    loop {
        // Draw.
        ui.clear()?;
        ui.text(16, 14, "PurrDroid keeps Android encrypted with a password and any keyfiles.")?;
        ui.text(16, 30, "Without them there's no way back in: write the password down.")?;
        ui.text(16, 58, "Which Android?")?;
        if images.is_empty() {
            ui.radio(28, 80, "Android in the emulator (needs the Android SDK's emulator)", false, false)?;
        }
        for (i, img) in images.iter().take(4).enumerate() {
            ui.radio(28, 80 + i as i16 * 24, &img.label, choice == i, true)?;
        }
        ui.radio(28, 80 + rows * 24, "Android from an ISO file (BlissOS, with Google Play or microG)", choice == iso, true)?;
        let note = match images.get(choice) {
            Some(img) => img.note.as_str(),
            None => "You drop the ISO on PurrDroid next; it's encrypted into the store.",
        };
        ui.text_color(46, 102 + rows * 24, DARK, note)?;
        ui.text(16, 180 + dy, "Password:")?;
        ui.text(16, 210 + dy, "Again:")?;
        ui.field(f1, &"*".repeat(fields[0].chars().count()), focus == 0)?;
        ui.field(f2, &"*".repeat(fields[1].chars().count()), focus == 1)?;
        ui.text(16, 242 + dy, &keyfile_label(keyfiles.len()))?;
        if !keyfiles.is_empty() {
            ui.button(clear, "Clear", true)?;
        }
        for (i, l) in wrap(&error, 80).iter().enumerate() {
            ui.text_color(16, 280 + dy + i as i16 * 16, RED, l)?;
        }
        ui.button(ok, "Create", true)?;
        ui.button(cancel, "Cancel", true)?;
        ui.flush()?;

        let mut submit = false;
        match ui.next(Duration::from_secs(3600))? {
            Ev::Close => return Ok(None),
            Ev::Key { sym, ch } => match sym {
                0xff1b => return Ok(None),
                0xff09 | 0xfe20 => focus = 1 - focus,
                0xff0d | 0xff8d => {
                    if focus == 0 {
                        focus = 1;
                    } else {
                        submit = true;
                    }
                }
                0xff08 => {
                    fields[focus].pop();
                }
                _ => {
                    if let Some(c) = ch {
                        if fields[focus].len() < 1024 {
                            fields[focus].push(c);
                        }
                    }
                }
            },
            Ev::Click { x, y } => {
                if f1.hit(x, y) {
                    focus = 0;
                } else if f2.hit(x, y) {
                    focus = 1;
                } else if x < 480 && (78..78 + (rows + 1) * 24).contains(&y) {
                    let row = ((y - 78) / 24) as usize;
                    if row == iso || row < images.len() {
                        choice = row;
                    }
                } else if clear.hit(x, y) {
                    keyfiles.clear();
                } else if ok.hit(x, y) {
                    submit = true;
                } else if cancel.hit(x, y) {
                    return Ok(None);
                }
            }
            Ev::PasteAt { x, y } => {
                if f1.hit(x, y) || f2.hit(x, y) {
                    focus = usize::from(f2.hit(x, y));
                    ui.clip.ask(&ui.conn, ui.win)?;
                }
            }
            Ev::Paste(text) => {
                for c in text.chars().filter(|c| !c.is_control()) {
                    if fields[focus].len() < 1024 {
                        fields[focus].push(c);
                    }
                }
            }
            Ev::Drop(Dropped::Files(f)) => {
                for p in f {
                    if !keyfiles.contains(&p) {
                        keyfiles.push(p);
                    }
                }
            }
            _ => {}
        }
        if submit {
            if fields[0].chars().count() < 8 && keyfiles.is_empty() {
                error = "Use at least 8 characters (a few words is best), or a keyfile as well.".into();
            } else if *fields[0] != *fields[1] {
                error = "The two passwords don't match.".into();
                fields[1].clear();
                focus = 1;
            } else {
                let password = std::mem::take(&mut fields[0]);
                return Ok(Some(Setup { engine: images.get(choice).map_or(Engine::Iso, |i| Engine::Emulator(i.path.clone())), password, keyfiles }));
            }
        }
    }
}

// ---- Get Android (ISO) ----

pub enum Next {
    Install,
    Start,
    Quit,
}

/// For an Android from an ISO that isn't installed yet. `has_iso` says
/// whether one was imported already; `import` encrypts a dropped ISO into
/// the store, counting bytes done into the counter (it's run on its own
/// thread while the window shows the progress).
pub fn get_android(mut has_iso: bool, installed: bool, import: &mut (dyn FnMut(&Path, &AtomicU64) -> Res<()> + Send)) -> Res<Next> {
    let (w, h) = (520u16, 300u16);
    let mut ui = Ui::new("PurrDroid: get Android", w, h)?;
    let area = R { x: 16, y: 60, w: w - 32, h: 110 };
    let install = R { x: 16, y: h as i16 - 44, w: 170, h: 28 };
    let start = R { x: 196, y: h as i16 - 44, w: 200, h: 28 };
    let quit = R { x: w as i16 - 106, y: h as i16 - 44, w: 90, h: 28 };
    let mut message = String::new();
    loop {
        ui.clear()?;
        ui.text(16, 14, "Android isn't installed yet. Get a BlissOS ISO (x86_64) from its")?;
        ui.text(16, 30, "website, then drop it here. Next, Install opens its installer.")?;
        if has_iso {
            ui.drop_area(area, &["The ISO is in the encrypted store.", "Drop another ISO here to use that one instead."])?;
        } else {
            ui.drop_area(area, &["Drop the Android ISO here", "It's encrypted into PurrDroid's store; the original stays where it is."])?;
        }
        for (i, l) in wrap(&message, 80).iter().enumerate().take(3) {
            ui.text_color(16, 182 + i as i16 * 16, RED, l)?;
        }
        ui.button(install, "Install Android", has_iso)?;
        // Nothing to start until the installer has run.
        ui.button(start, "It's installed: start it", installed)?;
        ui.button(quit, "Quit", true)?;
        ui.flush()?;
        match ui.next(Duration::from_secs(3600))? {
            Ev::Close | Ev::Key { sym: 0xff1b, .. } => return Ok(Next::Quit),
            Ev::Click { x, y } if install.hit(x, y) && has_iso => return Ok(Next::Install),
            Ev::Click { x, y } if start.hit(x, y) && installed => return Ok(Next::Start),
            Ev::Click { x, y } if quit.hit(x, y) => return Ok(Next::Quit),
            Ev::Drop(Dropped::Files(files)) => {
                let Some(iso) = files.into_iter().next() else { continue };
                let total = std::fs::metadata(&iso).map(|m| m.len()).unwrap_or(1).max(1);
                let done = AtomicU64::new(0);
                let finished = AtomicBool::new(false);
                let mut result: Option<Res<()>> = None;
                std::thread::scope(|s| -> Res<()> {
                    let job = s.spawn(|| {
                        let r = import(&iso, &done).map_err(|e| e.to_string());
                        finished.store(true, Ordering::Relaxed);
                        r
                    });
                    while !finished.load(Ordering::Relaxed) {
                        let part = done.load(Ordering::Relaxed) as f64 / total as f64;
                        ui.clear()?;
                        ui.text(16, 14, "Encrypting the ISO into PurrDroid's store...")?;
                        ui.progress(R { x: 16, y: 60, w: w - 32, h: 24 }, part)?;
                        ui.text(16, 96, &format!("{}%", (part * 100.0) as u32))?;
                        ui.flush()?;
                        let _ = ui.next(Duration::from_millis(200))?;
                    }
                    result = Some(job.join().map_err(|_| "the import stopped")?.map_err(Into::into));
                    Ok(())
                })?;
                match result.unwrap() {
                    Ok(()) => {
                        has_iso = true;
                        message = format!(
                            "Encrypted {} (you can delete the original). Next: press Install Android, and pick Installation in its menu.",
                            iso.file_name().unwrap_or_default().to_string_lossy()
                        );
                    }
                    Err(e) => message = format!("Couldn't import it: {e}"),
                }
            }
            _ => {}
        }
    }
}
