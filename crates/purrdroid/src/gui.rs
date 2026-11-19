//! Small X11 dialogs in the Windows 95 look: the password box (when
//! PurrDroid is started from the Start menu, with no terminal to ask in)
//! and a message box. Text is drawn with the X server's own "fixed" font.

use std::error::Error;
use std::path::PathBuf;

use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::CURRENT_TIME;
use zeroize::Zeroizing;

pub type Res<T> = Result<T, Box<dyn Error>>;

pub const GREY: u32 = 0xc0c0c0;
pub const WHITE: u32 = 0xffffff;
pub const DARK: u32 = 0x808080;
pub const BLACK: u32 = 0x000000;

/// The keyboard's mapping, to turn key codes into keysyms and characters.
pub struct Keymap {
    min: u8,
    per: usize,
    syms: Vec<u32>,
}

impl Keymap {
    pub fn load(conn: &RustConnection) -> Res<Keymap> {
        let s = conn.setup();
        let (min, max) = (s.min_keycode, s.max_keycode);
        let r = conn.get_keyboard_mapping(min, max - min + 1)?.reply()?;
        Ok(Keymap { min, per: r.keysyms_per_keycode as usize, syms: r.keysyms })
    }

    /// The keysym for `code`, shifted or not.
    pub fn keysym(&self, code: u8, shift: bool) -> u32 {
        if code < self.min || self.per == 0 {
            return 0;
        }
        let i = (code - self.min) as usize * self.per;
        let base = self.syms.get(i).copied().unwrap_or(0);
        let shifted = self.syms.get(i + 1).copied().filter(|&s| s != 0).unwrap_or(base);
        if shift {
            shifted
        } else {
            base
        }
    }

    /// The character a key press types, if it types one.
    pub fn char(&self, code: u8, state: u16) -> Option<char> {
        let shift = state & u16::from(KeyButMask::SHIFT) != 0;
        let caps = state & u16::from(KeyButMask::LOCK) != 0;
        let mut sym = self.keysym(code, shift);
        if caps && (0x61..=0x7a).contains(&sym) {
            sym -= 0x20;
        } else if caps && (0x41..=0x5a).contains(&sym) && shift {
            sym += 0x20;
        }
        match sym {
            0x20..=0x7e | 0xa0..=0xff => char::from_u32(sym),
            0x0100_0000..=0x0110_ffff => char::from_u32(sym - 0x0100_0000),
            _ => None,
        }
    }
}

/// Drawing with the core "fixed" font.
pub struct Pen {
    pub gc: Gcontext,
    pub char_w: i16,
    pub ascent: i16,
    pub line_h: i16,
}

impl Pen {
    pub fn new(conn: &RustConnection, win: Window) -> Res<Pen> {
        let font = conn.generate_id()?;
        conn.open_font(font, b"fixed")?;
        let gc = conn.generate_id()?;
        conn.create_gc(gc, win, &CreateGCAux::new().font(font).graphics_exposures(0))?;
        let q = conn.query_font(font)?.reply()?;
        let char_w = q.max_bounds.character_width.max(6);
        Ok(Pen { gc, char_w, ascent: q.font_ascent, line_h: q.font_ascent + q.font_descent })
    }

    pub fn fill(&self, conn: &RustConnection, d: Drawable, color: u32, x: i16, y: i16, w: u16, h: u16) -> Res<()> {
        conn.change_gc(self.gc, &ChangeGCAux::new().foreground(color))?;
        conn.poly_fill_rectangle(d, self.gc, &[Rectangle { x, y, width: w, height: h }])?;
        Ok(())
    }

    pub fn text(&self, conn: &RustConnection, d: Drawable, fg: u32, bg: u32, x: i16, y: i16, s: &str) -> Res<()> {
        conn.change_gc(self.gc, &ChangeGCAux::new().foreground(fg).background(bg))?;
        // Latin-1 only, as the core font has it; the rest shows as '?'.
        let bytes: Vec<u8> = s.chars().map(|c| if (c as u32) < 256 { c as u8 } else { b'?' }).take(255).collect();
        conn.image_text8(d, self.gc, x, y + self.ascent, &bytes)?;
        Ok(())
    }

    /// A raised (or, `sunk`, lowered) Windows 95 edge around a rectangle.
    pub fn bevel(&self, conn: &RustConnection, d: Drawable, x: i16, y: i16, w: u16, h: u16, sunk: bool) -> Res<()> {
        let (hi, lo) = if sunk { (DARK, WHITE) } else { (WHITE, DARK) };
        self.fill(conn, d, hi, x, y, w, 1)?;
        self.fill(conn, d, hi, x, y, 1, h)?;
        self.fill(conn, d, lo, x, y + h as i16 - 1, w, 1)?;
        self.fill(conn, d, lo, x + w as i16 - 1, y, 1, h)?;
        Ok(())
    }
}

pub fn atom(conn: &RustConnection, name: &str) -> Res<Atom> {
    Ok(conn.intern_atom(false, name.as_bytes())?.reply()?.atom)
}

/// Makes a top-level window with a title, which closing asks to end.
pub fn window(conn: &RustConnection, screen: usize, w: u16, h: u16, title: &str, mask: EventMask) -> Res<(Window, Atom)> {
    let s = &conn.setup().roots[screen];
    let win = conn.generate_id()?;
    let x = (s.width_in_pixels.saturating_sub(w) / 2) as i16;
    let y = (s.height_in_pixels.saturating_sub(h) / 2) as i16;
    conn.create_window(
        s.root_depth,
        win,
        s.root,
        x,
        y,
        w,
        h,
        0,
        WindowClass::INPUT_OUTPUT,
        s.root_visual,
        &CreateWindowAux::new().background_pixel(GREY).event_mask(mask),
    )?;
    conn.change_property8(PropMode::REPLACE, win, AtomEnum::WM_NAME, AtomEnum::STRING, title.as_bytes())?;
    let utf8 = atom(conn, "UTF8_STRING")?;
    conn.change_property8(PropMode::REPLACE, win, atom(conn, "_NET_WM_NAME")?, utf8, title.as_bytes())?;
    conn.change_property8(PropMode::REPLACE, win, AtomEnum::WM_CLASS, AtomEnum::STRING, b"purrdroid\0PurrDroid\0")?;
    let protocols = atom(conn, "WM_PROTOCOLS")?;
    let delete = atom(conn, "WM_DELETE_WINDOW")?;
    conn.change_property32(PropMode::REPLACE, win, protocols, AtomEnum::ATOM, &[delete])?;
    Ok((win, delete))
}

/// Tells the window manager `win` is `w` x `h` only (a dialog laid out for
/// that size): it opens at it and isn't stretched or maximized. It's also
/// a dialog, under a name of its own: FerroOS's window manager remembers
/// each program's window size by name, and the password box's size would
/// otherwise be used for Android's window too.
pub fn fixed_size(conn: &RustConnection, win: Window, w: u16, h: u16) -> Res<()> {
    let (w, h) = (i32::from(w), i32::from(h));
    let hints = x11rb::properties::WmSizeHints { min_size: Some((w, h)), max_size: Some((w, h)), ..Default::default() };
    hints.set_normal_hints(conn, win)?;
    let dialog = atom(conn, "_NET_WM_WINDOW_TYPE_DIALOG")?;
    conn.change_property32(PropMode::REPLACE, win, atom(conn, "_NET_WM_WINDOW_TYPE")?, AtomEnum::ATOM, &[dialog])?;
    conn.change_property8(PropMode::REPLACE, win, AtomEnum::WM_CLASS, AtomEnum::STRING, b"purrdroid-dialog\0PurrDroid\0")?;
    Ok(())
}

/// A rectangle in a dialog.
#[derive(Clone, Copy)]
pub struct Area {
    pub x: i16,
    pub y: i16,
    pub w: u16,
    pub h: u16,
}

impl Area {
    pub const fn new(x: i16, y: i16, w: u16, h: u16) -> Area {
        Area { x, y, w, h }
    }
    pub fn has(&self, x: i16, y: i16) -> bool {
        x >= self.x && y >= self.y && x < self.x + self.w as i16 && y < self.y + self.h as i16
    }
}

impl Pen {
    /// A Windows 95 push button; the default one (Enter) has a black edge.
    pub fn button(&self, conn: &RustConnection, d: Drawable, r: Area, label: &str, enabled: bool, default: bool) -> Res<()> {
        self.fill(conn, d, GREY, r.x, r.y, r.w, r.h)?;
        if default {
            self.fill(conn, d, BLACK, r.x, r.y, r.w, r.h)?;
            self.fill(conn, d, GREY, r.x + 1, r.y + 1, r.w - 2, r.h - 2)?;
            self.bevel(conn, d, r.x + 1, r.y + 1, r.w - 2, r.h - 2, false)?;
        } else {
            self.bevel(conn, d, r.x, r.y, r.w, r.h, false)?;
        }
        let tw = label.chars().count() as i16 * self.char_w;
        let ty = r.y + (r.h as i16 - self.line_h) / 2;
        let tx = r.x + (r.w as i16 - tw) / 2;
        if !enabled {
            self.text(conn, d, WHITE, GREY, tx + 1, ty + 1, label)?;
        }
        self.text(conn, d, if enabled { BLACK } else { DARK }, GREY, tx, ty, label)
    }

    /// A sunken white text box showing `shown` (its end, if it's too long),
    /// with the caret after it when `caret`.
    pub fn field(&self, conn: &RustConnection, d: Drawable, r: Area, shown: &str, caret: bool) -> Res<()> {
        self.fill(conn, d, WHITE, r.x, r.y, r.w, r.h)?;
        self.bevel(conn, d, r.x, r.y, r.w, r.h, true)?;
        let room = ((r.w as i16 - 12) / self.char_w).max(1) as usize;
        let n = shown.chars().count();
        let visible: String = shown.chars().skip(n.saturating_sub(room)).collect();
        let ty = r.y + (r.h as i16 - self.line_h) / 2;
        self.text(conn, d, BLACK, WHITE, r.x + 6, ty, &visible)?;
        if caret {
            let cx = r.x + 6 + visible.chars().count() as i16 * self.char_w;
            self.fill(conn, d, BLACK, cx, r.y + 4, 1, r.h - 8)?;
        }
        Ok(())
    }
}

/// Asking X for what's on the clipboard, and reading it when it comes.
pub struct Clipboard {
    clipboard: Atom,
    utf8: Atom,
    prop: Atom,
}

impl Clipboard {
    pub fn new(conn: &RustConnection) -> Res<Clipboard> {
        Ok(Clipboard { clipboard: atom(conn, "CLIPBOARD")?, utf8: atom(conn, "UTF8_STRING")?, prop: atom(conn, "PURRDROID_PASTE")? })
    }

    /// Asks for it; a `SelectionNotify` brings it (see `read`).
    pub fn ask(&self, conn: &RustConnection, win: Window) -> Res<()> {
        conn.convert_selection(win, self.clipboard, self.utf8, self.prop, CURRENT_TIME)?;
        conn.flush()?;
        Ok(())
    }

    /// All of the text, if `sn` is the clipboard's answer (for pasting into
    /// Android).
    pub fn read_all(&self, conn: &RustConnection, win: Window, sn: &SelectionNotifyEvent) -> Option<String> {
        if sn.selection != self.clipboard {
            return None;
        }
        if sn.property == x11rb::NONE {
            return Some(String::new());
        }
        let r = conn.get_property(true, win, self.prop, AtomEnum::ANY, 0, 1 << 18).ok()?.reply().ok()?;
        Some(String::from_utf8_lossy(&r.value).into_owned())
    }

    /// The text, if `sn` is the clipboard's answer: its first line, without
    /// the line break (a password copied with one would never match).
    /// `None` if it's another selection's.
    pub fn read(&self, conn: &RustConnection, win: Window, sn: &SelectionNotifyEvent) -> Option<Zeroizing<String>> {
        if sn.selection != self.clipboard {
            return None;
        }
        let mut text = Zeroizing::new(String::new());
        if sn.property != x11rb::NONE {
            if let Ok(Ok(r)) = conn.get_property(true, win, self.prop, AtomEnum::ANY, 0, 1 << 14).map(|c| c.reply()) {
                let bytes = Zeroizing::new(r.value);
                let s = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
                text.push_str(s.split(['\n', '\r']).next().unwrap_or(""));
            }
        }
        Some(text)
    }
}

/// What the password box was answered with.
pub enum Answer {
    /// OK: the password, and the keyfiles dropped on the box.
    Ok(Zeroizing<String>, Vec<PathBuf>),
    Cancel,
    /// "Reset PurrDroid…", and the reset confirmed: wipe everything.
    Reset,
}

const PW_W: u16 = 460;
const PW_H: u16 = 250;
const PW_FIELD: Area = Area::new(14, 34, PW_W - 28 - 72, 24);
const PW_SHOW: Area = Area::new(PW_W as i16 - 14 - 64, 34, 64, 24);
const PW_LIST: Area = Area::new(14, 90, PW_W - 28, 58);
const PW_CLEAR: Area = Area::new(PW_W as i16 - 14 - 120, 156, 120, 24);
const PW_RESET: Area = Area::new(14, 210, 140, 24);
const PW_OK: Area = Area::new(PW_W as i16 - 14 - 75 - 8 - 75, 210, 75, 24);
const PW_CANCEL: Area = Area::new(PW_W as i16 - 14 - 75, 210, 75, 24);
const MENU_W: u16 = 150;
const MENU_ITEM: i16 = 20;

/// Asks for a password in a small window. Keyfiles can be dropped on it
/// (`given` are the ones given already, shown in its list). With
/// `offer_reset` it has "Reset PurrDroid…", for a forgotten password.
pub fn ask_password(title: &str, prompt: &str, given: &[PathBuf], offer_reset: bool) -> Res<Answer> {
    let (conn, screen) = x11rb::connect(None)?;
    let keymap = Keymap::load(&conn)?;
    let atoms = crate::xdnd::Atoms::new(&conn)?;
    let clip = Clipboard::new(&conn)?;
    let mask = EventMask::EXPOSURE | EventMask::KEY_PRESS | EventMask::BUTTON_PRESS | EventMask::STRUCTURE_NOTIFY;
    let (win, delete) = window(&conn, screen, PW_W, PW_H, title, mask)?;
    fixed_size(&conn, win, PW_W, PW_H)?;
    crate::xdnd::make_aware(&conn, &atoms, win)?;
    let pen = Pen::new(&conn, win)?;
    conn.map_window(win)?;
    conn.flush()?;

    let mut typed = Zeroizing::new(String::new());
    let mut dropped: Vec<PathBuf> = Vec::new();
    let mut incoming = None;
    let mut show = false;
    // The right-click menu, where it opened.
    let mut menu: Option<(i16, i16)> = None;
    let menu_items = |show: bool| ["Paste", "Clear", if show { "Hide password" } else { "Show password" }];

    let draw = |typed: &str, dropped: &[PathBuf], show: bool, menu: Option<(i16, i16)>| -> Res<()> {
        pen.fill(&conn, win, GREY, 0, 0, PW_W, PW_H)?;
        pen.text(&conn, win, BLACK, GREY, 14, 14, prompt)?;
        let shown: String = if show { typed.to_string() } else { "*".repeat(typed.chars().count()) };
        pen.field(&conn, win, PW_FIELD, &shown, true)?;
        pen.button(&conn, win, PW_SHOW, if show { "Hide" } else { "Show" }, true, false)?;

        pen.text(&conn, win, BLACK, GREY, 14, 72, "Keyfiles (files or folders; drop them on this box):")?;
        pen.fill(&conn, win, WHITE, PW_LIST.x, PW_LIST.y, PW_LIST.w, PW_LIST.h)?;
        pen.bevel(&conn, win, PW_LIST.x, PW_LIST.y, PW_LIST.w, PW_LIST.h, true)?;
        let all: Vec<&PathBuf> = given.iter().chain(dropped.iter()).collect();
        let row = |i: i16| PW_LIST.y + 5 + i * (pen.line_h + 3);
        let name = |p: &PathBuf| {
            let n = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string());
            if p.is_dir() {
                format!("{n}/  (every file in it)")
            } else {
                n
            }
        };
        if all.is_empty() {
            pen.text(&conn, win, DARK, WHITE, PW_LIST.x + 6, row(0), "None: just the password.")?;
        }
        for (i, p) in all.iter().take(3).enumerate() {
            let label = if i == 2 && all.len() > 3 { format!("...and {} more", all.len() - 2) } else { name(p) };
            let room = ((PW_LIST.w as i16 - 12) / pen.char_w) as usize;
            let label: String = label.chars().take(room).collect();
            pen.text(&conn, win, BLACK, WHITE, PW_LIST.x + 6, row(i as i16), &label)?;
        }
        pen.button(&conn, win, PW_CLEAR, "Clear keyfiles", !dropped.is_empty(), false)?;

        // A line between the keyfiles and the answers, as Windows 95 has.
        pen.fill(&conn, win, DARK, 14, 196, PW_W - 28, 1)?;
        pen.fill(&conn, win, WHITE, 14, 197, PW_W - 28, 1)?;
        if offer_reset {
            pen.button(&conn, win, PW_RESET, "Reset PurrDroid...", true, false)?;
        }
        pen.button(&conn, win, PW_OK, "OK", true, true)?;
        pen.button(&conn, win, PW_CANCEL, "Cancel", true, false)?;

        if let Some((mx, my)) = menu {
            let h = MENU_ITEM as u16 * 3 + 4;
            pen.fill(&conn, win, GREY, mx, my, MENU_W, h)?;
            pen.bevel(&conn, win, mx, my, MENU_W, h, false)?;
            for (i, item) in menu_items(show).iter().enumerate() {
                pen.text(&conn, win, BLACK, GREY, mx + 12, my + 2 + i as i16 * MENU_ITEM + (MENU_ITEM - pen.line_h) / 2, item)?;
            }
        }
        conn.flush()?;
        Ok(())
    };

    let mut focused = false;
    loop {
        let ev = conn.wait_for_event()?;
        match ev {
            Event::Expose(e) if e.count == 0 => draw(&typed, &dropped, show, menu)?,
            Event::MapNotify(_) if !focused => {
                focused = true;
                let _ = conn.set_input_focus(InputFocus::PARENT, win, CURRENT_TIME);
                conn.flush()?;
            }
            Event::KeyPress(k) => {
                let state = u16::from(k.state);
                let ctrl = state & u16::from(KeyButMask::CONTROL) != 0;
                let shift = state & u16::from(KeyButMask::SHIFT) != 0;
                let sym = keymap.keysym(k.detail, false);
                if menu.take().is_some() && sym == 0xff1b {
                    draw(&typed, &dropped, show, menu)?;
                    continue;
                }
                match sym {
                    0xff0d | 0xff8d => return Ok(Answer::Ok(typed, dropped)),
                    0xff1b => return Ok(Answer::Cancel),
                    0xff08 if ctrl => typed.clear(),
                    0xff08 => {
                        typed.pop();
                    }
                    // Ctrl+V, Shift+Insert: paste.
                    0x76 | 0x56 if ctrl => clip.ask(&conn, win)?,
                    0xff63 if shift => clip.ask(&conn, win)?,
                    // Ctrl+U: clear.
                    0x75 | 0x55 if ctrl => typed.clear(),
                    _ if ctrl => {}
                    _ => {
                        if let Some(c) = keymap.char(k.detail, state) {
                            if typed.len() < 1024 {
                                typed.push(c);
                            }
                        }
                    }
                }
                draw(&typed, &dropped, show, menu)?;
            }
            Event::ButtonPress(b) => {
                let (x, y) = (b.event_x, b.event_y);
                if let Some((mx, my)) = menu.take() {
                    let item = (y - my - 2).div_euclid(MENU_ITEM);
                    if (mx..mx + MENU_W as i16).contains(&x) && (0..3).contains(&item) && b.detail != 3 {
                        match item {
                            0 => clip.ask(&conn, win)?,
                            1 => typed.clear(),
                            _ => show = !show,
                        }
                    }
                    if b.detail != 3 {
                        draw(&typed, &dropped, show, menu)?;
                        continue;
                    }
                }
                match b.detail {
                    // Right: the menu, kept inside the box.
                    3 => {
                        let mx = x.min(PW_W as i16 - MENU_W as i16 - 2);
                        let my = y.min(PW_H as i16 - MENU_ITEM * 3 - 6);
                        menu = Some((mx, my));
                    }
                    // Middle: X's usual paste.
                    2 if PW_FIELD.has(x, y) => clip.ask(&conn, win)?,
                    1 if PW_SHOW.has(x, y) => show = !show,
                    1 if PW_CLEAR.has(x, y) => dropped.clear(),
                    1 if PW_OK.has(x, y) => return Ok(Answer::Ok(typed, dropped)),
                    1 if PW_CANCEL.has(x, y) => return Ok(Answer::Cancel),
                    1 if offer_reset && PW_RESET.has(x, y) => {
                        if confirm_reset()? {
                            return Ok(Answer::Reset);
                        }
                        let _ = conn.set_input_focus(InputFocus::PARENT, win, CURRENT_TIME);
                    }
                    _ => {}
                }
                draw(&typed, &dropped, show, menu)?;
            }
            Event::ClientMessage(c) => {
                if c.type_ == atoms.enter || c.type_ == atoms.position || c.type_ == atoms.drop || c.type_ == atoms.leave {
                    crate::xdnd::on_message(&conn, &atoms, win, &mut incoming, &c)?;
                } else if c.data.as_data32()[0] == delete {
                    return Ok(Answer::Cancel);
                }
            }
            Event::SelectionNotify(sn) => {
                if let Some(text) = clip.read(&conn, win, &sn) {
                    for c in text.chars().filter(|c| !c.is_control()) {
                        if typed.len() < 1024 {
                            typed.push(c);
                        }
                    }
                } else if let Some(crate::xdnd::Dropped::Files(files)) = crate::xdnd::read_drop(&conn, &atoms, win, &mut incoming, &sn) {
                    for f in files {
                        if !dropped.contains(&f) && !given.contains(&f) {
                            dropped.push(f);
                        }
                    }
                }
                draw(&typed, &dropped, show, menu)?;
            }
            _ => {}
        }
    }
}

const RS_W: u16 = 460;
const RS_H: u16 = 236;
const RS_FIELD: Area = Area::new(14, 150, 200, 24);
const RS_WIPE: Area = Area::new(RS_W as i16 - 14 - 130 - 8 - 75, 196, 130, 24);
const RS_CANCEL: Area = Area::new(RS_W as i16 - 14 - 75, 196, 75, 24);

/// "Reset PurrDroid": what it does, and RESET typed to go ahead. True if it was.
pub fn confirm_reset() -> Res<bool> {
    let (conn, screen) = x11rb::connect(None)?;
    let keymap = Keymap::load(&conn)?;
    let clip = Clipboard::new(&conn)?;
    let mask = EventMask::EXPOSURE | EventMask::KEY_PRESS | EventMask::BUTTON_PRESS | EventMask::STRUCTURE_NOTIFY;
    let (win, delete) = window(&conn, screen, RS_W, RS_H, "Reset PurrDroid", mask)?;
    fixed_size(&conn, win, RS_W, RS_H)?;
    let pen = Pen::new(&conn, win)?;
    conn.map_window(win)?;
    conn.flush()?;
    let lines = [
        "Reset wipes PurrDroid: Android, its apps and everything in",
        "them, and the vault with the keys to it all. It's for a",
        "forgotten password, or to start again from nothing.",
        "",
        "It can't be undone. No password or keyfile opens it again.",
        "",
        "Type RESET to go ahead:",
    ];
    let mut typed = String::new();
    let ready = |t: &str| t.trim().eq_ignore_ascii_case("reset");
    let draw = |typed: &str| -> Res<()> {
        pen.fill(&conn, win, GREY, 0, 0, RS_W, RS_H)?;
        for (i, l) in lines.iter().enumerate() {
            pen.text(&conn, win, BLACK, GREY, 14, 14 + i as i16 * (pen.line_h + 3), l)?;
        }
        pen.field(&conn, win, RS_FIELD, typed, true)?;
        pen.button(&conn, win, RS_WIPE, "Wipe everything", ready(typed), false)?;
        pen.button(&conn, win, RS_CANCEL, "Cancel", true, true)?;
        conn.flush()?;
        Ok(())
    };
    let mut focused = false;
    loop {
        match conn.wait_for_event()? {
            Event::Expose(e) if e.count == 0 => draw(&typed)?,
            Event::MapNotify(_) if !focused => {
                focused = true;
                let _ = conn.set_input_focus(InputFocus::PARENT, win, CURRENT_TIME);
                conn.flush()?;
            }
            Event::KeyPress(k) => {
                let state = u16::from(k.state);
                let ctrl = state & u16::from(KeyButMask::CONTROL) != 0;
                match keymap.keysym(k.detail, false) {
                    // Enter is Cancel's (the default) until RESET is typed.
                    0xff0d | 0xff8d => return Ok(ready(&typed)),
                    0xff1b => return Ok(false),
                    0xff08 => {
                        typed.pop();
                    }
                    0x76 | 0x56 if ctrl => clip.ask(&conn, win)?,
                    _ if ctrl => {}
                    _ => {
                        if let Some(c) = keymap.char(k.detail, state) {
                            if typed.len() < 20 {
                                typed.push(c);
                            }
                        }
                    }
                }
                draw(&typed)?;
            }
            Event::ButtonPress(b) if b.detail == 1 => {
                if RS_WIPE.has(b.event_x, b.event_y) && ready(&typed) {
                    return Ok(true);
                }
                if RS_CANCEL.has(b.event_x, b.event_y) {
                    return Ok(false);
                }
            }
            Event::SelectionNotify(sn) => {
                if let Some(t) = clip.read(&conn, win, &sn) {
                    typed.push_str(t.chars().take(20).collect::<String>().as_str());
                    draw(&typed)?;
                }
            }
            Event::ClientMessage(c) if c.data.as_data32()[0] == delete => return Ok(false),
            _ => {}
        }
    }
}

/// Runs `job` with a small window saying `text` and how far it's got
/// (`job` is told done and total), until it's finished.
pub fn working<R: Send>(title: &str, text: &str, job: impl FnOnce(&mut dyn FnMut(u64, u64)) -> R + Send) -> Res<R> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let (done, total, finished) = (AtomicU64::new(0), AtomicU64::new(0), AtomicBool::new(false));
    let (conn, screen) = x11rb::connect(None)?;
    let (w, h) = (400u16, 90u16);
    let (win, _delete) = window(&conn, screen, w, h, title, EventMask::EXPOSURE)?;
    fixed_size(&conn, win, w, h)?;
    let pen = Pen::new(&conn, win)?;
    conn.map_window(win)?;
    conn.flush()?;
    let draw = |d: u64, t: u64| -> Res<()> {
        pen.fill(&conn, win, GREY, 0, 0, w, h)?;
        pen.text(&conn, win, BLACK, GREY, 14, 14, text)?;
        let bar = Area::new(14, 44, w - 28, 22);
        pen.fill(&conn, win, WHITE, bar.x, bar.y, bar.w, bar.h)?;
        pen.bevel(&conn, win, bar.x, bar.y, bar.w, bar.h, true)?;
        if t > 0 {
            let filled = ((bar.w - 4) as u64 * d.min(t) / t) as u16;
            pen.fill(&conn, win, 0x000080, bar.x + 2, bar.y + 2, filled, bar.h - 4)?;
        }
        conn.flush()?;
        Ok(())
    };
    let result = std::thread::scope(|s| {
        let worker = s.spawn(|| {
            let r = job(&mut |d, t| {
                done.store(d, Ordering::Relaxed);
                total.store(t, Ordering::Relaxed);
            });
            finished.store(true, Ordering::Release);
            r
        });
        while !finished.load(Ordering::Acquire) {
            while let Ok(Some(_)) = conn.poll_for_event() {}
            let _ = draw(done.load(Ordering::Relaxed), total.load(Ordering::Relaxed));
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        worker.join()
    });
    let _ = conn.destroy_window(win);
    let _ = conn.flush();
    result.map_err(|_| "the work stopped part-way".into())
}

/// A small "starting" window with a moving bar, shown from its own thread
/// until dropped: for waits with nothing else on screen.
pub struct Splash {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Splash {
    pub fn show(title: &str, text: &str) -> Splash {
        use std::sync::atomic::{AtomicBool, Ordering};
        let done = std::sync::Arc::new(AtomicBool::new(false));
        let (title, text, stop) = (title.to_string(), text.to_string(), done.clone());
        let thread = std::thread::spawn(move || {
            let run = || -> Res<()> {
                let (conn, screen) = x11rb::connect(None)?;
                let (w, h) = (400u16, 90u16);
                let (win, _delete) = window(&conn, screen, w, h, &title, EventMask::EXPOSURE)?;
                fixed_size(&conn, win, w, h)?;
                let pen = Pen::new(&conn, win)?;
                conn.map_window(win)?;
                let mut at = 0u16;
                while !stop.load(Ordering::Relaxed) {
                    while let Ok(Some(_)) = conn.poll_for_event() {}
                    pen.fill(&conn, win, GREY, 0, 0, w, h)?;
                    pen.text(&conn, win, BLACK, GREY, 14, 14, &text)?;
                    let bar = Area::new(14, 44, w - 28, 22);
                    pen.fill(&conn, win, WHITE, bar.x, bar.y, bar.w, bar.h)?;
                    pen.bevel(&conn, win, bar.x, bar.y, bar.w, bar.h, true)?;
                    let room = bar.w - 4 - 60;
                    pen.fill(&conn, win, 0x000080, bar.x + 2 + (at % room) as i16, bar.y + 2, 60, bar.h - 4)?;
                    conn.flush()?;
                    at = at.wrapping_add(6);
                    std::thread::sleep(std::time::Duration::from_millis(60));
                }
                conn.destroy_window(win)?;
                conn.flush()?;
                Ok(())
            };
            let _ = run();
        });
        Splash { done, thread: Some(thread) }
    }
}

impl Drop for Splash {
    fn drop(&mut self) {
        self.done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Shows a message with an OK button, and waits for it.
pub fn message(title: &str, text: &str) -> Res<()> {
    let (conn, screen) = x11rb::connect(None)?;
    // Long lines wrapped at word breaks, 80 characters at most.
    let mut wrapped: Vec<String> = Vec::new();
    for line in text.lines() {
        let mut cur = String::new();
        for word in line.split(' ') {
            if !cur.is_empty() && cur.chars().count() + 1 + word.chars().count() > 80 {
                wrapped.push(std::mem::take(&mut cur));
            }
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
        wrapped.push(cur);
    }
    let lines: Vec<&str> = wrapped.iter().map(String::as_str).collect();
    let longest = lines.iter().map(|l| l.chars().count()).max().unwrap_or(10).clamp(20, 90) as u16;
    let (w, h) = (longest * 6 + 40, lines.len() as u16 * 14 + 80);
    let mask = EventMask::EXPOSURE | EventMask::KEY_PRESS | EventMask::BUTTON_PRESS;
    let (win, delete) = window(&conn, screen, w, h, title, mask)?;
    fixed_size(&conn, win, w, h)?;
    let pen = Pen::new(&conn, win)?;
    conn.map_window(win)?;
    conn.flush()?;
    let bx = (w / 2) as i16 - 40;
    let by = h as i16 - 40;
    loop {
        match conn.wait_for_event()? {
            Event::Expose(_) => {
                pen.fill(&conn, win, GREY, 0, 0, w, h)?;
                for (i, l) in lines.iter().enumerate() {
                    pen.text(&conn, win, BLACK, GREY, 20, 16 + i as i16 * pen.line_h.max(13), l)?;
                }
                pen.bevel(&conn, win, bx, by, 80, 26, false)?;
                pen.text(&conn, win, BLACK, GREY, bx + 34, by + 6, "OK")?;
                conn.flush()?;
            }
            Event::KeyPress(_) => return Ok(()),
            Event::ButtonPress(b) if (bx..bx + 80).contains(&b.event_x) && (by..by + 26).contains(&b.event_y) => return Ok(()),
            Event::ClientMessage(c) if c.data.as_data32()[0] == delete => return Ok(()),
            _ => {}
        }
    }
}
