//! XDND, the Linux desktop's drag and drop, both ways:
//!
//! * into PurrDroid's window: files (from the File Manager, say) or text
//!   dropped on Android's screen are sent into Android;
//! * out of it: a file that came out of Android, dragged from the tray at
//!   the bottom of the window onto another program's window.
//!
//! The dragging-out half is FerroOS File Manager's (ferro-files/xdnd.rs),
//! so both behave the same: the whole exchange happens when the button is
//! let go, and a window that never answers can't hold PurrDroid up.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use x11rb::connection::Connection;
use x11rb::protocol::xproto::*;
use x11rb::protocol::Event;
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;
use x11rb::CURRENT_TIME;

use crate::gui::{atom, Res};

const VERSION: u32 = 5;

pub struct Atoms {
    pub aware: Atom,
    pub enter: Atom,
    pub position: Atom,
    pub status: Atom,
    pub leave: Atom,
    pub drop: Atom,
    pub finished: Atom,
    pub selection: Atom,
    pub copy: Atom,
    pub type_list: Atom,
    pub uri_list: Atom,
    pub text_plain: Atom,
    pub utf8_text: Atom,
    pub utf8_string: Atom,
    pub wm_type: Atom,
    pub desktop: Atom,
    /// Where a dropped selection is put for us to read.
    pub dropped: Atom,
}

impl Atoms {
    pub fn new(conn: &RustConnection) -> Res<Self> {
        Ok(Self {
            aware: atom(conn, "XdndAware")?,
            enter: atom(conn, "XdndEnter")?,
            position: atom(conn, "XdndPosition")?,
            status: atom(conn, "XdndStatus")?,
            leave: atom(conn, "XdndLeave")?,
            drop: atom(conn, "XdndDrop")?,
            finished: atom(conn, "XdndFinished")?,
            selection: atom(conn, "XdndSelection")?,
            copy: atom(conn, "XdndActionCopy")?,
            type_list: atom(conn, "XdndTypeList")?,
            uri_list: atom(conn, "text/uri-list")?,
            text_plain: atom(conn, "text/plain")?,
            utf8_text: atom(conn, "text/plain;charset=utf-8")?,
            utf8_string: atom(conn, "UTF8_STRING")?,
            wm_type: atom(conn, "_NET_WM_WINDOW_TYPE")?,
            desktop: atom(conn, "_NET_WM_WINDOW_TYPE_DESKTOP")?,
            dropped: atom(conn, "PURRDROID_DROP")?,
        })
    }
}

fn property32(conn: &RustConnection, win: Window, prop: Atom) -> Vec<u32> {
    conn.get_property(false, win, prop, AtomEnum::ANY, 0, 1024)
        .ok()
        .and_then(|c| c.reply().ok())
        .and_then(|r| r.value32().map(|v| v.collect()))
        .unwrap_or_default()
}

fn send(conn: &RustConnection, to: Window, kind: Atom, data: [u32; 5]) {
    let _ = conn.send_event(false, to, EventMask::NO_EVENT, ClientMessageEvent::new(32, to, kind, data));
    let _ = conn.flush();
}

// ---- Dropping into PurrDroid ----

/// What's being dragged over our window, between XdndEnter and the drop.
pub struct Incoming {
    source: Window,
    /// The kind asked for at the drop: the list of files if offered, else
    /// text.
    want: Option<Atom>,
}

/// What was dropped.
pub enum Dropped {
    Files(Vec<PathBuf>),
    Text(String),
}

pub fn make_aware(conn: &RustConnection, atoms: &Atoms, win: Window) -> Res<()> {
    conn.change_property32(PropMode::REPLACE, win, atoms.aware, AtomEnum::ATOM, &[VERSION])?;
    Ok(())
}

/// Handles one XDND client message sent to our window `win`. Returns the
/// time of the drop when the selection has been asked for (it arrives as a
/// SelectionNotify, for [`read_drop`]).
pub fn on_message(conn: &RustConnection, atoms: &Atoms, win: Window, incoming: &mut Option<Incoming>, msg: &ClientMessageEvent) -> Res<()> {
    let d = msg.data.as_data32();
    if msg.type_ == atoms.enter {
        let source = d[0];
        let types: Vec<Atom> =
            if d[1] & 1 != 0 { property32(conn, source, atoms.type_list) } else { d[2..5].iter().copied().filter(|&a| a != 0).collect() };
        let want = [atoms.uri_list, atoms.utf8_text, atoms.utf8_string, atoms.text_plain].into_iter().find(|t| types.contains(t));
        *incoming = Some(Incoming { source, want });
    } else if msg.type_ == atoms.position {
        let accept = incoming.as_ref().is_some_and(|i| i.source == d[0] && i.want.is_some());
        send(conn, d[0], atoms.status, [win, accept as u32, 0, 0, if accept { atoms.copy } else { 0 }]);
    } else if msg.type_ == atoms.leave {
        *incoming = None;
    } else if msg.type_ == atoms.drop {
        match incoming.as_ref().and_then(|i| i.want.map(|w| (i.source, w))) {
            Some((_, want)) => {
                conn.convert_selection(win, atoms.selection, want, atoms.dropped, d[2])?;
                conn.flush()?;
            }
            None => {
                send(conn, d[0], atoms.finished, [win, 0, 0, 0, 0]);
                *incoming = None;
            }
        }
    }
    Ok(())
}

/// Reads what was dropped, once the selection has arrived, and tells the
/// source it's finished.
pub fn read_drop(conn: &RustConnection, atoms: &Atoms, win: Window, incoming: &mut Option<Incoming>, ev: &SelectionNotifyEvent) -> Option<Dropped> {
    if ev.selection != atoms.selection {
        return None;
    }
    let inc = incoming.take()?;
    let mut out = None;
    if ev.property != x11rb::NONE {
        if let Some(r) = conn.get_property(true, win, atoms.dropped, AtomEnum::ANY, 0, 4 << 20).ok().and_then(|c| c.reply().ok()) {
            let text = String::from_utf8_lossy(&r.value).into_owned();
            out = Some(if ev.target == atoms.uri_list { parse_uri_list(&text) } else { Dropped::Text(text) });
        }
    }
    send(conn, inc.source, atoms.finished, [win, out.is_some() as u32, if out.is_some() { atoms.copy } else { 0 }, 0, 0]);
    out
}

/// A text/uri-list as files, or (when it holds links rather than files) as
/// text.
fn parse_uri_list(text: &str) -> Dropped {
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let files: Vec<PathBuf> = lines
        .iter()
        .filter_map(|l| l.strip_prefix("file://"))
        .map(|rest| {
            // file://host/path: only the path matters.
            let path = if rest.starts_with('/') { rest } else { rest.find('/').map(|i| &rest[i..]).unwrap_or("") };
            PathBuf::from(percent_decode(path))
        })
        .filter(|p| p.is_absolute())
        .collect();
    if files.len() == lines.len() && !files.is_empty() {
        Dropped::Files(files)
    } else {
        Dropped::Text(lines.join("\n"))
    }
}

// ---- Dragging out of PurrDroid (as ferro-files does it) ----

#[derive(Debug, PartialEq, Eq)]
pub enum Under {
    Desktop,
    Taker(Window, u32),
    Other,
}

pub fn under(conn: &RustConnection, root: Window, atoms: &Atoms) -> Under {
    let Some(mut win) = conn.query_pointer(root).ok().and_then(|c| c.reply().ok()).map(|q| q.child) else { return Under::Desktop };
    if win == x11rb::NONE {
        return Under::Desktop;
    }
    for _ in 0..8 {
        if property32(conn, win, atoms.wm_type).contains(&atoms.desktop) {
            return Under::Desktop;
        }
        if let Some(&v) = property32(conn, win, atoms.aware).first() {
            return Under::Taker(win, v.min(VERSION));
        }
        match conn.query_pointer(win).ok().and_then(|c| c.reply().ok()).map(|q| q.child) {
            Some(child) if child != x11rb::NONE => win = child,
            _ => break,
        }
    }
    Under::Other
}

pub fn file_uri(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut out = String::from("file://");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn uri_list(paths: &[PathBuf]) -> String {
    paths.iter().map(|p| file_uri(p) + "\r\n").collect()
}

fn answer(conn: &RustConnection, atoms: &Atoms, req: &SelectionRequestEvent, list: &str) {
    let mut prop = req.property;
    if req.target == atoms.uri_list || req.target == atoms.text_plain {
        let body = if req.target == atoms.uri_list {
            list.to_owned()
        } else {
            list.lines().filter_map(|l| l.strip_prefix("file://")).map(|p| percent_decode(p) + "\n").collect()
        };
        let _ = conn.change_property8(PropMode::REPLACE, req.requestor, req.property, req.target, body.as_bytes());
    } else {
        prop = x11rb::NONE;
    }
    let notify = SelectionNotifyEvent {
        response_type: SELECTION_NOTIFY_EVENT,
        sequence: 0,
        time: req.time,
        requestor: req.requestor,
        selection: req.selection,
        target: req.target,
        property: prop,
    };
    let _ = conn.send_event(false, req.requestor, EventMask::NO_EVENT, notify);
    let _ = conn.flush();
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn wait_for(conn: &RustConnection, atoms: &Atoms, kind: Atom, from: Window, list: &str, within: Duration) -> Option<[u32; 5]> {
    let until = Instant::now() + within;
    while Instant::now() < until {
        match conn.poll_for_event() {
            Ok(Some(Event::ClientMessage(cm))) if cm.type_ == kind && cm.data.as_data32()[0] == from => return Some(cm.data.as_data32()),
            Ok(Some(Event::SelectionRequest(req))) if req.selection == atoms.selection => answer(conn, atoms, &req, list),
            Ok(Some(_)) => {}
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(_) => return None,
        }
    }
    None
}

/// Offers `paths` to `target`, let go at (`x`, `y`) on the screen. True if
/// it took them.
pub fn drop_files(
    conn: &RustConnection,
    atoms: &Atoms,
    source: Window,
    (target, version): (Window, u32),
    (x, y): (i32, i32),
    time: Timestamp,
    paths: &[PathBuf],
) -> bool {
    let list = uri_list(paths);
    let _ = conn.set_selection_owner(source, atoms.selection, time);
    send(conn, target, atoms.enter, [source, version << 24, atoms.uri_list, atoms.text_plain, 0]);
    let at = ((x.clamp(0, 0xffff) as u32) << 16) | (y.clamp(0, 0xffff) as u32);
    send(conn, target, atoms.position, [source, 0, at, time, atoms.copy]);
    let accepted = wait_for(conn, atoms, atoms.status, target, &list, Duration::from_millis(1500)).is_some_and(|d| d[1] & 1 == 1);
    if !accepted {
        send(conn, target, atoms.leave, [source, 0, 0, 0, 0]);
        return false;
    }
    send(conn, target, atoms.drop, [source, 0, time, 0, 0]);
    let _ = wait_for(conn, atoms, atoms.finished, target, &list, Duration::from_secs(5));
    let _ = conn.set_selection_owner(x11rb::NONE, atoms.selection, CURRENT_TIME);
    let _ = conn.flush();
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_lists() {
        match parse_uri_list("file:///home/a/My%20Pics/x.png\r\nfile://host/tmp/b\r\n") {
            Dropped::Files(f) => assert_eq!(f, vec![PathBuf::from("/home/a/My Pics/x.png"), PathBuf::from("/tmp/b")]),
            _ => panic!(),
        }
        match parse_uri_list("# comment\r\nhttps://example.org/\r\n") {
            Dropped::Text(t) => assert_eq!(t, "https://example.org/"),
            _ => panic!(),
        }
        assert_eq!(file_uri(Path::new("/a b")), "file:///a%20b");
    }
}
