//! A small NBD server: hands PurrDroid's encrypted disks to QEMU over a Unix
//! socket, so QEMU only ever sees decrypted sectors in memory and never
//! touches the disk files (it isn't given the keys, or the files).
//!
//! It speaks the "fixed newstyle" handshake with `NBD_OPT_GO` (and the older
//! `NBD_OPT_EXPORT_NAME`), and simple replies: read, write, flush, trim and
//! write-zeroes. One connection per export, served on its own thread.

use std::collections::HashMap;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;

use purrdroid_store::BlockDev;

const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
const REPLY_MAGIC: u64 = 0x0003_e889_0455_65a9;
const REQUEST_MAGIC: u32 = 0x2560_9513;
const SIMPLE_REPLY: u32 = 0x6744_6698;

const FLAG_FIXED_NEWSTYLE: u16 = 1;
const FLAG_NO_ZEROES: u16 = 2;

const OPT_EXPORT_NAME: u32 = 1;
const OPT_ABORT: u32 = 2;
const OPT_LIST: u32 = 3;
const OPT_INFO: u32 = 6;
const OPT_GO: u32 = 7;

const REP_ACK: u32 = 1;
const REP_SERVER: u32 = 2;
const REP_INFO: u32 = 3;
const REP_ERR_UNSUP: u32 = 0x8000_0001;
const REP_ERR_UNKNOWN: u32 = 0x8000_0006;
const REP_ERR_INVALID: u32 = 0x8000_0003;

const INFO_EXPORT: u16 = 0;
const INFO_BLOCK_SIZE: u16 = 3;

const TF_HAS_FLAGS: u16 = 1;
const TF_READ_ONLY: u16 = 2;
const TF_SEND_FLUSH: u16 = 4;
const TF_SEND_FUA: u16 = 8;
const TF_SEND_TRIM: u16 = 0x20;
const TF_SEND_WRITE_ZEROES: u16 = 0x40;

const CMD_READ: u16 = 0;
const CMD_WRITE: u16 = 1;
const CMD_DISC: u16 = 2;
const CMD_FLUSH: u16 = 3;
const CMD_TRIM: u16 = 4;
const CMD_WRITE_ZEROES: u16 = 6;
const CMD_FLAG_FUA: u16 = 1;

const EIO: u32 = 5;
const EPERM: u32 = 1;
const EINVAL: u32 = 22;
const ENOSPC: u32 = 28;

/// The largest request accepted (QEMU's own limit is 32 MiB).
const MAX_REQUEST: u32 = 32 << 20;

pub type Export = Arc<Mutex<dyn BlockDev>>;
pub type Exports = Arc<HashMap<String, Export>>;

/// Serves `exports` on `listener` until the listener fails. Each connection
/// gets its own thread. Any error on one connection only ends that one.
pub fn serve(listener: UnixListener, exports: Exports) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { break };
        let exports = exports.clone();
        thread::spawn(move || {
            if let Err(e) = handle(stream, &exports) {
                if e.kind() != io::ErrorKind::UnexpectedEof {
                    eprintln!("purrdroid: disk connection ended: {e}");
                }
            }
        });
    }
}

fn read_u16(r: &mut impl Read) -> io::Result<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}
fn read_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}
fn read_u64(r: &mut impl Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(u64::from_be_bytes(b))
}

fn opt_reply(w: &mut impl Write, opt: u32, kind: u32, data: &[u8]) -> io::Result<()> {
    w.write_all(&REPLY_MAGIC.to_be_bytes())?;
    w.write_all(&opt.to_be_bytes())?;
    w.write_all(&kind.to_be_bytes())?;
    w.write_all(&(data.len() as u32).to_be_bytes())?;
    w.write_all(data)
}

fn transmission_flags(disk: &dyn BlockDev) -> u16 {
    let mut f = TF_HAS_FLAGS | TF_SEND_FLUSH | TF_SEND_FUA;
    if disk.read_only() {
        f |= TF_READ_ONLY;
    } else {
        f |= TF_SEND_TRIM | TF_SEND_WRITE_ZEROES;
    }
    f
}

fn handle(stream: UnixStream, exports: &Exports) -> io::Result<()> {
    let mut r = BufReader::with_capacity(1 << 20, stream.try_clone()?);
    let mut w = BufWriter::with_capacity(1 << 20, stream);
    w.write_all(&NBDMAGIC.to_be_bytes())?;
    w.write_all(&IHAVEOPT.to_be_bytes())?;
    w.write_all(&(FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES).to_be_bytes())?;
    w.flush()?;
    let client_flags = read_u32(&mut r)?;
    let no_zeroes = client_flags & FLAG_NO_ZEROES as u32 != 0;

    // Option haggling, until an export is picked.
    let disk = loop {
        if read_u64(&mut r)? != IHAVEOPT {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad option magic"));
        }
        let opt = read_u32(&mut r)?;
        let len = read_u32(&mut r)?;
        if len > 64 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "option too long"));
        }
        let mut data = vec![0u8; len as usize];
        r.read_exact(&mut data)?;
        match opt {
            OPT_EXPORT_NAME => {
                let name = String::from_utf8_lossy(&data).into_owned();
                let Some(disk) = exports.get(&name) else {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "no such export"));
                };
                let d = disk.lock().unwrap();
                w.write_all(&d.len().to_be_bytes())?;
                w.write_all(&transmission_flags(&*d).to_be_bytes())?;
                if !no_zeroes {
                    w.write_all(&[0u8; 124])?;
                }
                w.flush()?;
                drop(d);
                break disk.clone();
            }
            OPT_ABORT => {
                opt_reply(&mut w, opt, REP_ACK, &[])?;
                w.flush()?;
                return Ok(());
            }
            OPT_LIST => {
                for name in exports.keys() {
                    let mut d = (name.len() as u32).to_be_bytes().to_vec();
                    d.extend_from_slice(name.as_bytes());
                    opt_reply(&mut w, opt, REP_SERVER, &d)?;
                }
                opt_reply(&mut w, opt, REP_ACK, &[])?;
            }
            OPT_INFO | OPT_GO => {
                if data.len() < 6 {
                    opt_reply(&mut w, opt, REP_ERR_INVALID, &[])?;
                    w.flush()?;
                    continue;
                }
                let nlen = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
                let name = data.get(4..4 + nlen).map(|n| String::from_utf8_lossy(n).into_owned());
                match name.as_ref().and_then(|n| exports.get(n)) {
                    None => opt_reply(&mut w, opt, REP_ERR_UNKNOWN, &[])?,
                    Some(disk) => {
                        let d = disk.lock().unwrap();
                        let mut info = INFO_EXPORT.to_be_bytes().to_vec();
                        info.extend_from_slice(&d.len().to_be_bytes());
                        info.extend_from_slice(&transmission_flags(&*d).to_be_bytes());
                        opt_reply(&mut w, opt, REP_INFO, &info)?;
                        // Sector-sized requests save a read-modify-write
                        // here; smaller ones still work.
                        let mut bs = INFO_BLOCK_SIZE.to_be_bytes().to_vec();
                        bs.extend_from_slice(&1u32.to_be_bytes());
                        bs.extend_from_slice(&4096u32.to_be_bytes());
                        bs.extend_from_slice(&MAX_REQUEST.to_be_bytes());
                        opt_reply(&mut w, opt, REP_INFO, &bs)?;
                        opt_reply(&mut w, opt, REP_ACK, &[])?;
                        drop(d);
                        if opt == OPT_GO {
                            w.flush()?;
                            break disk.clone();
                        }
                    }
                }
            }
            _ => opt_reply(&mut w, opt, REP_ERR_UNSUP, &[])?,
        }
        w.flush()?;
    };

    // Transmission.
    let mut buf = Vec::new();
    loop {
        if read_u32(&mut r)? != REQUEST_MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad request magic"));
        }
        let flags = read_u16(&mut r)?;
        let cmd = read_u16(&mut r)?;
        let handle = read_u64(&mut r)?;
        let offset = read_u64(&mut r)?;
        let len = read_u32(&mut r)?;
        if len > MAX_REQUEST {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "request too large"));
        }
        let reply = |w: &mut BufWriter<UnixStream>, err: u32| -> io::Result<()> {
            w.write_all(&SIMPLE_REPLY.to_be_bytes())?;
            w.write_all(&err.to_be_bytes())?;
            w.write_all(&handle.to_be_bytes())
        };
        let errno = |e: &io::Error| match e.kind() {
            io::ErrorKind::PermissionDenied => EPERM,
            io::ErrorKind::InvalidInput => EINVAL,
            io::ErrorKind::StorageFull => ENOSPC,
            _ => EIO,
        };
        match cmd {
            CMD_READ => {
                buf.resize(len as usize, 0);
                let res = disk.lock().unwrap().read_at(offset, &mut buf);
                match res {
                    Ok(()) => {
                        reply(&mut w, 0)?;
                        w.write_all(&buf)?;
                    }
                    Err(e) => {
                        eprintln!("purrdroid: read at {offset}: {e}");
                        reply(&mut w, errno(&e))?;
                    }
                }
            }
            CMD_WRITE => {
                buf.resize(len as usize, 0);
                r.read_exact(&mut buf)?;
                let mut d = disk.lock().unwrap();
                let mut res = d.write_at(offset, &buf);
                if res.is_ok() && flags & CMD_FLAG_FUA != 0 {
                    res = d.flush();
                }
                drop(d);
                reply(&mut w, res.as_ref().err().map(errno).unwrap_or(0))?;
            }
            CMD_FLUSH => {
                let res = disk.lock().unwrap().flush();
                reply(&mut w, res.as_ref().err().map(errno).unwrap_or(0))?;
            }
            CMD_TRIM | CMD_WRITE_ZEROES => {
                let mut d = disk.lock().unwrap();
                let mut res = if cmd == CMD_TRIM { d.trim(offset, len as usize) } else { d.write_zeroes(offset, len as usize) };
                if res.is_ok() && flags & CMD_FLAG_FUA != 0 {
                    res = d.flush();
                }
                drop(d);
                reply(&mut w, res.as_ref().err().map(errno).unwrap_or(0))?;
            }
            CMD_DISC => {
                let _ = disk.lock().unwrap().flush();
                w.flush()?;
                return Ok(());
            }
            _ => reply(&mut w, EINVAL)?,
        }
        // Reply at once when nothing more is waiting; otherwise keep
        // batching replies while QEMU has requests queued.
        if r.buffer().is_empty() {
            w.flush()?;
        }
    }
}
