//! What the NBD server serves: a disk as Android sees it, whichever way it's
//! stored (a plain encrypted disk, or a disk inside a hidden container).

use std::io;

pub trait BlockDev: Send {
    /// Size in bytes.
    fn len(&self) -> u64;
    fn read_only(&self) -> bool;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()>;
    /// Android doesn't need what's there any more; it may read as anything.
    fn trim(&mut self, offset: u64, len: usize) -> io::Result<()>;
    /// Must read as zeros afterwards.
    fn write_zeroes(&mut self, offset: u64, len: usize) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

impl BlockDev for crate::Disk {
    fn len(&self) -> u64 {
        crate::Disk::len(self)
    }
    fn read_only(&self) -> bool {
        crate::Disk::read_only(self)
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        crate::Disk::read_at(self, offset, buf)
    }
    fn write_at(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        crate::Disk::write_at(self, offset, data)
    }
    fn trim(&mut self, offset: u64, len: usize) -> io::Result<()> {
        // A filled disk keeps what's there: a forgotten sector would show
        // it's free (see disk.rs, "Discarding").
        if self.is_filled() {
            return Ok(());
        }
        self.discard(offset, len)
    }
    fn write_zeroes(&mut self, offset: u64, len: usize) -> io::Result<()> {
        // Reads as zeros afterwards, filled or not.
        self.discard(offset, len)
    }
    fn flush(&mut self) -> io::Result<()> {
        crate::Disk::flush(self)
    }
}
