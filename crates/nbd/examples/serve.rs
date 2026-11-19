//! For testing with qemu-img / qemu-io: `serve DISKFILE SOCKET SECTORS [hidden]`
//! makes (or opens) a disk under a fixed test key and serves it as "test".
//! With `hidden`, a deniable container of SECTORS 4 KiB blocks, serving the
//! real (upper) disk, saved every 5 s and every 0.5 s while idle.
use std::collections::HashMap;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let key = [0x42u8; 32];
    let path = std::path::Path::new(&a[1]);
    let sectors: u64 = a[3].parse().unwrap();
    let e: purrdroid_nbd::Export = if a.get(4).map(String::as_str) == Some("hidden") {
        use purrdroid_store::hidden;
        if !path.exists() {
            let bytes = sectors * 4096;
            hidden::create(path, bytes, &[0x41u8; 32], &key, hidden::disk_len_for(bytes)).unwrap();
        }
        let (c, id) = hidden::open(path, &key).unwrap();
        let saver = c.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            hidden::save(&saver).unwrap();
        });
        Arc::new(Mutex::new(hidden::Volume::new(c, id).unwrap()))
    } else if path.exists() {
        Arc::new(Mutex::new(purrdroid_store::Disk::open(path, &key, false).unwrap()))
    } else {
        Arc::new(Mutex::new(purrdroid_store::Disk::create(path, &key, sectors, false).unwrap()))
    };
    let _ = std::fs::remove_file(&a[2]);
    let l = UnixListener::bind(&a[2]).unwrap();
    let mut m = HashMap::new();
    m.insert("test".to_string(), e);
    purrdroid_nbd::serve(l, Arc::new(m));
}
