//! For testing: `snap SOCKET OUT.ppm` connects to QEMU's VNC socket, waits
//! for the screen to settle and saves it as a PPM picture.
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (frame, reader, _input) = purrdroid_rfb::connect(UnixStream::connect(&a[1]).unwrap()).unwrap();
    let f2 = frame.clone();
    std::thread::spawn(move || reader.run(f2, || {}));
    std::thread::sleep(Duration::from_secs(a.get(3).and_then(|s| s.parse().ok()).unwrap_or(3)));
    let f = frame.lock().unwrap();
    let mut out = format!("P6\n{} {}\n255\n", f.width, f.height).into_bytes();
    for p in &f.pixels {
        out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, *p as u8]);
    }
    std::fs::write(&a[2], out).unwrap();
    println!("{}x{}", f.width, f.height);
}
