# PurrDroid

Android apps on FerroOS (or any Linux with KVM), in a virtual machine where
every byte that reaches the disk is encrypted, and everything else stays in
memory. Written in Rust.

> **Heads up:** PurrDroid is new and hasn't had a security audit. The
> encryption, the disk server and the window have been tested on their own
> and together with QEMU; the bridge into Android (adb), dragging files
> and Tor mode haven't been tried against a real Android yet. See
> [What it doesn't do yet](#what-it-doesnt-do-yet).

## How it works

```
 FerroOS                                         virtual machine (QEMU + KVM)
 ┌──────────────────────────────────────────┐    ┌──────────────────────────┐
 │ purrdroid                                │    │ Android-x86 (BlissOS…)   │
 │  vault ── Argon2id → keys (in memory)    │    │                          │
 │  disks ── XChaCha20-Poly1305 per sector ─┼NBD─┤ virtio disk              │
 │  window ── VNC socket ──────────────────┼────┤ virtio GPU (virgl 3D)    │
 │  bridge ── adb, PurrDroid's own key ────┼────┤ adbd (127.0.0.1 only)    │
 │  Tor mode ── tor, state in memory ──────┼────┤ HTTP proxy, nothing else │
 └──────────────────────────────────────────┘    └──────────────────────────┘
   sockets, Tor, files on their way: $XDG_RUNTIME_DIR (tmpfs, refused otherwise)
```

- **Android** is a normal Android-x86 build: [BlissOS](https://blissos.org)
  is the one to use (it comes with Google Play, or with microG instead).
  Its ISO is imported into PurrDroid's encrypted storage and installed from
  there, so not even the installer stays on the disk in the clear.
- **A virtual machine, not a container**, so Android's apps run against
  their own kernel and can't reach FerroOS's. QEMU itself runs with its
  seccomp sandbox on, gets no files and no keys, and dies with PurrDroid.

## Encryption

Only these files are ever written, all in `~/.local/share/purrdroid`:

| File | What it is |
|---|---|
| `purrdroid.vault` | The keys and settings, sealed with your password and any keyfiles: Argon2id (192 MiB, 3 passes, about a second a guess), then XChaCha20-Poly1305. Four slots, one per Android; slots not in use are random bytes. |
| `android.disk` | Android's disk. Every 4 KiB sector is sealed on its own with XChaCha20-Poly1305 under a random 256-bit key, its number and the disk's id bound in, so sectors can't be changed, swapped or moved between disks unnoticed. In hidden mode, a [deniable](https://github.com/anti-ghostsec/deniable) container instead (below). |
| `media.disk` | The imported ISO, sealed the same way. |

None of them has a magic number or anything else in the clear: without the
password, they're random bytes (and, for a plain disk not yet filled, holes
of zeros; `init --fill` writes it all once).

**Against quantum computers:** there's no public-key cryptography here,
which is what a quantum computer breaks. A 256-bit symmetric key keeps 128
bits of strength even against Grover's algorithm, out of reach for any
computer, quantum or not. The weak point is the password: pick a long one,
or add a keyfile.

Everything that isn't encrypted is in memory: the decrypted sectors (they
go straight from PurrDroid to QEMU over a socket), Android's RAM (no swap
file; PurrDroid and its keys can't be read by other programs or dumped),
Tor's state, and files on their way in or out.

### Keyfiles

Any number of files (or folders: every file directly in one) whose
contents are needed as well as the password, with any command:

```sh
purrdroid keyfile ~/usb/purr.key                 # a new one: 64 random bytes
purrdroid --keyfile ~/usb/purr.key --keyfile ~/Pictures/cat.jpg
```

The same scheme as Enclave: each keyfile is hashed with SHA-512 and goes
into Argon2id as its secret input, so neither the password nor the keyfiles
open anything alone. Their order doesn't matter. A keyfile must never change
by a byte (a photo that gets edited or re-saved stops working), so keep
copies. In the password box (started from the Start menu), drop keyfiles on
it from the File Manager. `purrdroid passwd --new-keyfile PATH` changes them;
`passwd` with no `--new-keyfile` drops them.

### Hidden Android

```sh
purrdroid init --hidden --size 64 [--decoy-keyfile PATH] [--keyfile PATH]
```

Two Androids in one container from the `deniable` crate (the storage Enclave
hides its vaults in): a decoy, and above it the real one. The decoy password
opens an ordinary-looking PurrDroid with one Android in it; nothing in the
vault or the container shows there's another slot or another disk, how many
there are, or where. Each has its own adb key, serial number and network
address. Install each as usual, once with each password (`import` the ISO
again with the second password first).

- **Use the real one day to day.** Opening the real one opens the decoy's
  disk too, so its writes go around the decoy's. With only the decoy open,
  its writes can land on the real one's data, which it knows nothing about.
- Both Androids see the same size of disk and share the room; together they
  can't hold more than the container.
- `deniable` writes a disk's whole block map at each save, so in hidden mode
  PurrDroid saves every 5 seconds (and when Android stops) instead of
  whenever Android asks. Each save is all-or-nothing: after a power cut the
  disk is as it was at the last save, whole, and the last few seconds are
  lost. It's also slower than a plain disk, and wears an SSD more.

**Duress password:** `purrdroid duress` sets a password (with keyfiles or
not, `--duress-keyfile`) that, given instead of a real one, destroys the
vault on the spot and answers "wrong password" as usual. Without the vault
the disks are noise, however big.

**Reset (wipe everything):** the password box has *Reset PurrDroid...*, for a
forgotten password or starting over (`purrdroid destroy` from a terminal).
Once RESET is typed it writes over the vault first, so nothing can open the
rest even if it's cut short, then every disk (only the parts that hold
anything, so a big sparse disk is quick), syncs them and removes them. On an
SSD the drive may keep old copies of overwritten blocks where no program can
reach them; there the vault is what matters: the disks' keys exist only in
it, and an old copy of it still needs the password and keyfiles.

### Next to VeraCrypt

| | VeraCrypt | PurrDroid |
|---|---|---|
| Cipher | AES, Serpent, Twofish (or cascades), XTS | XChaCha20-Poly1305 |
| Notices changed data | No | Yes, every sector |
| Password hash | PBKDF2 (Argon2id in recent versions) | Argon2id, 192 MiB |
| Keyfiles | Yes | Yes (Enclave's scheme) |
| Hidden volume | Yes | Yes (`deniable`) |
| Duress password | No | Yes |
| Random-looking, no header | Yes | Yes |

PurrDroid's disk cipher is the `deniable` crate's, not the AES-256-GCM of
Enclave's own vault files: AES-GCM's 12-byte random nonces are only safe for
about four billion writes under one key, which a busy disk can reach in a
few years; XChaCha20's 24-byte nonces aren't limited that way.

## Setting up

You need KVM (`/dev/kvm`), and QEMU for an Android from an ISO. The
[releases](https://github.com/anti-ghostsec/PurrDroid/releases) have it
ready-made for x86_64 Linux (one static program); from the source, Rust
builds it. Either way `./install.sh` adds it for your user only
(`~/.local/bin` and the Start menu). Then open
**PurrDroid** from the Start menu; everything is done in its windows, no
terminal needed:

1. **Set up PurrDroid** (the first time): pick the Android, type the
   password twice, and drop any keyfiles on the window.
   - *Android 15 for testing apps*: the Android SDK's emulator image (see
     [the emulator engine](#the-emulator-engine-android-15-test-images)).
   - *Android from an ISO*: a [BlissOS](https://blissos.org) ISO, with
     Google Play or microG.
2. **The password box** each time after that: drop keyfiles on it too.
3. For an ISO: **get Android**: drop the ISO on the window (it's encrypted
   into the store, with a progress bar), click **Install Android** and pick
   *Installation* in its boot menu; when it's done, **It's installed: start
   it**.
4. While Android runs: drop APKs on PurrDroid's window to install them, and
   any other file or text to send it to an app in Android.

In BlissOS's installer: create one partition on the disk (`vda`), format it
ext4, say yes to GRUB, and reboot. When Android has started, switch the
bridge on once: **Settings → About → tap Build number 7 times**, then
**Settings → System → Developer options → USB debugging**, and tap **Allow**
when Android asks about PurrDroid's key. (The emulator engine needs none of
this.)

**Google Play:** sign in as on a phone. Google may call the device
uncertified; register it at google.com/android/uncertified. Keep in mind
that Google Play is Google: signing in tells Google which apps you use. The
microG build, or no account at all with F-Droid or Aurora, keeps more to
yourself.

Everything can also be done from a terminal (`purrdroid help`), for scripts.

## The emulator engine: Android 15 test images

For trying apps (AnonpheneOS's, say) on the Android 15 x86_64 image from the
Android SDK (`system-images;android-35;default;x86_64`, a userdebug build
signed with AOSP's public test key, so apps signed with that key get their
system permissions):

```sh
purrdroid init --emulator [--sdk ~/.local/opt/android-sdk] [--keyfile PATH]
purrdroid                                # its own window; --no-window for none
purrdroid apk AnonSecureFolder.apk AnonPrivacy.apk
purrdroid shell 'su 0 am start -n app.anonphene.securefolder/.FolderActivity'
```

**/e/OS, the most private choice.** e Foundation publishes x86_64 emulator
images of /e/OS (LineageOS without Google; microG in its place): userdebug
builds signed with the same AOSP test key, so your own apps, Wisp and
AnonpheneOS's (system permissions included) install as they do on the SDK's
image. Get the newest `IMG-e-…-sdk_phone_x86_64.zip` from
`https://ota.ecloud.global/test/sdk_phone_x86_64/`, check its SHA-256 and
unzip it into the SDK as `system-images/android-35/lineage/` (for Android 15).
The setup window then lists it first; from a terminal, `purrdroid init
--emulator --image system-images/android-35/lineage/x86_64/`. They're test
builds: no real accounts on them. Apps built for ARM only don't run on an
x86_64 Android; build them for `x86_64` too.

It runs under Google's Android Emulator from the SDK, with no window of its
own: it draws on this PC's GPU off-screen (in software if it can't), and
PurrDroid shows Android in its one window, with a toolbar (Back, Home, Apps,
Power, volume, the network) and the tray for files from Android, talking to
the emulator's control service on 127.0.0.1 with the token it makes. The
emulator keeps an AVD as
plain files, so PurrDroid keeps it off the disk: the AVD is made in a private
folder in memory (`/dev/shm` on most systems), every folder the emulator
writes to points into it (nothing goes to `~/.android`), Android's state from
last time is decrypted into it, and when Android stops it's sealed back into
the encrypted store (two files take turns, so a crash part-way keeps the
last good one) and the folder in memory is removed. Android trusts
PurrDroid's adb key from the first boot; `apk` installs and prints what
Android said, `shell` runs a command as `adb shell` does (as root with
`su 0`, on a userdebug image).

A browser that wasn't installed before becomes Android's browser, the one
web links open in. For [Wisp](https://github.com/anti-ghostsec/wisp), drop
its x86_64 build (`android/build-android.sh x86_64`, `wisp-x86.apk`) on the
window.

- Android's data is in memory while it runs (about 0.5 GiB fresh, more as
  apps go in), and `--data GiB` (default 4) sets its partition's size.
- Memory, all of it from the PC's RAM: Android gets 2 GiB (`--ram MB` for
  more), and the emulator and its folder take about 2 GiB on top. PurrDroid
  starts only if 1.5 GiB would still be left for everything else (with
  less, Android gets 1.5 GiB), and shuts Android down if the PC gets down
  to 400 MiB free. Without swap a PC that runs out freezes, so it's the
  emulator the kernel stops first if it comes to that.
- If PurrDroid is killed outright, that session's changes are lost; the
  state from before stays. A leftover folder in memory is removed at the
  next start.
- The test key is public: on such an image, anyone's app signed with it
  gets system permissions. Fine for testing, not for an Android you rely on.
- It's Google's emulator: PurrDroid turns its usage metrics and crash
  reports off (a crash report is a dump of memory, Android's decrypted data
  in it, sent to Google; its crash handler isn't even started), and its
  control service (gRPC, on 127.0.0.1, with a token only in PurrDroid's
  folder in memory) is how PurrDroid shows it; it may still look for its
  own updates. Google's emulator calls some GPU drivers (some of Intel's) unsafe
  and would draw in software; PurrDroid uses the GPU anyway (`--software-gpu`
  goes back to software, slower). Tor mode isn't there yet for it
  (`--net off` is: airplane mode).

## Using it

- **From FerroOS to Android:** drop files or text on PurrDroid's window,
  or pick *Android (PurrDroid)* in FerroOS's Share box, or
  `purrdroid send FILE...` / `purrdroid send --text "..."`. The files land
  in Android's `Download/From FerroOS` and Android's share sheet opens, so
  you pick the app. An `.apk` opens Android's installer instead.
- **From Android to FerroOS:** save or share a file to `Download/To FerroOS`
  (Android's Files can). It's moved out of Android into memory and shows
  in the tray along the bottom of the window: drag it onto any window, or
  click it for FerroOS's Share box. The **x** forgets it.
- **Network:** `purrdroid --net direct` (the default), `--net tor` (every
  app through Tor; the machine has no other way out, so apps that don't
  use Android's proxy just can't connect), or `--net off`. The choice is
  remembered, like `--ram MB`, `--cpus N`, `--screen 1280x800`,
  `--no-gpu` and `--no-sound`.
- **Closing the window** shuts Android down properly.

There's no shared clipboard, shared folder, microphone, camera or
location: nothing crosses unless you send it. Android's serial number,
UUID and network address are random, made once per vault.

## What it doesn't do yet

- The bridge (sending files and text in, the tray, the Tor proxy setting)
  speaks adb's protocol as Android does, but hasn't yet been run against
  a real Android. Nor have dragging into and out of the window.
- Apps that check Play Integrity (banking, some games, streaming) won't run:
  Google sees a virtual machine, as with any emulator.
- ARM-only apps need the ARM translation BlissOS can turn on in its
  settings, and run slower.
- Rolling one sector of a plain disk back to an older copy of itself isn't
  detected (as with LUKS), and a plain disk that isn't filled shows which
  parts are used. Two crashes in a row while one sector is being written
  can leave that sector unreadable.
- A hidden setup can only be made at `init`: a plain one can't be turned
  into one later.
- The window has no shared clipboard and can't change Android's screen
  size when resized (it scales instead).
- The adb port is on 127.0.0.1: other programs on this PC can reach it, but
  without PurrDroid's key adbd gives them nothing.
- Only x86-64 Linux with KVM. QEMU's 3D (virgl) needs a GPU render node;
  without one Android draws in software, slower.

## Building

```sh
cargo build --release
cargo test --release     # Argon2id is slow without optimisation
```

A `v*` tag (matching the version in `Cargo.toml`) has GitHub build the
release: tests, a static x86_64 build, a `.tar.gz` with its SHA-256, and a
signed build provenance (`gh attestation verify FILE --repo anti-ghostsec/PurrDroid`).

| Crate | What it is |
|---|---|
| `crates/store` | The vault, keyfiles, the encrypted disk format and hidden containers |
| `crates/nbd` | The NBD server that hands the disks to QEMU |
| `crates/adb` | A small adb client with its own RSA key |
| `crates/rfb` | A small VNC client for QEMU's screen |
| `crates/purrdroid` | The program: commands, the VM, the window, the bridge, Tor mode |

The vault uses `vaultkit` from [deniable](https://github.com/anti-ghostsec/deniable).

## License

MIT or Apache-2.0, as you prefer.
