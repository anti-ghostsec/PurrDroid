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
 │  disks ── XChaCha20-Poly1305 ───────────┼NBD─┤ virtio disk              │
 │  window ── VNC (socket pair) ───────────┼────┤ virtio GPU (virgl 3D)    │
 │  bridge ── adb, PurrDroid's own key ────┼────┤ adbd (127.0.0.1 only)    │
 │  Tor mode ── tor, guards in the vault ──┼────┤ HTTP proxy, nothing else │
 └──────────────────────────────────────────┘    └──────────────────────────┘
   Tor, the control socket, files on their way: $XDG_RUNTIME_DIR (tmpfs, refused otherwise)
```

- **Android** is a normal Android-x86 build: [BlissOS](https://blissos.org)
  is the one to use (it comes with Google Play, or with microG instead).
  Its ISO is imported into PurrDroid's encrypted storage and installed from
  there, and wiped once Android starts from its own disk. The ISO you
  downloaded stays where it was unless you have PurrDroid overwrite it
  (`import --remove`).
- **QEMU's disks, screen and control** each come over a socket pair
  PurrDroid makes and hands it already connected: there's no socket file
  anywhere that another program could open to read the decrypted disk, see
  the screen, type into Android, or tell QEMU to save its memory to a file.
- **A virtual machine, not a container**, so Android's apps run against
  their own kernel and can't reach FerroOS's. QEMU itself runs with its
  seccomp sandbox on, gets no files and no keys, and dies with PurrDroid.

## Encryption

Only these files are ever written, all in `~/.local/share/purrdroid`:

| File | What it is |
|---|---|
| `purrdroid.vault` | The keys and settings, sealed with your password and any keyfiles: Argon2id (192 MiB, 3 passes, about a second a guess), then XChaCha20-Poly1305. Four slots, one per Android; slots not in use are random bytes. |
| `android.disk` | Android's disk: a [deniable](https://github.com/anti-ghostsec/deniable) container, filled with random bytes when it's made (32 GiB unless `init --size` says otherwise), holding one Android's disk, or two for a [hidden Android](#hidden-android). Blocks are sealed with XChaCha20-Poly1305 under a random 256-bit key and bound to their place, so they can't be changed or moved unnoticed. |
| `media.disk` | The imported ISO, every 4 KiB sector sealed on its own with XChaCha20-Poly1305 under a random 256-bit key, its number and the disk's id bound in. It's there only until Android is installed: the first time Android starts from its own disk, it's written over and removed. |

None of them has a magic number or anything else in the clear: without the
password, they're random bytes.

**Upgrading from 0.1.3 or before:** a PurrDroid set up then keeps working as
it is. Its `android.disk`, unless it was made with `--hidden`, is the older
kind: every 4 KiB sector sealed on its own, sparse (it shows how much of it
has been used) unless it was made with `--fill`. It isn't converted (that
would need room for a second copy); to move to a container, copy what you
want out of Android, `purrdroid destroy`, and set it up again. A hidden setup
from then is already a container; its vault slots are relabelled at the next
start so a decoy's reads like any other's, but it was made at 64 GiB, where a
setup without a hidden Android was 32.

**Against quantum computers:** there's no public-key cryptography here,
which is what a quantum computer breaks. A 256-bit symmetric key keeps 128
bits of strength even against Grover's algorithm, out of reach for any
computer, quantum or not. The weak point is the password: pick a long one,
or add a keyfile.

Everything that isn't encrypted is in memory: the decrypted sectors (they
go straight from PurrDroid to QEMU over a socket pair), Android's RAM,
Tor's state (apart from its guards, which are kept sealed in the vault),
and files on their way in or out. Every PurrDroid command makes itself
impossible to dump or trace (no core dumps, not readable by other programs
of yours) before it asks for a password.

**Swap:** memory in RAM can still be swapped out to a disk. FerroOS has no
disk swap; on a PC that has, PurrDroid says so when Android starts. If the
memory-lock limit allows (`ulimit -l`, or `memlock` in
`/etc/security/limits.conf`: 2 GiB for PurrDroid itself, Android's memory
plus 1 GiB for QEMU, or `unlimited`), PurrDroid locks its own memory and has
QEMU lock Android's (`-overcommit mem-lock=on`; memory Android frees then
isn't handed back to the PC while it runs). With the usual 8 MiB limit
neither is locked, and only swap that's off or encrypted keeps them off the
disk. Swap in memory (zram) is fine. The emulator engine's memory, and
Android's state while it's in `/dev/shm`, can't be locked.

**Passwords** are read into buffers made big enough at the start (a buffer
that grows leaves a copy behind) and wiped afterwards. Pasting a password
into the password box works, but the desktop's clipboard (and any
clipboard manager) keeps its own copy: clear it afterwards.

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
purrdroid init --hidden [--decoy-keyfile PATH] [--keyfile PATH]
```

Two Androids in one container from the `deniable` crate (the storage Enclave
hides its vaults in): a decoy, and above it the real one. Every PurrDroid's
disk is such a container, the same size (unless `--size` is given), filled
with random bytes the same way, and every vault slot says the same about
its disk, so the decoy password opens what looks exactly like a PurrDroid
with one Android in it: nothing in the vault or the container shows there's
another slot or another disk, how many there are, or where. Each has its own
adb key, serial number and network address. Install each as usual, once with
each password, one after the other: `import` the ISO, `install`, and start
it once from its own disk (which wipes the ISO), then the same with the
other password. An ISO imported with one password is as good as none to the
other: it's told there's no complete ISO, as after an import that was cut
short.

Keep to the default size: a container much bigger than usual is a hint that
it holds more than one Android.

- **Use the real one day to day.** Opening the real one opens the decoy's
  disk too, so its writes go around the decoy's. With only the decoy open,
  its writes can land on the real one's data, which it knows nothing about.
- Both Androids see the same size of disk (90% of the container) and share
  the room; together they can't hold more than the container.
- `deniable` writes a disk's whole block map at each save (about 1 MiB for
  every GiB of disk), so PurrDroid saves every 5 seconds while Android
  writes (and when Android stops) instead of whenever Android asks. Each
  save is all-or-nothing: after a power cut the disk is as it was at the
  last save, whole, and the last few seconds are lost. It's slower than a
  plain encrypted file, and wears an SSD more. This is the same for every
  PurrDroid, hidden Android or not: that's what keeps them alike.

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

In BlissOS's installer (PurrDroid shows these steps when you press
Install): pick **Installation** in its first menu (on its own it starts
Live CD after a minute, which installs nothing); pick `vda1`, which
PurrDroid has already made, then ext4; and answer **Yes** to "Install Grub2
bootloader?", whose default is Skip: without it nothing can start Android.
Then Reboot. If the boot loader was skipped all the same, PurrDroid sees
the disk can't start and opens the installer again, saying what to pick. When Android has started, switch the
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
echo 'su 0 am start -n app.anonphene.securefolder/.FolderActivity' | purrdroid shell -
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

[AnonpheneOS](https://github.com/anti-ghostsec/AnonpheneOS)'s apps have no
icons: AnonpheneOS opens them from its own Settings and dialer, which other
Androids haven't got. Dropped on the window, *AnonpheneOS privacy* opens
straight away, and the toolbar's **Privacy** button opens it again; its
**Secure Folder** entry opens the Secure Folder (slowly the first time).

The mouse wheel scrolls by dragging (the emulator gives Android a
touchscreen, not a mouse), on a thread of its own: a quick spin is added up
into one drag, and never holds the window up.

- Android's data is in memory while it runs (about 0.5 GiB fresh, more as
  apps go in), and `--data GiB` (default 4) sets its partition's size.
- Memory, all of it from the PC's RAM: what Android is given (1.5 GiB on a
  PC with less than 16 GiB, 2 GiB otherwise, `--ram MB` to choose) plus about
  1.2 GiB for the emulator itself, and Android's data disk, which is in
  memory too and only grows (about 1 GiB with Wisp installed): about 3.7 GiB
  in all with Wisp open. (The emulator raises Android's memory to 2.5 GiB
  whatever it's asked for; PurrDroid hands its QEMU the size asked for
  instead, which saves 1 GiB.) PurrDroid starts only if 600 MiB would still be left
  for everything else, and shuts Android down properly if the PC stays
  under 250 MiB free for two seconds. Without swap a PC that runs out
  freezes, so it's the emulator the kernel stops first if it comes to that.
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
  goes back to software, slower). Tor mode isn't there yet for it.
  `--net off` is Android's airplane mode, switched on over adb: the first
  time, Android has the network until it has started and PurrDroid has
  reached it; Android keeps airplane mode, so after that it starts with its
  radios off (PurrDroid switches it off again when `--net` goes back to
  `direct`).

## Using it

- **From FerroOS to Android:** drop files or text on PurrDroid's window,
  or pick *Android (PurrDroid)* in FerroOS's Share box, or
  `purrdroid send FILE...` / `printf %s "..." | purrdroid send --text -`
  (text from stdin: what's on a command line can be read by any program on
  the PC while it runs; `--text "..."` works too). The files land
  in Android's `Download/From FerroOS` and Android's share sheet opens, so
  you pick the app. An `.apk` opens Android's installer instead.
- **From Android to FerroOS:** save or share a file to `Download/To FerroOS`
  (Android's Files can). It's moved out of Android into memory (a big one,
  a video say, into /dev/shm, which can hold up to half the PC's memory; it
  waits in Android while that would leave the PC short) and shows
  in the tray along the bottom of the window: drag it onto any window, or
  click it for FerroOS's Share box. The **x** forgets it.
- **Network:** `purrdroid --net direct` (the default), `--net tor` (every
  app through Tor; the machine has no other way out, so apps that don't
  use Android's proxy just can't connect), or `--net off` (no way out at
  all). The choice is remembered, like `--ram MB`, `--cpus N`,
  `--screen 1280x800`, `--no-gpu` and `--no-sound`.
  - *Direct* goes through [passt](https://passt.top) when it's installed
    (`apt install passt`, `dnf install passt`), told not to take Android's
    connections to its gateway (10.0.2.2) to this PC: Android reaches the
    internet but not the services listening on this PC's 127.0.0.1 (a
    database, a printer's page, another program's local API). Android is
    told to ask the name servers this PC's resolver asks (from
    `/etc/resolv.conf`, or systemd-resolved's list), since a resolver on
    127.0.0.1 is out of its reach. Without passt it's QEMU's own network,
    where 10.0.2.2 *is* this PC's 127.0.0.1; PurrDroid says so when it
    starts. (`PURRDROID_SLIRP=1` chooses QEMU's own network anyway.)
  - *Tor* gives each site its own circuits (the site's name is the SOCKS
    user name, which Tor keeps apart), so one exit relay doesn't see an
    app's traffic to many sites. Tor's guards, the few relays every circuit
    starts at, are kept (sealed in the vault) from one session to the next,
    as Tor intends; a new set every time would give the network many more
    chances to pick a bad one. They're the same relays every session, which
    is how Tor is meant to work.
- **Closing the window** shuts Android down properly.

- **Copy and paste:** Ctrl+V in PurrDroid's window pastes the desktop's
  clipboard into Android (on an ISO's Android it's typed in: plain letters,
  digits and signs only). Text copied in the emulator's Android becomes the
  desktop's clipboard; Android 11 (BlissOS) gives no way to read its
  clipboard, so that way it's the emulator only.

There's no shared folder, microphone, camera or location: nothing crosses
unless you send it or paste it. Android's serial number,
UUID and network address are random, made once per vault, and handed to
QEMU through descriptors rather than on its command line (which other
programs can read); the virtual PC's maker and processor name are QEMU's
generic ones. The processor's features are this PC's (`-cpu host`, which
KVM needs to be fast), so an app can still see what kind of processor it
is.

## What it doesn't do yet

- The bridge (sending files and text in, the tray, the Tor proxy setting)
  speaks adb's protocol as Android does, but hasn't yet been run against
  a real Android. Nor have dragging into and out of the window.
- Apps that check Play Integrity (banking, some games, streaming) won't run:
  Google sees a virtual machine, as with any emulator.
- ARM-only apps need the ARM translation BlissOS can turn on in its
  settings, and run slower.
- Someone who can write to the disk file can roll a block back to an older
  copy of itself; that's noticed only if it breaks the disk (as with LUKS).
  On an older plain disk (0.1.3 or before, not `--hidden`) the same goes for
  a sector; such a disk that isn't filled shows which parts are used, and
  two crashes in a row while one sector is being written can leave that
  sector unreadable.
- A hidden setup can only be made at `init`: one with a single Android
  can't have a second added later (PurrDroid can't know whether a slot or
  a disk is already taken without its password, and would overwrite it).
- Comparing two copies of the vault taken at different times shows which
  of its four slots changed in between: the slots whose Android was
  started. With a hidden Android, someone who has copies from before and
  after you used the real one sees a slot change that the decoy's password
  doesn't open. The container's cover writes blur the same
  comparison for the disk, as far as the decoy's own use can explain it.
- A PurrDroid set up with 0.1.3 or before without `--hidden` keeps its older
  plain disk (see [Upgrading](#encryption)): its vault and disk look unlike
  a hidden setup's.
- The window has no shared clipboard and can't change Android's screen
  size when resized (it scales instead).
- Programs running as you can still do what `purrdroid send`, `apk` and
  `shell` do, through PurrDroid's control socket (in its private folder in
  memory, for your user only), and that includes running commands in
  Android. And a program running as you that may trace others (with
  `kernel.yama.ptrace_scope` at 0) can read QEMU's memory, which holds
  Android's; most systems set it to 1, where only PurrDroid itself may.
  PurrDroid is no defence against software already running as you.
- The adb port is a TCP port on 127.0.0.1 (a random one each start): other
  programs on this PC, other users' included, can reach it. Without
  PurrDroid's key adbd gives them nothing, but on an ISO's Android they can
  make it ask "Allow USB debugging?" for their own key: tap Allow only right
  after you switched debugging on yourself, for PurrDroid's key.
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
