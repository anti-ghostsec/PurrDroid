#!/bin/sh
# Builds PurrDroid and adds it for the current user only: the program in
# ~/.local/bin, Start menu entries, and an entry Share can send to.
# Nothing is installed system-wide.  ./install.sh --uninstall removes it
# (but never your vault or Android's disk: see `purrdroid destroy`).
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$HOME/.local/bin"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}"
APPS="$DATA/applications"
ICONS="$DATA/icons/hicolor/scalable/apps"

if [ "$1" = "--uninstall" ]; then
    rm -f "$BIN/purrdroid" "$APPS/purrdroid.desktop" "$APPS/purrdroid-send.desktop" "$ICONS/purrdroid.svg"
    update-desktop-database "$APPS" 2>/dev/null || true
    echo "PurrDroid removed. Your vault and Android's disk are still in $DATA/purrdroid."
    exit 0
fi

# A release download has the program ready-made; from the source, it's built.
if [ -x "$DIR/purrdroid" ]; then
    PROGRAM="$DIR/purrdroid"
else
    command -v cargo >/dev/null || { echo "PurrDroid needs cargo first, to build it." >&2; exit 1; }
    (cd "$DIR" && cargo build --release --locked)
    PROGRAM="$DIR/target/release/purrdroid"
fi
command -v qemu-system-x86_64 >/dev/null ||
    echo "Note: QEMU isn't installed. It's needed for an Android from an ISO (not for the emulator engine)." >&2
[ -e /dev/kvm ] || echo "Warning: /dev/kvm isn't there; Android would be far too slow without it." >&2

mkdir -p "$BIN" "$APPS" "$ICONS"
install -m 0755 "$PROGRAM" "$BIN/purrdroid"
cp "$DIR/icons/purrdroid.svg" "$ICONS/purrdroid.svg"

cat > "$APPS/purrdroid.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=PurrDroid
GenericName=Android Apps
Comment=Android in an encrypted virtual machine
Exec=env PURRDROID_NO_LOG=1 $BIN/purrdroid gui
Icon=purrdroid
Terminal=false
Categories=System;Emulator;
X-Ferro-Share=false
DESK

# What FerroOS's Share box offers as "Android (PurrDroid)": apps, pictures,
# videos, music, PDFs and plain text, not every file there is (a key, a
# database or a document sent by mistake). Anything else can still be
# dropped on the window. Nothing it prints is kept in the session's log.
cat > "$APPS/purrdroid-send.desktop" <<DESK
[Desktop Entry]
Type=Application
Name=Android (PurrDroid)
Comment=Send to an app in Android
Exec=env PURRDROID_NO_LOG=1 $BIN/purrdroid send %F
Icon=purrdroid
Terminal=false
NoDisplay=true
MimeType=application/vnd.android.package-archive;image/*;video/*;audio/*;application/pdf;text/plain;
DESK

update-desktop-database "$APPS" 2>/dev/null || true
echo "PurrDroid added: open it from the Start menu."
