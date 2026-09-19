#!/usr/bin/env sh
# One-shot installer for the lc systemd service.
# Run as root on the deployment machine:
#   sudo ./install.sh [path-to-lc-binary]   (default: ./target/release/lc)
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_PATH="${1:-$SCRIPT_DIR/../../target/release/lc}"
BIN=/usr/local/bin/lc
LIB_DIR=/var/lib/lc
SERVICE=/etc/systemd/system/lc.service
ENVFILE=/etc/default/lc

if [ "$(id -u)" != "0" ]; then
    echo "error: run as root" >&2
    exit 1
fi

if [ ! -f "$BIN_PATH" ]; then
    echo "error: binary not found at $BIN_PATH (build with: cargo build --release)" >&2
    exit 1
fi

if [ -f "${LIB_DIR}/keys.json" ]; then
    echo "warning: ${LIB_DIR} already exists; keeping existing data and keys" >&2
fi

# service user (system account, no login shell)
if ! id lc >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin lc
fi

install -m755 "$BIN_PATH" "$BIN"
mkdir -p "$LIB_DIR"
chown lc:lc "$LIB_DIR"
chmod 750 "$LIB_DIR"

install -m644 "$SCRIPT_DIR/lc.service" "$SERVICE"
if [ ! -f "$ENVFILE" ]; then
    install -m640 -o root -g lc "$SCRIPT_DIR/lc.env.example" "$ENVFILE"
    echo "NOTE: edit $ENVFILE and set real credentials before starting!"
else
    echo "NOTE: keeping existing $ENVFILE"
fi

systemctl daemon-reload
echo "Installed. Next steps:"
echo "  1. edit $ENVFILE (set LC_ACCESS_KEY / LC_SECRET_KEY, optionally TLS)"
echo "  2. systemctl enable --now lc"
echo "  3. journalctl -u lc -f"
