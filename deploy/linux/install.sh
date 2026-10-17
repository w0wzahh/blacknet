#!/bin/sh
# Blacknet Linux install. Run as root:
#   sudo sh install.sh
set -eu

INSTALL_BIN=/usr/local/bin
DATA_DIR=/var/lib/blacknet
CONF_DIR=/etc/blacknet
SRC="$(cd "$(dirname "$0")/../.." && pwd)"

id blacknet >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin blacknet
mkdir -p "$DATA_DIR" "$CONF_DIR" "$DATA_DIR/web"

cp "$SRC/blacknet" "$INSTALL_BIN/blacknet"
chmod 0755 "$INSTALL_BIN/blacknet"

if [ -d "$SRC/web/dist" ]; then
  cp -r "$SRC/web/dist" "$DATA_DIR/web/dist"
fi

if [ ! -f "$CONF_DIR/config.yaml" ]; then
  cp "$SRC/config.example.yaml" "$CONF_DIR/config.yaml"
  # Point data_dir at the service data dir and serve the web root from there.
  sed -i 's|^data_dir:.*|data_dir: /var/lib/blacknet|' "$CONF_DIR/config.yaml"
fi
chown -R blacknet:blacknet "$DATA_DIR"
chmod 0600 "$CONF_DIR/config.yaml"

cp "$SRC/deploy/linux/blacknet.service" /etc/systemd/system/blacknet.service
systemctl daemon-reload
systemctl enable --now blacknet

echo ""
echo "Installed. Dashboard: http://<this-host>:8080"
echo "Config:   $CONF_DIR/config.yaml"
echo "Logs:     journalctl -u blacknet -f"
echo "Next: reserve this host's IP in your router, then set the router DNS to it."
