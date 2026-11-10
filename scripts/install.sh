#!/usr/bin/env bash
# Installs netwatch as a systemd service from an unpacked release or a build:
#   sudo netwatch-linux-x86_64/scripts/install.sh
#   cargo build --release && sudo scripts/install.sh
# scripts/get.sh downloads a release and runs this. An optional argument names
# the binary. An existing /etc/netwatch/netwatch.toml is kept.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)

if [[ $# -gt 0 ]]; then
    BIN=$(realpath "$1")
elif [[ -x $ROOT/netwatch && ! -d $ROOT/netwatch ]]; then
    BIN=$ROOT/netwatch                  # release archive: the binary sits next to scripts/
else
    BIN=$ROOT/target/release/netwatch
fi
[[ -x $BIN && ! -d $BIN ]] || { echo "no netwatch binary at $BIN; build first: cargo build --release" >&2; exit 1; }
cd "$ROOT"

install -m 0755 "$BIN" /usr/local/bin/netwatch
install -m 0755 scripts/netwatch-update-geoip /usr/local/bin/netwatch-update-geoip
install -m 0644 scripts/systemd/netwatch.service scripts/systemd/netwatch-update-geoip.service \
    scripts/systemd/netwatch-update-geoip.timer /etc/systemd/system/
# Automatic updates stay off until `sudo netwatch update --auto on`; this keeps the units current.
install -m 0644 scripts/systemd/netwatch-update.service scripts/systemd/netwatch-update.timer /etc/systemd/system/
echo "installed /usr/local/bin/netwatch ($(/usr/local/bin/netwatch --version))"

install -d -m 0755 /etc/netwatch
install -d -m 0750 /var/lib/netwatch
if [[ ! -e /etc/netwatch/netwatch.toml ]]; then
    /usr/local/bin/netwatch default-config >/etc/netwatch/netwatch.toml
    echo "wrote /etc/netwatch/netwatch.toml (interface = auto, mode = observe)"
fi
[[ -e /var/lib/netwatch/dbip-city-lite.mmdb ]] || /usr/local/bin/netwatch-update-geoip \
    || echo "GeoIP download failed; netwatch runs without locations until netwatch-update-geoip works" >&2

systemctl daemon-reload
systemctl enable --quiet --now netwatch-update-geoip.timer
systemctl enable --quiet netwatch.service
systemctl restart netwatch.service
sleep 3
if ! systemctl is-active --quiet netwatch.service; then
    systemctl --no-pager --lines=15 status netwatch.service >&2 || true
    echo "netwatch.service did not start; see: journalctl -u netwatch" >&2
    exit 1
fi
echo "started netwatch.service; logs: journalctl -u netwatch"
echo "UI: ssh -L 9180:127.0.0.1:9180 <this host>, then http://127.0.0.1:9180  ·  CLI: netwatch status"
