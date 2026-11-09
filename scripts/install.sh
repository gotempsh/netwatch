#!/usr/bin/env bash
# Installs netwatch as a systemd service, from a release archive or a build:
#   sudo netwatch-linux-x86_64/scripts/install.sh
#   cargo build --release && sudo scripts/install.sh
# An optional argument names the binary. An existing /etc/netwatch/netwatch.toml is kept.
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

install -d -m 0755 /etc/netwatch
install -d -m 0750 /var/lib/netwatch
if [[ ! -e /etc/netwatch/netwatch.toml ]]; then
    /usr/local/bin/netwatch default-config >/etc/netwatch/netwatch.toml
    iface=$(ip -j route show default | python3 -c 'import json,sys; r=json.load(sys.stdin); print(r[0]["dev"] if r else "")')
    [[ -n $iface ]] && sed -i "s/^interface = .*/interface = \"$iface\"/" /etc/netwatch/netwatch.toml
    echo "wrote /etc/netwatch/netwatch.toml (interface = ${iface:-eno1}, mode = observe)"
fi
[[ -e /var/lib/netwatch/dbip-city-lite.mmdb ]] || /usr/local/bin/netwatch-update-geoip || true

systemctl daemon-reload
systemctl enable --now netwatch-update-geoip.timer
systemctl enable netwatch.service
systemctl restart netwatch.service
sleep 3
systemctl --no-pager --lines=8 status netwatch.service
