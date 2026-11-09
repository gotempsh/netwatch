#!/bin/sh
# Container entrypoint: fetch GeoIP data on first start, refresh it monthly
# (what the systemd timer does on a host install), then run the daemon.
set -e
CFG=${NETWATCH_CONFIG:-/etc/netwatch/netwatch.toml}
if [ "$#" -gt 0 ]; then
    exec netwatch -c "$CFG" "$@"
fi
[ -e /var/lib/netwatch/dbip-city-lite.mmdb ] || netwatch-update-geoip \
    || echo "GeoIP download failed; locations stay empty until the next try" >&2
( while sleep 86400; do
    if [ -n "$(find /var/lib/netwatch/dbip-city-lite.mmdb -mtime +30 2>/dev/null)" ] \
        || [ ! -e /var/lib/netwatch/dbip-city-lite.mmdb ]; then
        netwatch-update-geoip || true
    fi
done ) &
exec netwatch -c "$CFG" run
