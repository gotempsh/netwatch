#!/usr/bin/env bash
# End-to-end test without touching real interfaces or the real sshd: a network
# namespace plays "the internet" (203.0.113.0/24) behind a veth pair, netwatch
# watches the host end, and a throwaway sshd (its own systemd unit, so the
# production netwatch never sees its log) takes the brute force.
#
#   sudo scripts/e2e-netns.sh [path/to/netwatch]
#   sudo IMAGE=netwatch:latest scripts/e2e-netns.sh   # the container image instead
#
# Checks detection (port scan, SSH brute force, ban/unban), the API Host check and
# database mode, and visibility
# (flows with process attribution, HTTP and DNS dissection, failed connects,
# listen events).
set -euo pipefail

NS=nwtest
HOST_IF=nw0
HOST_IP=203.0.113.1
ATTACKER=203.0.113.50
SSH_PORT=2222
SSH_UNIT=netwatch-e2e-sshd
DIR=$(mktemp -d)
CFG=$DIR/netwatch.toml
API=127.0.0.1:9181
if [[ -n ${IMAGE:-} ]]; then
    # Same flags as docker-compose.yml; the test directory is shared at the same path.
    BIN=$DIR/netwatch-in-docker
    printf '#!/bin/sh\nexec docker run --rm --network host --pid host --privileged -v %s:%s -e RUST_LOG --entrypoint netwatch %s "$@"\n' \
        "$DIR" "$DIR" "$IMAGE" >"$BIN"
    chmod +x "$BIN"
else
    BIN=$(realpath "${1:-./target/release/netwatch}")
fi

cleanup() {
    [[ -n ${PID:-} ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
    [[ -n ${WEB_PID:-} ]] && kill "$WEB_PID" 2>/dev/null || true
    systemctl stop $SSH_UNIT 2>/dev/null || true
    systemctl reset-failed $SSH_UNIT 2>/dev/null || true
    ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null || true
    ip netns del $NS 2>/dev/null || true
    ip link del $HOST_IF 2>/dev/null || true
}
trap cleanup EXIT

ip netns add $NS
ip link add $HOST_IF type veth peer name nw1
ip link set nw1 netns $NS
ip addr add $HOST_IP/24 dev $HOST_IF
ip link set $HOST_IF up
ip -n $NS addr add $ATTACKER/24 dev nw1
ip -n $NS link set nw1 up
ip -n $NS link set lo up

cat >"$CFG" <<EOF
interface = "$HOST_IF"
xdp_mode = "skb"
mode = "observe"
db_path = "$DIR/netwatch.db"
api_listen = "$API"
control_socket = "$DIR/control.sock"
tick_secs = 2
allow_wireguard_peers = false
allow_tailscale_peers = false
allow_cloudflare = false
feeds = []
ssh_units = ["$SSH_UNIT.service"]
flow_interfaces = []
EOF

RUST_LOG=info "$BIN" -c "$CFG" run >"$DIR/daemon.log" 2>&1 &
PID=$!
for _ in $(seq 150); do curl -sf "http://$API/api/overview" >/dev/null && break; sleep 0.2; done

# Started after netwatch so the listen tracepoint sees it.
echo "== throwaway sshd on $HOST_IP:$SSH_PORT"
ssh-keygen -q -t ed25519 -N '' -f "$DIR/hostkey"
cat >"$DIR/sshd_config" <<EOF
Port $SSH_PORT
ListenAddress $HOST_IP
HostKey $DIR/hostkey
PidFile none
UsePAM no
PasswordAuthentication yes
KbdInteractiveAuthentication no
EOF
mkdir -p /run/sshd
/usr/sbin/sshd -t -f "$DIR/sshd_config"
systemd-run --quiet --unit=$SSH_UNIT /usr/sbin/sshd -D -e -f "$DIR/sshd_config"

# Fake internet services in the namespace: HTTP on 8080 and DNS on 53.
cat >"$DIR/dns.py" <<'EOF'
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("203.0.113.50", 53))
while True:
    q, addr = s.recvfrom(512)
    end = q.index(b"\0", 12) + 5
    name = q[12:end - 4]
    if name.startswith(b"\x07missing"):
        s.sendto(q[:2] + b"\x81\x83" + q[4:6] + b"\0\0\0\0\0\0" + q[12:end], addr)
    else:
        ans = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.50")
        s.sendto(q[:2] + b"\x81\x80" + q[4:6] + b"\0\x01\0\0\0\0" + q[12:end] + ans, addr)
EOF
mkdir -p "$DIR/www/e2e" && echo hello >"$DIR/www/e2e/path"
ip netns exec $NS python3 "$DIR/dns.py" &
ip netns exec $NS python3 -m http.server 8080 --bind $ATTACKER --directory "$DIR/www" >/dev/null 2>&1 &
sleep 1

echo "== inbound: Apache path traversal (CVE-2021-41773) and a .env probe against a host web server"
python3 -m http.server 18081 --bind $HOST_IP --directory "$DIR/www" >/dev/null 2>&1 &
WEB_PID=$!
sleep 1
ip netns exec $NS curl -s -o /dev/null --max-time 3 --path-as-is "http://$HOST_IP:18081/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" || true
ip netns exec $NS curl -s -o /dev/null --max-time 3 "http://$HOST_IP:18081/.env" || true
sleep 4  # so the exploit, not the scan, raises the first ban proposal

echo "== port scan from $ATTACKER (ports 1-200)"
ip netns exec $NS bash -c "for p in \$(seq 1 200); do timeout 0.2 bash -c \"echo >/dev/tcp/$HOST_IP/\$p\" 2>/dev/null; done; true"

echo "== SSH attempts with bogus users"
for u in admin oracle test guest; do
    ip netns exec $NS ssh -p $SSH_PORT -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no "$u@$HOST_IP" true 2>/dev/null || true
done

echo "== outbound: DNS lookups, an HTTP request, a refused connect"
python3 - <<EOF
import socket, struct
for i, name in enumerate([b"e2e.example.org", b"missing.example.org"]):
    q = struct.pack(">HHHHHH", 0x4e00 + i, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p for p in name.split(b".")) + b"\0" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    s.sendto(q, ("$ATTACKER", 53)); s.recv(512)
EOF
curl -s -o /dev/null -H "Host: e2e.example.org" -A "netwatch-e2e" "http://$ATTACKER:8080/e2e/path"
curl -s -o /dev/null --max-time 2 "http://$ATTACKER:9/" || true

sleep 14
NW=("$BIN" -c "$CFG")
echo; echo "== netwatch ip $ATTACKER"
"${NW[@]}" ip $ATTACKER
echo; echo "== netwatch flows --history --ip $ATTACKER"
"${NW[@]}" flows --history --ip $ATTACKER -n 15
echo; echo "== netwatch dns"
"${NW[@]}" dns
echo; echo "== netwatch events"
"${NW[@]}" events
echo; echo "== netwatch ifaces"
"${NW[@]}" ifaces
echo; echo "== netwatch proposals"
"${NW[@]}" proposals

fail=0
check() { # check <api path> <description> <python expression over the JSON j>
    local path=$1 desc=$2 expr=$3
    if curl -s "http://$API$path" | python3 -c "import json,sys; j=json.load(sys.stdin); sys.exit(0 if ($expr) else 1)"; then
        echo "OK: $desc"
    else
        echo "FAIL: $desc"; fail=1
    fi
}
F="/api/flows?view=all&window=1h&limit=500&ip=$ATTACKER"
check "$F" "inbound SSH flow owned by sshd" \
    "any(f['dir']=='in' and f['lport']==$SSH_PORT and (f['process'] or '').startswith('sshd') and f['bytes_in']>0 for f in j)"
check "$F" "inbound SSH flow carries the client banner" \
    "any(f['lport']==$SSH_PORT and 'SSH-2.0' in ((f['app'] or {}).get('ssh_client') or '') for f in j)"
check "$F" "outbound HTTP flow owned by curl with host and path" \
    "any(f['dir']=='out' and f['rport']==8080 and f['process']=='curl' and (f['app'] or {}).get('http_host')=='e2e.example.org' and (f['app'] or {}).get('http_path')=='/e2e/path' for f in j)"
check "$F" "remote named from DNS answers" \
    "any(f.get('remote_name')=='e2e.example.org' for f in j)"
check "$F" "scan probes recorded as inbound flows" \
    "sum(1 for f in j if f['dir']=='in' and f['proto']=='tcp') >= 150"
check "/api/dns?window=1h" "DNS answer parsed" \
    "any(q['qname']=='e2e.example.org' and q['rcode']=='NOERROR' and '$ATTACKER' in q['answers'] for q in j['queries'])"
check "/api/dns?window=1h" "NXDOMAIN recorded" \
    "any(q['qname']=='missing.example.org' and q['rcode']=='NXDOMAIN' for q in j['queries'])"
check "/api/conn_events?window=1h" "failed connect to port 9 attributed to curl" \
    "any(e['kind']=='connect_failed' and e['rport']==9 and e['process']=='curl' for e in j)"
check "/api/conn_events?window=1h" "no phantom connects from the test namespace" \
    "not any(e['kind']=='connect_failed' and e['local']=='$ATTACKER' for e in j)"
check "/api/listeners" "the namespace's HTTP server is not a host listener" \
    "not any(l['port']==8080 for l in j)"
check "/api/conn_events?window=1h" "sshd listen event" \
    "any(e['kind']=='listen' and e['lport']==$SSH_PORT for e in j)"
check "/api/listeners" "sshd listener on $SSH_PORT" \
    "any(l['port']==$SSH_PORT and (l['process'] or '').startswith('sshd') for l in j)"
check "/api/interfaces" "flow programs on $HOST_IF and all tracepoints attached" \
    "any(i['name']=='$HOST_IF' and i['flows'] for i in j['interfaces']) and all(t['attached'] for t in j['tracepoints'])"
check "$F" "exploit request tagged with its CVE" \
    "any(f['lport']==18081 and (f['app'] or {}).get('cve')=='CVE-2021-41773' for f in j)"
check "/api/sources/$ATTACKER" "exploit_attempt finding names the CVE and the service" \
    "any(x['kind']=='exploit_attempt' and 'CVE-2021-41773' in x['summary'] and '18081/tcp (python' in x['summary'] for x in j['findings'])"
check "/api/proposals" "exploit ban proposal carries the evidence" \
    "any(p['action']=='ban' and 'CVE-2021-41773' in p['reason'] for p in j)"

ID=$(curl -s "http://$API/api/proposals" | python3 -c 'import json,sys; p=[x for x in json.load(sys.stdin) if x["action"]=="ban"]; print(p[0]["id"] if p else "")')
if [[ -n $ID ]]; then
    echo; echo "== approve #$ID, then the attacker should be dropped"
    "${NW[@]}" approve "$ID"
    if ip netns exec $NS timeout 3 bash -c "echo >/dev/tcp/$HOST_IP/$SSH_PORT" 2>/dev/null; then
        echo "FAIL: attacker still reaches port $SSH_PORT after the ban"; fail=1
    else
        echo "OK: attacker is dropped"
    fi
    "${NW[@]}" unban $ATTACKER
    ip netns exec $NS timeout 3 bash -c "echo >/dev/tcp/$HOST_IP/$SSH_PORT" 2>/dev/null \
        && echo "OK: reachable again after unban" || { echo "FAIL: still blocked after unban"; fail=1; }
else
    echo "FAIL: no ban proposal was raised"; fail=1
fi

code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: rebind.example' "http://$API/api/overview")
[[ $code == 403 ]] && echo "OK: API refuses a foreign Host" || { echo "FAIL: foreign Host got $code, not 403"; fail=1; }
mode=$(stat -c %a "$DIR/netwatch.db")
[[ $mode == 600 ]] && echo "OK: database is 0600" || { echo "FAIL: database mode $mode, not 600"; fail=1; }

kinds=$(curl -s "http://$API/api/sources/$ATTACKER" | python3 -c 'import json,sys; print(" ".join(f["kind"] for f in json.load(sys.stdin)["findings"]))')
for k in port_scan ssh_bruteforce; do
    [[ " $kinds " == *" $k "* ]] && echo "OK: finding $k" || { echo "FAIL: missing finding $k (have: $kinds)"; fail=1; }
done
[[ $fail == 0 ]] && echo "E2E PASSED" || { echo "E2E FAILED; daemon log: $DIR/daemon.log"; trap - EXIT; cleanup; exit 1; }
