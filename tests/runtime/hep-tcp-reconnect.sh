#!/bin/bash
#
# Runtime regression test for transport_hep: HEP over TCP must survive the
# collector closing the connection repeatedly while traffic is flowing.
#
# Runs inside a rockylinux:9 container as root with NET_RAW + NET_ADMIN.
# Expects the captagent RPM in ${RPM_DIR:-/tmp/build}. Writes the captagent
# log back to ${RPM_DIR}/captagent-runtime.log.
#
# Exit 0 on pass, 1 on failure.
#
set -u
exec 2>&1

RPM_DIR="${RPM_DIR:-/tmp/build}"
CYCLES="${CYCLES:-6}"
CYCLE_GAP="${CYCLE_GAP:-3}"
BURST="${BURST:-5}"
FD_SLACK="${FD_SLACK:-2}"
ETC=/usr/local/captagent/etc/captagent
PREFIX=/usr/local/captagent

fail() { echo "### FAIL: $*"; [ -f /tmp/captagent.log ] && { echo "--- captagent.log (tail) ---"; tail -40 /tmp/captagent.log; cp /tmp/captagent.log "$RPM_DIR/captagent-runtime.log" 2>/dev/null; }; exit 1; }

echo "### install captagent RPM and test tools"
dnf -y -q install epel-release >/dev/null || fail "epel-release install failed"
dnf -y -q install "$RPM_DIR"/captagent-*.rpm nmap-ncat python3 procps-ng iproute >/dev/null || fail "package install failed"

BIN=$PREFIX/sbin/captagent
[ -x "$BIN" ] || fail "captagent binary missing at $BIN"

echo "### render captagent.xml from template"
sed -e "s#@module_dir@#$PREFIX/lib/captagent/modules#" \
    -e "s#@agent_config_dir@#$ETC/#" \
    -e "s#@agent_capture_plan@#$ETC/captureplans#" \
    -e "s#@agent_backup@#$ETC/backup#" \
    -e "s#@agent_chroot@#$ETC#" \
    "$ETC/captagent.xml.in" > "$ETC/captagent.xml" || fail "could not render captagent.xml"

echo "### configure hepsocket profile: HEP over TCP to 127.0.0.1:9060"
sed -i 's/capture-proto" value="udp"/capture-proto" value="tcp"/; s/capture-port" value="9061"/capture-port" value="9060"/' "$ETC/transport_hep.xml"
grep -q 'capture-proto" value="tcp"' "$ETC/transport_hep.xml" || fail "transport_hep.xml not switched to tcp"
ip link set lo up 2>/dev/null || true

hep_server() { ncat -l -k 127.0.0.1 9060 >/dev/null 2>&1 & echo $!; }
SRV=$(hep_server); sleep 0.5

echo "### start captagent"
"$BIN" -f "$ETC/captagent.xml" > /tmp/captagent.log 2>&1 &
CAPT=$!
sleep 3
kill -0 "$CAPT" 2>/dev/null || fail "captagent died at startup"

echo "### traffic generator: SIP OPTIONS over UDP to 127.0.0.1:5060, ~200/s"
python3 - << 'PY' &
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = ("OPTIONS sip:ping@127.0.0.1 SIP/2.0\r\n"
       "Via: SIP/2.0/UDP 127.0.0.1:5062;branch=z9hG4bK-%d\r\n"
       "From: <sip:test@127.0.0.1>;tag=abc%d\r\nTo: <sip:ping@127.0.0.1>\r\n"
       "Call-ID: call-%d@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n"
       "User-Agent: hep-tcp-reconnect-test\r\nContent-Length: 0\r\n\r\n")
i = 0
while True:
    s.sendto((msg % (i, i, i)).encode(), ("127.0.0.1", 5060)); i += 1
    time.sleep(0.005)
PY
GEN=$!
sleep 3

fds() { ls /proc/"$CAPT"/fd 2>/dev/null | wc -l; }
BASE_FDS=$(fds)
echo "baseline: fds=$BASE_FDS"

cleanup() { kill "$GEN" "$SRV" "$CAPT" 2>/dev/null; sleep 1; cp /tmp/captagent.log "$RPM_DIR/captagent-runtime.log" 2>/dev/null; }

for cycle in $(seq 1 "$CYCLES"); do
  kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null
  sleep "$CYCLE_GAP"
  SRV=$(hep_server)
  sleep "$CYCLE_GAP"
  ALIVE=$(kill -0 "$CAPT" 2>/dev/null && echo yes || echo no)
  echo "cycle $cycle: alive=$ALIVE fds=$(fds)"
  [ "$ALIVE" = yes ] || { cleanup; fail "captagent died during cycle $cycle"; }
done

echo "### burst: $BURST kills in ~2 seconds"
for i in $(seq 1 "$BURST"); do kill "$SRV" 2>/dev/null; wait "$SRV" 2>/dev/null; sleep 0.2; SRV=$(hep_server); sleep 0.2; done
sleep 4
ALIVE=$(kill -0 "$CAPT" 2>/dev/null && echo yes || echo no)
END_FDS=$(fds)
echo "after burst: alive=$ALIVE fds=$END_FDS"

echo "### send failures logged (expect roughly one per disconnect)"
grep -c 'tcp send failed' /tmp/captagent.log || true
echo "### state transitions (if logged at this debug level)"
grep -o 'state change: [A-Z_]* => [A-Z_]*' /tmp/captagent.log | sort | uniq -c || true

cleanup
[ "$ALIVE" = yes ] || fail "captagent died during burst"
[ "$END_FDS" -le $((BASE_FDS + FD_SLACK)) ] || fail "fd count grew from $BASE_FDS to $END_FDS (leak)"
grep -q 'tcp send failed' /tmp/captagent.log || fail "no TCP send failures logged; the disconnect path was never exercised"
echo "### PASS: captagent survived $CYCLES cycles plus a $BURST-kill burst; fds $BASE_FDS -> $END_FDS"
exit 0
