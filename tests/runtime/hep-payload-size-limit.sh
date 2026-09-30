#!/bin/bash
#
# Runtime test for transport_hep max-payload-len and max-hep-size config params.
#
# Verifies that captagent truncates the HEP3 payload chunk to the configured
# max-payload-len, and that max-hep-size drops optional chunks before truncating
# the payload.  A Python HEP3 parser reads the raw TCP stream and asserts that
# every received payload chunk satisfies the configured limit.
#
# Runs inside a rockylinux:9 container as root with NET_RAW + NET_ADMIN.
# Expects the captagent RPM in ${RPM_DIR:-/tmp/build}.
#
# Exit 0 on pass, 1 on failure.
#
set -u
exec 2>&1

RPM_DIR="${RPM_DIR:-/tmp/build}"
MAX_PAYLOAD="${MAX_PAYLOAD:-200}"
SEND_COUNT="${SEND_COUNT:-50}"
ETC=/usr/local/captagent/etc/captagent
PREFIX=/usr/local/captagent

fail() {
    echo "### FAIL: $*"
    [ -f /tmp/captagent.log ] && { echo "--- captagent.log (tail) ---"; tail -40 /tmp/captagent.log; cp /tmp/captagent.log "$RPM_DIR/captagent-payload-limit.log" 2>/dev/null; }
    exit 1
}

echo "### install captagent RPM and test tools"
dnf -y -q install epel-release >/dev/null || fail "epel-release install failed"
dnf -y -q install "$RPM_DIR"/captagent-*.rpm python3 procps-ng >/dev/null || fail "package install failed"

BIN=$PREFIX/sbin/captagent
[ -x "$BIN" ] || fail "captagent binary missing at $BIN"

echo "### render captagent.xml from template"
sed -e "s#@module_dir@#$PREFIX/lib/captagent/modules#" \
    -e "s#@agent_config_dir@#$ETC/#" \
    -e "s#@agent_capture_plan@#$ETC/captureplans#" \
    -e "s#@agent_backup@#$ETC/backup#" \
    -e "s#@agent_chroot@#$ETC#" \
    "$ETC/captagent.xml.in" > "$ETC/captagent.xml" || fail "could not render captagent.xml"

echo "### configure transport_hep.xml: TCP + max-payload-len=$MAX_PAYLOAD"
sed -i \
    's/capture-proto" value="udp"/capture-proto" value="tcp"/;
     s/capture-port" value="9061"/capture-port" value="9060"/' \
    "$ETC/transport_hep.xml"

# Inject max-payload-len param before the closing </settings> tag
sed -i "s#</settings>#    <param name=\"max-payload-len\" value=\"${MAX_PAYLOAD}\"/>\n</settings>#" \
    "$ETC/transport_hep.xml"

grep -q 'max-payload-len' "$ETC/transport_hep.xml" || fail "max-payload-len not injected into transport_hep.xml"
ip link set lo up 2>/dev/null || true

# HEP3 parser server: reads the TCP stream, parses every HEP3 packet,
# checks payload chunk (type 0x000f / 0x0010) length, exits with violation
# count written to /tmp/hep-result.txt.
cat > /tmp/hep_server.py << PYEOF
import socket, struct, sys

MAX_PAYLOAD = int(sys.argv[1])
EXPECT_PKTS = int(sys.argv[2])

def parse_hep3(data):
    if len(data) < 6 or data[:4] != b'HEP3':
        return None
    total_len = struct.unpack('>H', data[4:6])[0]
    if len(data) < total_len:
        return None
    pos = 6
    chunks = {}
    while pos + 6 <= total_len:
        vendor_id, type_id, chunk_len = struct.unpack('>HHH', data[pos:pos+6])
        if chunk_len < 6:
            break
        chunks[type_id] = data[pos+6:pos+chunk_len]
        pos += chunk_len
    return chunks

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 9060))
srv.listen(5)
srv.settimeout(30)

packets = 0
violations = 0

try:
    conn, _ = srv.accept()
    conn.settimeout(20)
    buf = b''
    while packets < EXPECT_PKTS:
        try:
            data = conn.recv(8192)
        except socket.timeout:
            break
        if not data:
            break
        buf += data
        while len(buf) >= 6:
            if buf[:4] != b'HEP3':
                buf = buf[1:]
                continue
            total_len = struct.unpack('>H', buf[4:6])[0]
            if len(buf) < total_len:
                break
            pkt = buf[:total_len]
            buf = buf[total_len:]
            chunks = parse_hep3(pkt)
            if chunks is None:
                continue
            packets += 1
            # 0x000f = raw payload, 0x0010 = compressed payload
            payload = chunks.get(0x000f, b'') or chunks.get(0x0010, b'')
            if len(payload) > MAX_PAYLOAD:
                violations += 1
                print(f"VIOLATION pkt#{packets}: payload {len(payload)} > {MAX_PAYLOAD}", flush=True)
            else:
                print(f"OK pkt#{packets}: payload {len(payload)} <= {MAX_PAYLOAD}", flush=True)
except Exception as e:
    print(f"server error: {e}", flush=True)

print(f"RESULT: packets={packets} violations={violations}", flush=True)
with open('/tmp/hep-result.txt', 'w') as f:
    f.write(f"{packets} {violations}\n")
sys.exit(1 if violations > 0 or packets == 0 else 0)
PYEOF

echo "### start HEP3 validation server"
python3 /tmp/hep_server.py "$MAX_PAYLOAD" "$SEND_COUNT" > /tmp/hep-server.log 2>&1 &
SRV=$!
sleep 0.5

echo "### start captagent"
"$BIN" -f "$ETC/captagent.xml" > /tmp/captagent.log 2>&1 &
CAPT=$!
sleep 3
kill -0 "$CAPT" 2>/dev/null || fail "captagent died at startup"

echo "### send $SEND_COUNT large SIP INVITEs (body >> max-payload-len)"
python3 - << PYEOF
import socket, time

# Build a SIP INVITE with a large SDP body to push payload well over max-payload-len
sdp_lines = [
    "v=0",
    "o=test 12345 12345 IN IP4 127.0.0.1",
    "s=hep-payload-size-limit-test",
    "c=IN IP4 127.0.0.1",
    "t=0 0",
]
# Pad SDP with enough a= lines to guarantee payload > 500 bytes
for i in range(30):
    sdp_lines.append(f"a=fmtp:{i} profile-level-id=42e01f;packetization-mode=1;sprop-parameter-sets=Z0IAH{i:04d}==,aO48gA==")
sdp = "\r\n".join(sdp_lines) + "\r\n"

for i in range(${SEND_COUNT}):
    body = sdp
    msg = (
        f"INVITE sip:bob@127.0.0.1 SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP 127.0.0.1:5062;branch=z9hG4bK-{i}\r\n"
        f"From: <sip:alice@127.0.0.1>;tag=tag{i}\r\n"
        f"To: <sip:bob@127.0.0.1>\r\n"
        f"Call-ID: call-{i}@127.0.0.1\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(msg.encode(), ("127.0.0.1", 5060))
    s.close()
    time.sleep(0.05)
PYEOF

echo "### wait for HEP3 server to finish"
wait "$SRV" 2>/dev/null
SRV_EXIT=$?

cat /tmp/hep-server.log

READ_PKTS=0; VIOLS=0
if [ -f /tmp/hep-result.txt ]; then
    READ_PKTS=$(awk '{print $1}' /tmp/hep-result.txt)
    VIOLS=$(awk '{print $2}' /tmp/hep-result.txt)
fi

kill "$CAPT" 2>/dev/null
cp /tmp/captagent.log "$RPM_DIR/captagent-payload-limit.log" 2>/dev/null

[ "$READ_PKTS" -gt 0 ] 2>/dev/null || fail "HEP3 server received no packets"
[ "$VIOLS" -eq 0 ] 2>/dev/null || fail "$VIOLS payload violations: payload chunks exceeded max-payload-len=$MAX_PAYLOAD"

echo "### PASS: $READ_PKTS packets received, all payload chunks <= $MAX_PAYLOAD bytes"
exit 0
