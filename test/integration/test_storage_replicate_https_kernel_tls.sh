#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket and port window, so it runs beside the others
# Integration test: storage replicates a large object to an https target by sendfile through kernel TLS, and a small
# one, or any with kernel TLS off, as before.
#
# What each part would catch:
#   * a file body sent in the clear on a connection the kernel does not encrypt yet, or OpenSSL's records sent
#     through the kernel once more: a replica that never arrives, or arrives torn and refused by its MD5
#   * the body source sent as well as the file, which the destination refuses as a body longer than its length
#   * the source no longer the way where the kernel cannot take the key (SOCKETLEY_KERNEL_TLS=0 stands for that)
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: storage replicates to an https target through kernel TLS ==="
command -v openssl >/dev/null 2>&1 || { echo "  SKIP: openssl is required"; exit 0; }
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
[ -r /proc/net/tls_stat ] || { echo "  SKIP: the kernel has no TLS layer here (modprobe tls)"; exit 0; }
daemon_isolate replktls
# Beside the daemons' own directories, which each daemon_stop takes with it.
T=$(mktemp -d)
unset SOCKETLEY_CONFIG
trap 'daemon_stop; rm -rf "$T"' EXIT
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 \
    -addext "subjectAltName=IP:127.0.0.1" -keyout "$T/k.pem" -out "$T/c.pem" >/dev/null 2>&1
AK=AKIAREPLKTLS00000001; SK=replktlssecretreplktlssecret0123456789ab
printf '%s:%s\n' "$AK" "$SK" > "$T/creds"
head -c $((6 << 20)) /dev/urandom > "$T/big"; head -c $((100 << 10)) /dev/urandom > "$T/small"
tx() { awk '$1=="TlsTxSw" {print $2}' /proc/net/tls_stat; }

# One pair per arm: a source in the clear replicating to a destination over TLS, trusted by the daemon.
pair() {   # arm port-offset [setting]
    local arm=$1 PS=$((SL_PORT_BASE + $2)) PD=$((SL_PORT_BASE + $2 + 1))
    echo "dst https://127.0.0.1:$PD us-east-1 $AK $SK" > "$T/targets.$arm"
    "$BIN" create storage "src$arm" -p "$PS" --dir "$T/src$arm" --anonymous --replication-targets "$T/targets.$arm" -s \
        >/dev/null 2>&1
    "$BIN" create storage "dst$arm" -p "$PD" --dir "$T/dst$arm" --credentials "$T/creds" --tls --cert "$T/c.pem" \
        --key "$T/k.pem" -s >/dev/null 2>&1
    for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PS/" && break; sleep 0.1; done
    for _ in $(seq 1 50); do curl -sk -o /dev/null "https://127.0.0.1:$PD/" && break; sleep 0.1; done
    PYTHONWARNINGS=ignore python3 - "$PS" "$PD" "$AK" "$SK" <<'PY'
import boto3, sys
from botocore.config import Config
ps, pd, ak, sk = sys.argv[1:5]
cfg = Config(signature_version="s3v4", s3={"addressing_style": "path"})
src = boto3.client("s3", endpoint_url="http://127.0.0.1:%s" % ps, aws_access_key_id="x", aws_secret_access_key="y",
                   region_name="us-east-1", config=cfg)
dst = boto3.client("s3", endpoint_url="https://127.0.0.1:%s" % pd, verify=False, aws_access_key_id=ak,
                   aws_secret_access_key=sk, region_name="us-east-1", config=cfg)
for c, b in ((src, "srcb"), (dst, "dstb")):
    c.create_bucket(Bucket=b); c.put_bucket_versioning(Bucket=b, VersioningConfiguration={"Status": "Enabled"})
src.put_bucket_replication(Bucket="srcb", ReplicationConfiguration={"Role": "arn:aws:iam::123456789012:role/dst", "Rules": [
    {"ID": "all", "Priority": 1, "Status": "Enabled", "Filter": {"Prefix": ""}, "Destination": {"Bucket": "arn:aws:s3:::dstb"},
     "DeleteMarkerReplication": {"Status": "Disabled"}}]})
PY
    echo "$PS $PD"
}
replica() {   # dst-port key -> sha of the replica once it is there
    local i
    for i in $(seq 1 200); do
        [ "$(curl -sk -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -I \
              "https://127.0.0.1:$1/dstb/$2")" = 200 ] && break
        sleep 0.05
    done
    curl -sk --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" "https://127.0.0.1:$1/dstb/$2" | sha256sum | cut -c1-16
}
sha() { sha256sum < "$1" | cut -c1-16; }

SSL_CERT_FILE="$T/c.pem" daemon_start "$BIN"
read -r PS PD < <(pair on 1922 | tail -1)
errors_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: '$1=="client_errors" {print $2}'; }
done_of() { "$BIN" stats "$1" 2>/dev/null | awk -F: '$1=="replication_completed" {print $2}'; }
wait_done() { for _ in $(seq 1 200); do [ "$(done_of "$1")" -ge "$2" ] 2>/dev/null && return; sleep 0.05; done; }
t0=$(tx); e0=$(errors_of dston)
curl -s -T "$T/big" "http://127.0.0.1:$PS/srcb/big" >/dev/null
wait_done srcon 1; sleep 0.5; e1=$(errors_of dston)
got=$(replica "$PD" big)
if [ "$got" = "$(sha "$T/big")" ] && [ "$(tx)" -gt "$t0" ]; then ok
else bad "a large object reaches an https target whole, through kernel TLS" "replica $got, kernel TLS sockets $t0 -> $(tx)"; fi
# The body goes once: a source sent as well as the file is a second copy, which the destination parses as requests
# that are no requests.
if [ "${e1:-x}" = "${e0:-y}" ]; then ok
else bad "and the body goes once, nothing after it" "the destination counted $e0 -> $e1 client errors"; fi
curl -s -T "$T/small" "http://127.0.0.1:$PS/srcb/small" >/dev/null
got=$(replica "$PD" small)
[ "$got" = "$(sha "$T/small")" ] && ok || bad "a small one reaches it whole as before" "replica $got"
daemon_stop

# The way where the kernel cannot take the key: the source, beside the file.
daemon_isolate replktls-off
SSL_CERT_FILE="$T/c.pem" SOCKETLEY_KERNEL_TLS=0 daemon_start "$BIN"
read -r PS PD < <(pair off 1924 | tail -1)
t0=$(tx)
curl -s -T "$T/big" "http://127.0.0.1:$PS/srcb/big" >/dev/null
got=$(replica "$PD" big)
if [ "$got" = "$(sha "$T/big")" ] && [ "$(tx)" = "$t0" ]; then ok
else bad "with kernel TLS off the large object goes by its source, whole" "replica $got, kernel TLS sockets $t0 -> $(tx)"; fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
