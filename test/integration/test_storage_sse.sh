#!/usr/bin/env bash
# Integration test: server-side encryption on the storage runtime.
#
# ─── WHAT THIS HOLDS DOWN ───────────────────────────────────────────────────
#
#   SSE-S3      PUT, CreateMultipartUpload and CopyObject with AES256 are
#               answered with it; GET, HEAD, ranges across chunk and part
#               boundaries, partNumber, multipart in place and copied,
#               UploadPartCopy and copies in every direction read the plaintext;
#               the ETag stays the plaintext's MD5, and a copy of a COMPOSITE
#               source, sealed or opened, has the FULL_OBJECT checksum of its
#               plaintext; an object sent without a checksum, SSE-S3, SSE-C or an
#               SSE-S3 upload with no algorithm, and every copy into or out of a
#               sealed body, has S3's default CRC64NVME of its plaintext, which a
#               SIGKILL with every journal removed reads back from its header
#   on disk     an object's file never holds its plaintext, which a clear
#               object's file does, so the search can fail
#   default     PutBucketEncryption / Get / Delete, AES256 only, aws:kms refused;
#               a bucket with a default encrypts every new object, copy and upload
#   SSE-C       over TLS only: the right key reads, a missing one is 400, another
#               is 403, a key whose MD5 does not match is 400; the ETag is not
#               the MD5; nothing of it is held in memory; multipart and copies
#   SSE-C list  a completion binds the part list with the key it carries, else
#               with a MAC under the master key, else is refused 400; a header
#               that drops the last part, or the MAC, reads nothing
#   refusals    SSE-C over plain HTTP, aws:kms, an unknown algorithm, AES256 on a
#               runtime with no key, a key file others may read or of the wrong length
#   recovery    a clean restart and a SIGKILL with every journal removed bring
#               every encrypted object back from its file
#   shards      with --shards 2 a default set through one shard is the other's,
#               and every object reads alike through its owner and the other
#   versioning  every version of an encrypted key reads back by its id
#   tampering   a header cut to a chunk boundary or to empty, two parts' chunks
#               swapped, a part dropped from the header and a record set back to
#               format 1 are each an error, never shorter or mixed data
#   part list   an encrypted upload of parts of nine sizes, numbered with gaps,
#               whose list does not fit the header (made small here by
#               SOCKETLEY_STORAGE_PART_LIST_MAX) completes and reads by range and
#               partNumber, after a restart too; each part's SHA-256 follows a
#               sealed body, copied or sealed in place, and under SSE-C a MAC
#   pool        small SSE-S3 puts take a pooled file, and one whose worker is
#               killed after its rename (SOCKETLEY_STORAGE_KILL_AFTER_RENAME) and
#               whose rename is then lost is rolled forward by the next start
#   policy      a bucket policy with s3:x-amz-server-side-encryption refuses
#               uploads that do not ask for AES256
#
# The assertions live in lib_storage_sse.py, which prints one line each.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgsse

P1=$((SL_PORT_BASE+1650))
P2=$((SL_PORT_BASE+1651))
P3=$((SL_PORT_BASE+1652))
T="$SOCKETLEY_TMPD"
CERTS="$T/certs"

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
has() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "got '$2', want '$3'"; fi; }
contains() { if has "$2" "$3"; then ok "$1"; else bad "$1" "no '$3' in: $2"; fi; }

RUNTIMES="sse ssetls ssenokey ssetlsnokey sses x1 x2 x3"
cleanup() {
    for r in $RUNTIMES; do "$BIN" stop "$r" >/dev/null 2>&1 || true; done
    sleep 0.3
    for r in $RUNTIMES; do "$BIN" remove "$r" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
wait_up() {   # port [curl args]
    local p=$1; shift
    for _ in $(seq 1 100); do
        [ "$(code "$@" "$p")" != 000 ] && return 0
        sleep 0.1
    done
    return 1
}
wait_nodes() {   # node...
    local node t
    for node in "$@"; do
        for t in $(seq 1 150); do
            [ "$(code --unix-socket "$node" http://x/)" = 200 ] && continue 2
            sleep 0.1
        done
        return 1
    done
}
run_lib() {   # label runtime mode args...
    local label=$1 rt=$2; shift 2
    local out rc p f
    out=$(RUNTIME=$rt python3 "$HERE/lib_storage_sse.py" "$@" 2>&1); rc=$?
    echo "$out" | grep -E '^  (PASS|FAIL|SKIP)'
    p=$(echo "$out" | grep -c '^  PASS')
    f=$(echo "$out" | grep -c '^  FAIL')
    PASS=$((PASS+p)); FAIL=$((FAIL+f)); TOTAL=$((TOTAL+p+f))
    if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then bad "$label" "exit $rc: $out"; fi
}

echo "=== Integration: storage server-side encryption ==="
for tool in openssl curl python3; do
    command -v "$tool" >/dev/null 2>&1 || { echo "  FAIL: $tool is required"; exit 1; }
done
python3 -c 'import boto3' 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }

mkdir -p "$CERTS"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$CERTS/srv-key.pem" -out "$CERTS/srv.pem" \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 || true
[ -s "$CERTS/srv.pem" ] || { echo "  FAIL: openssl could not make the test certificate"; exit 1; }

KEY="$T/master.key"
head -c 32 /dev/urandom > "$KEY"
chmod 600 "$KEY"
# Read by the workers the daemon starts: a part list over 48 bytes goes after the body, and a put of a
# killme/ key kills its worker right after its rename.
export SOCKETLEY_STORAGE_PART_LIST_MAX=48 SOCKETLEY_STORAGE_KILL_AFTER_RENAME=killme/
daemon_start "$BIN"

# ── the key file ────────────────────────────────────────────────────────────
head -c 32 /dev/urandom > "$T/open.key"; chmod 644 "$T/open.key"
out=$("$BIN" create storage x1 -p "$P3" --dir "$T/x1" --anonymous --sse-key-file "$T/open.key" -s 2>&1); rc=$?
expect "a key file other users may read is refused" "$([ "$rc" -ne 0 ] && echo refused)" refused
"$BIN" remove x1 >/dev/null 2>&1
head -c 31 /dev/urandom > "$T/short.key"; chmod 600 "$T/short.key"
out=$("$BIN" create storage x2 -p "$P3" --dir "$T/x2" --anonymous --sse-key-file "$T/short.key" -s 2>&1); rc=$?
expect "a key file of 31 bytes is refused" "$([ "$rc" -ne 0 ] && echo refused)" refused
"$BIN" remove x2 >/dev/null 2>&1
printf '%064x\n' 7 > "$T/hex.key"; chmod 600 "$T/hex.key"
out=$("$BIN" create storage x3 -p "$P3" --dir "$T/x3" --anonymous --sse-key-file "$T/hex.key" -s 2>&1); rc=$?
expect "a key file of 64 hex digits is taken" "$rc" 0
"$BIN" stop x3 >/dev/null 2>&1; "$BIN" remove x3 >/dev/null 2>&1
out=$("$BIN" create storage x3 -p "$P3" --dir "$T/x3" --anonymous --sse-key-file 2>&1); rc=$?
expect "--sse-key-file with no path is refused" "$rc" 1

# ── a cleartext runtime with a master key ───────────────────────────────────
DATA="$T/objects"
if ! "$BIN" create storage sse -p "$P1" --dir "$DATA" --anonymous --sse-key-file "$KEY" -s >/dev/null 2>&1; then
    echo "  FAIL [create]: the runtime was not created"
    exit 1
fi
wait_up "http://127.0.0.1:$P1/" || bad "the runtime comes up" "no answer on $P1"
contains "show names the key file" "$("$BIN" show sse 2>&1)" "\"sse_key_file\": \"$KEY\""
out=$("$BIN" edit sse --sse-key-file "$T/hex.key" 2>&1)
contains "edit refuses the key file and points at import" "$out" "import"
run_lib "the main half ran" sse main "$P1" "$DATA"
run_lib "the recovery half ran" sse recovery "$P1" "$DATA"
run_lib "the tamper half ran" sse tamper "$P1" "$DATA"
run_lib "the layout half ran" sse layout "$P1" "$DATA"
run_lib "the pool half ran" sse pool "$P1" "$DATA"
run_lib "the policy half ran" sse policy "$P1"
"$BIN" stop sse >/dev/null 2>&1

# ── a TLS runtime with a master key, for SSE-C ──────────────────────────────
if ! "$BIN" create storage ssetls -p "$P2" --dir "$T/tlsobjects" --anonymous --sse-key-file "$KEY" \
        --tls --cert "$CERTS/srv.pem" --key "$CERTS/srv-key.pem" -s >/dev/null 2>&1; then
    bad "create with --tls" "the runtime was not created"
else
    wait_up "https://localhost:$P2/" --cacert "$CERTS/srv.pem" || bad "the TLS runtime comes up" "no answer on $P2"
    run_lib "the TLS half ran" ssetls tls "$P2" "$CERTS/srv.pem" "$T/tlsobjects"
    "$BIN" stop ssetls >/dev/null 2>&1
fi

# ── a runtime without one ───────────────────────────────────────────────────
if ! "$BIN" create storage ssenokey -p "$P3" --dir "$T/nokey" --anonymous -s >/dev/null 2>&1; then
    bad "create without a key" "the runtime was not created"
else
    wait_up "http://127.0.0.1:$P3/" || bad "the keyless runtime comes up" "no answer on $P3"
    run_lib "the keyless half ran" ssenokey nokey "$P3"
    "$BIN" stop ssenokey >/dev/null 2>&1
fi

# ── a TLS runtime without one, so an SSE-C completion has only the key to bind with ──
if ! "$BIN" create storage ssetlsnokey -p "$P3" --dir "$T/tlsnokey" --anonymous \
        --tls --cert "$CERTS/srv.pem" --key "$CERTS/srv-key.pem" -s >/dev/null 2>&1; then
    bad "create with --tls and no key" "the runtime was not created"
else
    wait_up "https://localhost:$P3/" --cacert "$CERTS/srv.pem" || bad "the keyless TLS runtime comes up" "no answer on $P3"
    run_lib "the keyless TLS half ran" ssetlsnokey tlsnokey "$P3" "$CERTS/srv.pem" "$T/tlsnokey"
    "$BIN" stop ssetlsnokey >/dev/null 2>&1
fi

# ── two shards ──────────────────────────────────────────────────────────────
SDATA="$T/shardobjects"
SOCK="$T/sses.sock"
NODES=("$T/sses#0.sock" "$T/sses#1.sock")
if ! "$BIN" create storage sses --listen "unix:$SOCK" --dir "$SDATA" --anonymous --sse-key-file "$KEY" \
        --shards 2 -s >/dev/null 2>&1; then
    bad "create with --shards 2" "the runtime was not created"
else
    wait_nodes "${NODES[@]}" || bad "both shards answer" "no answer from ${NODES[*]}"
    run_lib "the shards half ran" sses shards "${NODES[@]}" "$SDATA"
fi

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
