#!/usr/bin/env bash
# Integration test: server access logging (?logging)
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a BucketLoggingStatus S3 refuses taken, or one taken and not read back
#   * the policy S3 documents for a log target refused, or read as letting anyone in
#   * an answer to a logged bucket's request missing from its log, or a line
#     whose fields are not the request's
#   * a log object named other than prefix, date and a unique suffix, or a
#     partitioned one not under owner, region, bucket and date
#   * a bucket that is not logged written into a log, or logging that goes on
#     after it was turned off or stops at a restart
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: server access logging ==="
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stglog
trap 'daemon_stop' EXIT
export SOCKETLEY_STORAGE_LOG_FLUSH_MS=300
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1899))
U="http://127.0.0.1:$P1"
"$BIN" create storage lg -p "$P1" --dir "$SOCKETLEY_TMPD/lg" --anonymous --shards 2 -s >/dev/null 2>&1
up() { for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$U/")" != 000 ] && return 0; sleep 0.1; done; return 1; }
up || bad "the runtime serves" "no answer on $P1"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
for b in src logs src2 quiet; do curl -s -X PUT "$U/$b" -o /dev/null; done
sleep 0.3

# Every log object's text under prefix $1 of the logs bucket, once $2 lines match pattern $3, within ten seconds.
logs_text() {
    local out=""
    for _ in $(seq 1 100); do
        out=""
        for k in $(curl -s "$U/logs?list-type=2&prefix=$1" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g'); do
            out="$out$(curl -s "$U/logs/$k")
"
        done
        [ "$(printf '%s' "$out" | grep -c -- "${3:-.}")" -ge "$2" ] && break
        sleep 0.1
    done
    printf '%s' "$out"
}

# ── the document ──
check "a bucket that is not logged answers an empty status" \
    "$(curl -s "$U/src?logging" | grep -c '<BucketLoggingStatus[^>]*></BucketLoggingStatus>')" 1
check "a target that is not there is InvalidTargetBucketForLogging" \
    "$(curl -s -X PUT "$U/src?logging" --data '<BucketLoggingStatus><LoggingEnabled><TargetBucket>nope</TargetBucket><TargetPrefix>x/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>' | grep -c '<Code>InvalidTargetBucketForLogging</Code>')" 1
check "grants are AccessControlListNotSupported" \
    "$(curl -s -X PUT "$U/src?logging" --data '<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>x/</TargetPrefix><TargetGrants/></LoggingEnabled></BucketLoggingStatus>' | grep -c '<Code>AccessControlListNotSupported</Code>')" 1
check "a document that is no status is MalformedXML" "$(code -X PUT "$U/src?logging" --data '<Logging/>')" 400
check "logging is turned on" \
    "$(code -X PUT "$U/src?logging" --data '<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>site/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>')" 200
check "and read back" "$(curl -s "$U/src?logging" | grep -c '<TargetBucket>logs</TargetBucket><TargetPrefix>site/</TargetPrefix>')" 1
check "an object has no logging" "$(code "$U/src/k?logging")" 501
# The policy S3 documents for a log target names the delivery service, which is taken and lets nobody in.
LOGPOL='{"Version":"2012-10-17","Statement":[{"Sid":"S3ServerAccessLogsPolicy","Effect":"Allow","Principal":{"Service":"logging.s3.amazonaws.com"},"Action":["s3:PutObject"],"Resource":"arn:aws:s3:::logs/site/*","Condition":{"ArnLike":{"aws:SourceArn":"arn:aws:s3:::src"},"StringEquals":{"aws:SourceAccount":"123456789012"}}}]}'
check "a log target's policy naming the delivery service is taken" "$(code -X PUT "$U/logs?policy" --data "$LOGPOL")" 204
check "and is not public" "$(curl -s "$U/logs?policyStatus" | grep -c '<IsPublic>false</IsPublic>')" 1

# ── the lines ──
curl -s -A 'logtest/1.0' -X PUT --data-binary hello "$U/src/a%20b" -o /dev/null
curl -s -A 'logtest/1.0' "$U/src/a%20b" -o /dev/null
curl -s -A 'logtest/1.0' "$U/src/missing" -o /dev/null
curl -s -A 'logtest/1.0' -I "$U/src/a%20b" -o /dev/null
curl -s -A 'logtest/1.0' "$U/quiet" -o /dev/null
text=$(logs_text site/ 4 logtest/1.0)
check "four answers, four lines" "$(printf '%s\n' "$text" | grep -c 'logtest/1.0')" 4
check "a put names its operation, key, status and size" \
    "$(printf '%s\n' "$text" | grep -c '^socketley src \[[0-9]*/[A-Z][a-z]*/[0-9]*:[0-9:]* +0000\] 127\.0\.0\.1 - [^ ]* REST\.PUT\.OBJECT a%20b "PUT /src/a%20b HTTP/1\.1" 200 - - 5 ')" 1
check "a get the bytes it sent" "$(printf '%s\n' "$text" | grep -c 'REST\.GET\.OBJECT a%20b "GET /src/a%20b HTTP/1\.1" 200 - 5 ')" 1
check "a miss its status and error code" "$(printf '%s\n' "$text" | grep -c 'REST\.GET\.OBJECT missing "GET /src/missing HTTP/1\.1" 404 NoSuchKey ')" 1
check "a head" "$(printf '%s\n' "$text" | grep -c 'REST\.HEAD\.OBJECT a%20b ')" 1
check "with the client's user agent and host" "$(printf '%s\n' "$text" | grep -c "\"logtest/1.0\" - - - - - 127.0.0.1:$P1 - - -$")" 4
check "a bucket that is not logged is in no log" "$(printf '%s\n' "$text" | grep -c ' quiet ')" 0
# A DeleteObjects is one line for the request and one for each key, as S3 writes a batch.
DEL='<Delete><Object><Key>d1</Key></Object><Object><Key>d2</Key></Object></Delete>'
curl -s -A 'batch/1.0' -X POST "$U/src?delete" -H "Content-MD5: $(printf '%s' "$DEL" | openssl md5 -binary | base64)" --data "$DEL" -o /dev/null
text=$(logs_text site/ 3 batch/1.0)
check "a DeleteObjects is a MULTI_OBJECT_DELETE line" "$(printf '%s\n' "$text" | grep -c 'REST\.POST\.MULTI_OBJECT_DELETE - "POST /src?delete HTTP/1\.1" 200 ')" 1
check "and a BATCH.DELETE.OBJECT line for each key" "$(printf '%s\n' "$text" | grep -cE 'BATCH\.DELETE\.OBJECT d[12] .* 204 - ')" 2
keys=$(curl -s "$U/logs?list-type=2&prefix=site/" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g')
check "a log object is named prefix, delivery time and a unique suffix" \
    "$(printf '%s\n' "$keys" | grep -vcE '^site/[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9A-F]{16}$')" 0

# ── partitioned ──
curl -s -X PUT "$U/src2?logging" --data '<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>p/</TargetPrefix><TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>EventTime</PartitionDateSource></PartitionedPrefix></TargetObjectKeyFormat></LoggingEnabled></BucketLoggingStatus>' -o /dev/null
curl -s "$U/src2/none" -o /dev/null
logs_text p/ 1 'GET /src2/none' >/dev/null
keys=$(curl -s "$U/logs?list-type=2&prefix=p/" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g')
check "a partitioned log is under owner, region, bucket and date" \
    "$(printf '%s\n' "$keys" | grep -vcE '^p/socketley/us-east-1/src2/[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9A-F]{16}$')" 0
check "and there is one" "$([ -n "$keys" ] && echo yes)" yes

# ── a restart keeps it, an empty status ends it ──
"$BIN" stop lg >/dev/null 2>&1; "$BIN" start lg >/dev/null 2>&1; up
curl -s -A 'after-restart' "$U/src/a%20b" -o /dev/null
check "a restart keeps logging" "$(logs_text site/ 1 after-restart | grep -c 'after-restart')" 1
check "an empty status turns it off" "$(code -X PUT "$U/src?logging" --data '<BucketLoggingStatus/>')" 200
check "after which the bucket answers an empty status" "$(curl -s "$U/src?logging" | grep -c '<LoggingEnabled>')" 0
curl -s -A 'after-off' "$U/src/a%20b" -o /dev/null
sleep 2
check "and nothing more is logged" "$(logs_text site/ 0 | grep -c 'after-off')" 0

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
