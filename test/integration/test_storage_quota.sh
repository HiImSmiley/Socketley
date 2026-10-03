#!/usr/bin/env bash
# Integration test: bucket quotas (?quota) and user quotas (max_bytes in the credentials file)
#
# ─── WHY THIS FILE EXISTS ───────────────────────────────────────────────────
#
# A quota is judged where every write of a key is, by the shard that owns it,
# one write at a time, so a bucket or a user cannot go past it by racing; a
# landing shard that knows the key refuses a body before reading it.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a quota document that is not one taken, or one taken and not read back
#   * a write past MaxBytes or MaxObjects stored, or an overwrite that adds no
#     object refused at MaxObjects
#   * versions not counted against MaxObjects in a versioned bucket
#   * a quota lost by a restart, or still held after DELETE ?quota
#   * two shards together storing past the bucket's bytes
#   * a user's buckets together storing past max_bytes, or a user who is no
#     admin setting a quota
# suite: isolated
set -uo pipefail
BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ports.sh"
exec 2>&1

echo "=== Integration: bucket and user quotas ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
check() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }

daemon_isolate stgquota
trap 'daemon_stop' EXIT
daemon_start "$BIN"
P1=$((SL_PORT_BASE + 1891)); P2=$((SL_PORT_BASE + 1892)); P3=$((SL_PORT_BASE + 1893))
up() { for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$1/" && return 0; sleep 0.1; done; return 1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
body() { curl -s "$@"; }
blob() { head -c "$1" /dev/zero | tr '\0' x; }

"$BIN" create storage qa -p "$P1" --dir "$SOCKETLEY_TMPD/qa" --anonymous -s >/dev/null 2>&1
up "$P1" || bad "the runtime serves" "no answer on $P1"
U="http://127.0.0.1:$P1"
curl -s -X PUT "$U/qbucket" -o /dev/null

# ── the document ──
check "a document that is no quota is MalformedXML" \
    "$(code -X PUT "$U/qbucket?quota" --data '<Quota><Max>1</Max></Quota>')" 400
check "a bucket without a quota answers NoSuchBucketQuota" "$(code "$U/qbucket?quota")" 404
check "a quota is set" \
    "$(code -X PUT "$U/qbucket?quota" --data '<BucketQuota><MaxBytes>10000</MaxBytes><MaxObjects>3</MaxObjects></BucketQuota>')" 200
got=$(body "$U/qbucket?quota")
check "and read back" "$(echo "$got" | grep -c '<MaxBytes>10000</MaxBytes><MaxObjects>3</MaxObjects>')" 1
check "an object has no quota" "$(code "$U/qbucket/k?quota")" 501

# ── objects and bytes ──
for i in 1 2 3; do blob 1000 > "$SOCKETLEY_TMPD/b1k"; done
r=""; for i in 1 2 3; do r="$r$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/b1k" "$U/qbucket/o$i")"; done
check "three objects fit MaxObjects 3" "$r" 200200200
check "a fourth is QuotaExceeded" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/b1k" "$U/qbucket/o4")" 403
check "saying so" "$(body -X PUT --data-binary @"$SOCKETLEY_TMPD/b1k" "$U/qbucket/o4" | grep -c '<Code>QuotaExceeded</Code>')" 1
check "an overwrite adds no object and is taken" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/b1k" "$U/qbucket/o1")" 200
blob 8500 > "$SOCKETLEY_TMPD/b8k"
check "an overwrite past MaxBytes is QuotaExceeded" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/b8k" "$U/qbucket/o1")" 403
check "and the object is as it was" "$(body "$U/qbucket/o1" | wc -c)" 1000
check "a delete makes room" "$(code -X DELETE "$U/qbucket/o3")" 204
check "for a new object" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/b1k" "$U/qbucket/o5")" 200

# ── a restart keeps it, a delete takes it away ──
"$BIN" stop qa >/dev/null 2>&1; "$BIN" start qa >/dev/null 2>&1; up "$P1"
check "a restart keeps the quota" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/b1k" "$U/qbucket/o6")" 403
check "DELETE ?quota removes it" "$(code -X DELETE "$U/qbucket?quota")" 204
check "after which the bucket has none" "$(code "$U/qbucket?quota")" 404
check "and takes a fourth object" "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/b1k" "$U/qbucket/o6")" 200

# ── versions count ──
curl -s -X PUT "$U/vbucket" -o /dev/null
curl -s -X PUT "$U/vbucket?versioning" --data '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>' -o /dev/null
curl -s -X PUT "$U/vbucket?quota" --data '<BucketQuota><MaxObjects>2</MaxObjects></BucketQuota>' -o /dev/null
r=""; for i in 1 2 3; do r="$r$(code -X PUT --data-binary "v$i" "$U/vbucket/same")"; done
check "in a versioned bucket every version counts against MaxObjects" "$r" 200200403

# ── two shards share a bucket's bytes ──
"$BIN" create storage qs -p "$P2" --dir "$SOCKETLEY_TMPD/qs" --anonymous --shards 2 -s >/dev/null 2>&1
up "$P2" || bad "the sharded runtime serves" "no answer on $P2"
S="http://127.0.0.1:$P2"
curl -s -X PUT "$S/sbucket" -o /dev/null
sleep 0.3
curl -s -X PUT "$S/sbucket?quota" --data '<BucketQuota><MaxBytes>8000</MaxBytes></BucketQuota>' -o /dev/null
taken=0; for i in $(seq 1 20); do [ "$(code -X PUT --data-binary @"$SOCKETLEY_TMPD/b1k" "$S/sbucket/k$i")" = 200 ] && taken=$((taken+1)); done
[ "$taken" -ge 2 ] && [ "$taken" -le 8 ] && ok || bad "two shards together stay within MaxBytes" "$taken of 20 1000-byte puts taken"

# ── a user's buckets share max_bytes ──
CREDS="$SOCKETLEY_TMPD/creds"
cat > "$CREDS" <<EOF
AKIAQUOTAADMIN000000:quotaadminsecretquotaadminsecret0000000

[alice]
max_bytes = 5000
AKIAQUOTAALICE000000:quotaalicesecretquotaalicesecret0000000
EOF
"$BIN" create storage qu -p "$P3" --dir "$SOCKETLEY_TMPD/qu" --credentials "$CREDS" -s >/dev/null 2>&1
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$P3/" && break; sleep 0.1; done
out=$(python3 - "$P3" "$HERE" <<'PY'
import http.client, sys
sys.path.insert(0, sys.argv[2])
import lib_s3_signing as sig
port = int(sys.argv[1])
keys = {"admin": ("AKIAQUOTAADMIN000000", "quotaadminsecretquotaadminsecret0000000"),
        "alice": ("AKIAQUOTAALICE000000", "quotaalicesecretquotaalicesecret0000000")}
def req(who, method, path, query="", body=b""):
    ak, sk = keys[who]
    s = sig.sign(method, path, query, "127.0.0.1:%d" % port, ak, sk, sig.sha256hex(body))
    c = http.client.HTTPConnection("127.0.0.1", port)
    c.request(method, path + ("?" + query if query else ""), body=body, headers=s.headers)
    r = c.getresponse(); data = r.read(); c.close()
    return r.status, data
out = []
out.append(req("alice", "PUT", "/alice-one")[0])
out.append(req("alice", "PUT", "/alice-two")[0])
out.append(req("alice", "PUT", "/alice-one/a", body=b"x" * 2000)[0])
out.append(req("alice", "PUT", "/alice-two/b", body=b"x" * 2000)[0])
out.append(req("alice", "PUT", "/alice-two/c", body=b"x" * 2000)[0])
out.append(req("alice", "PUT", "/alice-one?quota", "quota", b"<BucketQuota><MaxBytes>1</MaxBytes></BucketQuota>")[0])
out.append(req("admin", "PUT", "/admin-one")[0])
out.append(req("admin", "PUT", "/admin-one/d", body=b"x" * 9000)[0])
out.append(req("admin", "GET", "/alice-one", "quota")[0])
print(" ".join(map(str, out)))
PY
)
set -- $out
check "alice makes two buckets" "$1 $2" "200 200"
check "and stores 4000 bytes over them" "$3 $4" "200 200"
check "and is refused past her 5000" "$5" 403
check "a user who is no admin may not set a quota" "$6" 403
check "an admin's buckets are not hers" "$7 $8" "200 200"
check "an admin reads a bucket's quota, none here" "$9" 404

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || { echo "  FAILED"; exit 1; }
