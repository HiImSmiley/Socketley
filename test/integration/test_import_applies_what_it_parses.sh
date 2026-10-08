#!/usr/bin/env bash
# Integration test: import applies the fields the man page documents for it,
# and tells the worker.
#
# man/socketley.1's "Edit: JSON Configuration Fields" table lists sixteen proxy
# fields and marks none of the nine service-mesh ones (read-only). The
# interactive `socketley edit NAME` goes through this same command: cli.cpp
# dumps the document, opens $EDITOR, and sends the result back as `import`.
#
# Measured before this fix, on a private daemon:
#
#     create proxy p -p P --backend B
#     show p > doc.json          # edit circuit_timeout to 15, retry_count to 3
#     import p "$(cat doc.json)" -> exit 0, nothing printed
#     show p                     -> neither field is there; still 30 and 0
#
# cmd_import's `case runtime_proxy` applied seven of sixteen -- protocol,
# strategy, backends and the three mesh_client_* paths. The nine were parsed
# into cfg, handed to no setter, and then save_runtime() at the end of the
# function wrote the unchanged instance back over the state file. So the
# document door and the flag door disagreed: `edit p --circuit-timeout 15`
# always worked.
#
# The server half was the same, narrower: http_dir and http_cache are parsed
# and printed by `show` and were applied nowhere.
#
# ─── THE SECOND MISSING HOP ─────────────────────────────────────────────────
#
# cmd_edit ends by pushing the whole document to every worker, with a comment
# saying why: "Without this the edit was stored, reported by `show`, answered
# 0 -- and the process holding the port went on enforcing the value it was
# spawned with." cmd_import ended at save_runtime() with no push at all, and
# send_config had exactly ONE call site in the tree. So even the seven fields
# it did apply only reached the daemon's placeholder. That block is a function
# now and both doors call it.
#
# ─── WHY PRESENCE AND NOT "!= DEFAULT" ──────────────────────────────────────
#
# apply_proxy_config is shared with the boot restore, which has only the value
# to go on: a state file is the whole truth and an absent field means the
# default, so it tests "!= default". A document has its key set, and needs to:
# an operator putting circuit_timeout BACK to 30 is asking for 30, and a
# "!= 30" test drops the request silently. One list, two questions -- because a
# tenth mesh field added to a copy of that list is a field one of the two doors
# would not apply. The last case below is exactly that: 15 -> 30.
set -euo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_create.sh"
. "$(dirname "$0")/lib_ports.sh"
. "$(dirname "$0")/lib_ready.sh"
daemon_isolate importfields

P_PRX=$((SL_PORT_BASE+1850))
P_BCK=$((SL_PORT_BASE+1851))
P_SRV=$((SL_PORT_BASE+1852))
NAMES="if_prx if_srv"

PASS=0; FAIL=0; TOTAL=0

cleanup() {
    for n in $NAMES; do "$BIN" stop "$n" >/dev/null 2>&1 || true; done
    sleep 0.3
    for n in $NAMES; do "$BIN" remove "$n" >/dev/null 2>&1 || true; done
    daemon_stop
}
trap cleanup EXIT

ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

check() {   # label expected actual
    if [ "$2" = "$3" ]; then ok; else bad "$1" "expected '$2', got '$3'"; fi
}

# One field out of `show`, without a JSON parser in the assertion: the value is
# whatever follows the key up to the comma.
field() {   # name key
    "$BIN" show "$1" 2>/dev/null \
        | sed -n "s/^ *\"$2\": *\(.*\?\),\{0,1\}$/\1/p" | sed 's/,$//;s/^"//;s/"$//'
}

# The document with a set of edits applied, the way the interactive editor
# hands it back.
reimport() {   # name  python-dict-expression
    local name=$1 edits=$2
    "$BIN" show "$name" > "$SOCKETLEY_TMPD/doc.json" 2>/dev/null
    python3 - "$SOCKETLEY_TMPD/doc.json" "$edits" <<'PYEOF'
import json, sys
path, edits = sys.argv[1], sys.argv[2]
d = json.load(open(path))
d.update(eval(edits))
open(path + ".new", "w").write(json.dumps(d))
PYEOF
    "$BIN" import "$name" "$(tr -d '\n' < "$SOCKETLEY_TMPD/doc.json.new")" 2>&1
}

echo "=== Integration: import applies what it parses ==="
daemon_start "$BIN"

# ─── 1. The nine service-mesh fields, on a stopped proxy ────────────────────
create_ok "a proxy" "$BIN" create proxy if_prx -p "$P_PRX" \
    --backend "127.0.0.1:$P_BCK"

OUT=$(reimport if_prx '{"health_check":1,"health_interval":11,"health_path":"/hz","health_threshold":7,"circuit_threshold":9,"circuit_timeout":15,"backend_timeout":9,"retry_count":3,"retry_all":True}')
if [ -z "$OUT" ]; then ok; else bad "the import is accepted" "got '$OUT'"; fi

check "health_check"      "1"    "$(field if_prx health_check)"
check "health_interval"   "11"   "$(field if_prx health_interval)"
check "health_path"       "/hz"  "$(field if_prx health_path)"
check "health_threshold"  "7"    "$(field if_prx health_threshold)"
check "circuit_threshold" "9"    "$(field if_prx circuit_threshold)"
check "circuit_timeout"   "15"   "$(field if_prx circuit_timeout)"
check "backend_timeout"   "9"    "$(field if_prx backend_timeout)"
check "retry_count"       "3"    "$(field if_prx retry_count)"
check "retry_all"         "true" "$(field if_prx retry_all)"

# ─── 2. A field put back to its default is honoured ─────────────────────────
# The whole reason the shared list needed a second question. "!= 30" would
# leave 15 here and report success.
OUT=$(reimport if_prx '{"circuit_timeout":30}')
if [ -z "$OUT" ]; then ok; else bad "putting a default back is accepted" "got '$OUT'"; fi
# `show` omits a field that equals its default, so the absence IS the assertion.
check "circuit_timeout went back to 30" "" "$(field if_prx circuit_timeout)"

# ─── 3. Omitting a mesh path leaves it alone; "" clears it ─────────────────
# This is the case that caught a stale paragraph in the man page rather than a
# defect in the code.  The page said in one place that omitting client_ca /
# client_cert / client_key clears them, and thirty lines earlier that "a field
# the document does not mention is left alone.  Clearing one is written out
# rather than implied" -- which is the newer rule and a deliberate one: a
# runtime configured for TLS could be handed {"name":"x"} and answer in
# cleartext afterwards with the command reporting success.  The code follows
# the newer rule, the stale paragraph is corrected, and this asserts both
# halves so they cannot drift apart again.
"$BIN" edit if_prx --client-cert /a.pem --client-key /a.key >/dev/null 2>&1 || true
if [ -n "$(field if_prx mesh_client_cert)" ]; then ok; else
    bad "the mTLS pair was set to begin with" "mesh_client_cert is empty"; fi

"$BIN" show if_prx > "$SOCKETLEY_TMPD/doc.json"
python3 - "$SOCKETLEY_TMPD/doc.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
for k in ("mesh_client_cert", "mesh_client_key", "mesh_client_ca"):
    d.pop(k, None)
open(sys.argv[1] + ".new", "w").write(json.dumps(d))
PYEOF
"$BIN" import if_prx "$(tr -d '\n' < "$SOCKETLEY_TMPD/doc.json.new")" >/dev/null 2>&1 || true
check "an omitted mesh path is left alone" "/a.pem" "$(field if_prx mesh_client_cert)"

# And the spelling that does clear it, which is the documented recovery for a
# runtime whose certificate files have gone.
OUT=$(reimport if_prx "{'mesh_client_cert':'','mesh_client_key':'','mesh_client_ca':''}")
if [ -z "$OUT" ]; then ok; else bad "an empty mesh path is accepted" "got '$OUT'"; fi
check "and \"\" clears it" "" "$(field if_prx mesh_client_cert)"

# ─── 4. And the worker hears it, on a runtime that is already serving ──────
# send_config had one call site in the tree, in cmd_edit. This is the other
# door, and the one the interactive editor uses.
"$BIN" start if_prx >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_PRX" >/dev/null 2>&1 || true

# `grep -c` prints 0 and exits 1 on no match, so `|| true` and not `|| echo 0`.
BEFORE=$(grep -c "applied an edit to the running runtime" "$SOCKETLEY_DLOG" 2>/dev/null || true)
OUT=$(reimport if_prx '{"retry_count":5}')
if [ -z "$OUT" ]; then ok; else bad "import on a running proxy is accepted" "got '$OUT'"; fi
sleep 0.8
AFTER=$(grep -c "applied an edit to the running runtime" "$SOCKETLEY_DLOG" 2>/dev/null || true)
check "the worker was told" "1" "$((AFTER - BEFORE))"
check "and the value moved"  "5" "$(field if_prx retry_count)"

"$BIN" stop if_prx >/dev/null 2>&1 || true

# ─── 5. The server's two, which had the same hole ──────────────────────────
create_ok "a server" "$BIN" create server if_srv -p "$P_SRV"
mkdir -p "$SOCKETLEY_TMPD/www"
printf 'hello\n' > "$SOCKETLEY_TMPD/www/index.html"
OUT=$(reimport if_srv "{'http_dir':'$SOCKETLEY_TMPD/www','http_cache':True}")
if [ -z "$OUT" ]; then ok; else bad "the server import is accepted" "got '$OUT'"; fi
check "http_dir"   "$SOCKETLEY_TMPD/www" "$(field if_srv http_dir)"
check "http_cache" "true"                "$(field if_srv http_cache)"

# It is a real static root and not just a stored string: the runtime serves it.
"$BIN" start if_srv >/dev/null 2>&1 || true
ready_tcp 127.0.0.1 "$P_SRV" >/dev/null 2>&1 || true
BODY=$(timeout 5 python3 - "$P_SRV" <<'PYEOF' 2>/dev/null || echo "-"
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5); s.settimeout(3)
s.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
buf = b""
while True:
    try:
        c = s.recv(4096)
    except Exception:
        break
    if not c: break
    buf += c
print("hello" if b"hello" in buf else buf[:40].decode("latin1"))
PYEOF
)
check "and the directory is really served" "hello" "$BODY"

# ─── 6. A port the document cannot hold is refused, not truncated ──────────
# cfg.port is a uint16_t and parse_json_string fills it with
# static_cast<uint16_t>(json_get_int(...)), so 70000 used to arrive as 4464 --
# accepted, exit 0, and `show` reporting a port nobody typed.  Measured: 70000
# -> 4464, -1 -> 65535.  The flag door has always refused the same input,
# because parse_uint16() checks std::errc::result_out_of_range.
#
# The document is re-read raw here for the same reason `listen` already was:
# once the parser has narrowed the value there is nothing left to judge.
KEEP=$(field if_srv port)
for BADPORT in 70000 -1 99999999999 notanumber; do
    # `|| true` because reimport hands back the import's own status, and a
    # refusal is a 1 -- which under `set -e` ends the file at the assignment,
    # after the refusal it was checking has already been produced.
    OUT=$(reimport if_srv "{'port':$( [ "$BADPORT" = notanumber ] && echo "'x'" || echo "$BADPORT" )}") || true
    case "$OUT" in
        *"is not a port number"*) ok ;;
        *) bad "port $BADPORT is refused" "import said '${OUT:-<nothing>}'" ;;
    esac
done
check "and the runtime kept the port it had" "$KEEP" "$(field if_srv port)"

# The spelling that is fine still is, so the refusal is about the range and not
# about the field.  Stopped first, because a RUNNING runtime refuses a port
# change on its own and correctly -- "cannot change port while running" -- and
# that refusal would hide whether the range check let this one through.
"$BIN" stop if_srv >/dev/null 2>&1 || true
sleep 0.3
OUT=$(reimport if_srv "{'port':$((P_SRV+3))}") || true
if [ -z "$OUT" ]; then ok; else bad "a port in range is accepted" "got '$OUT'"; fi
check "and it moved" "$((P_SRV+3))" "$(field if_srv port)"

# A document without "name" is about the runtime the command names; one that is no object is still refused.
OUT=$("$BIN" import if_prx '{"circuit_timeout": 17}' 2>&1)
if [ -z "$OUT" ]; then ok; else bad "a document without a name is the named runtime's" "got '$OUT'"; fi
check "and it is applied" "17" "$(field if_prx circuit_timeout)"
check "text that is no object is refused" "invalid JSON" "$("$BIN" import if_prx 'circuit_timeout 17' 2>&1)"
check "and so is an empty name" "invalid JSON" "$("$BIN" import if_prx '{"name": ""}' 2>&1)"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
[ "$FAIL" -eq 0 ]
