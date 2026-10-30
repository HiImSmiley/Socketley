#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: /metrics carries every runtime type's own figures, through the one catalog, and the facts the
# daemon's alerts look at as series a rule can read.
#
# What each part would catch:
#   * a type whose figures never reach /metrics, as nine of twelve did while only storage, mail and tunnel had appenders
#   * a family written under the wrong TYPE, which turns rate() into nonsense
#   * a storage, mail or tunnel series renamed or relabelled, which dashboards and the tests beside this one read
#   * a fact that does not follow the world: a state that does not flip on a stop, a restart not counted, a tunnel
#     agent still counted linked after it went, a ratio outside (0,1]
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }

echo "=== Integration: every runtime type's figures in /metrics, and the daemon's facts ==="
daemon_isolate metricscat
T=$SOCKETLEY_TMPD
B=$((SL_PORT_BASE + 1700))
PM=$((B+0)); PS=$((B+1)); PX=$((B+2)); PXS=$((B+3)); PC=$((B+4)); PQ=$((B+5)); PD=$((B+6)); PN=$((B+7))
PI=$((B+8)); PL=$((B+9)); PST=$((B+10)); PE=$((B+11))
unset SOCKETLEY_CONFIG
mkdir -p "$HOME/.config/socketley"
printf 'config = {\n    metrics_port = %s\n}\n' "$PM" > "$HOME/.config/socketley/config.lua"
trap 'daemon_stop' EXIT
daemon_start "$BIN"

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext "subjectAltName=DNS:localhost" \
    -keyout "$T/k.pem" -out "$T/c.pem" 2>/dev/null
KEY=AKIAMETRICSCATALOG00
SEC=metricscatalogsecretmetricscat00
printf 'access_key = %s\nsecret_key = %s\n' "$KEY" "$SEC" > "$T/creds"
chmod 600 "$T/creds"
mkdir -p "$T/st" "$T/here"

made() {  # name, then the create's arguments
    local name=$1; shift
    local out
    out=$("$BIN" create "$@" -s 2>&1) || bad "$name is made" "$out"
}
made server  server srv -p "$PS" --mode inout
made client  client cl -t "127.0.0.1:$PS"
made proxy   proxy px -p "$PX" --backend "127.0.0.1:$PS"
made proxy   proxy pxs -p "$PXS" --tls --cert "$T/c.pem" --key "$T/k.pem" --backend "127.0.0.1:$PS"
made cache   cache ca -p "$PC" --maxmemory 64M
made mqtt    mqtt mq -p "$PQ" --anonymous
printf 'backend metricscatalogsecret0123\n' > "$T/keys"
made db      db dbx -p "$PD" --keys "$T/keys"
made dns     dns ns -p "$PN" --zone example.test --publish 127.0.0.1 --proxy none
made idp     idp auth -p "$PI" --issuer "http://127.0.0.1:$PI"
made mail    mail ml -p "$PL" --mail-domain example.test
made storage storage st -p "$PST" --dir "$T/st" --access-key "$KEY" --secret-key "$SEC" --max-bytes 1M
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PST/" && break; sleep 0.1; done
S() { curl -s --user "$KEY:$SEC" --aws-sigv4 'aws:amz:us-east-1:s3' "$@"; }
S -o /dev/null -X PUT "http://127.0.0.1:$PST/docs"
printf 'hello' | S -o /dev/null -X PUT --data-binary @- "http://127.0.0.1:$PST/docs/a.txt"
made sync    sync sy --dir "$T/here" --storage "st/docs" --credentials "$T/creds" --every 2s
made tunnel  tunnel tn --mode edge -p "$PE"
for _ in $(seq 1 50); do ss -ltn "sport = :$PE" | grep -q LISTEN && break; sleep 0.1; done
INV=$("$BIN" tunnel tn invite home --tcp "web:127.0.0.1:$PS" 2>&1)
made agent   tunnel home --mode agent --to "http://127.0.0.1:$PE" --join "$INV" --offer "web=127.0.0.1:$PS"

# A hit, a miss and a write the cache's ratio has to show.
python3 - "$PC" <<'PY'
import socket, sys
c = socket.create_connection(("127.0.0.1", int(sys.argv[1])), 5)
def cmd(*a):
    c.sendall(b"*%d\r\n" % len(a) + b"".join(b"$%d\r\n%s\r\n" % (len(x), x) for x in a))
    got = b""
    while not got.endswith(b"\r\n"):
        got += c.recv(4096)
cmd(b"SET", b"k", b"v" * 4096); cmd(b"GET", b"k"); cmd(b"GET", b"nope")
PY
# A query the dns runtime has to count, over UDP.
python3 - "$PN" <<'PY'
import socket, struct, sys
q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\x07example\x04test\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(q, ("127.0.0.1", int(sys.argv[1])))
try: s.recvfrom(4096)
except Exception: pass
PY

get() { curl -s -m 8 "http://127.0.0.1:$PM/metrics"; }
val() { awk -v n="$1" '$1==n{print $2; exit}' <<<"$M"; }
# Asked until the figures every worker publishes have reached the daemon, a second at most apart.
M=""
for _ in $(seq 1 60); do
    M=$(get)
    [ "$(val 'socketley_cache_get_hits_total{name="ca"}')" = 1 ] &&
        [ "$(val 'socketley_tunnel_agents_connected{name="tn"}')" = 1 ] &&
        [ -n "$(val 'socketley_dns_queries_total{name="ns",transport="udp"}')" ] &&
        [ "$(val 'socketley_dns_queries_total{name="ns",transport="udp"}')" != 0 ] && break
    sleep 0.5
done

# ── every type, its family with the right TYPE and a series of the runtime ──
has_type() {  # family type
    grep -qx "# TYPE $1 $2" <<<"$M"
}
series() {  # type family TYPE series
    if has_type "$2" "$3" && [ -n "$(val "$4")" ]; then ok
    else bad "$1: $4 is a $3" "TYPE line: '$(grep "^# TYPE $2 " <<<"$M")', series: '$(grep -F "$2{" <<<"$M" | head -2 | tr '\n' ' ')'"; fi
}
series server  socketley_server_peak_connections        gauge   'socketley_server_peak_connections{name="srv"}'
series client  socketley_client_dial_attempts_total      counter 'socketley_client_dial_attempts_total{name="cl"}'
series proxy   socketley_proxy_backends                  gauge   'socketley_proxy_backends{name="px"}'
series proxy   socketley_proxy_backend_failures_total    counter 'socketley_proxy_backend_failures_total{name="px"}'
series cache   socketley_cache_get_misses_total          counter 'socketley_cache_get_misses_total{name="ca"}'
series cache   socketley_cache_memory_used_bytes         gauge   'socketley_cache_memory_used_bytes{name="ca"}'
series mqtt    socketley_mqtt_sessions_connected         gauge   'socketley_mqtt_sessions_connected{name="mq"}'
series mqtt    socketley_mqtt_received_total             counter 'socketley_mqtt_received_total{name="mq",qos="1"}'
series db      socketley_db_documents                    gauge   'socketley_db_documents{name="dbx"}'
series db      socketley_db_writes_total                 counter 'socketley_db_writes_total{name="dbx"}'
series dns     socketley_dns_responses_total             counter 'socketley_dns_responses_total{name="ns",rcode="NXDOMAIN"}'
series idp     socketley_idp_sign_ins_barred_total       counter 'socketley_idp_sign_ins_barred_total{name="auth"}'
series idp     socketley_idp_accounts                    gauge   'socketley_idp_accounts{name="auth"}'
series mail    socketley_mail_queued                     gauge   'socketley_mail_queued{name="ml"}'
series mail    socketley_mail_blocklisted                gauge   'socketley_mail_blocklisted{name="ml"}'
series storage socketley_storage_objects                 gauge   'socketley_storage_objects{name="st"}'
series sync    socketley_sync_failing                    gauge   'socketley_sync_failing{name="sy"}'
series sync    socketley_sync_failures_total             counter 'socketley_sync_failures_total{name="sy"}'
series tunnel  socketley_tunnel_agents_joined            gauge   'socketley_tunnel_agents_joined{name="tn"}'
series tunnel  socketley_tunnel_agents_connected         gauge   'socketley_tunnel_agents_connected{name="tn"}'
series cache   socketley_cache_stat                      untyped 'socketley_cache_stat{name="ca",stat="mesh_links"}'

# The numbers are the runtimes' own: one hit, one miss, one query, one object, one agent of one.
[ "$(val 'socketley_cache_get_hits_total{name="ca"}') $(val 'socketley_cache_get_misses_total{name="ca"}')" = "1 1" ] && ok \
    || bad "the cache's hit and miss are counted" "$(grep -F 'socketley_cache_get_' <<<"$M" | grep -v '^#' | tr '\n' ' ')"
[ "$(val 'socketley_dns_queries_total{name="ns",transport="udp"}')" -ge 1 ] 2>/dev/null && ok \
    || bad "the dns query is counted" "$(grep -F 'socketley_dns_queries_total' <<<"$M" | tr '\n' ' ')"
[ "$(val 'socketley_tunnel_agents_joined{name="tn"}') $(val 'socketley_tunnel_agents_connected{name="tn"}')" = "1 1" ] && ok \
    || bad "the edge counts its one agent, joined and linked" "$(grep -F 'socketley_tunnel_agents' <<<"$M" | grep -v '^#' | tr '\n' ' ')"
# A family is written once: a second TYPE line for any name is a scrape Prometheus refuses whole.
dups=$(grep '^# TYPE ' <<<"$M" | awk '{print $3}' | sort | uniq -d | tr '\n' ' ')
[ -z "$dups" ] && ok || bad "each family has one TYPE line" "twice: $dups"
# And its series come together under it, since a series after another family's head belongs to that one.
scattered=$(awk '/^# TYPE /{fam=$3; seen[fam]=1; next} /^#/||/^$/{next}
                 {n=$1; sub(/\{.*/, "", n); if (n != fam && n in seen) print n}' <<<"$M" | sort -u | tr '\n' ' ')
[ -z "$scattered" ] && ok || bad "each family's series follow its head" "apart: $scattered"

# ── the names storage, mail and tunnel had before the catalog, each with its TYPE ──
while read -r fam typ; do
    has_type "$fam" "$typ" && ok || bad "the old family $fam is still a $typ" "$(grep "^# TYPE $fam " <<<"$M")"
done <<'EOF'
socketley_storage_buckets gauge
socketley_storage_objects gauge
socketley_storage_bytes_stored gauge
socketley_storage_bytes_received_total counter
socketley_storage_bytes_sent_total counter
socketley_storage_zero_copy_bytes_total counter
socketley_storage_tls_handshakes_total counter
socketley_storage_tls_failures_total counter
socketley_storage_http2_connections_total counter
socketley_storage_http2_streams_total counter
socketley_storage_http2_refused_total counter
socketley_storage_http2_resets_received_total counter
socketley_storage_http2_resets_sent_total counter
socketley_storage_http2_goaways_total counter
socketley_storage_http3_connections_total counter
socketley_storage_http3_open_connections gauge
socketley_storage_http3_streams_total counter
socketley_storage_http3_retries_total counter
socketley_storage_http3_forwarded_total counter
socketley_storage_notify_sent_total counter
socketley_storage_notify_failed_total counter
socketley_storage_notify_queued gauge
socketley_storage_notify_dropped_total counter
socketley_storage_replication_pending gauge
socketley_storage_replication_completed_total counter
socketley_storage_replication_failed_total counter
socketley_storage_replication_retries_total counter
socketley_storage_replication_bytes_total counter
socketley_storage_cluster_pending gauge
socketley_storage_cluster_sent_total counter
socketley_storage_cluster_failed_total counter
socketley_storage_cluster_received_total counter
socketley_storage_cluster_seeding gauge
socketley_storage_cluster_overflows_total counter
socketley_storage_cluster_synced_total counter
socketley_storage_cluster_sync_timeouts_total counter
socketley_storage_scrub_objects_total counter
socketley_storage_scrub_bytes_total counter
socketley_storage_scrub_corrupt_total counter
socketley_storage_scrub_passes_total counter
socketley_storage_scrub_heals_total counter
socketley_storage_scrub_unhealed_total counter
socketley_storage_compressed_objects_total counter
socketley_storage_compressed_bytes_in_total counter
socketley_storage_compressed_bytes_out_total counter
socketley_storage_tier_moved_total counter
socketley_storage_tier_moved_bytes_total counter
socketley_storage_tier_failed_total counter
socketley_storage_tier_reads_total counter
socketley_storage_tier_read_failures_total counter
socketley_storage_lifecycle_expired_total counter
socketley_storage_lifecycle_aborted_total counter
socketley_storage_multipart_completed_total counter
socketley_storage_media_made_total counter
socketley_storage_media_failed_total counter
socketley_storage_fsyncs_total counter
socketley_storage_requests_total counter
socketley_storage_stat untyped
socketley_mail_received_total counter
socketley_mail_delivered_total counter
socketley_mail_deferred_total counter
socketley_mail_bounced_total counter
socketley_mail_queued gauge
socketley_mail_queued_bytes gauge
socketley_mail_quarantined_total counter
socketley_mail_auth_failed_total counter
socketley_mail_stat untyped
socketley_tunnel_links gauge
socketley_tunnel_agents gauge
socketley_tunnel_streams_total counter
socketley_tunnel_refused_total counter
socketley_tunnel_visitors_refused_total counter
socketley_tunnel_bytes_in_total counter
socketley_tunnel_bytes_out_total counter
socketley_tunnel_shares gauge
socketley_tunnel_flows gauge
socketley_tunnel_datagrams_total counter
socketley_tunnel_datagrams_dropped_total counter
EOF
# Their labels as they were: the op, the catch-all's stat, and a figure the catch-all keeps beside its new family.
for s in 'socketley_storage_requests_total{name="st",op="put"}' 'socketley_storage_stat{name="st",stat="multipart_created"}' \
         'socketley_storage_stat{name="st",stat="max_bytes"}' 'socketley_mail_stat{name="ml",stat="mail_self_listed"}' \
         'socketley_mail_stat{name="ml",stat="mail_complaints"}' 'socketley_tunnel_links{name="tn"}'; do
    [ -n "$(val "$s")" ] && ok || bad "the series $s is still there" "$(grep -F "${s%%\{*}{" <<<"$M" | head -3 | tr '\n' ' ')"
done
[ "$(val 'socketley_storage_requests_total{name="st",op="put"}')" -ge 1 ] 2>/dev/null && ok \
    || bad "the storage's put is counted" "$(val 'socketley_storage_requests_total{name="st",op="put"}')"

# ── the facts ──
st() { val "socketley_runtime_state{name=\"$1\",type=\"$2\",state=\"$3\"}"; }
[ "$(st srv server running) $(st srv server stopped) $(st srv server failed) $(st srv server created)" = "1 0 0 0" ] && ok \
    || bad "a running server's state is 1 for running alone" "$(grep -F 'socketley_runtime_state{name="srv"' <<<"$M" | tr '\n' ' ')"
ratio_ok() { awk -v r="$1" 'BEGIN { exit !(r != "" && r > 0 && r <= 1) }'; }
disk=$(grep '^socketley_disk_free_ratio{path="' <<<"$M" | head -1 | awk '{print $2}')
ratio_ok "$disk" && has_type socketley_disk_free_ratio gauge && ok || bad "a disk's free ratio is in (0,1]" "'$disk'"
mem=$(val socketley_host_memory_available_ratio)
ratio_ok "$mem" && ok || bad "the host's available memory ratio is in (0,1]" "'$mem'"
left=$(val "socketley_cert_expiry_seconds{name=\"pxs\",path=\"$T/c.pem\"}")
awk -v l="$left" 'BEGIN { exit !(l != "" && l > 86400 && l <= 172800) }' && has_type socketley_cert_expiry_seconds gauge && ok \
    || bad "a two-day certificate has between one and two days left" "'$left' $(grep '^socketley_cert' <<<"$M" | tr '\n' ' ')"
q=$(val 'socketley_runtime_quota_ratio{name="ca",type="cache"}')
awk -v r="$q" 'BEGIN { exit !(r != "" && r > 0 && r < 1) }' && ok || bad "the cache holds a share of its limit" "'$q'"
qs=$(val 'socketley_runtime_quota_ratio{name="st",type="storage"}')
# Five bytes of a mebibyte, as the storage's own figures say.
awk -v r="$qs" 'BEGIN { exit !(r != "" && r > 0 && r < 0.001) }' && ok || bad "the storage holds its five bytes of 1M" "'$qs'"
[ "$(val 'socketley_mail_blocklisted{name="ml"}')" = 0 ] && ok || bad "an unlisted mail runtime is not blocklisted" \
    "$(val 'socketley_mail_blocklisted{name="ml"}')"
r0=$(val 'socketley_runtime_restarts_total{name="cl"}')
[ "$r0" = 0 ] && has_type socketley_runtime_restarts_total counter && ok || bad "a client never restarted says 0" "'$r0'"

# A stop flips the state, a killed worker the supervisor puts back is a restart, and an agent stopped is not linked.
"$BIN" stop srv >/dev/null 2>&1
pid=$("$BIN" stats cl 2>/dev/null | sed -n 's/^pid://p' | head -1)
[ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
"$BIN" stop home >/dev/null 2>&1
for _ in $(seq 1 60); do
    sleep 0.5
    M=$(get)
    [ "$(st srv server stopped)" = 1 ] && [ "$(val 'socketley_runtime_restarts_total{name="cl"}')" = 1 ] &&
        [ "$(val 'socketley_tunnel_agents_connected{name="tn"}')" = 0 ] && break
done
[ "$(st srv server running) $(st srv server stopped)" = "0 1" ] && ok \
    || bad "a stopped server's state is 1 for stopped alone" "$(grep -F 'socketley_runtime_state{name="srv"' <<<"$M" | tr '\n' ' ')"
[ "$(val 'socketley_runtime_restarts_total{name="cl"}')" = 1 ] && ok \
    || bad "a worker killed and put back is one restart" "pid '$pid', $(grep -F 'restarts_total{name="cl"' <<<"$M")"
[ "$(val 'socketley_tunnel_agents_joined{name="tn"}') $(val 'socketley_tunnel_agents_connected{name="tn"}')" = "1 0" ] && ok \
    || bad "an agent stopped is still expected and no longer linked" "$(grep -F 'socketley_tunnel_agents' <<<"$M" | grep -v '^#' | tr '\n' ' ')"
[ -z "$(val 'socketley_server_peak_connections{name="srv"}')" ] && ok \
    || bad "a stopped server's own figures are gone" "$(val 'socketley_server_peak_connections{name="srv"}')"

echo "  Results: $PASS/$((PASS+FAIL)) passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
