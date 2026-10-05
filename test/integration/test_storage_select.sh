#!/usr/bin/env bash
# Integration test: SelectObjectContent runs a SQL expression over a CSV or JSON object and answers in AWS's event
# stream, read by boto3's own parser.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * records, Stats or End missing from the stream, or a frame boto3 cannot
#     parse
#   * a filter, a projection, an aggregate or LIMIT answered wrong, over a
#     body larger than a window, a compressed one and an encrypted one
#   * an expression that is not SQL, or a key that is not there, answered
#     other than as S3 does
#   * the policy's GetObject not deciding who may select
# suite: isolated
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
export BIN
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"

daemon_isolate stgselect
P=$((SL_PORT_BASE+1999))
export ADMIN_AK="AKIASELECTADMIN00001"
export ADMIN_SK="select/admin/secret"
export READER_AK="AKIASELECTREADER0001"
export READER_SK="select/reader/secret"

cleanup() { "$BIN" stop sel >/dev/null 2>&1; "$BIN" remove sel >/dev/null 2>&1; daemon_stop; }
trap cleanup EXIT

echo "=== Integration: storage SelectObjectContent ==="
python3 -c "import boto3" 2>/dev/null || { echo "  SKIP: boto3 is required"; exit 0; }
daemon_start "$BIN"
T="$SOCKETLEY_TMPD"
cat > "$T/creds" <<CREDS
[admin]
$ADMIN_AK:$ADMIN_SK
admin = true
[reader]
$READER_AK:$READER_SK
policy = {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::sel/open/*"}]}
CREDS
head -c 32 /dev/urandom > "$T/master.key"; chmod 600 "$T/master.key"
"$BIN" create storage sel -p "$P" --dir "$T/data" --credentials "$T/creds" --sse-key-file "$T/master.key" \
    --compress 1s --shards 2 -s >/dev/null 2>&1 || { echo "  FAIL [create]: the runtime was not created"; exit 1; }
for _ in $(seq 1 100); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done

python3 - "$P" <<'PY'
import os, sys, time
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
port = int(sys.argv[1])
def client(ak, sk):
    return boto3.client("s3", endpoint_url="http://127.0.0.1:%d" % port, region_name="us-east-1",
                        aws_access_key_id=ak, aws_secret_access_key=sk,
                        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))
c = client(os.environ["ADMIN_AK"], os.environ["ADMIN_SK"])
reader = client(os.environ["READER_AK"], os.environ["READER_SK"])
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    passed, failed = (passed + 1, failed) if cond else (passed, failed + 1)
    print(("  PASS: " if cond else "  FAIL [%s]: " % name) + (name if cond else str(detail)[:600]), flush=True)
def select(key, sql, fmt="csv", header="USE", out="csv", cl=c, **kw):
    inp = {"CSV": {"FileHeaderInfo": header}} if fmt == "csv" else {"JSON": {"Type": "LINES"}}
    outs = {"CSV": {}} if out == "csv" else {"JSON": {}}
    try:
        r = cl.select_object_content(Bucket="sel", Key=key, Expression=sql, ExpressionType="SQL",
                                     InputSerialization=inp, OutputSerialization=outs, **kw)
        records, stats, ended = b"", None, False
        for ev in r["Payload"]:
            if "Records" in ev:
                records += ev["Records"]["Payload"]
            elif "Stats" in ev:
                stats = ev["Stats"]["Details"]
            elif "End" in ev:
                ended = True
        return records.decode(), stats, ended
    except ClientError as e:
        return e.response["Error"]["Code"], None, False

c.create_bucket(Bucket="sel")
rows = ["id,name,city,amount"] + ["%d,user%d,%s,%d" % (i, i, ("Berlin", "Paris", "Rome")[i % 3], i % 100)
                                  for i in range(120000)]
csv = ("\n".join(rows) + "\n").encode()
c.put_object(Bucket="sel", Key="people.csv", Body=csv)
c.put_object(Bucket="sel", Key="open/sealed.csv", Body=csv[:200000], ServerSideEncryption="AES256")
c.put_object(Bucket="sel", Key="events.json", Body=b"".join(
    b'{"kind":"%s","n":%d,"tags":{"env":"%s"}}\n' % (("click", "view")[i % 2].encode(), i, (b"prod", b"dev")[i % 4 == 0])
    for i in range(1000)))

out, stats, ended = select("people.csv", "SELECT s.name FROM S3Object s WHERE s.city = 'Rome' AND CAST(s.amount AS INT) > 97")
want = "".join("user%d\n" % i for i in range(120000) if i % 3 == 2 and i % 100 > 97)
check("a filter and a projection over a body of many windows", out == want, (out[:200], len(out), len(want)))
check("the stream ends with Stats of the bytes scanned, and End",
      ended and stats and stats["BytesScanned"] == len(csv) and stats["BytesReturned"] == len(out), stats)
out, _, _ = select("people.csv", "SELECT COUNT(*), SUM(CAST(amount AS INT)), MAX(CAST(id AS INT)) FROM S3Object")
check("aggregates are one record", out == "%d,%d,%d\n" % (120000, sum(i % 100 for i in range(120000)), 119999), out)
out, _, _ = select("people.csv", "SELECT * FROM S3Object LIMIT 3")
check("LIMIT stops after its records", out == "".join(r + "\n" for r in rows[1:4]), out)
out, _, _ = select("events.json", "SELECT s.n FROM S3Object s WHERE s.tags.env = 'dev' AND s.kind = 'click'",
                   fmt="json", out="json")
check("JSON lines with a nested path, answered as JSON",
      out == "".join('{"n":%d}\n' % i for i in range(1000) if i % 4 == 0 and i % 2 == 0), out[:200])
out, _, _ = select("open/sealed.csv", "SELECT COUNT(*) FROM S3Object")
# The slice ends inside a line, which is a record of its own.
check("an SSE-S3 object is read in its plaintext",
      out == "%d\n" % (len([l for l in csv[:200000].split(b"\n") if l]) - 1), out)
check("a reader its policy lets GetObject may select", select("open/sealed.csv", "SELECT COUNT(*) FROM S3Object",
                                                           cl=reader)[0].strip().isdigit())
check("and one it does not is AccessDenied",
      select("people.csv", "SELECT COUNT(*) FROM S3Object", cl=reader)[0] == "AccessDenied")
code = select("people.csv", "SELEKT nothing")[0]
check("an expression that is not SQL is refused before the stream", code not in ("", None) and "\n" not in code, code)
check("a key that is not there is NoSuchKey", select("nope.csv", "SELECT * FROM S3Object")[0] == "NoSuchKey")

# Once the compaction has taken the CSV, the same query reads the chunks.
import subprocess
def compressed():
    out = subprocess.run([os.environ["BIN"], "stats", "sel"], capture_output=True, text=True).stdout
    return sum(int(l.split(":")[1]) for l in out.splitlines() if l.startswith("compressed_objects:"))
end = time.time() + 30
while time.time() < end and compressed() < 2:
    time.sleep(0.5)
check("the CSV and the JSON are compressed meanwhile", compressed() >= 2, compressed())
out2, _, _ = select("people.csv", "SELECT s.name FROM S3Object s WHERE s.city = 'Rome' AND CAST(s.amount AS INT) > 97")
check("and a compressed object answers the same", out2 == want, (out2[:200], len(out2)))
print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(failed)
PY
rc=$?
"$BIN" stats sel 2>&1 | awk -F: '$1=="selects"{s+=$2} $1=="compressed_objects"{z+=$2} END{print "  stats: selects " s ", compressed " z}'
[ "$rc" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$rc"
