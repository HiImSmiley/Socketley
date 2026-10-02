#!/usr/bin/env python3
"""S3 event notifications on the storage runtime, delivered to a webhook this script serves.

usage: lib_storage_notify.py MODE ARGS...

  main PORT HOOK OTHER      the configuration's put and get, its refusals, every event the runtime emits with
                            the payload S3 gives it, prefix and suffix filters, a webhook that answers 500 and
                            one that is down until it comes up, and the bound on what waits
  tls PORT SECURE CERT KEY  an https webhook with a certificate the target's ca= names
  dns PORT HOOK HOSTS       a webhook named by a host the HOSTS file maps, followed when it maps it elsewhere
  users PORT HOOK           a runtime with users: the principal and address of a signed request and of one a
                            bucket policy lets in
  restart PORT HOOK        after a clean stop and a start: the configuration is still there and still sends
  crash PORT HOOK           the webhook is down while a PUT is answered, the worker is killed with SIGKILL before
                            the event could go, and the event arrives from the restarted worker's outbox
  shards HOOK NODE0 NODE1   two shards, one node each: every change sends one event, whichever shard took it

HOOK and OTHER are the ports the two webhook targets listen on.
Prints one PASS or FAIL line per assertion and exits with the number of failures.
"""
import http.client
import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET

MODE = sys.argv[1]
BIN = os.environ.get("BIN", "")
RUNTIME = os.environ.get("RUNTIME", "nt")
QUEUE_MAX = int(os.environ.get("SOCKETLEY_STORAGE_NOTIFY_QUEUE", "10000"))
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
ARN = "arn:socketley:webhook:::"
B = "notifyb"

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name, flush=True)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, str(detail)[:800]), flush=True)


def wait_for(fn, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.1)
    return fn()


# ── the webhook ─────────────────────────────────────────────────────────────
class Hook:
    """A webhook on 127.0.0.1:port that keeps every POST it is sent and answers it with `status`."""

    def __init__(self, port, tls=None, host="127.0.0.1"):
        self.port = port
        self.tls = tls
        self.host = host
        self.got = []
        self.status = 200
        self.server = None
        self.lock = threading.Lock()

    def up(self):
        hook = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                with hook.lock:
                    hook.got.append({"path": self.path, "headers": dict(self.headers), "body": body,
                                     "status": hook.status})
                self.send_response(hook.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        http.server.ThreadingHTTPServer.allow_reuse_address = True
        self.server = http.server.ThreadingHTTPServer((self.host, self.port), Handler)
        if self.tls:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*self.tls)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def down(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def records(self):
        """Every record the webhook answered 2xx, as (eventName, key, record)."""
        out = []
        with self.lock:
            for g in self.got:
                if g["status"] // 100 != 2:
                    continue
                try:
                    for r in json.loads(g["body"])["Records"]:
                        out.append((r["eventName"], r["s3"]["object"]["key"], r))
                except Exception:
                    out.append(("unparsed", "", g["body"]))
        return out

    def clear(self):
        with self.lock:
            self.got = []


# ── the runtime ─────────────────────────────────────────────────────────────
class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=60)
        self.path_ = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(60)
        self.sock.connect(self.path_)


TARGET = None


def req(method, path, body=b"", headers=None, target=None):
    t = target or TARGET
    c = UnixConn(t) if isinstance(t, str) else http.client.HTTPConnection("127.0.0.1", t, timeout=60)
    try:
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, dict((k.lower(), v) for k, v in r.getheaders()), r.read()
    finally:
        c.close()


def code_of(body):
    try:
        return ET.fromstring(body).findtext("Code")
    except Exception:
        return None


def stats_shards():
    out = subprocess.run([BIN, "stats", RUNTIME], capture_output=True, text=True).stdout
    shards, cur = {}, 0
    for line in out.splitlines():
        if line.startswith("[shard "):
            cur = int(line[7:].rstrip("]"))
            shards[cur] = {}
        elif ":" in line:
            k, v = line.split(":", 1)
            shards.setdefault(cur, {})[k.strip()] = v.strip()
    return shards


def nstats():
    """The notify_ lines of `stats`, per shard, for a failure's detail."""
    return {k: {n: v for n, v in s.items() if n.startswith("notify_")} for k, s in stats_shards().items()}


def stat(name):
    return sum(int(s.get(name, "0") or 0) for s in stats_shards().values())


def worker_pid():
    for s in stats_shards().values():
        if s.get("pid"):
            return s["pid"]
    return None


def rule(kind, rid, name, events, prefix=None, suffix=None):
    f = ""
    if prefix is not None or suffix is not None:
        f = "<Filter><S3Key>"
        if prefix is not None:
            f += "<FilterRule><Name>prefix</Name><Value>%s</Value></FilterRule>" % prefix
        if suffix is not None:
            f += "<FilterRule><Name>suffix</Name><Value>%s</Value></FilterRule>" % suffix
        f += "</S3Key></Filter>"
    ev = "".join("<Event>%s</Event>" % e for e in events)
    rid_x = "<Id>%s</Id>" % rid if rid else ""
    return "<%sConfiguration>%s<%s>%s</%s>%s%s</%sConfiguration>" % (kind, rid_x, kind, name, kind, ev, f, kind)


def doc(*rules):
    return ('<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">%s'
            '</NotificationConfiguration>' % "".join(rules)).encode()


def put_cfg(body, bucket=B, headers=None):
    st, _, b = req("PUT", "/%s?notification" % bucket, body, headers)
    return st, code_of(b) if st != 200 else None, b


def get_cfg(bucket=B):
    st, _, b = req("GET", "/%s?notification" % bucket)
    return st, b


def cfg_rules(body):
    root = ET.fromstring(body)
    out = []
    for c in root:
        kind = c.tag.replace(NS, "").replace("Configuration", "")
        out.append((kind, c.findtext(NS + "Id"), c.findtext(NS + kind),
                    sorted(e.text for e in c.findall(NS + "Event")),
                    sorted((r.findtext(NS + "Name"), r.findtext(NS + "Value")) for r in c.iter(NS + "FilterRule"))))
    return out


def events_for(hook, key):
    return [(n, r) for n, k, r in hook.records() if k == key]


def wait_event(hook, key, name, timeout=15):
    return wait_for(lambda: any(n == name for n, _ in events_for(hook, key)), timeout)


def post_form(bucket, key, data):
    boundary = "----notifyform"
    body = ("--%s\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n%s\r\n"
            "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n" % (boundary, key, boundary)).encode() + data + \
           ("\r\n--%s--\r\n" % boundary).encode()
    return req("POST", "/" + bucket, body, {"Content-Type": "multipart/form-data; boundary=" + boundary})


# ── main ────────────────────────────────────────────────────────────────────
def mode_main(port, hook_port, other_port):
    global TARGET
    TARGET = port
    hook = Hook(hook_port)
    hook.up()
    other = Hook(other_port)

    st, _, _ = req("PUT", "/" + B)
    check("the bucket is made", st == 200, st)
    st, b = get_cfg()
    check("a bucket with no configuration answers an empty one",
          st == 200 and ET.fromstring(b).tag == NS + "NotificationConfiguration" and len(ET.fromstring(b)) == 0, (st, b))

    # Refusals.
    check("a destination that is not a webhook's ARN is refused InvalidArgument",
          put_cfg(doc(rule("Queue", "q", "arn:aws:sqs:us-east-1:123456789012:q", ["s3:ObjectCreated:*"])))[:2]
          == (400, "InvalidArgument"))
    st, c, b = put_cfg(doc(rule("Queue", "q", ARN + "nosuch", ["s3:ObjectCreated:*"])))
    check("a webhook the runtime was not given is refused InvalidArgument, naming its ARN",
          (st, c) == (400, "InvalidArgument") and (ARN + "nosuch").encode() in b, (st, c, b))
    check("unless x-amz-skip-destination-validation asks for no check",
          put_cfg(doc(rule("Queue", "q", ARN + "nosuch", ["s3:ObjectCreated:*"])), B,
                  {"x-amz-skip-destination-validation": "true"})[:2] == (200, None))
    check("an event S3 does not have is refused InvalidArgument",
          put_cfg(doc(rule("Queue", "q", ARN + "hook", ["s3:ObjectCreated:Nope"])))[:2] == (400, "InvalidArgument"))
    check("a configuration with no Event is MalformedXML",
          put_cfg(doc(rule("Queue", "q", ARN + "hook", [])))[:2] == (400, "MalformedXML"))
    check("a document that is not a NotificationConfiguration is MalformedXML",
          put_cfg(b"<Nope/>")[:2] == (400, "MalformedXML"))
    check("a filter rule that is neither prefix nor suffix is refused InvalidArgument",
          put_cfg(doc(rule("Queue", "q", ARN + "hook", ["s3:ObjectCreated:*"]).replace(
              "</Queue>", "</Queue>").replace("<Event>", "<Filter><S3Key><FilterRule><Name>middle</Name><Value>x"
                                              "</Value></FilterRule></S3Key></Filter><Event>", 1)))[:2]
          == (400, "InvalidArgument"))
    check("two configurations sharing an event on overlapping keys are refused InvalidArgument",
          put_cfg(doc(rule("Queue", "a", ARN + "hook", ["s3:ObjectCreated:*"], prefix="x/"),
                      rule("Topic", "b", ARN + "other", ["s3:ObjectCreated:Put"], prefix="x/y")))[:2]
          == (400, "InvalidArgument"))
    check("two configurations with one Id are refused InvalidArgument",
          put_cfg(doc(rule("Queue", "a", ARN + "hook", ["s3:ObjectCreated:*"]),
                      rule("Queue", "a", ARN + "hook", ["s3:ObjectRemoved:*"])))[:2] == (400, "InvalidArgument"))
    check("EventBridge is refused InvalidArgument",
          put_cfg(doc("<EventBridgeConfiguration/>"))[:2] == (400, "InvalidArgument"))
    check("a bucket that does not exist is NoSuchBucket",
          put_cfg(doc(rule("Queue", "q", ARN + "hook", ["s3:ObjectCreated:*"])), "nosuchbucket")[:2]
          == (404, "NoSuchBucket"))
    st, _, b = req("GET", "/%s/k?notification" % B)
    check("an object has no notification configuration: NotImplemented", (st, code_of(b)) == (501, "NotImplemented"),
          (st, b))

    # The configuration this test runs on: everything to `hook`, one filter in two rules.
    cfg = doc(rule("Queue", "created", ARN + "hook", ["s3:ObjectCreated:*"], prefix="c/"),
              rule("Topic", "removed", ARN + "hook", ["s3:ObjectRemoved:*"], prefix="c/"),
              rule("CloudFunction", "", ARN + "hook", ["s3:ObjectTagging:*"], prefix="c/"),
              rule("Queue", "lc", ARN + "hook", ["s3:LifecycleExpiration:*"], prefix="lc/"),
              rule("Queue", "pics", ARN + "other", ["s3:ObjectCreated:Put"], prefix="pics/", suffix=".jpg"))
    check("a configuration of every kind of destination is put", put_cfg(cfg)[:2] == (200, None))
    st, b = get_cfg()
    got = cfg_rules(b) if st == 200 else b
    check("GetBucketNotificationConfiguration answers it, an Id made for the one that had none", got == [
        ("Queue", "created", ARN + "hook", ["s3:ObjectCreated:*"], [("Prefix", "c/")]),
        ("Topic", "removed", ARN + "hook", ["s3:ObjectRemoved:*"], [("Prefix", "c/")]),
        ("CloudFunction", "notification-3", ARN + "hook", ["s3:ObjectTagging:*"], [("Prefix", "c/")]),
        ("Queue", "lc", ARN + "hook", ["s3:LifecycleExpiration:*"], [("Prefix", "lc/")]),
        ("Queue", "pics", ARN + "other", ["s3:ObjectCreated:Put"], [("Prefix", "pics/"), ("Suffix", ".jpg")]),
    ], got)

    # ObjectCreated:Put, and the record S3 sends for it.
    key = "c/dir/a b+c=d.txt"
    path = "/%s/%s" % (B, "c/dir/a%20b%2Bc%3Dd.txt")
    st, h, _ = req("PUT", path, b"hello world")
    check("a PUT is answered", st == 200, st)
    check("ObjectCreated:Put arrives", wait_event(hook, "c/dir/a+b%2Bc%3Dd.txt", "ObjectCreated:Put"), hook.records())
    evs = events_for(hook, "c/dir/a+b%2Bc%3Dd.txt")
    r = evs[0][1] if evs else {}
    s3 = r.get("s3", {})
    check("the record has S3's fields", r.get("eventVersion") == "2.1" and r.get("eventSource") == "aws:s3" and
          r.get("awsRegion") == "us-east-1" and s3.get("s3SchemaVersion") == "1.0" and
          s3.get("configurationId") == "created" and s3.get("bucket", {}).get("name") == B and
          s3.get("bucket", {}).get("arn") == "arn:aws:s3:::" + B, r)
    t = r.get("eventTime", "")
    check("eventTime is ISO 8601 in UTC to the millisecond", len(t) == 24 and t[10] == "T" and t.endswith("Z"), t)
    o = s3.get("object", {})
    check("the key is form-encoded as S3 encodes it, '/' kept and a space as '+'",
          o.get("key") == "c/dir/a+b%2Bc%3Dd.txt", o.get("key"))
    check("size and eTag are the object's", o.get("size") == 11 and '"' + o.get("eTag", "") + '"' == h.get("etag"),
          (o, h.get("etag")))
    check("a sequencer is given", len(o.get("sequencer", "")) == 16, o)
    check("an unsigned request on an --anonymous runtime is the principal anonymous, from the client's address",
          r.get("userIdentity", {}).get("principalId") == "anonymous" and
          r.get("requestParameters", {}).get("sourceIPAddress") == "127.0.0.1", (r.get("userIdentity"),
                                                                              r.get("requestParameters")))
    hk = hook.got[0]["headers"] if hook.got else {}
    check("it is POSTed as JSON with an event id to deduplicate by",
          hk.get("Content-Type") == "application/json" and hk.get("X-Socketley-Event-Id", "").isdigit(), hk)

    # A virtual-hosted request names its bucket in the Host, and its event names the bucket and the key it parsed.
    st, _, _ = req("PUT", "/c/vhost/key", b"vhost", {"Host": "%s.s3.notify.test:%d" % (B, port)})
    check("a virtual-hosted PUT is answered", st == 200, st)
    check("its event names the bucket from the Host and the whole path as the key",
          wait_event(hook, "c/vhost/key", "ObjectCreated:Put") and
          [r["s3"]["bucket"]["name"] for _, r in events_for(hook, "c/vhost/key")] == [B], events_for(hook, "c/vhost/key"))

    # Every other event.
    st, _, _ = post_form(B, "c/form", b"by a form")
    check("a form upload is answered", st in (200, 204), st)
    check("ObjectCreated:Post arrives", wait_event(hook, "c/form", "ObjectCreated:Post"), hook.records())
    st, _, _ = req("PUT", "/%s/c/copy" % B, b"", {"x-amz-copy-source": "/%s/c/form" % B})
    check("a copy is answered", st == 200, st)
    check("ObjectCreated:Copy arrives", wait_event(hook, "c/copy", "ObjectCreated:Copy"), hook.records())
    st, _, b = req("POST", "/%s/c/mpu?uploads" % B)
    upload = ET.fromstring(b).findtext(NS + "UploadId") if st == 200 else None
    st, h, _ = req("PUT", "/%s/c/mpu?partNumber=1&uploadId=%s" % (B, upload), b"p" * 1000)
    done = ('<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part>'
            '</CompleteMultipartUpload>' % h.get("etag")).encode()
    st, _, _ = req("POST", "/%s/c/mpu?uploadId=%s" % (B, upload), done)
    check("a multipart upload is completed", st == 200, st)
    check("ObjectCreated:CompleteMultipartUpload arrives, and no event for its part",
          wait_event(hook, "c/mpu", "ObjectCreated:CompleteMultipartUpload") and
          [n for n, _ in events_for(hook, "c/mpu")] == ["ObjectCreated:CompleteMultipartUpload"],
          events_for(hook, "c/mpu"))
    tagging = ('<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>a</Key><Value>1</Value>'
               '</Tag></TagSet></Tagging>').encode()
    check("tags are put", req("PUT", "/%s/c/copy?tagging" % B, tagging)[0] == 200)
    check("ObjectTagging:Put arrives", wait_event(hook, "c/copy", "ObjectTagging:Put"), events_for(hook, "c/copy"))
    check("tags are deleted", req("DELETE", "/%s/c/copy?tagging" % B)[0] == 204)
    check("ObjectTagging:Delete arrives", wait_event(hook, "c/copy", "ObjectTagging:Delete"), events_for(hook, "c/copy"))
    check("a delete is answered", req("DELETE", "/%s/c/form" % B)[0] == 204)
    check("ObjectRemoved:Delete arrives", wait_event(hook, "c/form", "ObjectRemoved:Delete"), events_for(hook, "c/form"))
    rec = [r for n, r in events_for(hook, "c/form") if n == "ObjectRemoved:Delete"]
    check("a removal's record has no size or eTag",
          rec and "size" not in rec[0]["s3"]["object"] and "eTag" not in rec[0]["s3"]["object"], rec)
    req("DELETE", "/%s/c/never-there" % B)

    # Filters: a key outside every prefix, and the pics rule's prefix and suffix to the other webhook.
    req("PUT", "/%s/elsewhere" % B, b"x")
    other.up()
    for k in ("pics/a.jpg", "pics/a.png", "pics.jpg", "pics/sub/b.jpg"):
        req("PUT", "/%s/%s" % (B, k), b"x")
    check("the prefix and suffix rule sends exactly the keys it matches",
          wait_for(lambda: len(other.records()) >= 2, 10) and
          sorted(k for _, k, _ in other.records()) == ["pics/a.jpg", "pics/sub/b.jpg"],
          [k for _, k, _ in other.records()])
    time.sleep(0.5)
    keys = [k for _, k, _ in hook.records()]
    check("no event for a key no rule matches, nor for a delete of a key that was not there",
          "elsewhere" not in keys and "c/never-there" not in keys and not any(k.startswith("pics") for k in keys), keys)

    # A versioned bucket: delete markers, and a version removed by its id.
    check("versioning is enabled", req("PUT", "/%s?versioning" % B,
          b'<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>')[0] == 200)
    st, h, _ = req("PUT", "/%s/c/v" % B, b"version one")
    vid = h.get("x-amz-version-id")
    check("a versioned put's event names its version",
          wait_event(hook, "c/v", "ObjectCreated:Put") and
          events_for(hook, "c/v")[0][1]["s3"]["object"].get("versionId") == vid, (vid, events_for(hook, "c/v")))
    st, h, _ = req("DELETE", "/%s/c/v" % B)
    marker = h.get("x-amz-version-id")
    check("a delete in a versioned bucket sends ObjectRemoved:DeleteMarkerCreated with the marker's version",
          wait_event(hook, "c/v", "ObjectRemoved:DeleteMarkerCreated") and
          [r["s3"]["object"].get("versionId") for n, r in events_for(hook, "c/v")
           if n == "ObjectRemoved:DeleteMarkerCreated"] == [marker], (marker, events_for(hook, "c/v")))
    req("DELETE", "/%s/c/v?versionId=%s" % (B, vid))
    check("a version removed by its id sends ObjectRemoved:Delete with that version",
          wait_event(hook, "c/v", "ObjectRemoved:Delete") and
          [r["s3"]["object"].get("versionId") for n, r in events_for(hook, "c/v") if n == "ObjectRemoved:Delete"]
          == [vid], events_for(hook, "c/v"))
    seqs = [r["s3"]["object"]["sequencer"] for _, r in events_for(hook, "c/v")]
    check("a key's events have growing sequencers", seqs == sorted(seqs) and len(set(seqs)) == len(seqs), seqs)

    # Lifecycle expiration, in a bucket of its own, with a day of a few seconds.
    LB = "nlc"
    req("PUT", "/" + LB)
    check("the lifecycle bucket takes the configuration",
          put_cfg(doc(rule("Queue", "lc", ARN + "hook", ["s3:LifecycleExpiration:*", "s3:ObjectRemoved:*"])), LB)[:2]
          == (200, None))
    req("PUT", "/%s/old" % LB, b"expires")
    lc = ('<LifecycleConfiguration><Rule><ID>x</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>'
          '<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>').encode()
    check("the lifecycle rule is put", req("PUT", "/%s?lifecycle" % LB, lc)[0] == 200)
    check("an expiry sends LifecycleExpiration:Delete and no ObjectRemoved",
          wait_event(hook, "old", "LifecycleExpiration:Delete", 30) and
          [n for n, _ in events_for(hook, "old")] == ["LifecycleExpiration:Delete"], events_for(hook, "old"))
    lc_rec = [r for _, r in events_for(hook, "old")]
    check("an expiry's principal is S3's own, and it has no client address",
          lc_rec and lc_rec[0]["userIdentity"]["principalId"] == "s3.amazonaws.com" and
          lc_rec[0]["requestParameters"]["sourceIPAddress"] == "", lc_rec)

    # A webhook that answers 500 is tried again until it answers 200.
    hook.status = 500
    req("PUT", "/%s/c/retry" % B, b"x")
    check("a 500 is a failure, counted", wait_for(lambda: stat("notify_failed") >= 2, 10), nstats())
    hook.status = 200
    check("and the event is sent again until it is taken", wait_event(hook, "c/retry", "ObjectCreated:Put", 20),
          events_for(hook, "c/retry"))

    # A webhook that is down: the events wait, are counted queued, and go when it comes up.
    hook.down()
    for i in range(5):
        req("PUT", "/%s/c/down%d" % (B, i), b"x")
    check("events wait while the webhook is down", wait_for(lambda: stat("notify_queued") == 5, 5), nstats())
    time.sleep(1)
    hook.up()
    check("and are all delivered once it is up",
          wait_for(lambda: all(events_for(hook, "c/down%d" % i) for i in range(5)), 20) and
          wait_for(lambda: stat("notify_queued") == 0, 5), nstats())

    # The bound: past it a new event is dropped and counted, and what was queued still goes.
    if QUEUE_MAX < 100:
        hook.down()
        dropped0 = stat("notify_dropped")
        for i in range(QUEUE_MAX + 3):
            req("PUT", "/%s/c/flood%03d" % (B, i), b"x")
        check("past the bound of %d waiting events a new one is dropped and counted" % QUEUE_MAX,
              wait_for(lambda: stat("notify_queued") == QUEUE_MAX and stat("notify_dropped") - dropped0 == 3, 5),
              nstats())
        hook.up()
        check("and the ones that waited are delivered",
              wait_for(lambda: stat("notify_queued") == 0, 30) and
              sum(1 for _, k, _ in hook.records() if k.startswith("c/flood")) >= QUEUE_MAX, nstats())

    s = stats_shards()[0]
    check("stats counts what was sent, failed, queued and dropped",
          all(k in s for k in ("notify_sent", "notify_failed", "notify_queued", "notify_dropped")) and
          int(s["notify_sent"]) >= 20 and s["notify_queued"] == "0", s)

    # Removing the configuration stops the events.
    check("an empty configuration removes it", put_cfg(doc())[:2] == (200, None))
    st, b = get_cfg()
    check("and GET answers an empty one", st == 200 and len(ET.fromstring(b)) == 0, b)
    req("PUT", "/%s/c/after" % B, b"x")
    time.sleep(1)
    check("and a change sends nothing", not events_for(hook, "c/after"), events_for(hook, "c/after"))
    # Put back for the restart to read.
    put_cfg(doc(rule("Queue", "created", ARN + "hook", ["s3:ObjectCreated:*"], prefix="r/")))
    hook.down()
    other.down()


def mode_tls(port, secure_port, cert, key):
    global TARGET
    TARGET = port
    secure = Hook(secure_port, (cert, key))
    secure.up()
    check("a configuration naming an https webhook is put",
          put_cfg(doc(rule("Queue", "created", ARN + "hook", ["s3:ObjectCreated:*"], prefix="r/"),
                      rule("Queue", "secure", ARN + "secure", ["s3:ObjectCreated:*"], prefix="tls/")))[:2]
          == (200, None))
    req("PUT", "/%s/tls/one" % B, b"over tls")
    check("an event reaches an https webhook whose certificate the target's ca= trusts",
          wait_event(secure, "tls/one", "ObjectCreated:Put"), secure.records())
    check("put back for the restart", put_cfg(doc(rule("Queue", "created", ARN + "hook", ["s3:ObjectCreated:*"],
                                                       prefix="r/")))[:2] == (200, None))
    secure.down()


def mode_users(port, hook_port):
    """A runtime with users: a signed request names its user, one let in by a bucket policy names anonymous."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import lib_storage_policy as lp
    alice = (os.environ["AKA"], os.environ["SKA"])
    hook = Hook(hook_port)
    hook.up()
    ub = "alice-events"
    check("alice makes a bucket", lp.req(port, "PUT", "/" + ub, key=alice).status == 200)
    cfg = doc(rule("Queue", "all", ARN + "hook", ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]))
    check("and gives it a notification configuration",
          lp.req(port, "PUT", "/" + ub, "notification", cfg, alice).status == 200)
    policy = json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::%s/anon/*" % ub}]})
    check("and a policy that lets anybody put under anon/", lp.put_policy(port, ub, policy, key=alice).status == 204)
    check("a signed PUT is answered", lp.req(port, "PUT", "/%s/signed" % ub, "", b"by alice", alice).status == 200)
    check("an unsigned PUT the policy lets in is answered", lp.req(port, "PUT", "/%s/anon/x" % ub, "", b"by anyone").status
          == 200)
    check("an unsigned PUT the policy does not let in is refused", lp.req(port, "PUT", "/%s/other" % ub, "", b"no").status
          == 403)
    wait_event(hook, "signed", "ObjectCreated:Put")
    wait_event(hook, "anon/x", "ObjectCreated:Put")
    s = [r for _, r in events_for(hook, "signed")]
    a = [r for _, r in events_for(hook, "anon/x")]
    check("a signed request's event names its user and the client's address",
          s and s[0]["userIdentity"]["principalId"] == "alice" and
          s[0]["requestParameters"]["sourceIPAddress"] == "127.0.0.1", s)
    check("one let in by a bucket policy names anonymous and the client's address",
          a and a[0]["userIdentity"]["principalId"] == "anonymous" and
          a[0]["requestParameters"]["sourceIPAddress"] == "127.0.0.1", a)
    check("the bucket's owner is still alice", s and s[0]["s3"]["bucket"]["ownerIdentity"]["principalId"] == "alice", s)
    check("a refused PUT sends nothing", not events_for(hook, "other"), events_for(hook, "other"))
    hook.down()


def mode_dns(port, hook_port, hosts_file):
    """A webhook named by a host: delivered to where the name points, and followed when it points elsewhere."""
    global TARGET
    TARGET = port
    first = Hook(hook_port, host="127.0.0.1")
    first.up()
    check("a configuration naming a webhook by its host name is put",
          put_cfg(doc(rule("Queue", "named", ARN + "named", ["s3:ObjectCreated:*"], prefix="dns/")))[:2] == (200, None))
    req("PUT", "/%s/dns/one" % B, b"x")
    check("an event reaches the address the name resolves to", wait_event(first, "dns/one", "ObjectCreated:Put"),
          first.records())
    resolves = stat("notify_resolves")
    # The name now points at another address, and nothing listens at the old one.
    with open(hosts_file, "w") as f:
        f.write("hooky.test 127.0.0.2\n")
    first.down()
    second = Hook(hook_port, host="127.0.0.2")
    second.up()
    req("PUT", "/%s/dns/two" % B, b"x")
    check("a refused connection asks for the name again, and the event reaches its new address",
          wait_event(second, "dns/two", "ObjectCreated:Put", 20), (second.records(), nstats()))
    check("which the resolver counts", wait_for(lambda: stat("notify_resolves") > resolves, 5), (resolves, nstats()))
    check("and nothing reached the old address", not events_for(first, "dns/two"), first.records())
    second.down()
    put_cfg(doc(rule("Queue", "created", ARN + "hook", ["s3:ObjectCreated:*"], prefix="r/")))


def mode_restart(port, hook_port):
    global TARGET
    TARGET = port
    hook = Hook(hook_port)
    hook.up()
    st, b = get_cfg()
    check("the configuration survives a stop and a start",
          st == 200 and cfg_rules(b) == [("Queue", "created", ARN + "hook", ["s3:ObjectCreated:*"], [("Prefix", "r/")])],
          b)
    req("PUT", "/%s/r/after-restart" % B, b"x")
    check("and still sends", wait_event(hook, "r/after-restart", "ObjectCreated:Put"), hook.records())
    hook.down()


def mode_crash(port, hook_port, data):
    global TARGET
    TARGET = port
    hook = Hook(hook_port)
    st, _, _ = req("PUT", "/%s/r/crash" % B, b"answered before the kill")
    check("a PUT is answered while the webhook is down", st == 200, st)
    # The counters `stats` shows are a moment old, so the wait is for them to catch up.
    check("its event waits", wait_for(lambda: stat("notify_queued") == 1, 5), nstats())
    outbox = os.path.join(data, ".notify", "outbox.0")
    check("in the outbox on disk", os.path.getsize(outbox) > 0 and b"r/crash" in open(outbox, "rb").read(),
          os.path.exists(outbox))
    pid = worker_pid()
    os.kill(int(pid), signal.SIGKILL)
    hook.up()

    def back():
        p = worker_pid()
        try:
            return p and p != pid and os.path.isdir("/proc/%s" % p) and req("GET", "/")[0] == 200
        except OSError:
            return False

    check("the worker comes back after SIGKILL", wait_for(back, 40), worker_pid())
    check("and the event of the answered PUT arrives from its outbox", wait_event(hook, "r/crash", "ObjectCreated:Put", 20),
          hook.records())
    check("sent by the new worker", wait_for(lambda: stat("notify_sent") >= 1, 5), nstats())
    hook.down()


def mode_shards(hook_port, nodes):
    global TARGET
    TARGET = nodes[0]
    hook = Hook(hook_port)
    hook.up()
    st, _, _ = req("PUT", "/" + B)
    check("the bucket is made", st == 200, st)
    check("the configuration is put through one shard",
          put_cfg(doc(rule("Queue", "all", ARN + "hook", ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"])))[:2]
          == (200, None))
    for node in nodes:
        st, b = get_cfg_on(node)
        check("and read through %s" % os.path.basename(node), st == 200 and len(cfg_rules(b)) == 1, b)
    n = 24
    for i in range(n):
        req("PUT", "/%s/s%02d" % (B, i), b"v" * (100 + i), target=nodes[i % 2])
    for i in range(n):
        req("DELETE", "/%s/s%02d" % (B, i), target=nodes[(i + 1) % 2])
    want = sorted(("ObjectCreated:Put", "s%02d" % i) for i in range(n)) + \
        sorted(("ObjectRemoved:Delete", "s%02d" % i) for i in range(n))
    wait_for(lambda: len(hook.records()) >= 2 * n, 20)
    time.sleep(0.5)
    got = sorted((name, k) for name, k, _ in hook.records())
    check("every change through either shard sends exactly one event", got == sorted(want),
          (len(got), [g for g in got if got.count(g) != 1][:6]))
    who = {r["userIdentity"]["principalId"] for _, _, r in hook.records()}
    check("and names the requester the shard that took it saw, carried to the owner", who == {"anonymous"}, who)
    def per():
        return {k: int(s.get("notify_sent", "0")) for k, s in stats_shards().items()}
    check("each event sent by the shard that owns its key, both shards owning some",
          wait_for(lambda: sum(per().values()) == 2 * n and all(v > 0 for v in per().values()), 5), per())
    hook.down()


def get_cfg_on(node):
    st, _, b = req("GET", "/%s?notification" % B, target=node)
    return st, b


if __name__ == "__main__":
    args = sys.argv[2:]
    if MODE == "main":
        mode_main(int(args[0]), int(args[1]), int(args[2]))
    elif MODE == "users":
        mode_users(int(args[0]), int(args[1]))
    elif MODE == "dns":
        mode_dns(int(args[0]), int(args[1]), args[2])
    elif MODE == "tls":
        mode_tls(int(args[0]), int(args[1]), args[2], args[3])
    elif MODE == "restart":
        mode_restart(int(args[0]), int(args[1]))
    elif MODE == "crash":
        mode_crash(int(args[0]), int(args[1]), args[2])
    elif MODE == "shards":
        mode_shards(int(args[0]), args[1:])
    sys.exit(min(failed, 100))
