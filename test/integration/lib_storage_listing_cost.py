#!/usr/bin/env python3
"""What a page of ListMultipartUploads and of ListObjectVersions costs, and a new version of a key.

usage: lib_storage_listing_cost.py PORT

Each cost is taken at a small and at a ten times larger count of what the bucket
holds, so the machine's speed cancels out: a page costs what it shows, and a PUT
what it writes, whatever the count.  Before, each page copied and sorted every
upload of the bucket, or read every version of the key to find its marker, and
each new version moved every older one of its key.

Prints one PASS or FAIL line per assertion and a final "Results:" line, and
exits with the number of failures.
"""
import http.client
import sys
import threading
import time
import xml.etree.ElementTree as ET

PORT = int(sys.argv[1])
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"
SMALL, LARGE = 2000, 20000
PAGES = 300

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS: " + name)
    else:
        failed += 1
        print("  FAIL [%s]: %s" % (name, detail))


def conn():
    return http.client.HTTPConnection("127.0.0.1", PORT, timeout=120)


def req(c, method, path, body=b""):
    c.request(method, path, body=body, headers={"Content-Length": str(len(body))})
    r = c.getresponse()
    return r.status, r.read(), r


def parallel(n, fn, workers=8):
    """fn(c, i) for i in range(n), over `workers` connections."""
    errors = []

    def run(w):
        c = conn()
        for i in range(w, n, workers):
            try:
                fn(c, i)
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
                return

    ts = [threading.Thread(target=run, args=(w,)) for w in range(workers)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return errors


def timed(fn):
    t0 = time.monotonic()
    fn()
    return time.monotonic() - t0


# ── ListMultipartUploads ────────────────────────────────────────────────────
def uploads_to(bucket, n, have):
    def one(c, i):
        st, _, _ = req(c, "POST", "/%s/u/%07d?uploads" % (bucket, have + i))
        if st != 200:
            raise RuntimeError("create %d" % st)
    return parallel(n - have, one)


def list_pages(bucket):
    c = conn()
    for i in range(PAGES):
        st, body, _ = req(c, "GET", "/%s?uploads&max-uploads=1&key-marker=u/%07d" % (bucket, i))
        if st != 200 or b"<Upload>" not in body:
            raise RuntimeError("list %d %s" % (st, body[:200]))


c = conn()
st, _, _ = req(c, "PUT", "/mpl")
check("the bucket of uploads is made", st == 200, str(st))
errs = uploads_to("mpl", SMALL, 0)
check("%d uploads are begun" % SMALL, not errs, "; ".join(errs[:3]))
list_pages("mpl")
small = timed(lambda: list_pages("mpl"))
errs = uploads_to("mpl", LARGE, SMALL)
check("%d uploads are begun" % LARGE, not errs, "; ".join(errs[:3]))
large = timed(lambda: list_pages("mpl"))
print("    uploads: %d pages at %d uploads %.3f s, at %d %.3f s" % (PAGES, SMALL, small, LARGE, large))
check("a page of uploads costs what it shows, not every upload of the bucket",
      large < 3 * small + 0.2, "%.3f s at %d against %.3f s at %d" % (large, LARGE, small, SMALL))

# A page goes on from its markers, a folder as one entry, as before.
st, body, _ = req(c, "GET", "/mpl?uploads&max-uploads=3&key-marker=u/0000004")
root = ET.fromstring(body)
keys = [u.find(NS + "Key").text for u in root.iter(NS + "Upload")]
check("a page after a key marker starts at the next key", keys == ["u/0000005", "u/0000006", "u/0000007"], str(keys))
check("a full page is truncated", root.find(NS + "IsTruncated").text == "true")
st, body, _ = req(c, "GET", "/mpl?uploads&delimiter=/&max-uploads=5")
root = ET.fromstring(body)
prefixes = [p.find(NS + "Prefix").text for p in root.iter(NS + "CommonPrefixes")]
check("the folder of every upload is one entry", prefixes == ["u/"] and root.find(NS + "IsTruncated").text == "false",
      str(prefixes))

# ── ListObjectVersions and PUT on a versioned key ───────────────────────────
VERSIONING = (b'<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
              b"<Status>Enabled</Status></VersioningConfiguration>")
st, _, _ = req(c, "PUT", "/vrs")
st2, _, _ = req(c, "PUT", "/vrs?versioning", VERSIONING)
check("the versioned bucket is made", st == 200 and st2 == 200, "%d %d" % (st, st2))

ids = []
ids_lock = threading.Lock()


def versions_to(n, have):
    def one(cc, i):
        st, _, r = req(cc, "PUT", "/vrs/k", b"x")
        if st != 200:
            raise RuntimeError("put %d" % st)
        with ids_lock:
            ids.append(r.getheader("x-amz-version-id"))
    return parallel(n - have, one)


def put_versions(n):
    def go():
        errs = versions_to(n, 0)
        if errs:
            raise RuntimeError("; ".join(errs[:3]))
    return timed(go)


def version_pages(marker):
    cc = conn()
    for _ in range(PAGES):
        st, body, _ = req(cc, "GET", "/vrs?versions&max-keys=1&key-marker=k&version-id-marker=" + marker)
        if st != 200 or b"<Version>" not in body:
            raise RuntimeError("versions %d %s" % (st, body[:200]))


put_small = put_versions(SMALL)
ids.sort()
small = timed(lambda: version_pages(ids[len(ids) // 2]))
put_large = put_versions(LARGE - SMALL)
ids.sort()
large = timed(lambda: version_pages(ids[len(ids) // 2]))
rate_small = SMALL / put_small
rate_large = (LARGE - SMALL) / put_large
print("    versions: %d PUTs/s to %d, %d PUTs/s to %d; %d pages at %d versions %.3f s, at %d %.3f s" %
      (rate_small, SMALL, rate_large, LARGE, PAGES, SMALL, small, LARGE, large))
check("a new version of a key costs what it writes, not every version the key has",
      rate_large > rate_small / 3, "%d/s up to %d, %d/s up to %d" % (rate_small, SMALL, rate_large, LARGE))
check("a page of versions costs what it shows, not every version of the key",
      large < 3 * small + 0.2, "%.3f s at %d against %.3f s at %d" % (large, LARGE, small, SMALL))

# The marker's version and the ones after it, newest first, as before.
newest_first = sorted(ids, reverse=True)
m = newest_first[100]
st, body, _ = req(c, "GET", "/vrs?versions&max-keys=2&key-marker=k&version-id-marker=" + m)
got = [v.find(NS + "VersionId").text for v in ET.fromstring(body).iter(NS + "Version")]
check("a page after a version marker starts at the next older version", got == newest_first[101:103],
      "%s, want %s" % (got, newest_first[101:103]))
st, body, _ = req(c, "GET", "/vrs?versions&max-keys=2")
root = ET.fromstring(body)
got = [(v.find(NS + "VersionId").text, v.find(NS + "IsLatest").text) for v in root.iter(NS + "Version")]
check("the first page is the latest and the next older", got == [(newest_first[0], "true"), (newest_first[1], "false")],
      str(got))
st, _, _ = req(c, "GET", "/vrs/k?versionId=" + newest_first[LARGE // 2])
check("a version deep in the list is read by its id", st == 200, str(st))
st, _, _ = req(c, "DELETE", "/vrs/k?versionId=" + newest_first[LARGE // 2])
st2, _, _ = req(c, "GET", "/vrs/k?versionId=" + newest_first[LARGE // 2])
check("a version deep in the list is removed by its id", st == 204 and st2 == 404, "%d %d" % (st, st2))

print("  Results: %d/%d passed (%d failed)" % (passed, passed + failed, failed))
sys.exit(failed)
