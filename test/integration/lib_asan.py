"""A resident-set bound, which a worker built with AddressSanitizer is not held to.

ASan's shadow memory and the quarantine its allocator keeps freed blocks in put
a sanitized worker well above any bound these tests set before it has done
anything, so the reading would be the allocator's and not the runtime's.  The
bound is printed as NOT ASSERTED there, as test_chunked_request_body.sh does.
"""


def sanitized(pid):
    try:
        with open("/proc/%d/maps" % int(pid)) as f:
            return "libasan" in f.read()
    except (OSError, ValueError):
        return False


def rss_check(check, pid, name, cond, detail=""):
    if sanitized(pid):
        print("  NOT ASSERTED [%s]: %s" % (name, detail))
        print("        sanitized build (ASan) — its allocator's residency is what this would measure")
        return
    check(name, cond, detail)
