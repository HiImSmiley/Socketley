#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: CalDAV and CardDAV on a mail runtime's JMAP port -- a client finding its principal and homes,
# putting, reading and deleting entries with their preconditions, the query, multiget and sync-collection reports,
# calendars made, changed and removed, an address book, another user's paths refused, and the sync token kept
# through a restart.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a client that cannot find its principal or its homes from /.well-known or the root
#   * a PUT over an entry the client did not know of, or under an etag that is no longer it
#   * a calendar entry that is no calendar taken
#   * a calendar-query whose component filter gives tasks for events, a multiget that drops a missing entry
#   * a sync-collection that misses a deletion, takes a token it never gave, or forgets its tokens on a restart
#   * a calendar made twice, a colour not kept, a removed calendar still there
#   * another user's calendars reachable, the entries showing as mail folders
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
command -v curl >/dev/null 2>&1 || { echo "  SKIP: curl is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() {
    while read -r verdict name; do
        case "$verdict" in ok) ok "$name" ;; bad) bad "${name%%:*}" "${name#*:}" ;; esac
    done
}

daemon_isolate mail_dav
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1950))
J=$((SL_PORT_BASE+1951))
PI=$((SL_PORT_BASE+1952))
PS=$((SL_PORT_BASE+1953))
trap daemon_stop EXIT

echo "=== Integration: CalDAV and CardDAV ==="

daemon_start "$BIN"
printf 'spa - http://localhost:5173/cb\n' > "$T/clients"
"$BIN" create idp auth -p "$PI" --clients "$T/clients" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
for u in alice bob; do
    "$BIN" idp-user auth add "$u" --password "${u}password1" --email "$u@example.test" >/dev/null 2>&1
done
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --jmap "$J" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$J" || bad "the JMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

tally < <(python3 - "$J" "$T/token" <<'PY'
import base64, http.client, re, sys
J, tokfile = int(sys.argv[1]), sys.argv[2]
def check(name, cond, info=""):
    print(("ok " if cond else "bad ") + name + ("" if cond else ": " + str(info)[:500].replace("\n", " ")))
AUTH = {"Authorization": "Basic " + base64.b64encode(b"alice:alicepassword1").decode()}
def req(method, path, body=None, headers=None, auth=True):
    c = http.client.HTTPConnection("127.0.0.1", J, timeout=10)
    h = dict(AUTH) if auth else {}
    h.update(headers or {})
    if body is not None and "Content-Type" not in h:
        h["Content-Type"] = "application/xml; charset=utf-8"
    c.request(method, path, body=body.encode() if isinstance(body, str) else body, headers=h)
    r = c.getresponse(); data = r.read().decode(errors="replace"); hs = {k.lower(): v for k, v in r.getheaders()}; c.close()
    return r.status, hs, data
def propfind(path, props, depth="0"):
    body = '<?xml version="1.0"?><d:propfind xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav" ' \
           'xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cs="http://calendarserver.org/ns/" ' \
           'xmlns:a="http://apple.com/ns/ical/"><d:prop>' + props + '</d:prop></d:propfind>'
    return req("PROPFIND", path, body, {"Depth": depth})

st, hs, _ = req("GET", "/.well-known/caldav", auth=False)
check("/.well-known/caldav leads to /dav/", st == 301 and hs.get("location") == "/dav/", (st, hs))
st, hs, _ = req("OPTIONS", "/dav/", auth=False)
check("OPTIONS says the DAV classes, calendar-access and addressbook among them", st == 200 and
      "calendar-access" in hs.get("dav", "") and "addressbook" in hs.get("dav", ""), (st, hs))
st, hs, _ = propfind("/", "<d:current-user-principal/>")
st0, hs0, _ = req("PROPFIND", "/dav/", "", {"Depth": "0"}, auth=False)
check("a PROPFIND not signed in is asked for its password", st0 == 401 and "basic" in hs0.get("www-authenticate", "").lower(), (st0, hs0))
st, _, d = propfind("/", "<d:current-user-principal/>")
check("the root names the user's principal", st == 207 and "<d:current-user-principal><d:href>/dav/alice/</d:href>" in d, d)
st, _, d = propfind("/dav/alice/", "<c:calendar-home-set/><card:addressbook-home-set/><c:calendar-user-address-set/><d:resourcetype/><cs:nothing/>")
check("the principal names its homes and its address", st == 207 and "<c:calendar-home-set><d:href>/dav/alice/calendars/</d:href>" in d and
      "<card:addressbook-home-set><d:href>/dav/alice/contacts/</d:href>" in d and "mailto:alice@example.test" in d and "<d:principal/>" in d, d)
check("and a property it has not as 404", "<cs:nothing/></d:prop><d:status>HTTP/1.1 404 Not Found" in d, d)
st, _, d = propfind("/dav/alice/calendars/", "<d:resourcetype/><d:displayname/><cs:getctag/><d:sync-token/><c:supported-calendar-component-set/>", "1")
check("the calendar home lists the calendar every user has", st == 207 and "<d:href>/dav/alice/calendars/personal/</d:href>" in d and
      "<c:calendar/>" in d and '<c:comp name="VEVENT"/>' in d and "<d:sync-token>http://socketley.net/ns/sync/" in d, d)

ev = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VEVENT\r\nUID:ev1\r\nDTSTART:20261026T090000Z\r\nSUMMARY:Treffen\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
todo = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:test\r\nBEGIN:VTODO\r\nUID:t1\r\nSUMMARY:Einkaufen\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"
cal = "/dav/alice/calendars/personal/"
ct = {"Content-Type": "text/calendar; charset=utf-8"}
st, hs, _ = req("PUT", cal + "ev1.ics", ev, dict(ct, **{"If-None-Match": "*"}))
etag = hs.get("etag", "")
check("PUT makes an entry, and says its etag", st == 201 and etag.startswith('"'), (st, hs))
st, _, _ = req("PUT", cal + "ev1.ics", ev, dict(ct, **{"If-None-Match": "*"}))
check("PUT with If-None-Match * over one there is refused", st == 412, st)
st, hs, d = req("GET", cal + "ev1.ics")
check("GET gives it back, with its etag", st == 200 and d == ev and hs.get("etag") == etag and hs.get("content-type", "").startswith("text/calendar"), (st, hs, d))
st, _, _ = req("PUT", cal + "ev1.ics", ev.replace("Treffen", "Treffen 2"), dict(ct, **{"If-Match": '"nope"'}))
check("PUT under an etag that is no longer it is refused", st == 412, st)
st, hs, _ = req("PUT", cal + "ev1.ics", ev.replace("Treffen", "Treffen 2"), dict(ct, **{"If-Match": etag}))
check("and under the one it has is taken, with a new etag", st == 204 and hs.get("etag") not in ("", etag), (st, hs))
# Two clients editing the same entry under the same etag: the check and the write are one step, so only one is taken.
import threading
st, hs, now = req("GET", cal + "ev1.ics")
seen = hs.get("etag", "")
answers = []
def edit(n):
    answers.append(req("PUT", cal + "ev1.ics", ev.replace("Treffen", "Race %d" % n), dict(ct, **{"If-Match": seen}))[0])
ts = [threading.Thread(target=edit, args=(n,)) for n in range(16)]
for t in ts: t.start()
for t in ts: t.join()
check("of sixteen edits under one etag at once exactly one is taken, the rest refused",
      sorted(set(answers)) == [204, 412] and answers.count(204) == 1, sorted(answers))
req("PUT", cal + "ev1.ics", now, ct)
st, _, d = req("PUT", cal + "bad.ics", "hello", ct)
check("a calendar entry that is no calendar is refused", st == 403 and "valid-calendar-data" in d, (st, d))
req("PUT", cal + "t1.ics", todo, ct)

q = lambda comp: ('<?xml version="1.0"?><c:calendar-query xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/>'
                  '</d:prop><c:filter><c:comp-filter name="VCALENDAR"><c:comp-filter name="%s"/></c:comp-filter></c:filter></c:calendar-query>' % comp)
st, _, d = req("REPORT", cal, q("VTODO"), {"Depth": "1"})
check("a calendar-query for tasks gives the task alone", st == 207 and "t1.ics" in d and "ev1.ics" not in d, d)
st, _, d = req("REPORT", cal, q("VEVENT"), {"Depth": "1"})
check("and one for events the event alone", st == 207 and "ev1.ics" in d and "t1.ics" not in d, d)
mg = ('<?xml version="1.0"?><c:calendar-multiget xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:prop><d:getetag/>'
      '<c:calendar-data/></d:prop><d:href>' + cal + 'ev1.ics</d:href><d:href>' + cal + 'gone.ics</d:href></c:calendar-multiget>')
st, _, d = req("REPORT", cal, mg, {"Depth": "1"})
check("a multiget gives the entry's data, and the missing one as 404", st == 207 and "SUMMARY:Treffen 2" in d and
      re.search(r"gone\.ics</d:href><d:status>HTTP/1.1 404", d), d)

sync = lambda tok: ('<?xml version="1.0"?><d:sync-collection xmlns:d="DAV:"><d:sync-token>%s</d:sync-token><d:sync-level>1</d:sync-level>'
                    '<d:prop><d:getetag/></d:prop></d:sync-collection>' % tok)
st, _, d = req("REPORT", cal, sync(""))
t1 = re.search(r"<d:sync-token>([^<]+)</d:sync-token>", d)
check("a first sync gives every entry and a token", st == 207 and "ev1.ics" in d and "t1.ics" in d and t1, d)
req("DELETE", cal + "t1.ics")
st, _, d = req("REPORT", cal, sync(t1.group(1)))
t2 = re.search(r"<d:sync-token>([^<]+)</d:sync-token>", d)
check("a sync since then gives the deletion alone", st == 207 and re.search(r"t1\.ics</d:href><d:status>HTTP/1.1 404", d) and
      "ev1.ics" not in d and t2 and t2.group(1) != t1.group(1), d)
open(tokfile, "w").write(t2.group(1))
st, _, d = req("REPORT", cal, sync("http://socketley.net/ns/sync/999999"))
check("a token never given is refused, so the client syncs again", st == 403 and "valid-sync-token" in d, (st, d))

mk = ('<?xml version="1.0"?><c:mkcalendar xmlns:d="DAV:" xmlns:c="urn:ietf:params:xml:ns:caldav"><d:set><d:prop>'
      '<d:displayname>Arbeit</d:displayname></d:prop></d:set></c:mkcalendar>')
st, _, _ = req("MKCALENDAR", "/dav/alice/calendars/work/", mk)
st2, _, _ = req("MKCALENDAR", "/dav/alice/calendars/work/", mk)
check("MKCALENDAR makes a calendar, and not twice", st == 201 and st2 == 405, (st, st2))
pp = ('<?xml version="1.0"?><d:propertyupdate xmlns:d="DAV:" xmlns:a="http://apple.com/ns/ical/"><d:set><d:prop>'
      '<a:calendar-color>#FF0000FF</a:calendar-color></d:prop></d:set></d:propertyupdate>')
st, _, d = req("PROPPATCH", "/dav/alice/calendars/work/", pp)
st2, _, d2 = propfind("/dav/alice/calendars/", "<d:displayname/><a:calendar-color/>", "1")
check("PROPPATCH keeps its colour, and the home lists it by its name", st == 207 and "HTTP/1.1 200 OK" in d and
      "<d:displayname>Arbeit</d:displayname>" in d2 and "<a:calendar-color>#FF0000FF</a:calendar-color>" in d2, (d, d2))
st, _, _ = req("DELETE", "/dav/alice/calendars/work/")
st2, _, _ = propfind("/dav/alice/calendars/work/", "<d:displayname/>")
check("a calendar deleted is gone", st == 204 and st2 == 404, (st, st2))
st, _, _ = req("PUT", "/dav/alice/calendars/work/x.ics", ev, ct)
check("and an entry for it has nowhere to go", st == 409, st)

vc = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:bob\r\nFN:Bob Builder\r\nEMAIL:bob@else.test\r\nEND:VCARD\r\n"
st, _, _ = req("PUT", "/dav/alice/contacts/default/bob.vcf", vc, {"Content-Type": "text/vcard"})
st2, _, d = propfind("/dav/alice/contacts/default/", "<d:resourcetype/><d:getetag/><card:supported-address-data/>", "1")
check("an address book takes a card, and lists it", st == 201 and st2 == 207 and "<card:addressbook/>" in d and "bob.vcf" in d, (st, d))
amg = ('<?xml version="1.0"?><card:addressbook-multiget xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"><d:prop>'
       '<card:address-data/></d:prop><d:href>/dav/alice/contacts/default/bob.vcf</d:href></card:addressbook-multiget>')
st, _, d = req("REPORT", "/dav/alice/contacts/default/", amg, {"Depth": "1"})
check("its multiget gives the card", st == 207 and "FN:Bob Builder" in d, d)
st, _, _ = propfind("/dav/bob/", "<d:displayname/>")
check("another user's principal is refused", st == 403, st)
st, _, d = req("POST", "/jmap/api", '{"using":["urn:ietf:params:jmap:core","urn:ietf:params:jmap:mail"],"methodCalls":[["Mailbox/get",{"ids":null},"m"]]}',
               {"Content-Type": "application/json"})
check("and the entries are no mail folder", st == 200 and "dav" not in d.lower() and "personal" not in d, d)
PY
)

"$BIN" stop m >/dev/null 2>&1; "$BIN" start m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$J" || bad "the JMAP port listens again" "$(tail -3 "$SOCKETLEY_DLOG")"
tok=$(cat "$T/token" 2>/dev/null)
got=$(curl -s -u alice:alicepassword1 -X REPORT -H 'Content-Type: application/xml' "http://127.0.0.1:$J/dav/alice/calendars/personal/" \
    --data "<?xml version=\"1.0\"?><d:sync-collection xmlns:d=\"DAV:\"><d:sync-token>$tok</d:sync-token><d:prop><d:getetag/></d:prop></d:sync-collection>")
case "$got" in *"<d:sync-token>$tok</d:sync-token>"*) case "$got" in *"<d:response>"*) bad "a restart keeps the tokens" "$got" ;; *) ok "a restart keeps the tokens, nothing changed since" ;; esac ;;
    *) bad "a restart keeps the tokens" "${tok:-no token} / $got" ;; esac
grep -c '' "$(find "$HOME" -path '*mail/m.dav/alice/calendars-personal.log' | head -1)" >/dev/null 2>&1 \
    && ok "the journal is under the runtime's state" || bad "the journal" "$(find "$HOME" -name '*.log' -path '*dav*')"

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || echo "  FAILED"
exit "$FAIL"
