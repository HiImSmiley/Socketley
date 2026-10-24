#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: `socketley send` with a template, a message for each recipient of a source, and what an
# advertisement carries to unsubscribe and what an unsubscribe does.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a placeholder not filled from the recipient's values, --set, or its default, a value put into the HTML unescaped,
#     or {{{raw}}} escaped; no plain text part beside the HTML
#   * --dry-run sending anything, or not showing the first recipient's message
#   * --check sending when the first recipient's message cannot be written, or stopping at a later one rather than
#     skipping it; without --check a missing value refused
#   * --inline not sending the image inside the message, by the Content-ID the HTML names
#   * --ad without List-Unsubscribe, its one-click POST, or a link of the recipient's own where {{unsubscribe}} is, or
#     below the message where it is not
#   * a link's GET unsubscribing (a mail scanner opening it would), its POST not, a forged token taken, a mailto:
#     unsubscribe not taken, an unsubscribed address sent another advertisement, or a mail that is none refused
#   * resubscribe not taking an address back
#   * the accounts of an idp or the documents of a db not given as recipients with their fields
#   * --test-to sending to anyone but the address it names, or more than one message
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/lib_ports.sh"
. "$HERE/lib_daemon.sh"
. "$HERE/lib_ready.sh"

command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }

PASS=0; FAIL=0; TOTAL=0
ok()  { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  PASS: $1"; }
bad() { TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
tally() { while read -r verdict rest; do [ "$verdict" = ok ] && ok "$rest" || bad "${rest%%: *}" "${rest#*: }"; done; }

daemon_isolate mail_campaign
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1950))
W=$((SL_PORT_BASE+1951))
PI=$((SL_PORT_BASE+1952))
PS=$((SL_PORT_BASE+1953))
PD=$((SL_PORT_BASE+1954))
NS=$((SL_PORT_BASE+1955))
SINK=$((SL_PORT_BASE+1956))
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    daemon_stop
}
trap cleanup EXIT

echo "=== Integration: templates, recipients and advertisements on a mail runtime ==="

python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal remote.test=MX:10:mx.remote.test mx.remote.test=127.0.0.1 >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_MX_PORT="$SINK"
mkdir -p "$T/sink"
python3 "$HERE/lib_smtp_sink.py" "$SINK" "$T/sink" >/dev/null 2>&1 &
PIDS+=($!)
ready_tcp 127.0.0.1 "$SINK" || bad "the sink listens" "-"

daemon_start "$BIN"
"$BIN" create idp auth -p "$PI" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
printf 'backend dbbackendsecret0123456789\n' > "$T/keys"; chmod 600 "$T/keys"
"$BIN" create db shop -p "$PD" --keys "$T/keys" -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/" "$PD/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add ann --password annpassword12 --name "Ann A" --email ann@remote.test >/dev/null 2>&1
"$BIN" idp-user auth set ann code=IDP-ANN >/dev/null 2>&1
"$BIN" idp-user auth add ben --password benpassword12 --email ben@remote.test --groups vip >/dev/null 2>&1
for d in '{"email":"dora@remote.test","name":"Dora","code":"DB-DORA"}' '{"email":"eli@remote.test","name":"Eli","code":"DB-ELI"}'; do
    curl -s -o /dev/null -X POST "http://127.0.0.1:$PD/c/customers" -H 'Authorization: Bearer dbbackendsecret0123456789' \
        -H 'Content-Type: application/json' -d "$d"
done
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --web "$W" --domain mail -s \
    >/dev/null 2>&1
for p in "$P" "$W"; do ready_tcp 127.0.0.1 "$p" || bad "port $p listens" "$(tail -3 "$SOCKETLEY_DLOG")"; done

cat > "$T/promo.html" <<'EOF'
<html><body><h1>Hello {{name|friend}}!</h1><p>Your code: <b>{{code}}</b></p><p>{{{banner}}}</p>
<img src="cid:logo.png"><p><a href="{{unsubscribe}}">unsubscribe</a></p></body></html>
EOF
cat > "$T/people.json" <<'EOF'
[{"email": "amy@remote.test", "name": "Amy <b>", "code": "A-1"},
 {"email": "bob@remote.test", "code": "B-2"},
 {"email": "cat@remote.test", "name": "Cat"}]
EOF
printf '\x89PNG\r\n\x1a\nlogo-bytes' > "$T/logo.png"
sent_to() { grep -l "^rcpt $1\$" "$T"/sink/* 2>/dev/null; }
wait_for() { for _ in $(seq 1 100); do [ -n "$(sent_to "$1")" ] && return 0; sleep 0.1; done; return 1; }
count() { ls "$T"/sink 2>/dev/null | grep -vc '^\.' ; }

# --dry-run: the first message shown, nothing sent.
out=$("$BIN" send m --template "$T/promo.html" --to "json:$T/people.json" --subject 'Hi {{name|there}}' \
      --from news@example.test --set banner='<i>autumn</i>' --dry-run 2>&1); rc=$?
case "$out" in *"To: \"Amy <b>\" <amy@remote.test>"*|*"amy@remote.test"*) ;; *) rc=99 ;; esac
case "$out" in *"Subject: Hi Amy <b>"*"Your code: A-1"*"(3 recipients in all; nothing sent)"*) [ "$rc" -eq 0 ] && ok "--dry-run shows the first message filled, and sends nothing" \
    || bad "--dry-run" "rc $rc: $out" ;; *) bad "--dry-run shows the first message filled, and sends nothing" "rc $rc: $out" ;; esac
sleep 0.5; [ "$(count)" -eq 0 ] && ok "and the sink got nothing" || bad "and the sink got nothing" "$(count)"

# --check: a first recipient whose message cannot be written stops them all.
printf '[{"email":"cat@remote.test"},{"email":"amy@remote.test","code":"A-1"}]' > "$T/first-bad.json"
out=$("$BIN" send m --template "$T/promo.html" --to "json:$T/first-bad.json" --subject 'x' --from news@example.test --check 2>&1); rc=$?
case "$out" in *"stopped before sending"*"{{code}}"*) [ "$rc" -eq 1 ] && ok "--check stops before sending when the first message has a placeholder without a value" \
    || bad "--check stops on the first" "rc $rc: $out" ;; *) bad "--check stops before sending when the first message has a placeholder without a value" "rc $rc: $out" ;; esac
sleep 0.5; [ "$(count)" -eq 0 ] && ok "and nothing went" || bad "and nothing went" "$(count)"

# --check past the first: a later recipient without a value is skipped, the rest sent.
out=$("$BIN" send m --template "$T/promo.html" --to "json:$T/people.json" --subject 'Hi {{name|there}}' \
      --from news@example.test --set banner='<i>autumn</i>' --inline "$T/logo.png" --ad --check --rate 50/s 2>&1); rc=$?
case "$out" in *"skipped cat@remote.test: nothing fills {{code}}"*"sent 2 of 3, skipped 1"*) [ "$rc" -eq 0 ] && ok "--check skips a later recipient without a value and sends the rest" \
    || bad "--check skips a later one" "rc $rc: $out" ;; *) bad "--check skips a later recipient without a value and sends the rest" "rc $rc: $out" ;; esac
wait_for amy@remote.test; wait_for bob@remote.test
tally < <(python3 - "$(sent_to amy@remote.test)" "$(sent_to bob@remote.test)" <<'PY'
import email, email.policy, sys
def check(name, ok, info=""):
    print(("ok " if ok else "bad ") + name + ("" if ok else ": " + str(info)[:400].replace("\n", " ")))
def msg(path):
    # The sink's envelope, its lines and a blank one, comes before the message.
    raw = open(path, "rb").read().split(b"\n\n", 1)[1] if path else b""
    return email.message_from_bytes(raw, policy=email.policy.default)
amy, bob = msg(sys.argv[1]), msg(sys.argv[2])
html = amy.get_body(("html",))
text = amy.get_body(("plain",))
h = html.get_content() if html else ""
check("each recipient is sent their own message, the subject filled", amy["Subject"] == "Hi Amy <b>" and bob["Subject"] == "Hi there", (amy["Subject"], bob["Subject"]))
check("a value goes into the HTML escaped, {{{raw}}} as it is", "Hello Amy &lt;b&gt;!" in h and "<i>autumn</i>" in h and "A-1" in h, h[:300])
check("a placeholder's default stands where the recipient has no value", "Hello friend!" in (bob.get_body(("html",)).get_content() if bob.get_body(("html",)) else ""), "")
check("a plain text part is written from the HTML beside it", text is not None and "Your code: A-1" in text.get_content(), text and text.get_content()[:200])
related = [p for p in amy.walk() if p.get_content_type() == "multipart/related"]
img = [p for p in amy.walk() if p.get("Content-ID") == "<logo.png>"]
check("--inline sends the image inside the message, by the Content-ID the HTML names", bool(related) and bool(img)
      and img[0].get_content() == b"\x89PNG\r\n\x1a\nlogo-bytes" and "cid:logo.png" in h, [p.get_content_type() for p in amy.walk()])
PY
)

# Without --check a missing value is empty, and the message goes.
rm -f "$T"/sink/*
out=$("$BIN" send m --template "$T/promo.html" --to cat@remote.test --subject 'Hi' --from news@example.test 2>&1); rc=$?
[ "$rc" -eq 0 ] && wait_for cat@remote.test && ok "without --check a placeholder without a value is empty, and the message goes" \
    || bad "without --check a missing value is empty" "rc $rc: $out"

# An advertisement: List-Unsubscribe, its one-click POST, and the recipient's own link.
rm -f "$T"/sink/*
out=$("$BIN" send m --template "$T/promo.html" --to dan@remote.test --set code=D-4 --subject 'Sale' --from news@example.test --ad 2>&1); rc=$?
printf 'Plain offer, no link in it.\n' > "$T/plain.txt"
out2=$("$BIN" send m --to eve@remote.test --set x=1 --subject 'Offer' --from news@example.test --ad --text "$(cat "$T/plain.txt")" 2>&1)
wait_for dan@remote.test; wait_for eve@remote.test
tally < <(python3 - "$(sent_to dan@remote.test)" "$(sent_to eve@remote.test)" "$T/link" <<'PY'
import email, email.policy, re, sys
def check(name, ok, info=""):
    print(("ok " if ok else "bad ") + name + ("" if ok else ": " + str(info)[:400].replace("\n", " ")))
def msg(path):
    # The sink's envelope, its lines and a blank one, comes before the message.
    raw = open(path, "rb").read().split(b"\n\n", 1)[1] if path else b""
    return email.message_from_bytes(raw, policy=email.policy.default)
dan, eve = msg(sys.argv[1]), msg(sys.argv[2])
lu = dan.get("List-Unsubscribe", "")
https = re.search(r"<(https://mail\.example\.test/unsubscribe\?t=[^>]+)>", lu)
check("an advertisement carries List-Unsubscribe, https and mailto, and its one-click POST",
      bool(https) and "<mailto:unsubscribe@example.test?subject=" in lu and dan.get("List-Unsubscribe-Post") == "List-Unsubscribe=One-Click", (lu, dan.get("List-Unsubscribe-Post")))
h = dan.get_body(("html",)).get_content()
check("its link is where the template says {{unsubscribe}}", bool(https) and https.group(1).replace("&", "&amp;") in h and "{{unsubscribe}}" not in h, h[-300:])
t = eve.get_body(("plain",)).get_content()
check("one whose template says no {{unsubscribe}} has the link below it", "Unsubscribe: https://mail.example.test/unsubscribe?t=" in t, t)
open(sys.argv[3], "w").write(https.group(1) if https else "")
PY
)
link=$(cat "$T/link"); path=${link#https://mail.example.test}
code=$(curl -s -o "$T/page" -w '%{http_code}' "http://127.0.0.1:$W$path")
grep -q 'method="post"' "$T/page" && [ "$code" = 200 ] && [ -z "$("$BIN" mail m unsubscribed)" ] \
    && ok "the link's GET asks, and unsubscribes no one" || bad "the link's GET asks, and unsubscribes no one" "$code $(head -c 200 "$T/page") / $("$BIN" mail m unsubscribed)"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$W$path" -d 'List-Unsubscribe=One-Click')
[ "$code" = 200 ] && [ "$("$BIN" mail m unsubscribed)" = "dan@remote.test" ] && ok "its POST, as a provider's one click sends it, unsubscribes the recipient" \
    || bad "its POST unsubscribes the recipient" "$code / $("$BIN" mail m unsubscribed)"
forged=$(printf '%s' "$path" | sed 's/[0-9a-f]\{4\}$/0000/')
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$W$forged")
[ "$code" = 404 ] && ok "a forged token is no link of this runtime's" || bad "a forged token is refused" "$code"
rm -f "$T"/sink/*
out=$("$BIN" send m --to dan@remote.test --to fay@remote.test --set x=1 --subject 'Sale' --from news@example.test --ad --text 'again' --rate 50/s 2>&1); rc=$?
case "$out" in *"skipped dan@remote.test: dan@remote.test unsubscribed"*"sent 1 of 2, skipped 1"*) wait_for fay@remote.test \
    && ok "an advertisement is not sent to one who unsubscribed, and is to the rest" || bad "the rest is sent" "$out" ;;
    *) bad "an advertisement is not sent to one who unsubscribed, and is to the rest" "rc $rc: $out" ;; esac
out=$("$BIN" send m --to dan@remote.test --subject 'Your receipt' --from news@example.test --text 'receipt' 2>&1); rc=$?
[ "$rc" -eq 0 ] && wait_for dan@remote.test && ok "a mail that is no advertisement still goes to them" || bad "a mail that is no advertisement still goes" "rc $rc: $out"
"$BIN" mail m resubscribe dan@remote.test >/dev/null 2>&1
[ -z "$("$BIN" mail m unsubscribed)" ] && ok "resubscribe takes the address back" || bad "resubscribe takes the address back" "$("$BIN" mail m unsubscribed)"

# The mailto: of List-Unsubscribe, its token in the Subject.
mailto_token=$(python3 -c "import re,sys; print(re.search(r'subject=([^>]+)>', open(sys.argv[1]).read()).group(1))" "$(sent_to fay@remote.test | head -1)" 2>/dev/null)
python3 - "$P" "$mailto_token" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]))
s.sendmail("fay@remote.test", ["unsubscribe@example.test"], "From: fay@remote.test\r\nTo: unsubscribe@example.test\r\nSubject: " + sys.argv[2] + "\r\n\r\nunsubscribe\r\n")
s.quit()
PY
for _ in $(seq 1 50); do "$BIN" mail m unsubscribed | grep -q fay@remote.test && break; sleep 0.1; done
"$BIN" mail m unsubscribed | grep -qx fay@remote.test && ok "a mail to the mailto: unsubscribes its recipient" \
    || bad "a mail to the mailto: unsubscribes its recipient" "$mailto_token / $("$BIN" mail m unsubscribed)"

# Recipients from an idp's accounts and a db's documents, with their fields.
rm -f "$T"/sink/*
printf 'Hi {{name|you}}, code {{code|none}}' > "$T/short.txt"
out=$("$BIN" send m --to idp:auth --to db:shop/customers --subject 'Codes' --from news@example.test --text "$(cat "$T/short.txt")" --rate 50/s 2>&1); rc=$?
case "$out" in *"sent 4 of 4"*) ok "idp:<runtime> and db:<runtime>/<collection> give their accounts and documents as recipients" ;;
    *) bad "idp:<runtime> and db:<runtime>/<collection> give their accounts and documents as recipients" "rc $rc: $out" ;; esac
for a in ann ben dora eli; do wait_for $a@remote.test; done
body_of() { f=$(sent_to "$1"); [ -n "$f" ] && sed -n '/^\r\?$/,$p' "$f" | tr -d '\r'; }
case "$(body_of ann@remote.test)" in *"Hi Ann A, code IDP-ANN"*) ok "an account's name and its own fields fill the placeholders" ;; *) bad "an account's fields fill the placeholders" "$(body_of ann@remote.test | head -c 300)" ;; esac
case "$(body_of dora@remote.test)" in *"Hi Dora, code DB-DORA"*) ok "a document's fields fill them" ;; *) bad "a document's fields fill them" "$(body_of dora@remote.test | head -c 300)" ;; esac
rm -f "$T"/sink/*
out=$("$BIN" send m --to idp:auth/vip --subject 'VIP' --from news@example.test --text 'vip' 2>&1)
case "$out" in *"sent 1 of 1"*) wait_for ben@remote.test && ok "idp:<runtime>/<group> gives the accounts of that group alone" || bad "the group's account is sent" "$out" ;;
    *) bad "idp:<runtime>/<group> gives the accounts of that group alone" "$out" ;; esac

# --test-to: one message, the first recipient's, to the address it names.
rm -f "$T"/sink/*
out=$("$BIN" send m --template "$T/promo.html" --to "json:$T/people.json" --subject 'Hi {{name|there}}' --from news@example.test \
      --test-to me@remote.test 2>&1); rc=$?
sleep 0.5
wait_for me@remote.test && [ "$(count)" -eq 1 ] && grep -q '^Subject: \[test\] Hi Amy' "$(sent_to me@remote.test)" \
    && ok "--test-to sends the first recipient's message to that address alone" || bad "--test-to sends one message" "rc $rc: $out / $(count)"

out=$("$BIN" mail m 2>&1)
case "$out" in *"m: mail for example.test"*"webmail    mail"*"queue"*"unsubscribed"*) ok "socketley mail <name> sums the runtime up" ;; *) bad "socketley mail <name> sums the runtime up" "$out" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
