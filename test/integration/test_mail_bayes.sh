#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: the spam filter that learns -- from what a user moves into Junk over IMAP, from a folder named to
# `socketley mail <m> learn`, and then a new message like the spam put in Junk by itself, one like the rest not.
#
# ─── WHAT EACH ASSERTION WOULD CATCH ────────────────────────────────────────
#
#   * a MOVE into Junk not learned as spam, or `learn` not reading the folder it names
#   * a trained filter not scoring new mail, putting what is like the spam anywhere but Junk, or the rest in Junk
#   * what it learned not folded into its file, or lost across a restart
#   * `mail trace` not saying what was delivered to an address or why a recipient was refused, or no log line of it
#   * `mail` without a name not finding the one mail runtime, or guessing between two
#   * the mail runtime's figures missing from the daemon's metrics, or `mail usage` not saying what a user holds
#   * --autoexpunge leaving Junk full, or reaching the INBOX
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

daemon_isolate mail_bayes
T="$SOCKETLEY_TMPD"
P=$((SL_PORT_BASE+1990)); IM=$((P+1)); PI=$((P+2)); PS=$((P+3)); NS=$((P+4))
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; daemon_stop' EXIT

echo "=== Integration: a spam filter that learns from what users move ==="

# Mail from this machine is not checked, so the senders below come from 127.0.0.2, their names asked of a resolver
# that knows none of them.
python3 "$HERE/lib_fake_dns.py" "$NS" 0 normal >/dev/null 2>&1 &
PIDS+=($!)
printf 'nameserver 127.0.0.1\noptions timeout:1 attempts:1 port:%s\n' "$NS" > "$T/resolv.conf"
# An hour of --autoexpunge is a second here.
export SOCKETLEY_RESOLV_CONF="$T/resolv.conf" SOCKETLEY_MAIL_BAYES_FOLD_MS=1500 SOCKETLEY_MAIL_QUEUE_SCALE=3600
# The daemon's metrics, for the mail runtime's figures among them.
MP=$((P+7))
unset SOCKETLEY_CONFIG
mkdir -p "$HOME/.config/socketley"
printf 'daemon = { metrics_port = %s }\n' "$MP" > "$HOME/.config/socketley/config.lua"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=mail.example.test" \
    -keyout "$T/key.pem" -out "$T/cert.pem" >/dev/null 2>&1
daemon_start "$BIN"
"$BIN" create idp auth -p "$PI" --issuer "http://127.0.0.1:$PI" -s >/dev/null 2>&1
"$BIN" create storage st -p "$PS" --dir "$T/data" --anonymous -s >/dev/null 2>&1
for p in "$PI/jwks" "$PS/"; do
    for _ in $(seq 1 100); do [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p")" != 000 ] && break; sleep 0.1; done
done
"$BIN" idp-user auth add alice --password alicepassword1 --email alice@example.test >/dev/null 2>&1
"$BIN" create mail m -p "$P" --mail-domain example.test --idp auth --storage st/mail --imap "$IM" \
    --tls --cert "$T/cert.pem" --key "$T/key.pem" -s >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" || bad "the IMAP port listens" "$(tail -3 "$SOCKETLEY_DLOG")"

keys() { curl -s "http://127.0.0.1:$PS/mail?list-type=2&prefix=alice/$1/" | grep -o '<Key>[^<]*</Key>' | sed 's/<[^>]*>//g'; }
stat_of() { "$BIN" stats m 2>/dev/null | sed -n "s/^ *$1[: ] *//p" | head -1; }
cat > "$T/mail.py" <<'PY'
import random, smtplib, sys, time, urllib.request
port, storage, kind, count, seed = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
spam = "cheap pills pharmacy discount viagra casino bonus jackpot lottery prize claim winner crypto profit guaranteed " \
       "refinance loan credit urgent offer exclusive deal".split()
ham = "meeting notes release plan review parser invoice september lunch friday team family dinner sunday project " \
      "deadline draft agenda minutes schedule budget report".split()
rng = random.Random(seed)
words = spam if kind == "spam" else ham
s = smtplib.SMTP("127.0.0.1", port, source_address=("127.0.0.2", 0))
s.ehlo("x")
for i in range(count):
    body = " ".join(rng.choice(words) for _ in range(40))
    subject = ("Offer: " if kind == "spam" else "Work: ") + " ".join(rng.choice(words) for _ in range(3))
    sender = ("promo%d@deals.test" if kind == "spam" else "colleague%d@work.test") % rng.randrange(5)
    s.sendmail(sender, ["alice@example.test"], "From: %s\r\nTo: alice@example.test\r\nSubject: %s\r\n\r\n%s\r\n"
               % (sender, subject, body))
s.quit()
PY
wait_count() {
    for _ in $(seq 1 200); do [ "$(keys "$1" | wc -l)" -ge "$2" ] && return 0; sleep 0.1; done; return 1
}

python3 "$T/mail.py" "$P" "$PS" spam 25 1 && python3 "$T/mail.py" "$P" "$PS" ham 25 2
wait_count INBOX 50 && ok "fifty messages for alice, half of them like spam" || bad "the messages arrive" "$(keys INBOX | wc -l)"
[ -z "$(stat_of mail_bayes_junked)" ] || [ "$(stat_of mail_bayes_junked)" = 0 ] \
    && ok "an untrained filter puts nothing in Junk" || bad "untrained" "$(stat_of mail_bayes_junked)"

moved=$(timeout 120 python3 - "$IM" <<'PY'
import imaplib, sys
M = imaplib.IMAP4("127.0.0.1", int(sys.argv[1]))
M.login("alice", "alicepassword1")
M.select("INBOX")
typ, data = M.uid("SEARCH", None, "SUBJECT", "Offer")
uids = data[0].split()
typ, _ = M.uid("MOVE", b",".join(uids), "Junk")
print(len(uids) if typ == "OK" else "MOVE " + typ)
PY
)
[ "$moved" = 25 ] && ok "alice moves the 25 into Junk over IMAP" || bad "the MOVE" "$moved"
out=$("$BIN" mail learn alice/INBOX --as ham 2>&1)
case "$out" in "learning 25 messages of alice's INBOX as not spam") ok "learn reads the folder it names" ;;
    *) bad "learn reads the folder it names" "$out" ;; esac
for _ in $(seq 1 200); do [ "$(stat_of mail_bayes_spam)" = 25 ] && [ "$(stat_of mail_bayes_ham)" = 25 ] && break; sleep 0.1; done
[ "$(stat_of mail_bayes_spam)" = 25 ] && ok "a MOVE into Junk is learned as spam" || bad "learned as spam" "$(stat_of mail_bayes_spam)"
[ "$(stat_of mail_bayes_ham)" = 25 ] && ok "and the folder learn named as not spam" || bad "learned as ham" "$(stat_of mail_bayes_ham)"

python3 "$T/mail.py" "$P" "$PS" spam 1 99
wait_count Junk 26 && ok "a new message like the spam goes into Junk by itself" || bad "new spam into Junk" "$(keys Junk | wc -l) / $(stat_of mail_bayes_junked)"
newest=$(keys Junk | while read -r k; do echo "$(curl -s "http://127.0.0.1:$PS/mail/$k" | grep -c 'x-spam-bayes=') $k"; done | grep '^1 ' | head -1)
[ -n "$newest" ] && ok "its header says the filter's score" || bad "x-spam-bayes" "$(keys Junk | head -3)"
python3 "$T/mail.py" "$P" "$PS" ham 1 98
wait_count INBOX 26 && [ "$(keys Junk | wc -l)" -eq 26 ] && ok "and one like the rest into INBOX" \
    || bad "new ham into INBOX" "INBOX $(keys INBOX | wc -l), Junk $(keys Junk | wc -l)"

# Folded into its file, the journal gone, and that file what a restart reads.
for _ in $(seq 1 100); do [ -n "$(find "$T" -name m.bayes 2>/dev/null)" ] && [ -z "$(find "$T" -name m.bayes.journal 2>/dev/null)" ] && break; sleep 0.1; done
[ -n "$(find "$T" -name m.bayes 2>/dev/null)" ] && [ -z "$(find "$T" -name 'm.bayes.journal' -o -name 'm.bayes.folding' 2>/dev/null)" ] \
    && ok "what it learned is folded into its file" || bad "folded" "$(find "$T" -name 'm.bayes*')"
"$BIN" restart m >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" >/dev/null 2>&1
python3 "$T/mail.py" "$P" "$PS" spam 1 97
wait_count Junk 27 && ok "and what it learned is what a restart scores with" || bad "kept across a restart" "Junk $(keys Junk | wc -l)"

# What became of the mail: delivered into the mailbox, and a recipient refused, both traced.
case "$("$BIN" mail trace alice@example.test 2>&1)" in *"-> alice@example.test  delivered"*) ok "mail trace says what was delivered to an address" ;;
    *) bad "mail trace says what was delivered" "$("$BIN" mail trace alice@example.test 2>&1 | tail -3)" ;; esac
python3 - "$P" <<'PY'
import smtplib, sys
s = smtplib.SMTP("127.0.0.1", int(sys.argv[1]), source_address=("127.0.0.2", 0))
s.ehlo("x")
s.mail("someone@else.test")
s.rcpt("nobody@example.test")
s.quit()
PY
case "$("$BIN" mail trace nobody@ 2>&1)" in *"someone@else.test -> nobody@example.test  refused: 550"*) ok "and why a recipient was refused" ;;
    *) bad "and why a recipient was refused" "$("$BIN" mail trace nobody@ 2>&1)" ;; esac
grep -q "from <someone@else.test> to <nobody@example.test>: refused" "$SOCKETLEY_DLOG" && ok "each a line of the log as well" \
    || bad "the log line" "$(grep -c 'to <' "$SOCKETLEY_DLOG")"

# The worker's figures reach the daemon a moment after they change, later under load.
for _ in $(seq 1 100); do
    metrics=$(curl -s "http://127.0.0.1:$MP/metrics")
    grep -qE '^socketley_mail_delivered_total\{name="m"\} [1-9]' <<<"$metrics" && grep -q '^socketley_mail_stat{name="m",stat="mail_bayes_spam"} 25' <<<"$metrics" && break
    sleep 0.1
done
grep -qE '^socketley_mail_delivered_total\{name="m"\} [1-9]' <<<"$metrics" && grep -q '^socketley_mail_stat{name="m",stat="mail_bayes_spam"} 25' <<<"$metrics" \
    && ok "the daemon's metrics carry the mail runtime's figures" || bad "mail metrics" "$(echo "$metrics" | grep -c socketley_mail)"

case "$("$BIN" mail usage 2>&1)" in *"alice"*"KiB  of no quota"*) ok "mail usage says what each user's mailboxes hold" ;;
    *) bad "mail usage" "$("$BIN" mail usage 2>&1)" ;; esac

# Junk emptied of what it held longer than --autoexpunge, the INBOX left as it is.
inbox=$(keys INBOX | wc -l)
"$BIN" import m --restart '{"autoexpunge": 3600}' >/dev/null 2>&1
ready_tcp 127.0.0.1 "$IM" >/dev/null 2>&1
python3 "$T/mail.py" "$P" "$PS" ham 1 96
for _ in $(seq 1 100); do [ "$(keys Junk | wc -l)" -eq 0 ] && break; sleep 0.1; done
[ "$(keys Junk | wc -l)" -eq 0 ] && [ "$(keys INBOX | wc -l)" -eq $((inbox+1)) ] && ok "--autoexpunge empties Junk of old mail and leaves the INBOX" \
    || bad "--autoexpunge" "Junk $(keys Junk | wc -l), INBOX $(keys INBOX | wc -l) of $((inbox+1))"

# The runtime's name goes unsaid while it is the only one, and is asked for once there are two.
"$BIN" create mail m2 -p $((P+6)) --mail-domain other.test -s >/dev/null 2>&1
case "$("$BIN" mail queue 2>&1)" in "name the mail runtime, one of "*) ok "with two mail runtimes the name is asked for" ;;
    *) bad "with two the name is asked for" "$("$BIN" mail queue 2>&1)" ;; esac

echo "  Results: $PASS/$TOTAL passed ($FAIL failed)"
[ "$FAIL" -eq 0 ] && echo "  OK" || exit 1
