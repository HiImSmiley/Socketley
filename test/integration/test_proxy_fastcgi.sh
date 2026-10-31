#!/usr/bin/env bash
# suite: isolated -- its own daemon, socket, state directory and port window, so it runs beside the others
# Integration test: a proxy whose backend is an application server spoken to by FastCGI (--backend fastcgi://...).
#
# What each part would catch:
#   * a request written as records the server cannot read: the CGI variables, the body by Content-Length or chunked
#   * an answer read back wrong: the status, the fields, a body over several records, HEAD, a redirect
#   * a script that is not one handed to the interpreter: a path outside --root, a hidden file, /upload.jpg/x.php
#   * httpoxy (a Proxy header as HTTP_PROXY), and a connection to the server not kept between requests
#   * a server that answers garbage taken as an answer rather than a 502
# A stub server in python checks the protocol exactly; php-fpm, where it is installed, runs real scripts.
set -uo pipefail

BIN="${BIN:-$(dirname "$0")/../../bin/Release/socketley}"
BIN=$(readlink -f "$BIN")
. "$(dirname "$0")/lib_daemon.sh"
. "$(dirname "$0")/lib_ports.sh"
exec 2>&1

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); }
bad() { FAIL=$((FAIL+1)); echo "  FAIL [$1]: $2"; }
expect() { if [ "$2" = "$3" ]; then ok; else bad "$1" "got '$2', want '$3'"; fi; }
has() { if printf '%s' "$2" | grep -qE -- "$3"; then ok; else bad "$1" "no /$3/ in: $(printf '%s' "$2" | head -c 400)"; fi; }
hasnt() { if printf '%s' "$2" | grep -qE -- "$3"; then bad "$1" "/$3/ in: $(printf '%s' "$2" | head -c 400)"; else ok; fi; }

echo "=== Integration: a proxy in front of a FastCGI application server ==="
command -v python3 >/dev/null 2>&1 || { echo "  SKIP: python3 is required"; exit 0; }
daemon_isolate proxyfcgi
T=$SOCKETLEY_TMPD
P=$((SL_PORT_BASE + 700))
unset SOCKETLEY_CONFIG
STUB_PID=""; FPM_PID=""
trap '[ -n "$STUB_PID" ] && kill $STUB_PID 2>/dev/null; [ -n "$FPM_PID" ] && kill $FPM_PID 2>/dev/null; daemon_stop' EXIT
daemon_start "$BIN"

# ── the site ────────────────────────────────────────────────────────────────
W="$T/www"
mkdir -p "$W/shop" "$W/uploads" "$W/.git"
for f in index.php hello.php shop/index.php shop/cart.php; do printf '<?php echo "%s";\n' "$f" > "$W/$f"; done
printf 'GIF89a <?php system("id"); ?>' > "$W/uploads/avatar.jpg"
printf 'SECRET=1\n' > "$W/.env"
printf 'body{}\n' > "$W/style.css"
printf '[core]\n' > "$W/.git/config"
printf '<?php echo 1;\n' > "$W/.git/hook.php"
mkdir -p "$W/.well-known" "$T/outside"
printf '<?php echo 1;\n' > "$W/.well-known/acme.php"
printf '<?php echo 1;\n' > "$T/outside/evil.php"
ln -s "$T/outside/evil.php" "$W/escape.php"
ln -s "$W/hello.php" "$W/alias.php"

# ── a FastCGI server that says what it was sent ─────────────────────────────
cat > "$T/stub.py" <<'PY'
import hashlib, json, os, socket, struct, sys, threading
path, log = sys.argv[1], sys.argv[2]
conns = [0]
def rec(t, content=b""):
    return struct.pack(">BBHHBB", 1, t, 1, len(content), 0, 0) + content
def pairs(b):
    out, i = {}, 0
    def ln():
        nonlocal i
        x = b[i]
        if x < 128:
            i += 1; return x
        v = struct.unpack(">I", b[i:i+4])[0] & 0x7fffffff; i += 4; return v
    while i < len(b):
        a = ln(); c = ln()
        out[b[i:i+a].decode()] = b[i+a:i+a+c].decode(errors="replace"); i += a + c
    return out
def serve(c, n):
    buf = b""
    while True:
        params, stdin, keep, ended = b"", b"", False, False
        while not ended:
            while len(buf) < 8:
                d = c.recv(65536)
                if not d: return
                buf += d
            v, t, rid, ln_, pad, _ = struct.unpack(">BBHHBB", buf[:8])
            while len(buf) < 8 + ln_ + pad:
                d = c.recv(65536)
                if not d: return
                buf += d
            content, buf = buf[8:8+ln_], buf[8+ln_+pad:]
            if t == 1: keep = bool(content[2] & 1)
            elif t == 4: params += content
            elif t == 5:
                if content: stdin += content
                else: ended = True
        p = pairs(params)
        mode = p.get("HTTP_X_MODE", "")
        info = {k: p.get(k) for k in ("SCRIPT_FILENAME", "SCRIPT_NAME", "PATH_INFO", "REQUEST_METHOD", "QUERY_STRING",
                "CONTENT_LENGTH", "CONTENT_TYPE", "HTTP_PROXY", "HTTP_COOKIE", "REQUEST_URI", "DOCUMENT_ROOT",
                "HTTP_X_UNDER_SCORE", "GATEWAY_INTERFACE", "REDIRECT_STATUS")}
        info["stdin"] = stdin[:4096].decode(errors="replace"); info["stdin_sha"] = hashlib.sha256(stdin).hexdigest()
        info["conn"] = n
        with open(log, "a") as f: f.write(json.dumps(info) + "\n")
        if mode == "garbage":
            c.sendall(b"this is not FastCGI at all\r\n"); c.close(); return
        out = b""
        if mode == "stderr": out += rec(7, b"PHP Warning: told the log\n")
        if mode == "404": head = b"Status: 404 Not Found\r\nContent-Type: text/plain\r\n\r\n"; body = b"nope"
        elif mode == "redirect": head = b"Location: https://example.test/there\r\n\r\n"; body = b""
        elif mode == "big": head = b"Content-Type: application/octet-stream\r\n\r\n"; body = bytes(range(256)) * 800
        elif mode == "nohead": head = b""; body = b""
        else: head = b"Content-Type: application/json\r\nX-Script: yes\r\n\r\n"; body = json.dumps(info).encode()
        whole = head + body
        for i in range(0, len(whole), 30000): out += rec(6, whole[i:i+30000])
        out += rec(6) + rec(3, b"\0\0\0\0\0\0\0\0")
        c.sendall(out)
        if not keep: c.close(); return
s = socket.socket(socket.AF_UNIX); s.bind(path); s.listen(16)
while True:
    c, _ = s.accept(); conns[0] += 1
    threading.Thread(target=serve, args=(c, conns[0]), daemon=True).start()
PY
python3 "$T/stub.py" "$T/stub.sock" "$T/stub.log" & STUB_PID=$!
for _ in $(seq 1 50); do [ -S "$T/stub.sock" ] && break; sleep 0.1; done

out=$("$BIN" create proxy site -p "$P" --backend "fastcgi://unix:$T/stub.sock" 2>&1); rc=$?
expect "a fastcgi backend without --root is refused" "$rc $(printf '%s' "$out" | grep -c 'root')" "1 1"
"$BIN" remove site >/dev/null 2>&1
"$BIN" create proxy site -p "$P" --domain site --backend "fastcgi://unix:$T/stub.sock" --root "$W" -s >/dev/null 2>&1 \
    || bad "a FastCGI proxy is made" "$(tail -3 "$SOCKETLEY_DLOG")"
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$P/" && break; sleep 0.1; done
U="http://127.0.0.1:$P"
last() { tail -1 "$T/stub.log" 2>/dev/null; }
j() { python3 -c "import json,sys; d=json.loads(sys.argv[1]); print($2)" "$1" 2>/dev/null; }

# ── a request, written as the server reads it ───────────────────────────────
r=$(curl -s -D "$T/h" "$U/hello.php?a=1&b=2" -H 'Cookie: x=1' -H 'Proxy: http://evil.test:8080' -H 'X_Under_Score: 1')
expect "a script's answer comes back with its fields" "$(grep -c '^X-Script: yes' "$T/h") $(head -1 "$T/h" | tr -d '\r')" "1 HTTP/1.1 200 OK"
L=$(last)
expect "SCRIPT_FILENAME is the script under --root" "$(j "$L" 'd["SCRIPT_FILENAME"]')" "$W/hello.php"
expect "and SCRIPT_NAME, QUERY_STRING and the method as CGI/1.1 says" \
    "$(j "$L" 'd["SCRIPT_NAME"]+" "+d["QUERY_STRING"]+" "+d["REQUEST_METHOD"]+" "+d["GATEWAY_INTERFACE"]')" "/hello.php a=1&b=2 GET CGI/1.1"
expect "a cookie is passed on" "$(j "$L" 'd["HTTP_COOKIE"]')" "x=1"
expect "a Proxy header is not (httpoxy), nor one whose name holds an underscore" \
    "$(j "$L" 'str(d["HTTP_PROXY"])+" "+str(d["HTTP_X_UNDER_SCORE"])')" "None None"

r=$(curl -s "$U/shop/cart.php/extra/part")
expect "what follows the script is PATH_INFO" "$(j "$(last)" 'd["SCRIPT_NAME"]+" "+d["PATH_INFO"]')" "/shop/cart.php /extra/part"
r=$(curl -s "$U/shop/")
expect "a directory is its index script" "$(j "$(last)" 'd["SCRIPT_NAME"]')" "/shop/index.php"
r=$(curl -s "$U/blog/2026/hello-world")
expect "a path nothing answers goes to the index script, as a front controller" \
    "$(j "$(last)" 'd["SCRIPT_NAME"]+" "+d["REQUEST_URI"]')" "/index.php /blog/2026/hello-world"

# ── bodies ──────────────────────────────────────────────────────────────────
r=$(curl -s -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data 'name=alice&x=1' "$U/hello.php")
L=$(last)
expect "a body by Content-Length is STDIN, with CONTENT_LENGTH and CONTENT_TYPE" \
    "$(j "$L" 'd["stdin"]+" "+d["CONTENT_LENGTH"]+" "+d["CONTENT_TYPE"]')" "name=alice&x=1 14 application/x-www-form-urlencoded"
r=$(printf 'chunked body here' | curl -s -X POST -H 'Transfer-Encoding: chunked' --data-binary @- "$U/hello.php")
expect "a chunked body is sent whole, with the CONTENT_LENGTH PHP needs" \
    "$(j "$(last)" 'd["stdin"]+" "+d["CONTENT_LENGTH"]')" "chunked body here 17"
head -c 300000 /dev/urandom > "$T/big.bin"
r=$(curl -s -X POST --data-binary @"$T/big.bin" "$U/hello.php")
expect "a body over several records arrives whole" "$(j "$(last)" 'd["CONTENT_LENGTH"]+" "+d["stdin_sha"]')" \
    "300000 $(sha256sum < "$T/big.bin" | cut -c1-64)"

# ── answers ─────────────────────────────────────────────────────────────────
expect "a script's Status is the answer's" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Mode: 404' "$U/hello.php")" 404
expect "a Location with no Status is a redirect" \
    "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'X-Mode: redirect' "$U/hello.php")" "302 https://example.test/there"
curl -s -o "$T/big.out" -H 'X-Mode: big' "$U/hello.php"
expect "an answer over several records comes back whole" "$(stat -c %s "$T/big.out")" 204800
expect "a HEAD is answered without a body" "$(curl -s -I -o /dev/null -w '%{http_code} %{size_download}' "$U/hello.php")" "200 0"
curl -s -o /dev/null -H 'X-Mode: stderr' "$U/hello.php"
for _ in $(seq 1 20); do grep -q 'told the log' "$SOCKETLEY_DLOG" && break; sleep 0.1; done
has "what the script writes to STDERR is in the log" "$(cat "$SOCKETLEY_DLOG")" 'PHP Warning: told the log'
expect "a server that answers no CGI head is a 502" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Mode: nohead' "$U/hello.php")" 502
expect "and one that answers garbage" "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Mode: garbage' "$U/hello.php")" 502

# ── one connection to the server for many requests ──────────────────────────
: > "$T/stub.log"
curl -s -o /dev/null -o /dev/null "$U/hello.php?n=1" "$U/hello.php?n=2"
expect "two requests share one connection to the server" "$(python3 -c '
import json,sys; print(len(set(json.loads(l)["conn"] for l in open(sys.argv[1]))))' "$T/stub.log")" 1

# ── what never reaches the interpreter ──────────────────────────────────────
: > "$T/stub.log"
code() { curl -s -o /dev/null -w '%{http_code}' --path-as-is "$U$1"; }
expect "a path out of --root is refused" "$(code '/../../etc/passwd')" 404
expect "and one spelled with %2e%2e" "$(code '/%2e%2e/%2e%2e/etc/passwd')" 404
expect "a hidden file is not served" "$(code '/.env')" 404
expect "nor a hidden directory's" "$(code '/.git/config')" 404
expect "an existing file that is no script does not reach the server" "$(code '/style.css')" 404
expect "nor a script in a hidden directory" "$(code '/.git/hook.php')" 404
expect "none of them did" "$(wc -l < "$T/stub.log")" 0
r=$(curl -s "$U/.well-known/acme.php")
expect "but .well-known is the one hidden directory a site serves" "$(j "$(last)" 'd["SCRIPT_NAME"]')" "/.well-known/acme.php"
r=$(curl -s "$U/escape.php")
expect "a link out of --root is never the script" "$(j "$(last)" 'd["SCRIPT_FILENAME"]')" "$W/index.php"
r=$(curl -s "$U/alias.php")
expect "a link that stays inside is" "$(j "$(last)" 'd["SCRIPT_FILENAME"]')" "$W/alias.php"
r=$(curl -s "$U/uploads/avatar.jpg/x.php")
expect "an upload asked for as /upload.jpg/x.php is never the script: the index script is" \
    "$(j "$(last)" 'd["SCRIPT_FILENAME"]')" "$W/index.php"

# ── php-fpm, where it is installed ──────────────────────────────────────────
FPM=$(ls /usr/sbin/php-fpm* 2>/dev/null | head -1)
if [ -n "$FPM" ]; then
    mkdir -p "$T/php"
    cat > "$T/php/page.php" <<'PHP'
<?php
header('X-From: php');
setcookie('seen', 'yes');
echo json_encode(['method' => $_SERVER['REQUEST_METHOD'], 'post' => $_POST, 'get' => $_GET,
                  'cookie' => $_COOKIE, 'self' => $_SERVER['PHP_SELF'], 'proxy' => getenv('HTTP_PROXY') ?: null]);
PHP
    printf '<?php http_response_code(418); echo "teapot";\n' > "$T/php/teapot.php"
    printf '<?php echo "front ", $_SERVER["REQUEST_URI"];\n' > "$T/php/index.php"
    cat > "$T/fpm.conf" <<EOF
[global]
error_log = $T/fpm.log
daemonize = no
pid = $T/fpm.pid
[www]
listen = $T/fpm.sock
pm = static
pm.max_children = 2
clear_env = yes
security.limit_extensions = .php
EOF
    "$FPM" -n -y "$T/fpm.conf" -p "$T" -d error_reporting=E_ALL > "$T/fpm.out" 2>&1 & FPM_PID=$!
    for _ in $(seq 1 50); do [ -S "$T/fpm.sock" ] && break; sleep 0.1; done
    "$BIN" create proxy php -p $((P+1)) --domain php --backend "fastcgi://unix:$T/fpm.sock" --root "$T/php" -s >/dev/null 2>&1
    for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$((P+1))/" && break; sleep 0.1; done
    V="http://127.0.0.1:$((P+1))"
    r=$(curl -s -D "$T/ph" -X POST --data 'a=1&b=two' -H 'Cookie: c=3' -H 'Proxy: http://evil.test' "$V/page.php?q=x")
    expect "php runs a script: method, POST, GET, cookie, PHP_SELF" \
        "$(j "$r" 'd["method"]+" "+d["post"]["b"]+" "+d["get"]["q"]+" "+d["cookie"]["c"]+" "+d["self"]+" "+str(d["proxy"])')" \
        "POST two x 3 /page.php None"
    has "and its headers and cookies come back" "$(cat "$T/ph")" 'X-From: php'
    has "set by setcookie" "$(cat "$T/ph")" 'Set-Cookie: seen=yes'
    expect "a status the script sets is the answer's" "$(curl -s -o /dev/null -w '%{http_code}' "$V/teapot.php")" 418
    expect "a route nothing answers is the front controller's" "$(curl -s "$V/some/route?x=1")" "front /some/route?x=1"
else
    echo "  SKIP: php-fpm is not installed, so only the stub server's half ran"
fi

echo
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
