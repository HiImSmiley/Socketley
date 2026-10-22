# A mail server for a test: lib_smtp_sink.py <port> <dir> [options], each message written to <dir> as it is taken,
# the envelope first ("from <addr>", "rcpt <addr>" lines, "tls 0|1", a blank line) and the data after.
#   --tls <cert> <key>    offer STARTTLS
#   --auth <user:pass>    offer AUTH PLAIN, and take mail only from it
#   --auth-login          offer AUTH LOGIN instead of PLAIN
#   --auth-code <code>    answer every AUTH with <code> (e.g. 454)
#   --mail <addr> <code>  answer MAIL FROM <addr> with <code>, once when it ends in "!"
#   --greet <code>        greet with <code> instead of 220
#   --reply <addr> <code> answer RCPT for <addr> with <code> (e.g. 550 or 451), once when <code> ends in "!"
#   --data <code>         answer the end of the data with <code>, once when it ends in "!"
#   --no-pipelining       leave PIPELINING out of EHLO
#   --chunking            offer CHUNKING, and take BDAT
#   --dsn                 offer DSN
#   --requiretls          offer REQUIRETLS inside TLS
# A message's file says "via DATA" or "via BDAT", and "mailparams"/"rcptparams <addr>" lines say what came with them.
# FAKESINK_ADDR binds another address than 127.0.0.1.
import base64, os, socket, ssl, sys, threading, time
port, out = int(sys.argv[1]), sys.argv[2]
args = sys.argv[3:]
tls = auth = None
replies, data_code, pipelining, chunking, dsn = {}, None, True, False, False
requiretls = False
auth_login, auth_code, mail_replies, greet = False, None, {}, "220"
i = 0
while i < len(args):
    a = args[i]
    if a == "--tls": tls = (args[i + 1], args[i + 2]); i += 3
    elif a == "--auth": auth = args[i + 1]; i += 2
    elif a == "--auth-login": auth_login = True; i += 1
    elif a == "--auth-code": auth_code = args[i + 1]; i += 2
    elif a == "--mail": mail_replies[args[i + 1].lower()] = args[i + 2]; i += 3
    elif a == "--greet": greet = args[i + 1]; i += 2
    elif a == "--reply": replies[args[i + 1].lower()] = args[i + 2]; i += 3
    elif a == "--data": data_code = args[i + 1]; i += 2
    elif a == "--no-pipelining": pipelining = False; i += 1
    elif a == "--chunking": chunking = True; i += 1
    elif a == "--dsn": dsn = True; i += 1
    elif a == "--requiretls": requiretls = True; i += 1
    else: raise SystemExit("unknown option " + a)
data_codes = {"d": data_code}
lock = threading.Lock()
seq = [0]
def take_code(table, key):
    with lock:
        c = table.get(key)
        if c and c.endswith("!"):
            table[key] = None
            return c[:-1]
        return c
def serve(conn):
    f = conn.makefile("rb")
    secure = [False]
    def say(x): conn.sendall(x.encode())
    say("%s sink ESMTP\r\n" % greet)
    if greet != "220":
        f.readline(); say("221 bye\r\n"); conn.close(); return
    frm, rcpts, authed = None, [], auth is None
    mparams, rparams, chunks = "", [], []
    while True:
        line = f.readline()
        if not line: break
        u = line.decode(errors="replace").rstrip("\r\n")
        v = u.upper()
        if v.startswith("EHLO") or v.startswith("HELO"):
            ext = ["sink", "8BITMIME", "SIZE 50000000"]
            if pipelining: ext.append("PIPELINING")
            if tls and not secure[0]: ext.append("STARTTLS")
            if auth: ext.append("AUTH LOGIN" if auth_login else "AUTH PLAIN")
            if chunking: ext.append("CHUNKING")
            if dsn: ext.append("DSN")
            if requiretls and secure[0]: ext.append("REQUIRETLS")
            say("".join("250-%s\r\n" % e for e in ext[:-1]) + "250 %s\r\n" % ext[-1])
        elif v == "STARTTLS" and tls:
            say("220 go ahead\r\n")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(*tls)
            conn = ctx.wrap_socket(conn, server_side=True); f = conn.makefile("rb"); secure[0] = True
        elif v.startswith("AUTH PLAIN") or v.startswith("AUTH LOGIN"):
            if v.startswith("AUTH PLAIN") == auth_login:
                say("504 5.5.4 mechanism not offered\r\n"); continue
            if v.startswith("AUTH LOGIN"):
                say("334 VXNlcm5hbWU6\r\n"); user_ = base64.b64decode(f.readline().strip()).decode()
                say("334 UGFzc3dvcmQ6\r\n"); pass_ = base64.b64decode(f.readline().strip()).decode()
            else:
                parts = base64.b64decode(u.split()[2]).split(b"\0")
                user_, pass_ = parts[1].decode(), parts[2].decode()
            if auth_code: say("%s %s.7.0 told to\r\n" % (auth_code, auth_code[0]))
            elif auth and user_ + ":" + pass_ == auth:
                authed = True; say("235 2.7.0 ok\r\n")
            else: say("535 5.7.8 no\r\n")
        elif v.startswith("MAIL FROM:"):
            if not authed: say("530 5.7.0 sign in\r\n"); continue
            frm, rcpts = u[10:].split(">")[0].lstrip("<"), []
            mparams, rparams, chunks = u[10:].split(">", 1)[1].strip(), [], []
            c = take_code(mail_replies, frm.lower())
            if c: say("%s %s.0.0 told to\r\n" % (c, c[0])); frm = None; continue
            say("250 ok\r\n")
        elif v.startswith("RCPT TO:"):
            if frm is None: say("503 5.5.1 need MAIL command\r\n"); continue
            to = u[8:].split(">")[0].lstrip("<")
            c = take_code(replies, to.lower())
            if c: say("%s %s.0.0 told to\r\n" % (c, c[0]))
            else:
                rcpts.append(to); rparams.append((to, u[8:].split(">", 1)[1].strip())); say("250 ok\r\n")
        elif v.startswith("BDAT ") and chunking:
            w_ = v.split()
            n_, last = int(w_[1]), len(w_) > 2 and w_[2] == "LAST"
            chunks.append(f.read(n_))
            if not rcpts: say("554 5.5.1 no recipients\r\n"); continue
            if not last: say("250 2.0.0 %d octets\r\n" % n_); continue
            c = take_code(data_codes, "d")
            if c:
                say("%s %s.0.0 told to\r\n" % (c, c[0])); continue
            body = [b"".join(chunks)]; chunks = []
            via = "BDAT"
            with lock:
                seq[0] += 1; n = seq[0]
            tmp = os.path.join(out, ".%06d" % n)
            with open(tmp, "wb") as w:
                w.write(("from %s\n" % frm).encode())
                for r in rcpts: w.write(("rcpt %s\n" % r).encode())
                w.write(("via %s\nmailparams %s\n" % (via, mparams)).encode())
                for r, p in rparams: w.write(("rcptparams %s %s\n" % (r, p)).encode())
                w.write(("tls %d\n\n" % (1 if secure[0] else 0)).encode())
                w.write(b"".join(body))
            os.rename(tmp, os.path.join(out, "%06d.eml" % n))
            say("250 2.0.0 taken %d\r\n" % n)
        elif v == "DATA":
            if not rcpts: say("554 5.5.1 no recipients\r\n"); continue
            say("354 go\r\n")
            body = []
            while True:
                l = f.readline()
                if not l or l == b".\r\n": break
                body.append(l[1:] if l.startswith(b"..") else l)
            c = take_code(data_codes, "d")
            if c:
                say("%s %s.0.0 told to\r\n" % (c, c[0])); continue
            via = "DATA"
            with lock:
                seq[0] += 1; n = seq[0]
            tmp = os.path.join(out, ".%06d" % n)
            with open(tmp, "wb") as w:
                w.write(("from %s\n" % frm).encode())
                for r in rcpts: w.write(("rcpt %s\n" % r).encode())
                w.write(("via %s\nmailparams %s\n" % (via, mparams)).encode())
                for r, p in rparams: w.write(("rcptparams %s %s\n" % (r, p)).encode())
                w.write(("tls %d\n\n" % (1 if secure[0] else 0)).encode())
                w.write(b"".join(body))
            os.rename(tmp, os.path.join(out, "%06d.eml" % n))
            say("250 2.0.0 taken %d\r\n" % n)
        elif v == "RSET": frm, rcpts = None, []; say("250 ok\r\n")
        elif v == "QUIT": say("221 bye\r\n"); break
        else: say("250 ok\r\n")
    conn.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((os.environ.get("FAKESINK_ADDR", "127.0.0.1"), port)); s.listen(64)
while True:
    c, _ = s.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
