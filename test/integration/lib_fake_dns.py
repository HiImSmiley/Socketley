# A nameserver for a test: lib_fake_dns.py <port> <delay_ms> <mode> name=ip ..., on FAKEDNS_ADDR (127.0.0.1 unless
# given), answering A and AAAA for the names given and NXDOMAIN for the rest; name=MX:<pref>:<host>, name=PTR:<host>, name=TXT:<text>
# and name=TLSA:<usage>:<selector>:<type>:<hex> give a name those records, and name=AD sets the AD bit on its answers,
# as a validating resolver does for a name DNSSEC signed.  name=SERVFAIL answers SERVFAIL for it, and name=NXFOR:<s>
# NXDOMAIN for <s> seconds from the first question about it.  <mode> is normal, truncate (every
# answer cut short), silent (none) or servfail.  A test points the resolver on the loop at it with SOCKETLEY_RESOLV_CONF
# and `options port:<port>`, which the system's resolver passes over.
import socket, struct, sys, threading, time
port, delay, mode = int(sys.argv[1]), float(sys.argv[2]) / 1000, sys.argv[3]
first_asked = {}
table = {}
for kv in sys.argv[4:]:
    n, ip = kv.split("=", 1)
    table.setdefault(n.lower().rstrip("."), []).append(ip)
def wire(name):
    return b"".join(bytes([len(l)]) + l.encode() for l in name.rstrip(".").split(".")) + b"\0"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
import os
s.bind((os.environ.get("FAKEDNS_ADDR", "127.0.0.1"), port))
def name_at(m, off):
    labels = []
    while m[off]:
        l = m[off]; labels.append(m[off + 1:off + 1 + l].decode()); off += 1 + l
    return ".".join(labels).lower(), off + 1
def answer(m, peer):
    if delay: time.sleep(delay)
    qid, flags = struct.unpack(">HH", m[:4])
    name, off = name_at(m, 12)
    qtype, qclass = struct.unpack(">HH", m[off:off + 4])
    q = m[12:off + 4]
    vals = table.get(name, [])
    if "SERVFAIL" in vals:
        s.sendto(struct.pack(">HHHHHH", qid, 0x8182, 1, 0, 0, 0) + q, peer); return
    for v in vals:
        if v.startswith("NXFOR:") and time.time() - first_asked.setdefault(name, time.time()) < float(v[6:]):
            s.sendto(struct.pack(">HHHHHH", qid, 0x8183, 1, 0, 0, 0) + q, peer); return
    ad = 0x0020 if "AD" in vals else 0
    if qtype in (12, 15, 16, 52):
        rrs = b""; n = 0
        for v in vals:
            if qtype == 15 and v.startswith("MX:"):
                _, pref, host = v.split(":", 2)
                rd = struct.pack(">H", int(pref)) + wire(host)
            elif qtype == 16 and v.startswith("TXT:"):
                t = v[4:].encode()
                rd = b"".join(bytes([len(t[i:i + 255])]) + t[i:i + 255] for i in range(0, max(len(t), 1), 255))
            elif qtype == 12 and v.startswith("PTR:"):
                rd = wire(v[4:])
            elif qtype == 52 and v.startswith("TLSA:"):
                _, u, sel, mt, hx = v.split(":", 4)
                rd = bytes([int(u), int(sel), int(mt)]) + bytes.fromhex(hx)
            else:
                continue
            rrs += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(rd)) + rd; n += 1
        if name not in table:
            s.sendto(struct.pack(">HHHHHH", qid, 0x8183, 1, 0, 0, 0) + q, peer); return
        s.sendto(struct.pack(">HHHHHH", qid, 0x8180 | ad, 1, n, 0, 0) + q + rrs, peer); return
    ips = [ip for ip in vals if not ip.startswith(("MX:", "TXT:", "TLSA:", "PTR:", "NXFOR:")) and ip not in ("AD", "SERVFAIL")
           and (":" in ip) == (qtype == 28)]
    if mode == "servfail":
        s.sendto(struct.pack(">HHHHHH", qid, 0x8182, 1, 0, 0, 0) + q, peer); return
    if name not in table:
        s.sendto(struct.pack(">HHHHHH", qid, 0x8183, 1, 0, 0, 0) + q, peer); return
    rrs = b""
    for ip in ips:
        rd = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
        rrs += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(rd)) + rd
    fl = 0x8180 | ad | (0x0200 if mode == "truncate" else 0)
    s.sendto(struct.pack(">HHHHHH", qid, fl, 1, len(ips), 0, 0) + q + rrs, peer)
while True:
    m, peer = s.recvfrom(4096)
    if mode == "silent":
        continue
    threading.Thread(target=answer, args=(m, peer), daemon=True).start()
