# A nameserver for a test: lib_fake_dns.py <port> <delay_ms> <mode> name=ip ..., on FAKEDNS_ADDR (127.0.0.1 unless
# given), answering A and AAAA for the names given and NXDOMAIN for the rest.  <mode> is normal, truncate (every
# answer cut short), silent (none) or servfail.  A test points the resolver on the loop at it with SOCKETLEY_RESOLV_CONF
# and `options port:<port>`, which the system's resolver passes over.
import socket, struct, sys, threading, time
port, delay, mode = int(sys.argv[1]), float(sys.argv[2]) / 1000, sys.argv[3]
table = {}
for kv in sys.argv[4:]:
    n, ip = kv.split("=")
    table.setdefault(n.lower().rstrip("."), []).append(ip)
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
    ips = [ip for ip in table.get(name, []) if (":" in ip) == (qtype == 28)]
    if mode == "servfail":
        s.sendto(struct.pack(">HHHHHH", qid, 0x8182, 1, 0, 0, 0) + q, peer); return
    if name not in table:
        s.sendto(struct.pack(">HHHHHH", qid, 0x8183, 1, 0, 0, 0) + q, peer); return
    rrs = b""
    for ip in ips:
        rd = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
        rrs += b"\xc0\x0c" + struct.pack(">HHIH", qtype, 1, 60, len(rd)) + rd
    fl = 0x8180 | (0x0200 if mode == "truncate" else 0)
    s.sendto(struct.pack(">HHHHHH", qid, fl, 1, len(ips), 0, 0) + q + rrs, peer)
while True:
    m, peer = s.recvfrom(4096)
    if mode == "silent":
        continue
    threading.Thread(target=answer, args=(m, peer), daemon=True).start()
