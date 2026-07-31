#!/usr/bin/env python3
"""Generate the seed corpus for the fuzz targets.

The seeds are generated rather than committed as blobs so that every one of them
is readable next to the reason it is there.  Regenerating is idempotent: the
same file names with the same contents, so re-running never churns the tree.

Every shape here is taken from traffic the project already produces:

  RESP     test/unit/test_resp_parser.cpp, test/integration/test_cache*.sh,
           test/benchmark/bench_cache_resp.sh
  WS       test/unit/test_ws_parser.cpp, test/load/lib/wsharness.py
  HTTP     test/load/lib/httpharness.py, test/integration/test_proxy_*.sh
  HTTPRESP test/load/lib/backend.py and the responses the proxy integration
           tests' backends return; see the section header further down
  CACHE    test/unit/test_cache_store.cpp — operation sequences rather than
           protocol messages; see the section header further down

plus, for each protocol, the boundary cases that a peer reaches by doing
nothing more clever than stopping mid-message.  A corpus of only valid traffic
teaches a mutator nothing about the error paths, and the error paths are where
this project's defects live.

WHAT ELSE IS TRACKED, AND WHAT IS NOT
-------------------------------------
Two kinds of file live in test/fuzz/corpus/ and no third kind:

  * the seeds this script generates, named "<label>-<digest>"; and
  * "found-<digest>" — a discovery kept because it reaches a coverage edge no
    generated seed reaches, or a crash case somebody reduced by hand.

Everything libFuzzer finds during a run goes to bin/fuzz-corpus/ instead, which
is gitignored and is what CI carries between runs through actions/cache.  It
used not to: run_fuzz.sh passed this directory to libFuzzer, libFuzzer writes
its discoveries into the first corpus directory on its command line, and a few
nights of that left 7158 unreadable files (30 MB) in the repository — 6746 of
them in corpus/cache alone, against 37 seeds.  A corpus in the repository that
nobody can read is not a corpus.

KEPT_BUDGET below is the second half of that fix.  run_fuzz.sh no longer lets
libFuzzer write here at all; this check catches it if some future runner does
anyway, by failing when a set holds more hand-kept files than it is supposed to.

Usage:  python3 test/fuzz/make_corpus.py [output-root]
        (default output root: the directory this script lives in, /corpus)
"""

import hashlib
import os
import struct
import sys

# ─────────────────────────────── RESP ────────────────────────────────────────


def resp_array(*args: bytes) -> bytes:
    out = b"*%d\r\n" % len(args)
    for a in args:
        out += b"$%d\r\n%s\r\n" % (len(a), a)
    return out


def resp_seeds():
    s = {}

    # Valid traffic: exactly what the cache integration tests and the RESP
    # benchmark put on the wire.
    s["set"] = resp_array(b"SET", b"key", b"value")
    s["get"] = resp_array(b"GET", b"key")
    s["del"] = resp_array(b"DEL", b"key")
    s["ping"] = resp_array(b"PING")
    s["incr"] = resp_array(b"INCR", b"counter")
    s["setex"] = resp_array(b"SETEX", b"key", b"60", b"value")
    s["mget"] = resp_array(b"MGET", b"a", b"b", b"c")
    s["subscribe"] = resp_array(b"SUBSCRIBE", b"channel")
    s["publish"] = resp_array(b"PUBLISH", b"channel", b"payload")
    s["hset"] = resp_array(b"HSET", b"hash", b"field", b"value")
    s["pipelined"] = resp_array(b"PING") + resp_array(b"GET", b"key") + resp_array(b"SET", b"k", b"v")

    # The inline (non-RESP) format the parser auto-detects on any first byte
    # that is not '*'.  The load harness in test/load/lib/probe.py speaks this.
    s["inline_set"] = b"set key value\r\n"
    s["inline_get"] = b"get key\r\n"
    s["inline_quoted"] = b'set key "value with spaces"\r\n'
    s["inline_multi"] = b"set a 1\r\nget a\r\ndel a\r\n"

    # Boundaries a peer reaches by stopping early.
    s["trunc_header"] = b"*3\r\n$3\r\nSET\r\n$3\r\nke"
    s["trunc_count"] = b"*3"
    s["trunc_bulk_hdr"] = b"*1\r\n$"
    s["empty"] = b""
    s["cr_only"] = b"\r"
    s["crlf_only"] = b"\r\n"

    # Boundaries a peer reaches on purpose.
    s["neg_count"] = b"*-1\r\n"
    s["zero_count"] = b"*0\r\n"
    s["huge_count"] = b"*999999\r\n$1\r\na\r\n"
    s["count_at_limit"] = b"*1024\r\n" + b"$1\r\na\r\n" * 1024
    s["count_over_limit"] = b"*1025\r\n$1\r\na\r\n"
    s["neg_bulk"] = b"*1\r\n$-1\r\n"
    s["huge_bulk"] = b"*1\r\n$999999999\r\nx\r\n"
    s["bulk_at_limit"] = b"*1\r\n$524288\r\n" + b"x" * 16 + b"\r\n"   # header lies; body short
    s["bulk_lies_short"] = b"*1\r\n$100\r\nshort\r\n"
    s["not_dollar"] = b"*1\r\nX\r\n"          # error in one parser, incomplete in the other
    s["leading_plus"] = b"*+1\r\n$1\r\na\r\n"
    s["space_count"] = b"* 1\r\n$1\r\na\r\n"
    s["nul_in_bulk"] = b"*2\r\n$3\r\nSET\r\n$3\r\na\x00b\r\n"
    s["nine_args"] = resp_array(*[b"a" * 9 for _ in range(9)])   # both fast paths
    s["ten_args"] = resp_array(*[b"a" * 10 for _ in range(10)])  # both slow paths
    s["empty_bulk"] = b"*2\r\n$0\r\n\r\n$0\r\n\r\n"
    s["binary_key"] = b"*3\r\n$3\r\nSET\r\n$4\r\n\xff\xfe\x00\x01\r\n$1\r\nv\r\n"
    s["no_crlf_ever"] = b"*1\r\n$5\r\nhello"
    s["bare_lf"] = b"*1\n$4\nPING\n"

    return s


# ──────────────────────────────── WebSocket ──────────────────────────────────


def ws_frame(opcode=0x1, payload=b"", fin=True, mask=None, force_len=None):
    b0 = (0x80 if fin else 0x00) | (opcode & 0x0F)
    n = len(payload) if force_len is None else force_len
    out = bytearray([b0])
    mb = 0x80 if mask is not None else 0x00
    if n < 126 and force_len is None:
        out.append(mb | n)
    elif n < 65536 and force_len is None:
        out.append(mb | 126)
        out += struct.pack("!H", n)
    else:
        out.append(mb | 127)
        out += struct.pack("!Q", n)
    if mask is not None:
        out += mask
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(out) + payload


def ws_seeds():
    s = {}
    m = b"\x37\xfa\x21\x3d"   # the mask key from test_ws_parser.cpp

    # Valid traffic: what wsharness.py and test_websocket_data.sh send.
    s["text_hello"] = ws_frame(0x1, b"Hello")
    s["text_masked"] = ws_frame(0x1, b"Hello", mask=m)
    s["text_empty"] = ws_frame(0x1, b"")
    s["marker_masked"] = ws_frame(0x1, b"7-42", mask=m)      # harness marker shape
    s["binary"] = ws_frame(0x2, bytes(range(256)))
    s["ping"] = ws_frame(0x9, b"pingdata")
    s["pong"] = ws_frame(0xA, b"pongdata")
    s["close"] = ws_frame(0x8, b"\x03\xe8")
    s["frag_start"] = ws_frame(0x1, b"part one", fin=False)
    s["frag_cont"] = ws_frame(0x0, b"part two", fin=True)
    s["two_frames"] = ws_frame(0x1, b"one", mask=m) + ws_frame(0x1, b"two", mask=m)
    s["len126"] = ws_frame(0x1, b"A" * 200)                  # 16-bit length field
    s["len126_masked"] = ws_frame(0x1, b"A" * 200, mask=m)
    s["len127"] = ws_frame(0x1, b"A" * 70000)                # 64-bit length field

    # Unmask tail coverage: the SIMD paths handle 32/16/8/4 byte blocks and then
    # a byte loop, so lengths either side of each block size matter.
    for n in (1, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65):
        s["unmask_%d" % n] = ws_frame(0x1, bytes((i * 7) & 0xFF for i in range(n)), mask=m)

    # Boundaries a peer reaches by stopping early.
    s["trunc_hdr1"] = b"\x81"
    s["trunc_ext16"] = b"\x81\x7e\x01"
    s["trunc_ext64"] = b"\x81\x7f\x00\x00\x00"
    s["trunc_mask"] = b"\x81\x85\x37\xfa"
    s["trunc_payload"] = ws_frame(0x1, b"Hello", mask=m)[:-2]
    s["empty"] = b""

    # Boundaries a peer reaches on purpose.
    s["len_lies_big"] = ws_frame(0x1, b"short", force_len=65535)
    s["len_over_max"] = b"\x81\x7f" + struct.pack("!Q", 17 * 1024 * 1024)
    s["len_max_u64"] = b"\x81\x7f" + b"\xff" * 8
    s["control_too_big"] = b"\x89\x7e\x01\x00" + b"x" * 256      # ping with 256 bytes
    s["control_fragmented"] = b"\x09\x05hello"                   # ping without FIN
    s["reserved_opcode"] = ws_frame(0x3, b"reserved")
    s["reserved_bits"] = bytes([0xF1, 0x05]) + b"hello"          # RSV1..3 set
    s["mask_zero"] = ws_frame(0x1, b"Hello", mask=b"\x00\x00\x00\x00")

    # The handshake key path: this input is also fed to ws_accept_key, and 92 is
    # the stack/heap boundary in ws_protocol.h.
    s["key_rfc"] = b"dGhlIHNhbXBsZSBub25jZQ=="
    s["key_92"] = b"K" * 92
    s["key_93"] = b"K" * 93
    s["key_200"] = b"K" * 200

    return s


# ─────────────────────────────────── HTTP ────────────────────────────────────


def http_seeds():
    s = {}

    # Valid traffic: httpharness.py drives exactly this, and the proxy
    # integration tests send the same with different prefixes.
    s["get_keepalive"] = (b"GET /pxh/3-17 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                          b"Connection: keep-alive\r\n\r\n")
    s["get_close"] = b"GET /px/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    s["get_bare_prefix"] = b"GET /px HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    s["post_body"] = (b"POST /px/submit HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                      b"Content-Length: 11\r\n\r\nhello world")
    s["ws_upgrade"] = (b"GET /pxw/ HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                       b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       b"Sec-WebSocket-Version: 13\r\n\r\n")
    s["hop_by_hop"] = (b"GET /px/ HTTP/1.1\r\nHost: 127.0.0.1\r\nKeep-Alive: timeout=5\r\n"
                       b"TE: trailers\r\nTrailer: Expires\r\nProxy-Authorization: Basic eA==\r\n"
                       b"Upgrade: h2c\r\nConnection: keep-alive\r\n\r\n")
    s["pipelined"] = (b"GET /px/a HTTP/1.1\r\nHost: h\r\n\r\n"
                      b"GET /px/b HTTP/1.1\r\nHost: h\r\n\r\n")
    s["chunked"] = (b"POST /px/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")

    # A request with NO headers at all.  Every other valid seed above carries at
    # least a Host, and that is exactly why this shape went untested: when the
    # request line is followed straight by the blank line, the first "\r\n" in
    # the buffer IS the start of the first "\r\n\r\n", so the two offsets
    # parse_http_request_line derives from them are equal.  Perfectly legal
    # HTTP/1.1 (and the common shape for HTTP/1.0), 18 bytes, and the smallest
    # input that reaches the header-block arithmetic with a zero-length block.
    s["no_headers"] = b"GET / HTTP/1.1\r\n\r\n"
    s["no_headers_10"] = b"GET / HTTP/1.0\r\n\r\n"

    # Boundaries a peer reaches by stopping early.
    s["line_only"] = b"GET /px/ HTTP/1.1\r\n"
    s["no_terminator"] = b"GET /px/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    s["partial_line"] = b"GET /px"
    s["empty"] = b""
    s["crlf_only"] = b"\r\n\r\n"

    # Request-line shapes.
    s["no_version"] = b"GET /px/\r\n\r\n"
    s["extra_spaces"] = b"GET  /px/  HTTP/1.1\r\nHost: h\r\n\r\n"
    s["space_in_version"] = b"GET /px/ HTTP/1.1 extra\r\nHost: h\r\n\r\n"
    s["no_space"] = b"GET\r\n\r\n"
    s["absolute_uri"] = b"GET http://elsewhere/px/ HTTP/1.1\r\nHost: h\r\n\r\n"
    s["long_path"] = b"GET /px/" + b"a" * 8000 + b" HTTP/1.1\r\nHost: h\r\n\r\n"
    s["nul_in_path"] = b"GET /px/a\x00b HTTP/1.1\r\nHost: h\r\n\r\n"

    # Smuggling shapes — the reason the oracle in fuzz_http_request.cpp exists.
    s["cl_te_crlf"] = (b"POST /px/ HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n"
                       b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    s["cl_te_bare_lf"] = (b"POST /px/ HTTP/1.1\r\nHost: h\r\nContent-Length: 6\n"
                          b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    s["cl_te_lf_first"] = (b"POST /px/ HTTP/1.1\nHost: h\nContent-Length: 6\n"
                           b"Transfer-Encoding: chunked\n\n0\r\n\r\n")
    s["cl_te_case"] = (b"POST /px/ HTTP/1.1\r\nHost: h\r\ncOnTeNt-LeNgTh: 6\r\n"
                       b"TrAnSfEr-EnCoDiNg: chunked\r\n\r\n")
    s["cl_te_spaced"] = (b"POST /px/ HTTP/1.1\r\nHost: h\r\nContent-Length : 6\r\n"
                         b"Transfer-Encoding: chunked\r\n\r\n")
    s["cl_twice"] = (b"POST /px/ HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n"
                     b"Content-Length: 7\r\n\r\n")
    s["te_obfuscated"] = (b"POST /px/ HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n"
                          b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n")
    s["header_no_colon"] = b"GET /px/ HTTP/1.1\r\nHost 127.0.0.1\r\nContent-Length: 5\r\n\r\n"
    s["header_15_chars"] = b"GET /px/ HTTP/1.1\r\nCcccccc-cccccc:\r\n\r\n"
    s["obs_fold"] = (b"POST /px/ HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n"
                     b" Transfer-Encoding: chunked\r\n\r\n")
    s["no_host"] = b"GET /px/ HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
    s["host_twice"] = b"GET /px/ HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"

    return s


# ──────────────────────────── HTTP responses ─────────────────────────────────
#
# fuzz_http_response reads its input as the byte stream a backend sends back,
# and derives the read boundaries itself — so these seeds are whole responses,
# and every one of them gets fed as one read, as two, and a byte at a time.
#
# What the target checks is the pooling decision, so the seeds are chosen for
# what they imply about where the response ends: the shapes a working backend
# produces, the shapes that make the end unknowable, and the ones where a
# lenient backend and this proxy would put it in different places.


def hresp(status, headers, body=b"", eol=b"\r\n"):
    out = b"HTTP/1.1 " + status + eol
    for h in headers:
        out += h + eol
    return out + eol + body


def httpresp_seeds():
    s = {}

    # ── what the proxy integration tests and the load harness actually see ──
    s["ok_body"] = hresp(b"200 OK", [b"Content-Length: 5", b"Content-Type: text/plain"], b"hello")
    s["ok_empty"] = hresp(b"200 OK", [b"Content-Length: 0"])
    s["ok_close"] = hresp(b"200 OK", [b"Content-Length: 2", b"Connection: close"], b"hi")
    s["ok_keepalive"] = hresp(b"200 OK", [b"Content-Length: 2", b"Connection: keep-alive"], b"hi")
    s["no_content"] = hresp(b"204 No Content", [])
    s["not_modified"] = hresp(b"304 Not Modified", [b"ETag: \"x\""])
    s["chunked"] = hresp(b"200 OK", [b"Transfer-Encoding: chunked"], b"5\r\nhello\r\n0\r\n\r\n")
    s["continue_then_ok"] = (hresp(b"100 Continue", []) +
                             hresp(b"200 OK", [b"Content-Length: 2"], b"ok"))
    s["error_502"] = hresp(b"502 Bad Gateway", [b"Content-Length: 11"], b"bad gateway")
    s["big_headers"] = hresp(b"200 OK", [b"X-Pad: " + b"p" * 4000, b"Content-Length: 1"], b"z")

    # ── no boundary at all: HTTP/1.0-style close-delimited ──
    # Nothing says where this ends short of EOF, so the socket is never at a
    # message boundary and must never be pooled.
    s["close_delimited"] = hresp(b"200 OK", [b"Content-Type: text/plain"], b"body with no length")

    # ── the two defects that were found by reading, kept as regressions ──
    # A bare LF between the two framing headers: one line to a CRLF-only
    # splitter (name Content-Length, value "6"), two lines to a backend.
    s["cl_lf_te"] = (b"HTTP/1.1 200 OK\r\nContent-Length: 6\nTransfer-Encoding: chunked\r\n\r\n"
                     b"5\r\nhello\r\n0\r\n\r\n")
    # A header block long enough that a 64 KB read cannot hold it is not what
    # splits one in practice — the backend flushing twice is.  The target
    # supplies that; this seed just makes the block big enough to be worth
    # splitting in several places.
    s["split_bait"] = hresp(b"200 OK",
                            [b"Content-Length: 4", b"X-A: " + b"a" * 200, b"X-B: " + b"b" * 200],
                            b"body")

    # ── Content-Length that two recipients read differently ──
    s["cl_te_chunked"] = hresp(b"200 OK", [b"Content-Length: 6", b"Transfer-Encoding: chunked"],
                               b"0\r\n\r\n")
    s["cl_te_identity"] = hresp(b"200 OK", [b"Content-Length: 4", b"Transfer-Encoding: identity"],
                                b"bodyandmore")
    s["cl_te_gzip"] = hresp(b"200 OK", [b"Content-Length: 4", b"Transfer-Encoding: gzip"],
                            b"bodyandmore")
    s["te_tab_value"] = hresp(b"200 OK", [b"Content-Length: 4", b"Transfer-Encoding:\tchunked"],
                              b"bodyandmore")
    s["cl_twice_same"] = hresp(b"200 OK", [b"Content-Length: 3", b"Content-Length: 3"], b"abc")
    s["cl_twice_diff"] = hresp(b"200 OK", [b"Content-Length: 3", b"Content-Length: 9"], b"abcdefghi")
    s["cl_trailing_junk"] = hresp(b"200 OK", [b"Content-Length: 3x"], b"abcdefghi")
    s["cl_leading_plus"] = hresp(b"200 OK", [b"Content-Length: +3"], b"abc")
    s["cl_hex"] = hresp(b"200 OK", [b"Content-Length: 0x10"], b"abc")
    s["cl_huge"] = hresp(b"200 OK", [b"Content-Length: 99999999999999999999999"], b"abc")
    s["cl_space_before_colon"] = hresp(b"200 OK", [b"Content-Length : 9", b"Content-Length: 3"],
                                       b"abcdefghi")
    s["obs_fold_te"] = (b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Any: v\r\n"
                        b"\tTransfer-Encoding: chunked\r\n\r\nbodyandmore")

    # ── Connection: close the parser can miss ──
    # The value is matched on its first two characters, so a list that does not
    # start with the close token reads as keep-alive.
    s["close_second_in_list"] = hresp(b"200 OK", [b"Content-Length: 2", b"Connection: keep-alive, close"], b"hi")
    s["close_upper"] = hresp(b"200 OK", [b"Content-Length: 2", b"Connection: CLOSE"], b"hi")

    # ── status lines ──
    s["status_no_reason"] = hresp(b"200", [b"Content-Length: 1"], b"x")
    s["status_short_code"] = hresp(b"2 OK", [b"Content-Length: 1"], b"x")
    s["status_no_space"] = b"HTTP/1.1\r\nContent-Length: 1\r\n\r\nx"
    s["status_leading_space"] = b" HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"
    s["status_1xx_only"] = hresp(b"103 Early Hints", [b"Link: </s.css>; rel=preload"])
    s["status_199"] = hresp(b"199 Weird", []) + hresp(b"200 OK", [b"Content-Length: 1"], b"x")

    # ── the 1xx rescan, found by this target on 2026-07-31 ──
    #
    # The scan clears response_bytes_seen when it parses an interim 1xx, so the
    # next read is treated as the head of a response again.  It is not, when the
    # backend flushed the 1xx together with the first lines of the real
    # response: the rest of that header block arrives in the following read and
    # is parsed as a whole response, and everything before the read boundary —
    # here the Transfer-Encoding — is never seen.  The socket is then declared
    # poolable after five body bytes of a chunked stream.
    #
    # The trailing byte is not part of the response.  fuzz_http_response takes
    # one of its read boundaries from the input's last byte (see cut list 2
    # there), and 70 is the offset just past "Transfer-Encoding: chunked\r\n" —
    # so this seed carries the read split that exposes it, rather than relying
    # on the mutator to rediscover it.
    s["interim_1xx_split"] = (b"HTTP/1.1 100 Continue\r\n\r\n"
                              b"HTTP/1.1 200 OK\r\n"
                              b"Transfer-Encoding: chunked\r\n"
                              b"Content-Length: 5\r\n\r\n"
                              b"5\r\nHELLO\r\n0\r\n\r\n"
                              b"\x46")
    # The same defect as the fuzzer first reduced it: with the real status line
    # cut away, a bare CR inside the fragment is never measured by the
    # CRLF-framing check either, because that check ran over the block the 1xx
    # ended and not over this one.
    s["interim_1xx_bare_cr"] = (b"HTTP/1.1 100 Continue\r\n\r\n"
                                b"HTTP/1.1 200 OK\r0Content-Length: 2\r\n\r\nok")

    # ── a second response behind the first: what a pooled socket must not carry ──
    s["pipelined"] = (hresp(b"200 OK", [b"Content-Length: 2"], b"hi") +
                      hresp(b"200 OK", [b"Content-Length: 2"], b"by"))
    s["body_longer_than_cl"] = hresp(b"200 OK", [b"Content-Length: 2"], b"hi-and-then-some")
    s["body_shorter_than_cl"] = hresp(b"200 OK", [b"Content-Length: 20"], b"short")

    # ── boundaries a backend reaches by stopping early or being odd ──
    s["headers_only"] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
    s["no_terminator"] = b"HTTP/1.1 200 OK\r\n"
    s["partial_status"] = b"HTTP/1."
    s["empty"] = b""
    s["crlf_only"] = b"\r\n\r\n"
    s["all_lf"] = b"HTTP/1.1 200 OK\nContent-Length: 2\n\nhi"
    s["bare_cr"] = b"HTTP/1.1 200 OK\rContent-Length: 2\r\n\r\nhi"
    s["header_no_colon"] = hresp(b"200 OK", [b"Content-Length: 2", b"GARBAGE"], b"hi")
    s["nul_in_header"] = hresp(b"200 OK", [b"Content-Length: 2", b"X-N: a\x00b"], b"hi")

    return s


# ───────────────────────────── cache_store programs ──────────────────────────
#
# fuzz_cache_ops does not take a protocol message.  It reads its input as a
# program: four bytes per operation — opcode, key, and two argument bytes — and
# runs it against a real cache_store, checking the store's invariants after
# every step.  So these seeds are programs, and each one is here because it is a
# shape a historical defect needed:
#
#   * a drained collection followed by a rewrite      (the orphaned LRU node)
#   * a limit switched on over data that already exists (the empty LRU)
#   * a write big enough to evict the key it is writing (self-eviction)
#   * keys and values either side of the 15-byte small-string limit
#     (the accounting that read 11x low)
#   * a refused write on a key that carries a TTL
#
# The tables below MUST stay in step with the ones in fuzz_cache_ops.cpp; the
# target reduces every byte modulo its table, so a mismatch does not corrupt
# anything, it just makes these seeds mean something other than what they say.

_OPS = [
    "SET", "SETNX", "GETSET", "APPEND", "INCR",
    "GET", "GETPTR", "EXPGET",
    "DEL",
    "EXPIRE", "PEXPIRE", "PERSIST", "TTL",
    "LPUSH", "RPUSH", "LPOP", "RPOP", "LINDEX",
    "SADD", "SREM", "SISMEMBER",
    "HSET", "HGET", "HDEL",
    "MAXMEM", "EVICTION", "SWEEP", "SAVELOAD", "SCAN", "KEYS",
]
_OP = {name: i for i, name in enumerate(_OPS)}

# Key table index -> the key's length, for readability at the call sites below.
K_EMPTY, K1, K2, K7, K14, K15, K16, K17, K26, K31, K32, K63 = range(12)

# Value-length selector: [0, 1, 5, 15, 16, 17, 32, 64, 100, 192]
V0, V1, V5, V15, V16, V17, V32, V64, V100, V192 = range(10)

# Member/field selector, 8 entries.
M0, M1, M2, M3, M4, M5, M6, M7 = range(8)

# Memory-limit selector: [0, 400, 800, 1600, 4000, 10000, 40000, 200000]
L_NONE, L400, L800, L1600, L4000, L10000, L40000, L200000 = range(8)

# Eviction selector: a % 3
E_NONE, E_LRU, E_RANDOM = 0, 1, 2

# TTL selector: the low bit of `a` picks "already elapsed" over "an hour out".
T_LONG, T_ELAPSED = 0, 1


def op(name, key=0, a=0, b=0):
    return bytes([_OP[name], key & 0xFF, a & 0xFF, b & 0xFF])


def prog(*steps):
    return b"".join(steps)


def cache_seeds():
    s = {}

    # ── the plain shapes, so the mutator has somewhere to start ──
    s["set_get"] = prog(op("SET", K7, V5, 4), op("GET", K7), op("DEL", K7))
    s["set_get_del_all_types"] = prog(
        op("SET", K7, V5, 4), op("RPUSH", K14, V5, 4), op("SADD", K15, M1),
        op("HSET", K16, M1, V5), op("KEYS"), op("SCAN"),
        op("DEL", K7), op("DEL", K14), op("DEL", K15), op("DEL", K16),
    )
    s["type_conflicts"] = prog(
        op("SET", K7, V5, 4), op("RPUSH", K7, V5, 4), op("SADD", K7, M1),
        op("HSET", K7, M1, V5), op("APPEND", K7, V5, 4), op("INCR", K7, 1),
    )

    # ── the small-string boundary the accounting turns on ──
    # 15 bytes live inside the string object; 16 buy a heap block, and the key
    # exists three times over once an LRU is running.
    s["sso_boundary"] = prog(
        op("MAXMEM", a=L40000), op("EVICTION", a=E_LRU),
        op("SET", K15, V15, 4), op("SET", K16, V16, 4),
        op("SET", K17, V17, 4), op("SET", K26, V100, 4),
        op("SET", K63, V192, 4), op("SET", K_EMPTY, V0, 4),
        op("GETPTR", K15), op("GETPTR", K16), op("GETPTR", K63),
        op("DEL", K15), op("DEL", K16), op("DEL", K17),
        op("DEL", K26), op("DEL", K63), op("DEL", K_EMPTY),
    )

    # ── the orphaned-LRU-node shape, straight out of the unit test ──
    # Draining a list deletes the key; the key then comes back.  If the drain
    # leaves its m_lru_order node behind, eviction walks the stale one.
    s["drain_then_rewrite"] = prog(
        op("MAXMEM", a=L800), op("EVICTION", a=E_LRU),
        op("RPUSH", K1, V1, 4), op("LPOP", K1),
        op("SET", K1, V64, 4), op("SET", K2, V64, 4),
        op("GETPTR", K1),
        op("SET", K7, V64, 4),
    )
    s["drain_set_and_hash"] = prog(
        op("MAXMEM", a=L800), op("EVICTION", a=E_LRU),
        op("SADD", K1, M0), op("SREM", K1, M0),
        op("HSET", K2, M0, V1), op("HDEL", K2, M0),
        op("SET", K1, V64, 4), op("SET", K2, V64, 4), op("SET", K7, V64, 4),
    )

    # ── a limit switched on over data that is already resident ──
    # touch_lru does nothing while there is no limit, so these keys are absent
    # from the eviction order until rebuild_lru puts them there.
    s["limit_enabled_late"] = prog(
        op("SET", K16, V100, 4), op("SET", K17, V100, 4), op("SET", K26, V100, 4),
        op("MAXMEM", a=L1600), op("EVICTION", a=E_LRU),
        op("SET", K31, V100, 4), op("SET", K32, V100, 4),
    )
    s["limit_toggled_off_and_on"] = prog(
        op("MAXMEM", a=L10000), op("EVICTION", a=E_LRU),
        op("SET", K16, V100, 4),
        op("MAXMEM", a=L_NONE), op("SET", K17, V100, 4),
        op("MAXMEM", a=L1600), op("SET", K26, V100, 4),
    )
    s["limit_lowered_under_data"] = prog(
        op("MAXMEM", a=L40000), op("EVICTION", a=E_LRU),
        op("SET", K16, V192, 4), op("SET", K17, V192, 4), op("SET", K26, V192, 4),
        op("MAXMEM", a=L400),
        op("SET", K31, V1, 4),
    )

    # ── eviction pressure ──
    s["evict_lru_pressure"] = prog(
        op("MAXMEM", a=L800), op("EVICTION", a=E_LRU),
        *[op("SET", k, V100, 4) for k in (K1, K2, K7, K14, K15, K16, K17)],
    )
    s["evict_random_pressure"] = prog(
        op("MAXMEM", a=L800), op("EVICTION", a=E_RANDOM),
        *[op("SET", k, V100, 4) for k in (K1, K2, K7, K14, K15, K16, K17)],
    )
    s["evict_none_refuses"] = prog(
        op("MAXMEM", a=L400), op("EVICTION", a=E_NONE),
        op("SET", K16, V192, 4), op("SET", K17, V192, 4),
        op("APPEND", K16, V192, 4), op("SADD", K26, M6), op("HSET", K31, M6, V192),
    )

    # ── a write large enough to evict the key it is writing ──
    # The limit is 400 on purpose: one 100-byte value under a 7-byte key costs
    # 332 of it, so the *second* write to that same key has to make room and the
    # only candidate is the key being written.
    s["self_evict_append"] = prog(
        op("MAXMEM", a=L400), op("EVICTION", a=E_LRU),
        op("SET", K7, V100, 4), op("EXPIRE", K7, T_LONG),
        op("APPEND", K7, V100, 5),
    )
    s["self_evict_set"] = prog(
        op("MAXMEM", a=L400), op("EVICTION", a=E_LRU),
        op("SET", K7, V100, 4), op("SET", K7, V192, 5), op("GET", K7),
    )
    s["self_evict_sadd"] = prog(
        op("MAXMEM", a=L400), op("EVICTION", a=E_LRU),
        op("SADD", K7, M2), op("SADD", K7, M6),
    )
    s["self_evict_rpush"] = prog(
        op("MAXMEM", a=L400), op("EVICTION", a=E_LRU),
        op("RPUSH", K7, V100, 4), op("RPUSH", K7, V192, 5),
    )
    s["self_evict_lpush"] = prog(
        op("MAXMEM", a=L400), op("EVICTION", a=E_LRU),
        op("LPUSH", K7, V100, 4), op("LPUSH", K7, V192, 5),
    )
    s["self_evict_hset"] = prog(
        op("MAXMEM", a=L400), op("EVICTION", a=E_LRU),
        op("HSET", K7, M2, V100), op("HSET", K7, M6, V192),
    )

    # ── a refused write on a key that carries a TTL ──
    s["refused_write_with_ttl"] = prog(
        op("HSET", K7, M0, V5), op("EXPIRE", K7, T_LONG),
        op("SET", K7, V5, 4), op("TTL", K7),
        op("MAXMEM", a=L400), op("EVICTION", a=E_NONE),
        op("SET", K16, V64, 4), op("EXPIRE", K16, T_LONG),
        op("SET", K16, V192, 4), op("TTL", K16),
    )

    # ── TTLs ──
    s["ttl_long_then_persist"] = prog(
        op("SET", K7, V5, 4), op("EXPIRE", K7, T_LONG), op("TTL", K7),
        op("PERSIST", K7), op("TTL", K7), op("PEXPIRE", K7, T_LONG), op("TTL", K7),
    )
    s["ttl_elapsed_then_sweep"] = prog(
        op("SET", K7, V5, 4), op("RPUSH", K14, V5, 4),
        op("SADD", K15, M1), op("HSET", K16, M1, V5),
        op("EXPIRE", K7, T_ELAPSED), op("EXPIRE", K14, T_ELAPSED),
        op("EXPIRE", K15, T_ELAPSED), op("EXPIRE", K16, T_ELAPSED),
        op("SWEEP"),
    )
    s["ttl_elapsed_then_read"] = prog(
        op("SET", K7, V5, 4), op("EXPIRE", K7, T_ELAPSED),
        op("GET", K7), op("EXPGET", K7), op("GET", K7),
    )
    s["ttl_overwritten_by_set"] = prog(
        op("SET", K7, V5, 4), op("EXPIRE", K7, T_LONG),
        op("SET", K7, V5, 5), op("TTL", K7),
    )

    # ── save / load ──
    s["saveload_empty"] = prog(op("SAVELOAD"))
    s["saveload_all_types"] = prog(
        op("SET", K7, V17, 4), op("RPUSH", K14, V17, 4), op("RPUSH", K14, V32, 5),
        op("SADD", K15, M2), op("SADD", K15, M3),
        op("HSET", K16, M2, V17), op("HSET", K16, M3, V32),
        op("EXPIRE", K7, T_LONG),
        op("SAVELOAD"),
    )
    s["saveload_under_limit"] = prog(
        op("MAXMEM", a=L10000), op("EVICTION", a=E_LRU),
        op("SET", K26, V100, 4), op("SET", K31, V100, 4), op("RPUSH", K32, V100, 4),
        op("SAVELOAD"),
    )

    # ── counters and string extras ──
    s["incr_roundtrip"] = prog(
        op("INCR", K7, 1), op("INCR", K7, 1), op("INCR", K7, 0xFF),   # +1 +1 -1
        op("SET", K7, V5, 3), op("INCR", K7, 5),                       # "99999" + 5
        op("SET", K7, V5, 4), op("INCR", K7, 5),                       # "VVVVV" is not a number
    )
    s["append_growth"] = prog(*([op("SET", K7, V1, 4)] + [op("APPEND", K7, V100, 5)] * 6))
    s["getset_setnx"] = prog(
        op("SETNX", K7, V5, 4), op("SETNX", K7, V5, 5),
        op("GETSET", K7, V17, 5), op("GETSET", K16, V17, 5),
    )

    # ── list and set edges ──
    s["list_both_ends"] = prog(
        op("RPUSH", K7, V5, 4), op("LPUSH", K7, V5, 5), op("RPUSH", K7, V5, 6),
        op("LINDEX", K7, 0), op("LINDEX", K7, 0xFF), op("LINDEX", K7, 100),
        op("RPOP", K7), op("LPOP", K7), op("LPOP", K7), op("LPOP", K7),
    )
    s["set_membership"] = prog(
        op("SADD", K7, M0), op("SADD", K7, M0), op("SISMEMBER", K7, M0),
        op("SREM", K7, M0), op("SISMEMBER", K7, M0), op("SREM", K7, M0),
    )
    s["hash_fields"] = prog(
        op("HSET", K7, M0, V5), op("HSET", K7, M0, V192), op("HGET", K7, M0),
        op("HDEL", K7, M0), op("HGET", K7, M0), op("HDEL", K7, M0),
    )

    # ── the empty key, which nothing else in the tree exercises ──
    s["empty_key"] = prog(
        op("SET", K_EMPTY, V5, 4), op("GET", K_EMPTY), op("EXPIRE", K_EMPTY, T_LONG),
        op("APPEND", K_EMPTY, V5, 5), op("TTL", K_EMPTY), op("DEL", K_EMPTY),
    )

    # ── degenerate inputs ──
    s["empty"] = b""
    s["short"] = b"\x00\x00\x00"          # under one whole operation
    s["one_op"] = op("SCAN")
    s["all_opcodes"] = prog(*[op(name, K7, 1, 1) for name in _OPS])

    return s


# ─────────────────────────────────── driver ──────────────────────────────────


# How many files a set may hold that this script did not generate.  These are
# the curated discoveries described above, plus headroom for a reduced crash
# case.  The numbers are deliberately specific: a set that has grown past its
# budget has had a fuzz run write into it, and that is the failure this catches.
KEPT_BUDGET = {
    "resp": 32,        # 22 kept: coverage edges the 40 generated seeds miss
    "ws": 8,           # 0 kept
    "http": 8,         # 0 kept
    "httpresp": 8,     # 0 kept
    "cache": 260,      # 240 kept: cache_store has far more reachable state than
                       # 37 hand-written programs can lay out
}


def write_set(root, name, seeds):
    d = os.path.join(root, name)
    os.makedirs(d, exist_ok=True)
    existing = {f for f in os.listdir(d)}
    written = 0
    for label, blob in sorted(seeds.items()):
        # The digest in the name keeps a changed seed from silently overwriting
        # a corpus entry that a past failure was reduced to.
        fn = "%s-%s" % (label, hashlib.sha1(blob).hexdigest()[:8])
        path = os.path.join(d, fn)
        existing.discard(fn)
        if os.path.exists(path):
            with open(path, "rb") as f:
                if f.read() == blob:
                    continue
        with open(path, "wb") as f:
            f.write(blob)
        written += 1
    return d, len(seeds), written, sorted(existing)


def main(argv):
    root = argv[1] if len(argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")
    total = 0
    over = 0
    for name, seeds in (("resp", resp_seeds()), ("ws", ws_seeds()),
                        ("http", http_seeds()), ("httpresp", httpresp_seeds()),
                        ("cache", cache_seeds())):
        d, count, written, stale = write_set(root, name, seeds)
        total += count
        print("%-8s %3d seeds -> %s (%d new/changed)" % (name, count, d, written))
        if stale:
            # Not deleted: a file here is a curated discovery or a reduced crash
            # case someone added by hand, and silently removing those is how a
            # regression corpus rots.  Named so it is a decision rather than an
            # accident.
            print("         %d kept file(s) this script did not generate: %s"
                  % (len(stale), ", ".join(stale[:8])))
        budget = KEPT_BUDGET.get(name, 8)
        if len(stale) > budget:
            print("ERROR: corpus/%s holds %d files this script did not generate, "
                  "budget is %d.\n"
                  "       A fuzz run has written its discoveries into the tracked "
                  "corpus.  They belong in bin/fuzz-corpus/ — check that "
                  "run_fuzz.sh still passes the work directory first.\n"
                  "       If they really are wanted, keep the ones that reach a "
                  "new coverage edge (see the header of this file) and raise the "
                  "budget deliberately."
                  % (name, len(stale), budget), file=sys.stderr)
            over += 1
    if over:
        return 2
    if total == 0:
        print("ERROR: generated no seeds at all", file=sys.stderr)
        return 2
    print("total %d seeds" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
