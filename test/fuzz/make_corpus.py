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


# ──────────────────────── server / client op programs ────────────────────────
#
# fuzz_server_ops and fuzz_client_ops take a program, not a message: four bytes
# per operation — opcode, and three argument bytes — run against a real runtime
# on a real io_uring loop, with the lifetime invariants checked after every step.
# So these seeds are programs, and each one is here because it is an *ordering*
# a historical defect needed:
#
#   * a stop with a read still in the ring, then a start in the same breath
#     (the reused request that armed twice, and the duplicated timer chains)
#   * a client that resets mid-response          (the descriptor reissued under
#                                                 a queued splice)
#   * a runtime destroyed while a timer it armed is still counting down
#     (the instance that was never freed)
#   * a disconnect issued from inside the callback that is reading the message
#     (the struct returned to the pool with a write still armed)
#   * an upstream pointed at a dead port, then stopped while backing off
#     (the reconnect timer nothing withdrew)
#
# The three leading bytes of an input are read as configuration *as well as* as
# the first step, so the first operation of every program below is chosen for
# what its bytes also say: bit 7 of byte 0 is UDP mode, bit 7 of byte 1 is the
# tick timer, and byte 2 selects what the callbacks do.
#
# The tables below MUST stay in step with the enums in fuzz_server_ops.cpp and
# fuzz_client_ops.cpp; the targets reduce every byte modulo their table, so a
# mismatch does not corrupt anything, it just makes these seeds mean something
# other than what they say.

_SRV_OPS = [
    "START", "STOP", "DESTROY",
    "PUMP",
    "CONNECT", "SEND", "RECV", "FIN", "ABORT",
    "BROADCAST", "SEND_TO", "DISCONNECT",
    "PIPE", "UNPIPE",
    "GROUP",
    "CONFIG",
    "STATS",
    "UPSTREAM",
]
_SRV = {n: i for i, n in enumerate(_SRV_OPS)}

# Server payload selector.
(P_EMPTY, P_LINE, P_FRAGMENT, P_TWO_LINES, P_CRLF, P_BIG_LINE, P_HUGE,
 P_HTTP_ROOT, P_HTTP_BLOB, P_HTTP_KA, P_HTTP_TRAV, P_HTTP_PART,
 P_WS_UPGRADE, P_WS_TEXT, P_WS_CLOSE, P_WS_FRAG,
 P_RESP_PING, P_AUTH_OK, P_AUTH_BAD) = range(19)

# Server CONFIG knobs: `a % 8`.
(C_MAXCONN, C_IDLE, C_DRAIN, C_RATE, C_MODE, C_CB, C_HTTPCACHE, C_UDP) = range(8)

# Callback behaviours, the value C_CB takes.
(CB_INERT, CB_BROADCAST, CB_ANSWER, CB_DISCONNECT,
 CB_ANSWER_DISCONNECT, CB_ON_DISCONNECT) = range(6)

_CLI_OPS = [
    "START", "STOP", "DESTROY", "PUMP",
    "LISTEN_UP", "LISTEN_DOWN",
    "ACCEPT", "PSEND", "PRECV", "PFIN", "PABORT",
    "SEND", "CONFIG", "STATS",
]
_CLI = {n: i for i, n in enumerate(_CLI_OPS)}

# Client payload selector.
(Q_EMPTY, Q_LINE, Q_FRAGMENT, Q_TWO_LINES, Q_CRLF, Q_BIG_LINE, Q_HUGE,
 Q_BINARY) = range(8)

# Client CONFIG knobs: `a % 5`.
(D_RECONNECT, D_MODE, D_CB, D_RATE, D_IDLE) = range(5)


def sop(name, a=0, b=0, c=0):
    return bytes([_SRV[name], a & 0xFF, b & 0xFF, c & 0xFF])


def cop(name, a=0, b=0, c=0):
    return bytes([_CLI[name], a & 0xFF, b & 0xFF, c & 0xFF])


def server_seeds():
    s = {}

    # ── the plain shapes, so the mutator has somewhere to start ──
    s["accept_line_close"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_LINE), sop("PUMP", 3),
        sop("RECV", 0), sop("ABORT", 0), sop("PUMP", 3), sop("STOP"))

    s["many_clients"] = prog(
        sop("START"),
        sop("CONNECT", 0), sop("CONNECT", 1), sop("CONNECT", 2), sop("CONNECT", 3),
        sop("PUMP", 3),
        sop("SEND", 0, P_LINE), sop("SEND", 1, P_TWO_LINES), sop("SEND", 2, P_FRAGMENT),
        sop("PUMP", 3), sop("BROADCAST", 0, P_LINE), sop("PUMP", 3),
        sop("ABORT", 0), sop("ABORT", 1), sop("PUMP", 3), sop("STOP"))

    # ── the orderings ──

    # A stop with a read still armed, then a start in the same breath.  This is
    # what `restart` does, and it is where the second accept chain and the second
    # idle-sweep chain came from.
    s["stop_start_with_read_armed"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_FRAGMENT),
        sop("STOP"), sop("START"),
        sop("CONNECT", 1), sop("PUMP", 3), sop("STOP"))

    # No pump at all between the stop and the start: every completion the run
    # produced is still in the ring when the next run arms over the top of it.
    s["restart_without_draining"] = prog(
        sop("START"), sop("CONNECT", 0), sop("SEND", 0, P_LINE),
        sop("STOP"), sop("START"), sop("STOP"), sop("START"), sop("STOP"))

    # A client that resets in the middle of a response.  The descriptor is closed
    # with a write still queued, and the next accept is what would take the
    # number.
    s["reset_mid_response"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_LINE), sop("BROADCAST", 0, P_BIG_LINE),
        sop("ABORT", 0), sop("CONNECT", 1), sop("PUMP", 3),
        sop("CONNECT", 2), sop("PUMP", 3), sop("STOP"))

    # The splice path: a non-HTML file goes file → shared pipe → socket, and the
    # client vanishes while it is in flight.
    s["splice_then_reset"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_HTTP_BLOB), sop("PUMP", 1),
        sop("ABORT", 0), sop("PUMP", 3),
        sop("CONNECT", 1), sop("SEND", 1, P_HTTP_BLOB), sop("PUMP", 3), sop("STOP"))

    # Two connections asking for the shared pipe at once: one gets the splice,
    # the other falls back to the malloc-and-read path.
    s["splice_contention"] = prog(
        sop("START"), sop("CONNECT", 0), sop("CONNECT", 1), sop("PUMP", 3),
        sop("SEND", 0, P_HTTP_BLOB), sop("SEND", 1, P_HTTP_BLOB),
        sop("PUMP", 3), sop("RECV", 0), sop("RECV", 1), sop("PUMP", 3), sop("STOP"))

    # The async-file path, and a keep-alive request that reuses the connection.
    s["http_file_keepalive"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_HTTP_KA), sop("PUMP", 3), sop("RECV", 0),
        sop("SEND", 0, P_HTTP_KA), sop("PUMP", 3), sop("RECV", 0),
        sop("SEND", 0, P_HTTP_TRAV), sop("PUMP", 3), sop("STOP"))

    # Half a request line and then nothing, then a reset.
    s["http_partial_then_reset"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_HTTP_PART), sop("PUMP", 3), sop("ABORT", 0),
        sop("PUMP", 3), sop("STOP"))

    # The disconnect is issued from inside the callback that is reading the
    # message — the struct is closed by the handler that is still using it.
    s["disconnect_from_callback"] = prog(
        sop("CONFIG", C_CB, CB_DISCONNECT), sop("START"),
        sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_TWO_LINES), sop("PUMP", 3),
        sop("CONNECT", 1), sop("SEND", 1, P_LINE), sop("PUMP", 3), sop("STOP"))

    # A write queued from the disconnect callback, which is the case close_conn()
    # re-examines what is in flight for.
    s["write_from_disconnect_callback"] = prog(
        sop("CONFIG", C_CB, CB_ON_DISCONNECT), sop("START"),
        sop("CONNECT", 0), sop("CONNECT", 1), sop("PUMP", 3),
        sop("SEND", 0, P_LINE), sop("PUMP", 3),
        sop("ABORT", 0), sop("PUMP", 3), sop("STOP"))

    # WebSocket: upgrade, a frame, a fragment nobody continues, then a reset.
    s["ws_upgrade_frames"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_WS_UPGRADE), sop("PUMP", 3), sop("RECV", 0),
        sop("SEND", 0, P_WS_TEXT), sop("PUMP", 3),
        sop("SEND", 0, P_WS_FRAG), sop("PUMP", 3),
        sop("SEND", 0, P_WS_CLOSE), sop("PUMP", 3), sop("STOP"))

    # Past the 1 MB partial cap with no framing in sight.
    s["huge_partial"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_HUGE), sop("PUMP", 3),
        sop("SEND", 0, P_HUGE), sop("PUMP", 3), sop("STOP"))

    # A FIN that leaves the write side open, with a response still owed.
    s["half_close_with_response_owed"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_LINE), sop("FIN", 0),
        sop("BROADCAST", 0, P_BIG_LINE), sop("PUMP", 3), sop("STOP"))

    # More clients than the limit allows: the accept path closes them itself.
    s["over_max_connections"] = prog(
        sop("CONFIG", C_MAXCONN, 2), sop("START"),
        sop("CONNECT", 0), sop("CONNECT", 1), sop("CONNECT", 2),
        sop("CONNECT", 3), sop("CONNECT", 4), sop("PUMP", 3),
        sop("SEND", 0, P_LINE), sop("PUMP", 3), sop("STOP"))

    # Zero-copy forwarding between two clients, and one of them leaving while it
    # is paired.
    s["pipe_pair_then_abort"] = prog(
        sop("START"), sop("CONNECT", 0), sop("CONNECT", 1), sop("PUMP", 3),
        sop("PIPE", 0, 1), sop("SEND", 0, P_LINE), sop("PUMP", 3),
        sop("ABORT", 1), sop("PUMP", 3), sop("SEND", 0, P_LINE),
        sop("PUMP", 3), sop("STOP"))

    # An upstream pointed at a port nothing listens on: the dial fails and the
    # runtime arms a reconnect timer, which the stop then has to withdraw.
    s["upstream_reconnect_timer"] = prog(
        sop("UPSTREAM"), sop("START"), sop("PUMP", 3),
        sop("STOP"), sop("START"), sop("PUMP", 3), sop("STOP"))

    # Destroyed with everything still in flight.
    s["destroy_mid_traffic"] = prog(
        sop("START"), sop("CONNECT", 0), sop("CONNECT", 1), sop("PUMP", 3),
        sop("SEND", 0, P_BIG_LINE), sop("SEND", 1, P_HTTP_BLOB),
        sop("DESTROY"), sop("START"), sop("CONNECT", 0), sop("PUMP", 3), sop("STOP"))

    # The idle-sweep timer is armed at start and withdrawn at stop; arming it
    # over several runs is what used to give the server a chain per restart.
    s["idle_sweep_across_restarts"] = prog(
        sop("CONFIG", C_IDLE, 1), sop("START"), sop("STOP"),
        sop("START"), sop("STOP"), sop("START"), sop("PUMP", 3), sop("STOP"))

    s["drain_on_stop"] = prog(
        sop("CONFIG", C_DRAIN, 1), sop("START"),
        sop("CONNECT", 0), sop("PUMP", 3), sop("SEND", 0, P_LINE),
        sop("BROADCAST", 0, P_BIG_LINE), sop("STOP"), sop("PUMP", 3))

    s["master_auth"] = prog(
        sop("CONFIG", C_MODE, 3), sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_AUTH_BAD), sop("PUMP", 3),
        sop("SEND", 0, P_AUTH_OK), sop("PUMP", 3),
        sop("BROADCAST", 0, P_LINE), sop("PUMP", 3), sop("STOP"))

    s["groups"] = prog(
        sop("START"), sop("CONNECT", 0), sop("CONNECT", 1), sop("PUMP", 3),
        sop("GROUP", 0, 0, 0), sop("GROUP", 1, 0, 0), sop("GROUP", 0, 0, 2),
        sop("PUMP", 3), sop("ABORT", 0), sop("PUMP", 3), sop("GROUP", 0, 0, 2),
        sop("PUMP", 3), sop("STOP"))

    s["rate_limited"] = prog(
        sop("CONFIG", C_RATE, 1), sop("START"), sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_TWO_LINES), sop("SEND", 0, P_TWO_LINES),
        sop("SEND", 0, P_TWO_LINES), sop("PUMP", 3), sop("STOP"))

    s["stats_while_churning"] = prog(
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3), sop("STATS"),
        sop("ABORT", 0), sop("STATS"), sop("PUMP", 3), sop("STATS"), sop("STOP"))

    # ── UDP: bit 7 of the first byte of the input selects it, so the first step
    #    carries it.  The recvmsg holds its own reference to the socket, so a
    #    stop does not end it, and a restart binds a second socket to the same
    #    port under SO_REUSEPORT. ──
    udp_start = bytes([_SRV["START"] | 0x80, 0, 0, 0])
    s["udp_datagrams"] = prog(
        udp_start, sop("CONNECT", 0), sop("PUMP", 3),
        sop("SEND", 0, P_LINE), sop("PUMP", 3),
        sop("SEND", 0, P_TWO_LINES), sop("PUMP", 3),
        sop("BROADCAST", 0, P_LINE), sop("PUMP", 3), sop("STOP"))
    s["udp_restart"] = prog(
        udp_start, sop("CONNECT", 0), sop("SEND", 0, P_LINE),
        sop("STOP"), sop("START"), sop("SEND", 0, P_LINE),
        sop("PUMP", 3), sop("STOP"))

    # ── the tick timer: bit 7 of the second byte.  It is a self-deleting
    #    io_handler with a timer of its own, and a start makes a new one whether
    #    or not the previous one has died. ──
    tick_start = bytes([_SRV["START"], 0x80, 0, 0])
    s["tick_across_restarts"] = prog(
        tick_start, sop("STOP"), sop("START"), sop("STOP"),
        sop("START"), sop("CONNECT", 0), sop("PUMP", 3), sop("STOP"))

    return s


def client_seeds():
    s = {}

    # ── the plain shapes ──
    s["connect_read_close"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("PSEND", 0, Q_LINE), cop("PUMP", 3),
        cop("SEND", 0, Q_LINE), cop("PUMP", 3), cop("PRECV", 0),
        cop("PABORT", 0), cop("PUMP", 3), cop("STOP"))

    # ── the orderings ──

    # One read request and one write request, reused across reconnects: a stop
    # with either still in the ring, then a start in the same breath.
    s["stop_start_with_read_armed"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("PSEND", 0, Q_FRAGMENT),
        cop("STOP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 1),
        cop("PSEND", 1, Q_LINE), cop("PUMP", 3), cop("STOP"))

    # No pump between them at all.
    s["restart_without_draining"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("STOP"), cop("START"),
        cop("STOP"), cop("START"), cop("STOP"))

    # The peer resets the connection while a write is queued behind a big one.
    s["reset_mid_write"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("SEND", 0, Q_BIG_LINE), cop("SEND", 0, Q_BIG_LINE),
        cop("PABORT", 0), cop("PUMP", 3), cop("SEND", 0, Q_LINE),
        cop("PUMP", 3), cop("STOP"))

    # Nothing is listening, so the dial is refused and a reconnect timer is
    # armed.  That timer hangs off no descriptor: only teardown's withdrawal
    # ends it, and until it reports the instance cannot be freed.
    s["refused_then_stop"] = prog(
        cop("START"), cop("PUMP", 3), cop("STOP"))

    s["refused_then_destroy"] = prog(
        cop("START"), cop("PUMP", 3), cop("DESTROY"),
        cop("START"), cop("PUMP", 3), cop("STOP"))

    # Connected, then the listener goes away and the peer resets: the runtime
    # loses the socket and arms the reconnect timer, and is then destroyed with
    # it still counting down.
    s["lose_connection_then_destroy"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("PSEND", 0, Q_LINE), cop("PUMP", 3),
        cop("LISTEN_DOWN"), cop("PABORT", 0), cop("PUMP", 3),
        cop("DESTROY"), cop("PUMP", 3))

    # A FIN from the peer with the write side still open, and a send after it.
    s["peer_half_close"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("PFIN", 0), cop("SEND", 0, Q_LINE), cop("PUMP", 3),
        cop("SEND", 0, Q_LINE), cop("PUMP", 3), cop("STOP"))

    # Past MAX_PARTIAL_SIZE with no newline in it.
    s["huge_partial"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("PSEND", 0, Q_HUGE), cop("PUMP", 3),
        cop("PSEND", 0, Q_HUGE), cop("PUMP", 3), cop("STOP"))

    # The runtime answers from inside the handler that delivered the message,
    # which arms a write on a socket that handler may be about to lose.
    s["echo_from_callback"] = prog(
        cop("CONFIG", D_CB, 2), cop("LISTEN_UP"), cop("START"), cop("PUMP", 3),
        cop("ACCEPT", 0), cop("PSEND", 0, Q_TWO_LINES), cop("PUMP", 3),
        cop("PABORT", 0), cop("PUMP", 3), cop("STOP"))

    # Sending from the disconnect callback: a send on a socket just lost.
    s["send_from_disconnect_callback"] = prog(
        cop("CONFIG", D_CB, 3), cop("LISTEN_UP"), cop("START"), cop("PUMP", 3),
        cop("ACCEPT", 0), cop("PSEND", 0, Q_LINE), cop("PUMP", 3),
        cop("PABORT", 0), cop("PUMP", 3), cop("STOP"))

    # Reconnect switched off: a dial that fails leaves the instance `failed`,
    # and it has already armed I/O by then.
    s["reconnect_disabled"] = prog(
        cop("CONFIG", D_RECONNECT, 0), cop("START"), cop("PUMP", 3),
        cop("STOP"), cop("START"), cop("PUMP", 3), cop("STOP"))

    # The listener comes and goes underneath a running client.
    s["listener_flapping"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("LISTEN_DOWN"), cop("PABORT", 0), cop("PUMP", 3),
        cop("LISTEN_UP"), cop("PUMP", 3), cop("ACCEPT", 1),
        cop("PSEND", 1, Q_LINE), cop("PUMP", 3), cop("STOP"))

    # Write queue: several sends with nothing draining them.
    s["queue_then_stop"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("SEND", 0, Q_BIG_LINE), cop("SEND", 0, Q_BIG_LINE),
        cop("SEND", 0, Q_BIG_LINE), cop("SEND", 0, Q_BIG_LINE),
        cop("STOP"), cop("PUMP", 3))

    s["send_only_mode"] = prog(
        cop("CONFIG", D_MODE, 2), cop("LISTEN_UP"), cop("START"), cop("PUMP", 3),
        cop("ACCEPT", 0), cop("SEND", 0, Q_LINE), cop("PUMP", 3),
        cop("PSEND", 0, Q_LINE), cop("PUMP", 3), cop("STOP"))

    # `edit --mode` has no "cannot change while running" guard, so a client
    # started send-only can be switched to receiving underneath itself.  Every
    # read this runtime submits comes from a completion, and send-only mode
    # never armed one, so nothing starts it reading.
    s["mode_out_then_in_while_connected"] = prog(
        cop("CONFIG", D_MODE, 2), cop("LISTEN_UP"), cop("START"), cop("PUMP", 3),
        cop("ACCEPT", 0), cop("SEND", 0, Q_LINE), cop("PUMP", 3),
        cop("CONFIG", D_MODE, 1), cop("PUMP", 3),
        cop("PSEND", 0, Q_LINE), cop("PUMP", 3), cop("STOP"))

    s["stats_while_churning"] = prog(
        cop("LISTEN_UP"), cop("START"), cop("PUMP", 3), cop("ACCEPT", 0),
        cop("STATS"), cop("PABORT", 0), cop("STATS"), cop("PUMP", 3),
        cop("STATS"), cop("STOP"))

    # The tick timer: bit 7 of the second byte of the input.
    tick_listen = bytes([_CLI["LISTEN_UP"], 0x80, 0, 0])
    s["tick_across_restarts"] = prog(
        tick_listen, cop("START"), cop("STOP"), cop("START"),
        cop("PUMP", 3), cop("ACCEPT", 0), cop("STOP"))

    return s


# ───────────────────────── event_loop completion programs ────────────────────
#
# fuzz_event_loop does not take a protocol message either.  It reads its input
# as a sequence of completions — six bytes per step: what to do, which owner or
# request, which descriptor, what result, which CQE flags, and one auxiliary
# byte — and feeds them to event_loop::dispatch_cqe(), checking the loop's own
# accounting after every one.  So these seeds are orders of arrival, and each
# one is here because it is the order a historical defect needed:
#
#   * a completion for an owner that deregistered after submitting it
#   * the same, carrying a provided buffer, which the loop has to return itself
#   * a multishot that reports with IORING_CQE_F_MORE and then without it
#   * close_fd() with a read still outstanding, then the read, then the cancel
#     acknowledgement it was waiting for
#   * a timeout withdrawn with IORING_OP_TIMEOUT_REMOVE: two completions, one
#     of which is counted and one of which is not
#   * a fixed-file index released while a submission still names it
#   * a handler that re-arms, closes its own descriptor, or deregisters itself
#     from inside its own on_cqe
#   * a splice, which names two descriptors and used to release only one
#
# The tables below MUST stay in step with the ones in fuzz_event_loop.cpp; the
# target reduces every byte modulo its own table, so a mismatch does not corrupt
# anything, it just makes these seeds mean something other than what they say.

_EL_OPS = [
    "ARM", "ARM_B",
    "CQE", "CQE_B", "CQE_C",
    "CQE_CANCEL", "CQE_NULL", "CQE_SIGNAL",
    "REGISTER", "DEREGISTER",
    "CLOSE_FD", "CANCEL_FD",
    "TIMEOUT_REMOVE", "POLL_REMOVE",
    "ALLOC_FIXED", "FREE_FIXED",
    "RETURN_CQE_BUF", "REUSE_FD", "QUERY",
]
_EL_OP = {name: i for i, name in enumerate(_EL_OPS)}

# submit_* helper selector, in the order of arm_kind in fuzz_event_loop.cpp.
_EL_KINDS = [
    "ACCEPT", "MSHOT_ACCEPT", "MSHOT_ACCEPT_DIRECT",
    "READ", "WRITE", "WRITEV", "RECVMSG", "SENDMSG",
    "TIMEOUT",
    "READ_PROVIDED", "RECV_MULTISHOT",
    "READ_FIXED", "WRITE_FIXED", "MSHOT_FIXED", "PROVIDED_FIXED", "SENDZC_FIXED",
    "SENDZC", "SPLICE", "FILE_READ", "CONNECT", "POLL",
    "READ_FIXED_BUF", "WRITE_FIXED_BUF",
]
_EL_KIND = {name: i for i, name in enumerate(_EL_KINDS)}

# Result selector, in the order of RES_TABLE.
_EL_RES = ["OK", "R1", "R15", "R64", "R4096", "R65535",
           "EAGAIN", "ECANCELED", "ENOBUFS", "ECONNRESET", "EPIPE", "EBADF",
           "EINVAL", "ENOENT", "EINTR", "EMFILE", "ETIME", "EFAULT", "MINUS1", "INTMIN"]
_EL_R = {name: i for i, name in enumerate(_EL_RES)}

# CQE flag bits, as the target decodes them.
EL_MORE, EL_BUF, EL_NONEMPTY, EL_NOTIF = 1, 2, 4, 8

# What the handler does from inside its own on_cqe, in the order of
# handler_action.  NOWNERS is 5, NFDS 6, NFIXED 5, NREQS 12, 8 buffers a group.
_EL_ACTIONS = ["NONE", "REARM", "CLOSE_FD", "DEREGISTER", "QUERY"]
_EL_A = {name: i for i, name in enumerate(_EL_ACTIONS)}
_EL_NACTIONS = len(_EL_ACTIONS)


def el_aux(action="NONE", bid=0):
    """One byte carrying both the handler action (mod 5) and a buffer id (mod 8)."""
    want_a = _EL_A[action]
    for v in range(256):
        if v % _EL_NACTIONS == want_a and v % 8 == (bid % 8):
            return v
    raise ValueError("no aux byte for %s/%d" % (action, bid))


def el_owner(owner):
    """The byte that selects an owner; None means a submission with no owner."""
    return 0 if owner is None else (owner % 5) + 1


def el_step(op, a=0, b=0, c=0, d=0, e=0):
    return bytes([_EL_OP[op], a & 0xFF, b & 0xFF, c & 0xFF, d & 0xFF, e & 0xFF])


def el_arm(req, kind, owner=0, fd=0):
    # `c` picks the owner and doubles as the fixed-slot index; `d` picks the
    # descriptor and doubles as the buffer group.  Same coupling the target has.
    return el_step("ARM", a=req, b=_EL_KIND[kind], c=el_owner(owner), d=fd)


def el_cqe(req, res="OK", flags=0, action="NONE", bid=0):
    return el_step("CQE", a=req, c=_EL_R[res], d=flags, e=el_aux(action, bid))


def eventloop_seeds():
    s = {}

    # ── the plain shapes, so the mutator has somewhere to start ──
    s["read_complete"] = el_arm(0, "READ", owner=0, fd=0) + el_cqe(0, "R64")
    s["read_eof"] = el_arm(0, "READ", owner=0, fd=0) + el_cqe(0, "OK")
    s["short_read"] = el_arm(0, "READ", owner=0, fd=0) + el_cqe(0, "R1")
    s["write_epipe"] = el_arm(1, "WRITE", owner=1, fd=1) + el_cqe(1, "EPIPE")

    # ── a completion for an owner that retired after submitting it ──
    s["stale_owner"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_step("DEREGISTER", a=0)
        + el_cqe(0, "R64")
        + el_step("QUERY"))

    # The same, one slot recycled underneath it: the retired owner's slot goes
    # to a different handler before the completion lands.
    s["stale_owner_slot_recycled"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_step("DEREGISTER", a=0)
        + el_step("REGISTER", a=1)
        + el_step("REGISTER", a=2)
        + el_cqe(0, "R64")
        + el_step("QUERY"))

    # ── the provided-buffer leak: a discarded completion carrying a buffer ──
    s["stale_owner_with_buffer"] = (
        el_arm(0, "READ_PROVIDED", owner=0, fd=0)
        + el_step("DEREGISTER", a=0)
        + el_cqe(0, "R64", flags=EL_BUF, bid=3))
    s["multishot_buffer_stream"] = (
        el_arm(0, "RECV_MULTISHOT", owner=0, fd=1)
        + el_cqe(0, "R64", flags=EL_MORE | EL_BUF, bid=1)
        + el_cqe(0, "R64", flags=EL_MORE | EL_BUF, bid=2)
        + el_step("DEREGISTER", a=0)
        + el_cqe(0, "ENOBUFS", flags=EL_BUF, bid=3))
    s["return_cqe_buf"] = (
        el_arm(0, "READ_PROVIDED", owner=0, fd=0)
        + el_step("RETURN_CQE_BUF", a=0, e=5)
        + el_cqe(0, "R64"))

    # ── multishot that stops without saying so ──
    s["multishot_more_then_final"] = (
        el_arm(2, "RECV_MULTISHOT", owner=1, fd=2)
        + el_cqe(2, "R64", flags=EL_MORE)
        + el_cqe(2, "R64", flags=EL_MORE)
        + el_cqe(2, "ECANCELED"))
    s["multishot_accept_stops"] = (
        el_arm(3, "MSHOT_ACCEPT", owner=0, fd=3)
        + el_cqe(3, "R4096", flags=EL_MORE)
        + el_cqe(3, "EINVAL"))

    # ── close_fd with something still armed, and the cancel it submits ──
    s["close_with_read_armed"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_step("CLOSE_FD", a=0)
        + el_cqe(0, "ECANCELED")
        + el_step("CQE_CANCEL", a=0))
    s["close_from_handler"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_cqe(0, "OK", action="CLOSE_FD"))
    s["close_two_readers"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_arm(1, "WRITE", owner=0, fd=0)
        + el_step("CLOSE_FD", a=0)
        + el_cqe(0, "ECANCELED")
        + el_cqe(1, "ECANCELED")
        + el_step("CQE_CANCEL", a=0))
    s["cancel_then_close"] = (
        el_arm(0, "READ", owner=0, fd=1)
        + el_step("CANCEL_FD", a=1)
        + el_step("CLOSE_FD", a=1)
        + el_cqe(0, "ECANCELED")
        + el_step("CQE_CANCEL", a=1)
        + el_step("CQE_CANCEL", a=1))

    # ── a splice names two descriptors; only one used to be released ──
    s["splice_two_targets"] = (
        el_arm(4, "SPLICE", owner=2, fd=1)
        + el_step("CLOSE_FD", a=1)
        + el_cqe(4, "R4096")
        + el_step("CQE_CANCEL", a=1))

    # ── timeouts and the two completions a withdrawal produces ──
    s["timeout_fires"] = el_arm(5, "TIMEOUT", owner=3) + el_cqe(5, "ETIME")
    s["timeout_removed"] = (
        el_arm(5, "TIMEOUT", owner=3)
        + el_step("TIMEOUT_REMOVE", a=5)
        + el_step("CQE_NULL")                    # the withdrawal's own answer
        + el_cqe(5, "ECANCELED"))                # the timeout's, which is counted
    s["poll_removed"] = (
        el_arm(6, "POLL", owner=3, fd=2)
        + el_step("POLL_REMOVE", a=6)
        + el_step("CQE_NULL")
        + el_cqe(6, "ECANCELED"))

    # ── fixed-file indices, released while a submission still names them ──
    s["fixed_free_while_armed"] = (
        el_step("ALLOC_FIXED", a=0)
        + el_arm(7, "READ_FIXED", owner=0, fd=0)
        + el_step("FREE_FIXED", a=0)
        + el_cqe(7, "ECANCELED"))
    s["fixed_multishot_buffer"] = (
        el_step("ALLOC_FIXED", a=0)
        + el_arm(7, "MSHOT_FIXED", owner=0, fd=1)
        + el_cqe(7, "R64", flags=EL_MORE | EL_BUF, bid=1)
        + el_step("DEREGISTER", a=0)
        + el_cqe(7, "OK", flags=EL_BUF, bid=2)
        + el_step("FREE_FIXED", a=0))

    # ── handlers acting from inside their own on_cqe ──
    s["handler_rearms"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_cqe(0, "R64", action="REARM")
        + el_cqe(0, "OK"))
    s["handler_deregisters"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_arm(1, "WRITE", owner=0, fd=1)
        + el_cqe(0, "OK", action="DEREGISTER")
        + el_cqe(1, "R64"))
    s["handler_queries"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_arm(1, "READ", owner=0, fd=0)
        + el_cqe(0, "R64", action="QUERY")
        + el_cqe(1, "R64", action="QUERY"))

    # ── a descriptor number given away and taken back underneath a submission ──
    s["number_reissued"] = (
        el_arm(0, "READ", owner=0, fd=0)
        + el_step("REUSE_FD", a=0)
        + el_cqe(0, "EBADF"))

    # ── a submission nobody owns, and the stop eventfd ──
    s["no_owner"] = el_arm(0, "READ", owner=None, fd=0) + el_cqe(0, "R64")
    s["stop_signal"] = el_step("CQE_SIGNAL")

    # ── coverage floors ──
    s["all_arm_kinds"] = b"".join(
        el_arm(i % 12, k, owner=i % 5, fd=i % 6) + el_cqe(i % 12, "OK")
        for i, k in enumerate(_EL_KINDS))
    s["all_results"] = b"".join(
        el_arm(0, "READ", owner=0, fd=0) + el_cqe(0, r) for r in _EL_RES)
    s["all_ops"] = b"".join(el_step(name, a=1, b=3, c=1, d=1, e=1) for name in _EL_OPS)
    s["one_step"] = el_step("QUERY")

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
    "eventloop": 24,   # 0 kept
    "server": 8,       # 0 kept
    "client": 8,       # 0 kept
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
                        ("cache", cache_seeds()), ("server", server_seeds()),
                        ("client", client_seeds()),
                        ("eventloop", eventloop_seeds())):
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
