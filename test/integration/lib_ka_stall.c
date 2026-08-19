/* A keep-alive HTTP client that reports STALLS, not just failures.
 *
 * Not a test -- run_all.sh globs test_*.sh.  This is compiled and driven by
 * test_http_keepalive_no_stall.sh.
 *
 * ─── WHY IT IS C AND NOT PYTHON ─────────────────────────────────────────────
 *
 * The defect this looks for is a race between the server reaping a completion
 * and the client sending its next request, and the window is a few
 * microseconds wide.  A Python client loses that race by being slow: measured
 * on the same daemon, same file, same 20x20 shape, interleaved -- the C client
 * below reproduced the stall and a Python client written to the identical
 * protocol reported 400 of 400 answered, twice.  So an instrument written in
 * Python cannot see this, which is one reason nothing in this suite caught it.
 *
 * ─── WHAT IT DISTINGUISHES, AND WHY THAT MATTERS ────────────────────────────
 *
 * The failure is invisible to curl and nc: the server answers, and answers,
 * and then one request gets NO bytes at all -- no response, no FIN, no RST --
 * and the connection sits open until the client gives up.  curl calls that a
 * timeout, nc calls it an empty reply, and both read as flakiness.  So the
 * endings are counted separately, because they have different causes:
 *
 *   stall   the read timed out with nothing delivered for this request, while
 *           the connection was still open.  The server has gone silent.
 *   short   headers arrived, the body did not finish.
 *   fin     the server closed.  A different defect, not this one.
 *
 * Strictly one request at a time: the whole response is read before the next
 * request is written.  That is load-bearing.  Pipelining reaches a different
 * and larger defect in this server -- a pipelined request is parked in
 * conn->partial and never answered on ANY serving path, --http-cache included
 * -- and a client that pipelined would not tell the two apart.
 *
 * usage: lib_ka_stall <port> <burst> <bursts> <tmo_ms> <path> <marker>
 * prints one summary line; exit 0 only if every request was answered.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

int main(int argc, char **argv)
{
    if (argc < 7)
    {
        fprintf(stderr, "usage: %s <port> <burst> <bursts> <tmo_ms> <path> <marker>\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]), burst = atoi(argv[2]), nb = atoi(argv[3]), tmo = atoi(argv[4]);
    const char *path = argv[5], *marker = argv[6];

    char req[512];
    int reqlen = snprintf(req, sizeof req,
        "GET %s HTTP/1.1\r\nHost: t\r\nConnection: keep-alive\r\n\r\n", path);

    size_t cap = 1u << 23;
    char *buf = malloc(cap);
    if (!buf) { fprintf(stderr, "oom\n"); return 2; }

    long ok = 0, stall = 0, shortb = 0, fin = 0, other = 0, badmark = 0, noconn = 0;

    for (int b = 0; b < nb; b++)
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { noconn++; continue; }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        struct timeval tv = { tmo / 1000, (tmo % 1000) * 1000 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&sa, sizeof sa) < 0) { close(fd); noconn++; continue; }

        size_t have = 0;
        int died = 0;
        for (int i = 0; i < burst && !died; i++)
        {
            if (send(fd, req, (size_t)reqlen, 0) != reqlen) { other++; break; }

            /* headers */
            char *he = NULL;
            ssize_t r = 0;
            int se = 0;
            while (!(he = memmem(buf, have, "\r\n\r\n", 4)))
            {
                if (have >= cap) { other++; died = 1; break; }
                r = recv(fd, buf + have, cap - have, 0);
                se = errno;
                if (r <= 0) { died = 1; break; }
                have += (size_t)r;
            }
            if (died)
            {
                if (he == NULL && r == 0)                                   fin++;
                else if (he == NULL && (se == EAGAIN || se == EWOULDBLOCK))
                {
                    /* nothing at all for this request, connection still open:
                     * this is the stall.  `have` is what was left over from the
                     * previous response and must be zero on a framed stream. */
                    if (have == 0) stall++; else shortb++;
                }
                else                                                        other++;
                break;
            }

            size_t hlen = (size_t)(he - buf) + 4;
            if (strncmp(buf, "HTTP/1.1 200", 12) != 0) { other++; break; }
            long clen = -1;
            for (char *p = buf; p < he; p++)
            {
                if (strncasecmp(p, "Content-Length:", 15) == 0)
                { clen = strtol(p + 15, NULL, 10); break; }
                while (p < he && *p != '\n') p++;
            }
            if (clen < 0) { other++; break; }

            /* body */
            while (have < hlen + (size_t)clen)
            {
                if (have >= cap) { other++; died = 1; break; }
                r = recv(fd, buf + have, cap - have, 0);
                if (r <= 0) { shortb++; died = 1; break; }
                have += (size_t)r;
            }
            if (died) break;

            /* the marker must be in the body, or this is not the file: a 404 or
             * an empty 200 is FASTER than serving one and would read as health */
            if (!memmem(buf + hlen, (size_t)clen, marker, strlen(marker))) badmark++;
            ok++;
            memmove(buf, buf + hlen + clen, have - (hlen + clen));
            have -= hlen + clen;
        }
        close(fd);
    }

    long want = (long)burst * nb;
    printf("answered=%ld of %ld stall=%ld short=%ld fin=%ld other=%ld badmark=%ld noconn=%ld\n",
           ok, want, stall, shortb, fin, other, badmark, noconn);
    free(buf);
    return (ok == want && badmark == 0) ? 0 : 1;
}
