// Sequential Connection: close exchanges that close the moment the body is in,
// which is the client that wins the race against a late FIN.  Prints the number
// of whole bodies on stdout and each connection's local port on stderr, so a
// caller can count TIME-WAIT per 4-tuple.
//   lib_close_race <port> <path> <count> <body-bytes>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    int port = atoi(argv[1]), n = atoi(argv[3]); long want = atol(argv[4]);
    char req[256];
    int rl = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", argv[2]);
    static char buf[1 << 20];
    int whole = 0;
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(0x7f000001);
        if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0 || write(fd, req, rl) != rl) { close(fd); continue; }
        struct sockaddr_in me; socklen_t ml = sizeof me;
        if (getsockname(fd, (struct sockaddr *)&me, &ml) == 0) fprintf(stderr, "%d\n", ntohs(me.sin_port));
        long got = 0, body = -1; size_t hl = 0; char head[4096];
        for (;;) {
            ssize_t r = read(fd, buf, sizeof buf);
            if (r <= 0) break;
            if (body < 0) {
                size_t take = (size_t)r < sizeof head - hl - 1 ? (size_t)r : sizeof head - hl - 1;
                memcpy(head + hl, buf, take); hl += take; head[hl] = 0;
                char *e = strstr(head, "\r\n\r\n");
                if (!e) continue;
                body = (long)hl - (long)(e + 4 - head) + ((long)r - (long)take);
            } else body += r;
            if (body >= want) break;
        }
        got = body;
        close(fd);
        if (got == want) whole++;
    }
    printf("%d\n", whole);
    return 0;
}
