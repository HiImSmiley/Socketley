// Load shapes for measuring what a proxy holds, driven by a test that samples
// the worker's RSS while this runs; every client write gives up after 10 s.
// lib_hold_load up   <port> <conns> <bytes> : each conn sends <bytes> as fast as it can, never reads, holds 4 s
// lib_hold_load mix  <port> <conns> <bytes> : twenty 64-byte writes 5 ms apart first, then the same
// lib_hold_load down <port> <conns>         : each conn connects and never reads, holds 4 s
// lib_hold_load sink <port>                 : accept and never read (backend for `up`)
// lib_hold_load src  <port> <bytes>         : accept and send <bytes> per conn (backend for `down`)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
static int port; static long bytes;
static int dial(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(0x7f000001);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    struct timeval tv = {10, 0}; setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}
static void *up(void *x) {
    (void)x; int fd = dial(); if (fd < 0) return 0;
    static char b[65536]; long left = bytes;
    while (left > 0) { ssize_t w = write(fd, b, left < (long)sizeof b ? left : (long)sizeof b); if (w <= 0) break; left -= w; }
    sleep(4); close(fd); return 0;
}
static long outcome[4096]; static int errs[4096];
static void *mix(void *x) {
    long idx = (long)x; int fd = dial(); if (fd < 0) return 0;
    char small[64] = {0};
    for (int i = 0; i < 20; i++) { if (write(fd, small, sizeof small) <= 0) break; usleep(5000); }
    static char b[65536]; long left = bytes;
    while (left > 0) { ssize_t w = write(fd, b, left < (long)sizeof b ? left : (long)sizeof b); if (w <= 0) { errs[idx] = 1; break; } left -= w; }
    outcome[idx] = bytes - left;
    sleep(4); close(fd); return 0;
}
static void *down(void *x) { (void)x; int fd = dial(); if (fd < 0) return 0; sleep(4); close(fd); return 0; }
static void *src_one(void *x) {
    int fd = (int)(long)x; static char b[65536]; long left = bytes;
    while (left > 0) { ssize_t w = write(fd, b, left < (long)sizeof b ? left : (long)sizeof b); if (w <= 0) break; left -= w; }
    sleep(30); close(fd); return 0;
}
static int listen_on(int p) {
    int s = socket(AF_INET, SOCK_STREAM, 0), one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_port = htons(p); a.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 4096) < 0) { perror("listen"); exit(1); }
    return s;
}
int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    port = atoi(argv[2]);
    if (!strcmp(argv[1], "sink")) { int s = listen_on(port); for (;;) { if (accept(s, 0, 0) < 0) break; } return 0; }
    if (!strcmp(argv[1], "src")) { bytes = atol(argv[3]); int s = listen_on(port); for (;;) { int c = accept(s, 0, 0); if (c < 0) break; pthread_t t; pthread_create(&t, 0, src_one, (void *)(long)c); pthread_detach(t); } return 0; }
    int n = atoi(argv[3]); if (argc > 4) bytes = atol(argv[4]);
    pthread_t *t = malloc(sizeof(pthread_t) * n);
    for (int i = 0; i < n; i++) pthread_create(&t[i], 0, !strcmp(argv[1], "up") ? up : !strcmp(argv[1], "mix") ? mix : down, (void *)(long)i);
    for (int i = 0; i < n; i++) pthread_join(t[i], 0);
    if (!strcmp(argv[1], "mix")) { int full = 0, err = 0; for (int i = 0; i < n; i++) { full += outcome[i] == bytes; err += errs[i]; } fprintf(stderr, "mix: %d of %d wrote everything, %d saw an error\n", full, n, err); }
    return 0;
}
