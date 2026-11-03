// lib_ka_get_load <port> <connections> <seconds> <path>: one GET outstanding on each keep-alive connection, the next
// sent as its answer arrives, for the given time; prints how many answers each status had, "200:n", and how many
// connections the other side closed, "closed:m".
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

enum { MAXC = 1024, BUF = 65536 };

struct conn
{
    int fd;
    size_t have;
    char buf[BUF];
};

static long counts[600];
static char req[512];
static int req_len;

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static int send_get(struct conn* c)
{
    for (int off = 0; off < req_len;)
    {
        const ssize_t n = write(c->fd, req + off, req_len - off);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += n;
    }
    return 0;
}

// Takes every whole answer at the front of the buffer, counting its status and sending the next request for each.
static int drain(struct conn* c)
{
    for (;;)
    {
        c->buf[c->have] = 0;
        char* end = strstr(c->buf, "\r\n\r\n");
        if (!end)
            return 0;
        const char* cl = strcasestr(c->buf, "\r\ncontent-length:");
        const long len = (cl && cl < end) ? strtol(cl + 17, NULL, 10) : 0;
        const size_t whole = (size_t)(end + 4 - c->buf) + (size_t)len;
        if (c->have < whole)
            return 0;
        const int status = atoi(c->buf + 9);
        if (status > 0 && status < 600)
            counts[status]++;
        memmove(c->buf, c->buf + whole, c->have - whole);
        c->have -= whole;
        if (send_get(c) < 0)
            return -1;
    }
}

int main(int argc, char** argv)
{
    if (argc != 5)
        return 2;
    const int port = atoi(argv[1]), n = atoi(argv[2]);
    const double secs = atof(argv[3]);
    req_len = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: t\r\nConnection: keep-alive\r\n\r\n", argv[4]);
    if (n < 1 || n > MAXC || req_len <= 0 || req_len >= (int)sizeof req)
        return 2;
    static struct conn cs[MAXC];
    const int ep = epoll_create1(0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    for (int i = 0; i < n; ++i)
    {
        cs[i].fd = socket(AF_INET, SOCK_STREAM, 0);
        const int one = 1;
        setsockopt(cs[i].fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        if (connect(cs[i].fd, (struct sockaddr*)&a, sizeof a) < 0 || send_get(&cs[i]) < 0)
        {
            perror("connect");
            return 1;
        }
        struct epoll_event ev = {.events = EPOLLIN, .data.ptr = &cs[i]};
        epoll_ctl(ep, EPOLL_CTL_ADD, cs[i].fd, &ev);
    }
    const double end = now() + secs;
    static struct epoll_event evs[MAXC];
    long closed = 0;
    while (now() < end)
    {
        const int k = epoll_wait(ep, evs, MAXC, 200);
        for (int j = 0; j < k; ++j)
        {
            struct conn* c = evs[j].data.ptr;
            const ssize_t r = read(c->fd, c->buf + c->have, BUF - 1 - c->have);
            if (r > 0)
                c->have += (size_t)r;
            if (r <= 0 || drain(c) < 0)
            {
                closed++;
                epoll_ctl(ep, EPOLL_CTL_DEL, c->fd, NULL);
                close(c->fd);
            }
        }
    }
    for (int s = 0; s < 600; ++s)
        if (counts[s])
            printf("%d:%ld ", s, counts[s]);
    printf("closed:%ld\n", closed);
    return 0;
}
