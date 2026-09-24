// A websocket client that upgrades, sends a masked Close(1000), reads the Close
// back and closes at once, n times in sequence: the client that wins the race
// against a server FIN sent a turn late.  Prints the Close frames received on
// stdout and each connection's local port on stderr.
//   lib_ws_close_race <port> <count>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv)
{
    int port = atoi(argv[1]), n = atoi(argv[2]), got = 0;
    const char *up = "GET / HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                     "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
    unsigned char cl[8] = {0x88, 0x82, 1, 2, 3, 4, 0x03 ^ 1, 0xe8 ^ 2};
    char buf[4096];
    for (int i = 0; i < n; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in a = {0};
        a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(0x7f000001);
        if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); continue; }
        struct sockaddr_in me; socklen_t ml = sizeof me;
        if (getsockname(fd, (struct sockaddr *)&me, &ml) == 0) fprintf(stderr, "%d\n", ntohs(me.sin_port));
        if (write(fd, up, strlen(up)) < 0) { close(fd); continue; }
        size_t hl = 0; buf[0] = 0;
        while (!strstr(buf, "\r\n\r\n")) { ssize_t r = read(fd, buf + hl, sizeof buf - 1 - hl); if (r <= 0) break; hl += r; buf[hl] = 0; }
        if (write(fd, cl, sizeof cl) < 0) { close(fd); continue; }
        ssize_t r = read(fd, buf, sizeof buf);
        if (r >= 2 && (unsigned char)buf[0] == 0x88) got++;
        close(fd);
    }
    printf("%d\n", got);
    return 0;
}
