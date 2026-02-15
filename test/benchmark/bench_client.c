/*
 * High-performance benchmark client for Socketley
 * Measures connection rate and message throughput without shell overhead
 *
 * Compile: gcc -O3 -o bench_client bench_client.c -lpthread
 * Usage:   ./bench_client <host> <port> <mode> [options]
 *
 * Modes:
 *   conn <count>                - Connection rate test
 *   msg <count> <size>          - Message throughput (single connection)
 *   concurrent <clients> <msgs> - Concurrent clients test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>

static inline long long get_time_us(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000LL + tv.tv_usec;
}

static int connect_to(const char* host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

/* Connection rate test */
static void test_connection_rate(const char* host, int port, int count)
{
    printf("Connection Rate Test: %d connections to %s:%d\n", count, host, port);

    int success = 0, failed = 0;
    long long total_latency = 0;

    long long start = get_time_us();

    for (int i = 0; i < count; i++)
    {
        long long conn_start = get_time_us();
        int fd = connect_to(host, port);
        long long conn_end = get_time_us();

        if (fd >= 0)
        {
            success++;
            total_latency += (conn_end - conn_start);
            close(fd);
        }
        else
        {
            failed++;
        }

        if ((i + 1) % 1000 == 0)
            printf("  Progress: %d / %d\n", i + 1, count);
    }

    long long end = get_time_us();
    double elapsed_s = (end - start) / 1000000.0;
    double rate = success / elapsed_s;
    double avg_latency_us = success > 0 ? total_latency / (double)success : 0;

    printf("\nResults:\n");
    printf("  Success: %d, Failed: %d\n", success, failed);
    printf("  Time: %.3f seconds\n", elapsed_s);
    printf("  Rate: %.2f conn/sec\n", rate);
    printf("  Avg latency: %.2f us (%.2f ms)\n", avg_latency_us, avg_latency_us / 1000.0);
}

/* Message throughput test (single connection) */
static void test_message_throughput(const char* host, int port, int count, int size)
{
    printf("Message Throughput Test: %d messages, %d bytes each\n", count, size);

    int fd = connect_to(host, port);
    if (fd < 0)
    {
        printf("Failed to connect\n");
        return;
    }

    char* msg = malloc(size + 1);
    memset(msg, 'X', size);
    msg[size] = '\n';

    long long start = get_time_us();

    int success = 0;
    for (int i = 0; i < count; i++)
    {
        ssize_t n = write(fd, msg, size + 1);
        if (n == size + 1)
            success++;
    }

    long long end = get_time_us();
    close(fd);
    free(msg);

    double elapsed_s = (end - start) / 1000000.0;
    double rate = success / elapsed_s;
    double throughput_mb = (success * (size + 1)) / elapsed_s / (1024.0 * 1024.0);

    printf("\nResults:\n");
    printf("  Messages sent: %d\n", success);
    printf("  Time: %.3f seconds\n", elapsed_s);
    printf("  Rate: %.2f msg/sec\n", rate);
    printf("  Throughput: %.2f MB/sec\n", throughput_mb);
}

/* Concurrent clients test */
struct concurrent_args
{
    const char* host;
    int port;
    int msgs_per_client;
    int msg_size;
    int* success_count;
    pthread_mutex_t* mutex;
};

static void* concurrent_worker(void* arg)
{
    struct concurrent_args* args = (struct concurrent_args*)arg;

    int fd = connect_to(args->host, args->port);
    if (fd < 0) return NULL;

    char* msg = malloc(args->msg_size + 1);
    memset(msg, 'Y', args->msg_size);
    msg[args->msg_size] = '\n';

    int local_success = 0;
    for (int i = 0; i < args->msgs_per_client; i++)
    {
        ssize_t n = write(fd, msg, args->msg_size + 1);
        if (n == args->msg_size + 1)
            local_success++;
    }

    close(fd);
    free(msg);

    pthread_mutex_lock(args->mutex);
    *args->success_count += local_success;
    pthread_mutex_unlock(args->mutex);

    return NULL;
}

static void test_concurrent(const char* host, int port, int num_clients, int msgs_per_client)
{
    printf("Concurrent Test: %d clients, %d msgs each\n", num_clients, msgs_per_client);

    pthread_t* threads = malloc(num_clients * sizeof(pthread_t));
    struct concurrent_args* args = malloc(num_clients * sizeof(struct concurrent_args));
    int success_count = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    long long start = get_time_us();

    for (int i = 0; i < num_clients; i++)
    {
        args[i].host = host;
        args[i].port = port;
        args[i].msgs_per_client = msgs_per_client;
        args[i].msg_size = 64;
        args[i].success_count = &success_count;
        args[i].mutex = &mutex;
        pthread_create(&threads[i], NULL, concurrent_worker, &args[i]);
    }

    for (int i = 0; i < num_clients; i++)
        pthread_join(threads[i], NULL);

    long long end = get_time_us();

    double elapsed_s = (end - start) / 1000000.0;
    double rate = success_count / elapsed_s;

    printf("\nResults:\n");
    printf("  Total messages: %d\n", success_count);
    printf("  Time: %.3f seconds\n", elapsed_s);
    printf("  Aggregate rate: %.2f msg/sec\n", rate);

    free(threads);
    free(args);
}

/* Burst connection test - open many connections rapidly */
static void test_burst_connections(const char* host, int port, int count)
{
    printf("Burst Connection Test: %d simultaneous connections\n", count);

    int* fds = malloc(count * sizeof(int));
    int success = 0;

    long long start = get_time_us();

    /* Open all connections */
    for (int i = 0; i < count; i++)
    {
        fds[i] = connect_to(host, port);
        if (fds[i] >= 0)
            success++;
    }

    long long connected = get_time_us();

    /* Close all */
    for (int i = 0; i < count; i++)
    {
        if (fds[i] >= 0)
            close(fds[i]);
    }

    long long end = get_time_us();

    double connect_time = (connected - start) / 1000000.0;
    double rate = success / connect_time;

    printf("\nResults:\n");
    printf("  Connections opened: %d / %d\n", success, count);
    printf("  Connect time: %.3f seconds\n", connect_time);
    printf("  Rate: %.2f conn/sec\n", rate);

    free(fds);
}

int main(int argc, char** argv)
{
    if (argc < 4)
    {
        printf("Usage: %s <host> <port> <mode> [options]\n", argv[0]);
        printf("Modes:\n");
        printf("  conn <count>                - Connection rate test\n");
        printf("  burst <count>               - Burst connection test\n");
        printf("  msg <count> <size>          - Message throughput\n");
        printf("  concurrent <clients> <msgs> - Concurrent clients\n");
        return 1;
    }

    const char* host = argv[1];
    int port = atoi(argv[2]);
    const char* mode = argv[3];

    if (strcmp(mode, "conn") == 0 && argc >= 5)
    {
        test_connection_rate(host, port, atoi(argv[4]));
    }
    else if (strcmp(mode, "burst") == 0 && argc >= 5)
    {
        test_burst_connections(host, port, atoi(argv[4]));
    }
    else if (strcmp(mode, "msg") == 0 && argc >= 6)
    {
        test_message_throughput(host, port, atoi(argv[4]), atoi(argv[5]));
    }
    else if (strcmp(mode, "concurrent") == 0 && argc >= 6)
    {
        test_concurrent(host, port, atoi(argv[4]), atoi(argv[5]));
    }
    else
    {
        printf("Invalid mode or missing arguments\n");
        return 1;
    }

    return 0;
}
