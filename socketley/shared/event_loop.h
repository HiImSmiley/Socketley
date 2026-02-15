#pragma once
#include <atomic>
#include <cstdint>
#include <unordered_map>
#include <liburing.h>
#include <netinet/in.h>

#include "event_loop_definitions.h"

struct buf_ring_pool
{
    struct io_uring_buf_ring* ring{nullptr};
    char* base{nullptr};
    uint32_t buf_count{0};
    uint32_t buf_size{0};
};

class event_loop
{
public:
    explicit event_loop(uint32_t queue_depth = 2048);
    ~event_loop();

    bool init();
    void run();
    void request_stop();
    int get_signal_write_fd() const;

    // Batched submissions - these queue SQEs without submitting
    void submit_accept(int listen_fd, struct sockaddr_in* addr, socklen_t* addrlen, io_request* req);
    void submit_multishot_accept(int listen_fd, io_request* req);
    void submit_read(int fd, char* buf, uint32_t len, io_request* req);
    void submit_write(int fd, const char* buf, uint32_t len, io_request* req);
    void submit_writev(int fd, struct iovec* iovs, uint32_t count, io_request* req);
    void submit_recvmsg(int fd, struct msghdr* msg, io_request* req);

    // Provided buffer ring API
    bool setup_buf_ring(uint16_t group_id, uint32_t buf_count, uint32_t buf_size);
    void submit_read_provided(int fd, uint16_t group_id, io_request* req);
    char* get_buf_ptr(uint16_t group_id, uint16_t buf_id);
    void return_buf(uint16_t group_id, uint16_t buf_id);
    bool has_buf_ring(uint16_t group_id) const;

    // Flush all pending submissions (single syscall)
    void flush();

    struct io_uring* get_ring();

    // Check if multishot accept is supported
    static bool supports_multishot_accept();

private:
    void setup_signal_pipe();
    void process_cqes();

    struct io_uring m_ring{};
    std::atomic<bool> m_running;
    uint32_t m_queue_depth;
    uint32_t m_pending_submissions{0};
    int m_signal_pipe[2]{-1, -1};
    io_request m_signal_req{};
    char m_signal_buf{};
    bool m_multishot_supported{false};
    bool m_sqpoll_enabled{false};
    std::unordered_map<uint16_t, buf_ring_pool> m_buf_rings;
};
