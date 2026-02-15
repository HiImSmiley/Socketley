#pragma once
#include <unistd.h>
#include <utility>

// RAII wrapper for file descriptors
class scoped_fd
{
public:
    scoped_fd() noexcept : m_fd(-1) {}
    explicit scoped_fd(int fd) noexcept : m_fd(fd) {}

    ~scoped_fd() { reset(); }

    scoped_fd(const scoped_fd&) = delete;
    scoped_fd& operator=(const scoped_fd&) = delete;

    scoped_fd(scoped_fd&& other) noexcept : m_fd(other.release()) {}

    scoped_fd& operator=(scoped_fd&& other) noexcept
    {
        if (this != &other)
            reset(other.release());
        return *this;
    }

    int get() const noexcept { return m_fd; }
    explicit operator bool() const noexcept { return m_fd >= 0; }

    int release() noexcept
    {
        int fd = m_fd;
        m_fd = -1;
        return fd;
    }

    void reset(int fd = -1) noexcept
    {
        if (m_fd >= 0)
            ::close(m_fd);
        m_fd = fd;
    }

private:
    int m_fd;
};
