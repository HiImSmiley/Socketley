#pragma once

// A file a runtime appends lines to: opened on the first line rather than at
// start, appended to rather than truncated, and with its failure latched so an
// unwritable path is one complaint and not one per line through the runtime.
//
// Written once because two flags want exactly this and the second one is the
// signal: -w takes every received message, --log takes every state transition,
// and both had the same three things to get right -- do not create a file for a
// runtime that never writes, do not lose what a restart wrote before, and do
// not turn a bad path into a log flood.

#include "../loop/blocking_write.h"
#include "../util/logging.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <unistd.h>

namespace socketley
{

// Why `path` may not be written to, or empty if it may.
//
// Absolute only, for the reason unix_sock::path_refusal gives about socket
// paths: a relative path resolves against the DAEMON's working directory,
// which is wherever it happened to be started and is "/" under systemd.  An
// operator who types `--log app.log` and then cannot find app.log has been
// told nothing, which is the whole class of defect these two flags were fixed
// out of.
//
// Found by a test that passes `--log 'C:\'` as a JSON-escaping fixture and has
// nothing to do with logging: once --log actually opened its file, that left a
// file called C:\ in the repository root.
inline std::string appended_path_refusal(std::string_view flag,
                                         std::string_view path)
{
    if (path.empty())
        return {};   // not given is not the same as given wrong

    if (path[0] != '/')
        return std::string(flag) + " needs an absolute path (got \"" +
               std::string(path) + "\"): a relative one is resolved against the "
               "daemon's working directory, which is wherever it was started "
               "and is \"/\" under systemd\n";

    if (path.find('\0') != std::string_view::npos)
        return std::string(flag) + " path contains a NUL byte\n";

    return {};
}

class appending_file
{
public:
    appending_file() = default;
    ~appending_file() { close(); }

    appending_file(const appending_file&)            = delete;
    appending_file& operator=(const appending_file&) = delete;

    // What the operator called this file, for the complaint: "-w" or "--log".
    void set_label(std::string_view label) { m_label = label; }

    // A path that changed drops the descriptor, because an `edit` pointing the
    // flag somewhere else otherwise goes on appending to the file the runtime
    // was started with and the new name never receives a byte.  The latch is
    // cleared with it, so a corrected path is tried again.
    void set_path(std::string_view path)
    {
        if (path == m_path)
            return;
        close();
        m_path = path;

        // Latched here rather than at the open, because the flag doors refuse
        // a relative path and this is the backstop for every other route -- a
        // state file written before that refusal existed, most of all.  The
        // runtime keeps serving; a file it may not write is not a reason to
        // stop carrying traffic.
        const std::string why = appended_path_refusal(m_label, m_path);
        m_failed = !why.empty();
        if (m_failed)
            LOG_ERROR(why.c_str());
    }

    std::string_view path() const { return m_path; }

    // The line as given, with one newline added.  Bytes are not scrubbed: the
    // scrubbing the stdout paths do exists to stop a peer driving the
    // operator's terminal with an escape sequence, and a file is not a
    // terminal.
    void append(std::string_view line)
    {
        if (m_path.empty() || m_failed)
            return;

        if (m_fd < 0)
        {
            // 0600 because this is the operator's record of their own traffic,
            // and O_APPEND because a restart adding to the file is the whole
            // point of having one.
            m_fd = ::open(m_path.c_str(),
                          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
            if (m_fd < 0)
            {
                complain("could not be opened");
                return;
            }
        }

        // One write for the whole line, because N shards of one runtime are N
        // processes with the same path: an append this size is atomic on a
        // regular file, so the lines interleave without tearing.
        m_line.assign(line);
        m_line.push_back('\n');
        if (!write_all(m_fd, m_line.data(), m_line.size()))
            complain("could not be written");
        // A long line once does not keep its size here.
        if (m_line.capacity() > 64 * 1024)
            std::string().swap(m_line);
    }

    void close()
    {
        if (m_fd >= 0)
        {
            ::close(m_fd);
            m_fd = -1;
        }
    }

private:
    // Latched, or a runtime under load puts one line in the daemon log per
    // message through it.
    void complain(const char* what)
    {
        m_failed = true;
        LOG_ERROR((m_label + " " + m_path + " " + what + ": " +
                   std::string(std::strerror(errno)) +
                   " -- nothing is being written there").c_str());
    }

    std::string m_label{"a file"};
    std::string m_path;
    int         m_fd{-1};
    bool        m_failed{false};
    // The line and its newline, built here so a message costs no allocation.
    std::string m_line;
};

}  // namespace socketley
