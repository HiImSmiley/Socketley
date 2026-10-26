// Unit test: place_descriptors (socketley/shared/net/fd_placement.h), which a forked worker's descriptors go through.
//
// What each case would catch:
//   * a source sitting on another's destination destroyed by that placement before its own, as the control socket
//     was when it came back inside the mesh block and its worker never heard its configuration
//   * a placed descriptor left close-on-exec, which the worker would never see
//   * a source already on its own destination placed wrong, or a lifted copy landing on a destination
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "shared/net/fd_placement.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <random>
#include <vector>

namespace
{

ino_t inode_of(int fd)
{
    struct stat st{};
    return ::fstat(fd, &st) == 0 ? st.st_ino : 0;
}

// In a child of its own, so the test's descriptors can be put anywhere: each of `at` is a new socket put on that
// number, each moved to `want`; the child exits 0 when every destination is its socket and inheritable.
int run(const std::vector<int>& at, const std::vector<int>& want)
{
    const pid_t pid = ::fork();
    if (pid == 0)
    {
        std::vector<ino_t> inode(at.size());
        for (size_t i = 0; i < at.size(); ++i)
        {
            int sv[2];
            if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) < 0)
                _exit(10);
            // The pair's other end closed first, since it may hold the very number this socket is put on.
            ::close(sv[1]);
            // Placed with the close-on-exec flag a creation site gives, wherever the number is.
            if (sv[0] != at[i] && ::dup3(sv[0], at[i], O_CLOEXEC) < 0)
                _exit(11);
            inode[i] = inode_of(at[i]);
            // A stray copy kept off every number the case uses.
            if (sv[0] != at[i])
            {
                bool used = false;
                for (int a : at)
                    used = used || a == sv[0];
                if (!used)
                    ::close(sv[0]);
            }
        }
        std::vector<socketley::fd_move> moves;
        for (size_t i = 0; i < at.size(); ++i)
            moves.push_back({at[i], want[i]});
        if (!socketley::place_descriptors(moves.data(), moves.size()))
            _exit(12);
        for (size_t i = 0; i < want.size(); ++i)
        {
            if (inode_of(want[i]) != inode[i])
                _exit(20 + static_cast<int>(i));
            if (::fcntl(want[i], F_GETFD, 0) & FD_CLOEXEC)
                _exit(90);
        }
        _exit(0);
    }
    if (pid < 0)
        return -1;
    int st = 0;
    ::waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

} // namespace

TEST_CASE("a control socket that came back inside the mesh block keeps its connection")
{
    // In the order the worker's were once placed -- shard, clients, a mesh block of four from 8, link, map, and the
    // control socket last -- with the control's source on mesh slot 9.
    CHECK(run({30, 31, 40, 41, 42, 43, 32, 33, 9}, {4, 5, 8, 9, 10, 11, 7, 6, 3}) == 0);
}

TEST_CASE("sources on each other's destinations, in a cycle, all arrive")
{
    CHECK(run({4, 5, 6, 7, 3}, {3, 4, 5, 6, 7}) == 0);
    CHECK(run({5, 4}, {4, 5}) == 0);
}

TEST_CASE("a source already on its own number stays, and loses close-on-exec")
{
    CHECK(run({3, 20}, {3, 4}) == 0);
}

TEST_CASE("any placement of the sources among the destinations and above them")
{
    std::mt19937 rng(20261006);
    for (int round = 0; round < 300; ++round)
    {
        const int mesh = 1 + static_cast<int>(rng() % 12);
        std::vector<int> want = {3, 4, 5, 6, 7};
        for (int j = 0; j < mesh; ++j)
            want.push_back(8 + j);
        // Every source a distinct number from 3 to twice the top, so many fall on destinations.
        std::vector<int> pool;
        for (int f = 3; f < 2 * (8 + mesh); ++f)
            pool.push_back(f);
        std::shuffle(pool.begin(), pool.end(), rng);
        std::vector<int> at(pool.begin(), pool.begin() + static_cast<long>(want.size()));
        INFO("round " << round);
        REQUIRE(run(at, want) == 0);
    }
}
