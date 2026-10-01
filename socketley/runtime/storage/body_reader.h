#pragma once
// The plaintext of a range of an object's body, read from its open file a
// window at a time, with the next window read while the last is used.  A
// sealed body's windows are whole chunks, opened on a helper thread when they
// are large enough to be worth the hop, so the loop never decrypts a megabyte.
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "object_format.h"
#include "sse.h"
#include "../../shared/file_io.h"
#include "../../shared/hash_pool.h"

namespace socketley::storage
{

class body_reader : public std::enable_shared_from_this<body_reader>
{
public:
    // Plaintext [first, first + len) of the body at `data_off` in `fd`, which the caller keeps open; `key` null
    // reads the bytes as they are.  Null when `m` is sealed and its layout cannot be read.
    static std::shared_ptr<body_reader> make(file_io& io, hash_pool* pool, std::shared_ptr<bool> alive, int fd,
                                             uint64_t data_off, const object_meta& m, const sse_key* key,
                                             uint64_t first, uint64_t len);

    // The next window, valid until the next call: empty after the last, and `ok` false when the file
    // is shorter than its header says or a chunk does not open.
    using deliver = std::function<void(bool ok, std::string_view plain)>;
    void next(deliver cb);

private:
    body_reader() = default;

    enum class slot_state : uint8_t { idle, busy, ready, failed };
    struct slot
    {
        std::shared_ptr<std::string> cipher;
        std::shared_ptr<std::string> plain;
        size_t     skip{0};
        size_t     len{0};
        slot_state state{slot_state::idle};
    };

    void fetch();
    void read_done(int index, int64_t res, uint64_t want, std::shared_ptr<std::vector<sse_layout::chunk>> chunks);
    void hand_out();

    file_io*   m_io{nullptr};
    hash_pool* m_pool{nullptr};
    uint32_t   m_lane{0};
    std::shared_ptr<bool> m_alive;
    int        m_fd{-1};
    uint64_t   m_data_off{0};
    sse_layout m_layout;
    std::optional<sse_key> m_key;
    // The next plaintext byte to fetch, and the end of the range.
    uint64_t   m_pos{0};
    uint64_t   m_end{0};
    slot       m_slots[2];
    // Slots in the order their windows come, and the one the consumer holds.
    std::deque<int> m_order;
    int        m_held{-1};
    deliver    m_waiter;
};

// Opens a whole sealed body held in memory, as a small object's read brings it in with its header.
bool sse_open_body(const object_meta& m, const sse_key& key, std::string_view stored, std::string& plain);

}   // namespace socketley::storage
