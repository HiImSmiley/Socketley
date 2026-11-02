#pragma once
// The plaintext of a range of an object's body, read from its open file a
// window at a time, with the next window read while the last is used.  A
// sealed or compressed body's windows are whole chunks, opened on a helper
// thread when they are large enough to be worth the hop, so the loop never
// decrypts or decompresses a megabyte.
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "compression.h"
#include "object_format.h"
#include "sse.h"
#include "../../shared/loop/file_io.h"
#include "../../shared/loop/hash_pool.h"

namespace socketley::storage
{

class body_reader : public std::enable_shared_from_this<body_reader>
{
public:
    // Plaintext [first, first + len) of the body at `data_off` in `fd`, which the caller keeps open; `key` null
    // reads the bytes as they are, opened when they are compressed.  Null when `m` is sealed and its layout cannot be
    // read.
    static std::shared_ptr<body_reader> make(file_io& io, hash_pool* pool, std::shared_ptr<bool> alive, int fd,
                                             uint64_t data_off, const object_meta& m, const sse_key* key,
                                             uint64_t first, uint64_t len);

    // Bytes [off, off + len) of a body kept elsewhere, handed to `done` whole or not at all.
    using remote_fetch =
        std::function<void(uint64_t off, uint64_t len, std::function<void(bool ok, std::string bytes)> done)>;
    // Plaintext [first, first + len) of a body that `fetch` brings a window at a time, two of them in flight.
    static std::shared_ptr<body_reader> make_remote(std::shared_ptr<bool> alive, remote_fetch fetch, uint64_t first,
                                                    uint64_t len);

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
        // The compressed chunks the window holds.
        uint64_t   first_chunk{0};
        uint64_t   chunk_count{0};
    };

    // Whether the store has gone, dropping the waiting consumer if so.
    bool gone();
    void fetch();
    void load_list();
    void load_table();
    void read_done(int index, int64_t res, uint64_t want, std::shared_ptr<std::vector<sse_layout::chunk>> chunks);
    void hand_out();

    file_io*   m_io{nullptr};
    hash_pool* m_pool{nullptr};
    uint32_t   m_lane{0};
    std::shared_ptr<bool> m_alive;
    int        m_fd{-1};
    uint64_t   m_data_off{0};
    sse_layout m_layout;
    // The object while its part list, kept after its body, is still to be read.
    std::unique_ptr<object_meta> m_meta;
    part_trailer m_trailer;
    bool       m_list_reading{false};
    bool       m_list_failed{false};
    // A compressed body's chunks, once its table is read, and the record that says where the table is until then.
    std::shared_ptr<const lz4_table> m_table;
    std::optional<lz4_record> m_squeezed;
    remote_fetch m_remote;
    // The size of the next window from elsewhere.
    uint64_t   m_remote_window{0};
    // A window being started, whose fetch may answer before it returns.
    bool       m_fetching{false};
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
