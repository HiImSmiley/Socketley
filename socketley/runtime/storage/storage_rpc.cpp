// What another runtime's script asks of this one through socketley.storage.*:
// put, get, head, delete and list, answered through the request channel's ticket
// on a later turn.
//
// They are the same operations an S3 client asks for, on the same store, with
// the same counters and the same hooks, and they hold an object whole in memory
// (storage_rpc::max_value) where the S3 port streams it.
#include "storage_run.h"

#include <algorithm>

#include "s3_names.h"
#include "s3_xml.h"
#include "storage_instance.h"
#include "../../shared/logging.h"
#include "../../shared/runtime_manager.h"

namespace socketley::storage
{

using storage_rpc::op;

// One call in flight that has more than one step: a put feeding its staging
// buffer, or a get reading what the header read did not bring.
struct storage_run::rpc_state
{
    uint64_t    ticket{0};
    std::string bucket;
    std::string key;
    // put
    std::shared_ptr<put_op> put;
    std::string data;
    size_t      off{0};
    bool        finishing{false};
    // get
    int         fd{-1};
    size_t      data_off{0};
    std::string body;
    object_meta meta;
    bool        done{false};
};

namespace
{

storage_rpc::reply refusal(std::string code, std::string message)
{
    storage_rpc::reply r;
    r.ok      = false;
    r.code    = std::move(code);
    r.message = std::move(message);
    return r;
}

storage_rpc::reply refusal_for(st s)
{
    const s3_error e = error_for(s);
    return refusal(e.code, e.message);
}

constexpr std::string_view user_prefix = "x-amz-meta-";

}   // namespace

storage_rpc::object_info rpc_info_of(const object_meta& m, std::string key)
{
    storage_rpc::object_info i;
    i.key          = std::move(key);
    i.size         = m.size;
    i.etag         = m.etag();
    i.content_type = m.content_type;
    i.mtime_ms     = m.mtime_ms;
    for (const auto& [k, v] : m.extra)
        if (k.size() > user_prefix.size() && k.compare(0, user_prefix.size(), user_prefix) == 0)
            i.metadata.emplace_back(k.substr(user_prefix.size()), v);
    return i;
}

bool storage_run::serve_rpc(uint64_t ticket, std::string_view payload)
{
    if (m_stopped)
        return false;
    auto* mgr = m_owner.get_runtime_manager();
    if (!mgr)
        return false;

    // Answers exactly once, whichever step gets there first, and forgets what
    // was being kept for it.
    const auto answer = [this, ticket](op kind, const storage_rpc::reply& r)
    {
        m_rpc.erase(ticket);
        if (auto* m = m_owner.get_runtime_manager())
            m->requests().complete_deferred(ticket, request_status::ok, storage_rpc::encode(r, kind));
    };

    storage_rpc::request rq;
    if (!storage_rpc::decode(payload, rq))
    {
        answer(op::get, refusal("InvalidRequest", "the request could not be read"));
        return true;
    }
    if (!valid_bucket_name(rq.bucket) && rq.kind == op::put)
    {
        answer(rq.kind, refusal_for(st::invalid_bucket_name));
        return true;
    }
    ++m_c.requests;
    runtime_instance::stat_add(m_owner.m_stat_total_messages, 1);

    switch (rq.kind)
    {
        case op::head:
        {
            ++m_c.heads;
            if (!m_store.has_bucket(rq.bucket))
            {
                answer(rq.kind, refusal_for(st::no_such_bucket));
                return true;
            }
            // From memory when this shard owns the key and from the object's header otherwise.
            m_store.stat_object(rq.bucket, rq.key, [answer](st s, const object_meta& m)
            {
                if (s != st::ok)
                {
                    answer(op::head, refusal_for(s));
                    return;
                }
                storage_rpc::reply r;
                r.info = rpc_info_of(m);
                answer(op::head, r);
            });
            return true;
        }

        case op::list:
        {
            ++m_c.lists;
            list_query lq;
            lq.prefix      = rq.prefix;
            lq.delimiter   = rq.delimiter;
            lq.start_after = rq.start_after;
            lq.max_keys    = std::clamp<size_t>(rq.max_keys, 1, storage_rpc::max_list);
            // Every shard's keys, merged.
            m_node.list(rq.bucket, lq, [answer](st s, list_page page)
            {
                if (s != st::ok)
                {
                    answer(op::list, refusal_for(s));
                    return;
                }
                storage_rpc::reply r;
                r.truncated = page.truncated;
                for (const auto& o : page.objects)
                    r.objects.push_back(rpc_info_of(o.meta, o.key));
                r.prefixes = page.prefixes;
                // What the next page is asked to start after: the last thing this one said.
                if (page.truncated)
                {
                    std::string last;
                    if (!page.objects.empty())
                        last = page.objects.back().key;
                    if (!page.prefixes.empty() && page.prefixes.back() > last)
                        last = page.prefixes.back();
                    r.next = last;
                }
                answer(op::list, r);
            });
            return true;
        }

        case op::del:
        {
            ++m_c.deletes;
            m_store.remove(rq.bucket, rq.key, [this, answer, bucket = rq.bucket, key = rq.key](st s, bool existed)
            {
                if (s != st::ok)
                {
                    answer(op::del, refusal_for(s));
                    return;
                }
                answer(op::del, storage_rpc::reply{});
                if (existed)
                    notify_delete(bucket, key);
            });
            return true;
        }

        case op::get:
        {
            ++m_c.gets;
            if (!m_store.has_bucket(rq.bucket))
            {
                answer(rq.kind, refusal_for(st::no_such_bucket));
                return true;
            }
            // The size is known here for a key this shard owns; for another shard's the
            // file is opened with a guess and the header says.
            const bool mine = m_store.owns(rq.bucket, rq.key);
            const object_meta* mem = mine ? m_store.find(rq.bucket, rq.key) : nullptr;
            if (mine && !mem)
            {
                answer(rq.kind, refusal_for(st::no_such_key));
                return true;
            }
            const auto too_large = [](uint64_t size)
            {
                return refusal("EntityTooLarge", "the object is " + std::to_string(size) +
                       " bytes and a script may read at most " + std::to_string(storage_rpc::max_value) +
                       " -- read it over the S3 port");
            };
            if (mem && mem->size > storage_rpc::max_value)
            {
                answer(rq.kind, too_large(mem->size));
                return true;
            }
            auto state = std::make_shared<rpc_state>();
            state->ticket = ticket;
            state->bucket = rq.bucket;
            state->key    = rq.key;
            m_rpc[ticket] = state;
            const size_t want = mem ? static_cast<size_t>(stored_size(*mem)) : 60000;
            m_store.open_object(rq.bucket, rq.key, want,
                [this, state, answer, too_large](open_result o)
                {
                    if (state->done)
                    {
                        if (o.fd >= 0)
                            m_loop.close_fd(o.fd);
                        return;
                    }
                    if (o.status != st::ok)
                    {
                        state->done = true;
                        answer(op::get, refusal_for(o.status));
                        return;
                    }
                    if (o.meta.size > storage_rpc::max_value)
                    {
                        state->done = true;
                        m_loop.close_fd(o.fd);
                        answer(op::get, too_large(o.meta.size));
                        return;
                    }
                    // A script holds no client's key, so an object sealed under one is not its to read.
                    if (sse_mode_of(o.meta) == sse_mode::c)
                    {
                        state->done = true;
                        m_loop.close_fd(o.fd);
                        answer(op::get, refusal("InvalidRequest", "the object is encrypted with a customer key -- "
                                                                  "read it over the S3 port with that key"));
                        return;
                    }
                    state->fd       = o.fd;
                    state->data_off = o.data_off;
                    state->meta     = o.meta;
                    state->body     = std::move(o.prefetch);
                    // The rest, when the read that brought the header did not bring the body.
                    auto step = std::make_shared<std::function<void()>>();
                    std::weak_ptr<std::function<void()>> weak = step;
                    *step = [this, state, answer, weak]()
                    {
                        auto self = weak.lock();
                        if (state->done || !self)
                            return;
                        const size_t have = state->body.size();
                        const uint64_t whole = stored_size(state->meta);
                        if (have >= whole)
                        {
                            state->done = true;
                            m_loop.close_fd(state->fd);
                            state->fd = -1;
                            storage_rpc::reply r;
                            r.info = rpc_info_of(state->meta);
                            if (is_encrypted(state->meta))
                            {
                                sse_key key{};
                                s3_error err;
                                if (!sse_data_key(state->meta, std::nullopt, key, err) ||
                                    !sse_open_body(state->meta, key, state->body, r.data))
                                {
                                    answer(op::get, err.code.empty() ? refusal_for(st::io_error)
                                                                     : refusal(err.code, err.message));
                                    return;
                                }
                            }
                            else
                                r.data = std::move(state->body);
                            answer(op::get, r);
                            return;
                        }
                        const size_t n = static_cast<size_t>(std::min<uint64_t>(whole - have, 1u << 20));
                        state->body.resize(have + n);
                        if (!m_io.pread(state->fd, state->body.data() + have, static_cast<uint32_t>(n),
                                        state->data_off + have,
                                        [this, state, self, have, answer](int64_t res)
                                        {
                                            if (state->done)
                                                return;
                                            if (res <= 0)
                                            {
                                                // The file is shorter than its header said.
                                                state->done = true;
                                                m_loop.close_fd(state->fd);
                                                state->fd = -1;
                                                answer(op::get, refusal_for(st::io_error));
                                                return;
                                            }
                                            state->body.resize(have + static_cast<size_t>(res));
                                            (*self)();
                                        }))
                        {
                            state->done = true;
                            m_loop.close_fd(state->fd);
                            state->fd = -1;
                            answer(op::get, refusal_for(st::io_error));
                        }
                    };
                    (*step)();
                });
            return true;
        }

        case op::put:
        {
            ++m_c.puts;
            object_meta meta;
            meta.content_type = rq.content_type.empty() ? "binary/octet-stream" : rq.content_type;
            size_t user = 0;
            for (const auto& [k, v] : rq.metadata)
            {
                meta.extra.emplace_back(std::string(user_prefix) + k, v);
                user += k.size() + v.size();
            }
            if (user > 2048)
            {
                answer(rq.kind, refusal_for(st::metadata_too_large));
                return true;
            }
            // A bucket that encrypts its new objects encrypts a script's too.
            sse_seal_spec seal;
            const bool sealed = m_store.bucket_encrypts(rq.bucket);
            if (s3_error err; sealed && (!m_has_master || !sse_new_key({sse_mode::s3, std::nullopt, false}, false, meta, seal, err)))
            {
                answer(rq.kind, refusal("NotImplemented", "the bucket encrypts its objects and this runtime has no "
                                                          "--sse-key-file"));
                return true;
            }
            // A script's object is given S3's default checksum like a client's.
            meta.extra.emplace_back(std::string(checksum_header(default_checksum_algo)),
                                    std::string(checksum_b64_len(default_checksum_algo), 'A'));
            st why = st::ok;
            auto op_ptr = m_store.begin_put(rq.bucket, rq.key, std::move(meta), rq.data.size(), true, why, true,
                                            sealed ? &seal : nullptr);
            if (!op_ptr)
            {
                answer(rq.kind, refusal_for(why));
                return true;
            }
            op_ptr->track_checksum(default_checksum_algo, {});
            auto state = std::make_shared<rpc_state>();
            state->ticket = ticket;
            state->bucket = rq.bucket;
            state->key    = rq.key;
            state->put    = std::move(op_ptr);
            state->data   = std::move(rq.data);
            m_rpc[ticket] = state;

            // The put takes what fits, says when it has room for more, and says
            // once if it cannot go on; each of the three ends here.
            auto finish_with = [this, state, answer](const storage_rpc::reply& r)
            {
                if (state->done)
                    return;
                state->done = true;
                state->put->on_ready(nullptr);
                state->put->on_failed(nullptr);
                answer(op::put, r);
            };
            auto pump = std::make_shared<std::function<void()>>();
            *pump = [this, state, finish_with]()
            {
                if (state->done || state->finishing)
                    return;
                if (state->put->failed())
                {
                    finish_with(refusal_for(state->put->status()));
                    return;
                }
                while (state->off < state->data.size())
                {
                    const size_t took = state->put->append(state->data.data() + state->off,
                                                           state->data.size() - state->off);
                    state->off += took;
                    if (state->done)
                        return;
                    if (took == 0)
                        return;   // resumed by the put's ready callback
                }
                state->finishing = true;
                state->put->finish(nullptr, [this, state, finish_with](put_result pr)
                {
                    if (pr.status != st::ok)
                    {
                        finish_with(refusal_for(pr.status));
                        return;
                    }
                    storage_rpc::reply r;
                    r.info = rpc_info_of(pr.meta);
                    const std::string bucket = state->bucket;
                    const std::string key    = state->key;
                    finish_with(r);
                    notify_put(bucket, key, pr.meta);
                });
            };
            state->put->on_ready([pump]() { (*pump)(); });
            state->put->on_failed([finish_with](st why) { finish_with(refusal_for(why)); });
            (*pump)();
            return true;
        }
    }
    return false;
}

// A stop answers what is still owed: a put that will not be finished is
// removed and every call in flight is told the service went.
void storage_run::stop_rpc()
{
    auto* mgr = m_owner.get_runtime_manager();
    auto owed = std::move(m_rpc);
    m_rpc.clear();
    for (auto& [ticket, state] : owed)
    {
        if (state->done)
            continue;
        state->done = true;
        if (state->put)
        {
            state->put->on_ready(nullptr);
            state->put->on_failed(nullptr);
            state->put->abort();
        }
        if (state->fd >= 0)
        {
            m_loop.close_fd(state->fd);
            state->fd = -1;
        }
        if (mgr)
            mgr->requests().complete_deferred(
                ticket, request_status::ok,
                storage_rpc::encode(refusal("ServiceUnavailable", "the storage runtime is stopping"),
                                    op::get));
    }
}

}   // namespace socketley::storage
