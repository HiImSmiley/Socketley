#pragma once
// A user's mailbox written out as mbox files, a folder each under a directory, and mbox files read into it: what
// `socketley mail export` and `import` start on the first shard and the CLI asks after until it is done.  The files
// are read and written on the pool, the messages read and stored through the IMAP store one at a time.
#include <cstdint>
#include <memory>
#include <string>

#include "../../shared/loop/hash_pool.h"

namespace socketley::mail
{

class imap_store;

struct transfer_status
{
    bool done{false};
    // What became of it once done: a summary, or "error: ..." with why.
    std::string text;
    uint64_t count{0}, total{0};
};

// `user`'s folders as <dir>/<folder>.mbox, the directory made and refused where it holds anything.
void start_export(imap_store& store, hash_pool& pool, std::shared_ptr<bool> alive, std::string user, std::string dir,
                  std::shared_ptr<transfer_status> status);
// The mbox `path` names, or each under the directory it names, into `user`'s folders: a file's into the folder its
// name says, a message with Takeout's labels into the folder they say.
void start_import(imap_store& store, hash_pool& pool, std::shared_ptr<bool> alive, std::string user, std::string path,
                  std::shared_ptr<transfer_status> status);

}   // namespace socketley::mail
