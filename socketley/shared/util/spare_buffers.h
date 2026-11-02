#pragma once
// Large buffers a write is done with, kept for the next one on this thread: one freed past the allocator's thresholds
// went back to the kernel, and the next was faulted in and zeroed again -- up to 205 faults a 1 MiB answer over TLS.
#include <cstddef>
#include <memory>
#include <string>

namespace socketley::spare
{

// An empty string whose storage is kept, when it is of a size worth keeping, once its last owner lets go.
std::shared_ptr<std::string> buffer();

// Swaps into `into`, which is empty, the smallest kept buffer that holds `n`, when one does.
void take(std::string& into, size_t n);

}   // namespace socketley::spare
