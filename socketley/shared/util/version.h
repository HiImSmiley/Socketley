#pragma once

// The version, in one place -- in shared/ because the daemon needs it too, and
// reaching into cli/ for a constant is how /metrics came to hold its own copy.
#define SOCKETLEY_VERSION "1.1.0"
