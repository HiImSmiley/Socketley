#pragma once

// The version, in one place.
//
// It used to live in cli/cli.h behind an #ifndef, guarding against a definition
// from the build system that does not exist: SOCKETLEY_VERSION appears nowhere
// in premake5.lua or the generated makefiles, so the literal below was always
// the only definition there has ever been.  Three comments in this tree said
// "premake5.lua defines SOCKETLEY_VERSION" and none of them was true.
//
// That mattered because it was not actually one literal.  metrics_endpoint.cpp
// built its JSON with the version written out by hand:
//
//     j += "{\"version\":\"1.0.9\",\"uptime_seconds\":";
//
// so every version bump moved `socketley --version`, the daemon identification
// string and the .deb, and left /metrics reporting the release before it.  A
// monitoring system asking the daemon what it is would have been told the wrong
// answer, and nothing in the tree would have failed.
//
// Sited in shared/ rather than cli/ because the daemon needs it too, and a
// daemon file reaching into cli/ for a constant is how it ended up copied.
#define SOCKETLEY_VERSION "1.1.0"
