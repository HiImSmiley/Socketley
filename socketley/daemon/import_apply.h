#pragma once
// The fields an `import` document names, applied to a runtime: the one list `import` applies and fuzz_edit_merge
// drives, so what the fuzzer checks is what the command does.
#include <string>

class runtime_instance;
struct runtime_config;

// Only the keys the document names (runtime_config::has); a key it leaves out keeps the runtime's value.  Not the
// name, the script or a manager: those belong to the command.  False with `why` only for an ACME name or a server's
// upstream that cannot be, both of which `import` refuses before it calls this, so nothing is half applied.
//
// `restore` puts back what a runtime held, as edit's rollback does: the ACME names and address are set as they were,
// judged by nobody, since a state file of an older build may hold one today's check refuses and a rollback that
// stopped there left every field after it as the refused edit set it.
bool import_apply(runtime_instance& rt, const runtime_config& cfg, std::string& why, bool restore = false);
