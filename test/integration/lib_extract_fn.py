#!/usr/bin/env python3
"""Print one C++ function body, comments stripped.

    lib_extract_fn.py <file> <signature-prefix>

Not a test — run_all.sh globs test_*.sh, so this is only ever invoked.

Two mistakes made this a separate file rather than three lines inlined in a
test, and both produced an assertion that reported the same answer whether the
code was fixed or not:

  * A regex ending at "the next definition at column zero" does not find the
    end of a function.  Used against proxy_instance.cpp it swallowed 366 lines
    and the whole function after the one being asked about, so a resolver call
    in the NEXT function was reported as being in this one.  Braces are counted
    here instead.

  * Comments have to go first.  A comment explaining why a call was removed
    naturally contains the name of the call, so grepping the raw text finds the
    explanation and reports it as the thing it explains.  The first version of
    the DNS assertion failed on its own prose.

Neither is subtle in hindsight.  Both cost a red test that looked like a real
finding, which is the expensive kind of wrong.
"""
import re
import sys


def extract(path: str, signature: str) -> str:
    src = open(path).read()

    start = src.find(signature)
    if start < 0:
        return ''

    open_brace = src.find('{', start)
    if open_brace < 0:
        return ''

    depth, i = 0, open_brace
    while i < len(src):
        c = src[i]
        if src.startswith('//', i):
            nl = src.find('\n', i)
            i = len(src) if nl < 0 else nl
        elif src.startswith('/*', i):
            end = src.find('*/', i + 2)
            i = len(src) if end < 0 else end + 1
        elif c == '"' or (c == "'" and not src[i - 1].isalnum()):
            i += 1
            while i < len(src) and src[i] != c:
                i += 2 if src[i] == '\\' else 1
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                break
        i += 1
    else:
        return ''          # unbalanced: report nothing rather than half a body

    body = src[start:i + 1]

    # Strings are not stripped, deliberately: a call name inside a string
    # literal is worth reporting, and none of the callers ask about anything
    # that appears in one.
    body = re.sub(r'//[^\n]*', '', body)
    body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
    return body


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('usage: lib_extract_fn.py <file> <signature-prefix>')
    sys.stdout.write(extract(sys.argv[1], sys.argv[2]))
