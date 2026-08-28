#!/usr/bin/env bash
# Fails if a change touches a line that is not a comment.  Comment markers are
# per language: '#' is a comment in shell and the PREPROCESSOR in C++, so it is
# only treated as one for .sh files.
bad=0
for f in $(git diff --name-only -- socketley/ test/); do
  case "$f" in
    *.sh) pat='^(#)' ;;
    *)    pat='^(//|\*|/\*|\*/)' ;;
  esac
  n=$(git diff -U0 -- "$f" | grep -E '^[+-]' | grep -vE '^(\+\+\+|---)' \
      | sed -E 's/^[+-][[:space:]]*//' | grep -vE "$pat" | grep -vE '^$' | wc -l)
  if [ "$n" -gt 0 ]; then
    echo "  $f: $n Nicht-Kommentarzeile(n)"
    git diff -U0 -- "$f" | grep -E '^[+-]' | grep -vE '^(\+\+\+|---)' \
      | sed -E 's/^([+-])[[:space:]]*/\1 /' | grep -vE "^[+-] (//|\*|/\*|\*/|#)" \
      | grep -vE '^[+-] $' | head -4
    bad=1
  fi
done
[ "$bad" -eq 0 ] && echo "  nur Kommentarzeilen berührt"
exit $bad
