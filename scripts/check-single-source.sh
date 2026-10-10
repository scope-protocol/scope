#!/bin/sh
# The PDA seeds and the two account length constants are defined in crates/interface
# and imported everywhere else. This catches a second definition by name; a bare
# literal length such as 68 is not caught.
set -eu
cd "$(dirname "$0")/.."
bad=$(grep -rnE 'b"(ann|meta)"|ANNOUNCEMENT_LEN *[:=]|META_ENTRY_LEN *[:=]' \
  --include='*.rs' crates cli programs \
  | grep -v '^crates/interface/' || true)
if [ -n "$bad" ]; then
  echo "defined outside crates/interface:" >&2
  echo "$bad" >&2
  exit 1
fi
