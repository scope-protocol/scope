#!/bin/sh
# Seeds, program id bytes and account lengths are defined in crates/interface and
# imported everywhere else; a second copy would drift without any test noticing.
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
