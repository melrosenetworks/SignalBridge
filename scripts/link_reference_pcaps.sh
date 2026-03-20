#!/usr/bin/env bash
# Create symlinks under test/fixtures/reference/ -> ../../reference/ (repo-relative)
# and subdirs pcaps/lte, pcaps/5g. Run from repository root.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REF="$(cd "$ROOT/../.." && pwd)/reference"
FIX="$ROOT/test/fixtures"
LINKROOT="$FIX/reference"

if [[ ! -d "$REF" ]]; then
  echo "Error: reference directory not found: $REF" >&2
  echo "Expected: two levels above repo root (e.g. Melrose Networks/reference)." >&2
  exit 1
fi

mkdir -p "$LINKROOT/pcaps/lte" "$LINKROOT/pcaps/5g"

shopt -s nullglob

# From $LINKROOT: ../../../../../reference (via test, repo, DevRepo, Melrose Networks)
BASE_TOP="../../../../../reference"

for f in "$REF"/*.pcap "$REF"/*.pcapng; do
  [[ -f "$f" ]] || continue
  bn=$(basename "$f")
  ln -sf "$BASE_TOP/$bn" "$LINKROOT/$bn"
done

BASE_LTE="../../../../../../../reference/pcaps/lte"
BASE_5G="../../../../../../../reference/pcaps/5g"

for sub in pcaps/lte pcaps/5g; do
  [[ -d "$REF/$sub" ]] || continue
  for f in "$REF/$sub"/*; do
    [[ -f "$f" ]] || continue
    ext="${f##*.}"
    [[ "$ext" == "pcap" || "$ext" == "pcapng" ]] || continue
    bn=$(basename "$f")
    case "$sub" in
      pcaps/lte) ln -sf "$BASE_LTE/$bn" "$LINKROOT/$sub/$bn" ;;
      pcaps/5g)  ln -sf "$BASE_5G/$bn" "$LINKROOT/$sub/$bn" ;;
    esac
  done
done

echo "Linked under $LINKROOT (targets under $REF)"
