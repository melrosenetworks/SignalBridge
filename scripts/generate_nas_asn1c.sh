#!/bin/bash
# Generate C sources from ASN.1 in asn1/r17/ using asn1c (PER).
# Output: generated/nas_asn1c/
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASN_DIR="$ROOT/asn1/r17"
OUT_DIR="$ROOT/generated/nas_asn1c"
ASN1C="${ASN1C:-asn1c}"

if ! command -v "$ASN1C" &>/dev/null; then
  echo "Error: asn1c not found. Install asn1c (e.g. brew install asn1c) or set ASN1C=path/to/asn1c" >&2
  exit 1
fi

shopt -s nullglob
ASN_FILES=("$ASN_DIR"/*.asn)
if [[ ${#ASN_FILES[@]} -eq 0 ]]; then
  echo "No .asn files in $ASN_DIR — add Rel-17 modules, then re-run." >&2
  echo "See asn1/README.md and docs/ASN1C_NAS.md" >&2
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# Adjust flags for your asn1c fork (e.g. -gen-OER, -no-gen-example).
"$ASN1C" -fcompound-names -gen-PER -pdu=auto "${ASN_FILES[@]}"

echo "Generated under $OUT_DIR (review compiler flags and link skeleton support as needed)."
