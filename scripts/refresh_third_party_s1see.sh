#!/usr/bin/env bash
# Copy S1-SEE parser sources into third_party/s1see/. Run from any cwd.
set -euo pipefail
PUBLISH="$(cd "$(dirname "$0")/.." && pwd)"
S1SEE="${S1_SEE_SRC:-$(cd "${PUBLISH}/.." && pwd)/S1-SEE}"
DEST="${PUBLISH}/third_party/s1see"

die() { echo "refresh_third_party_s1see: $*" >&2; exit 1; }
[[ -f "${S1SEE}/src/s1ap_parser.cpp" ]] || die "S1-SEE not found at ${S1SEE} (set S1_SEE_SRC)"

mkdir -p "${DEST}/include/s1see/utils" "${DEST}/src/utils"
cp -p "${S1SEE}/include/s1see/utils/pcap_reader.h" "${DEST}/include/s1see/utils/"
cp -p "${S1SEE}/src/s1ap_parser.cpp" "${S1SEE}/src/s1ap_parser.h" "${DEST}/src/"
cp -p "${S1SEE}/src/nas_parser.cpp" "${S1SEE}/src/nas_parser.h" "${DEST}/src/"
cp -p "${S1SEE}/src/utils/pcap_reader.cc" "${DEST}/src/utils/"
echo "Updated ${DEST} from ${S1SEE}"
