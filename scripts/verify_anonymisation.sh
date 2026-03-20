#!/bin/bash
# Verify anonymisation: run compare_identities and report pass/fail.
# Usage: ./scripts/verify_anonymisation.sh [pcap_path]
# Exit 0 = anonymisation verified, 1 = IMSI leaks, 2 = script error
#
# VERIFY_ANON_KEEP_OUTPUT=1 — on failure, keep the temp anonymised PCAP and print its path
# (FAIL line frame numbers refer to that file, not the input pcapng).

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PCAP="${1:-$PROJECT_ROOT/test/fixtures/ngap_testattach.pcapng}"
SIGNALBRIDGE="${SIGNALBRIDGE:-$PROJECT_ROOT/build/signalbridge}"
CONFIG="${CONFIG:-$PROJECT_ROOT/config/conduit_anonymise.yaml}"

if [[ ! -f "$PCAP" ]]; then
  echo "Error: PCAP not found: $PCAP"
  exit 2
fi
if [[ ! -x "$SIGNALBRIDGE" ]]; then
  echo "Error: signalbridge not found: $SIGNALBRIDGE"
  echo "Build with: cmake -B build && cmake --build build"
  exit 2
fi
if [[ ! -f "$CONFIG" ]]; then
  echo "Error: config not found: $CONFIG"
  exit 2
fi

EXTRA_ARGS=()
if [[ "${VERIFY_ANON_KEEP_OUTPUT:-}" == "1" ]]; then
  EXTRA_ARGS+=(--keep-output-on-fail)
fi
python3 "$SCRIPT_DIR/compare_identities.py" "$PCAP" -s "$SIGNALBRIDGE" -c "$CONFIG" "${EXTRA_ARGS[@]}"
exit $?
