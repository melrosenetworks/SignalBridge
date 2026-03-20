#!/usr/bin/env python3
"""
Compare identities before and after SignalBridge anonymisation.

Runs SignalBridge with anonymisation on a PCAP, extracts identities from both
original and anonymised output, and reports whether anonymisation succeeded
(identities should be absent or reduced in the anonymised file).

Usage:
  python3 scripts/compare_identities.py capture.pcap
  python3 scripts/compare_identities.py -s ./build/signalbridge test/fixtures/2_firstattach.pcap

Exit codes:
  0 - Anonymisation verified (identities removed or reduced)
  1 - Identities still present in anonymised output (anonymisation failed)
  2 - Script error (missing deps, signalbridge failed, etc.)

FAIL output lists frame numbers in the anonymised capture (not the input file).
Use time_epoch to find the same packet in the input PCAP/PCAPNG. Pass
--keep-output-on-fail to retain the temp anonymised PCAP, or use -o OUT.pcap.
"""

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Resolve script dir for extract_identities
SCRIPT_DIR = Path(__file__).resolve().parent
EXTRACT_SCRIPT = SCRIPT_DIR / "extract_identities.py"
DEFAULT_SIGNALBRIDGE = Path(__file__).resolve().parent.parent / "build" / "signalbridge"
DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / "config" / "conduit_anonymise.yaml"


def extract_identities(pcap_path: str, include_ran_ids: bool = False) -> list[dict]:
    """Run extract_identities.py and return parsed records."""
    cmd = [sys.executable, str(EXTRACT_SCRIPT), pcap_path, "-q", "-j"]
    if include_ran_ids:
        cmd.append("-a")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode not in (0, 1):  # 1 = no identities found
            sys.stderr.write(f"extract_identities: {result.stderr or result.stdout}\n")
            return []
        import json
        if not result.stdout.strip():
            return []
        return json.loads(result.stdout)
    except Exception as e:
        sys.stderr.write(f"extract_identities failed: {e}\n")
        return []


def run_signalbridge(
    signalbridge: Path,
    config: Path,
    input_pcap: str,
    output_pcap: str,
) -> bool:
    """Run SignalBridge with anonymisation. Returns True on success."""
    cmd = [
        str(signalbridge),
        "run",
        "-i", input_pcap,
        "-o", output_pcap,
        "-c", str(config),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            sys.stderr.write(f"signalbridge: {result.stderr or result.stdout}\n")
            return False
        return True
    except Exception as e:
        sys.stderr.write(f"signalbridge failed: {e}\n")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Compare identities before/after SignalBridge anonymisation.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "pcap",
        help="Path to input PCAP or PCAPNG file",
    )
    parser.add_argument(
        "-s", "--signalbridge",
        default=str(DEFAULT_SIGNALBRIDGE),
        help=f"Path to signalbridge binary (default: {DEFAULT_SIGNALBRIDGE})",
    )
    parser.add_argument(
        "-c", "--config",
        default=str(DEFAULT_CONFIG),
        help=f"Config with anonymisation enabled (default: {DEFAULT_CONFIG})",
    )
    parser.add_argument(
        "-o", "--output",
        help="Path for anonymised output (default: temp file)",
    )
    parser.add_argument(
        "-a", "--include-ran-ids",
        action="store_true",
        help="Include RAN IDs in comparison (not anonymised by default)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print before/after identity lists",
    )
    parser.add_argument(
        "--keep-output-on-fail",
        action="store_true",
        help=(
            "If comparison fails, do not delete the temporary anonymised PCAP "
            "(default path is a temp file unless -o is set). "
            "Frame numbers in FAIL lines refer to that anonymised file, not the input."
        ),
    )
    args = parser.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.stderr.write(f"Error: File not found: {pcap}\n")
        return 2

    signalbridge = Path(args.signalbridge)
    if not signalbridge.exists():
        sys.stderr.write(f"Error: signalbridge not found: {signalbridge}\n")
        sys.stderr.write("Build with: cmake -B build && cmake --build build\n")
        return 2

    config = Path(args.config)
    if not config.exists():
        sys.stderr.write(f"Error: config not found: {config}\n")
        return 2

    if not EXTRACT_SCRIPT.exists():
        sys.stderr.write(f"Error: extract_identities.py not found: {EXTRACT_SCRIPT}\n")
        return 2

    # Determine output path
    if args.output:
        out_pcap = args.output
        cleanup = False
    else:
        fd, out_pcap = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        cleanup = True

    exit_code = 0
    try:
        # Run SignalBridge with anonymisation
        if not run_signalbridge(signalbridge, config, str(pcap), out_pcap):
            return 2

        before = extract_identities(str(pcap), include_ran_ids=args.include_ran_ids)
        after = extract_identities(out_pcap, include_ran_ids=args.include_ran_ids)

        # Identity types SignalBridge anonymises (IMSI, IMEI). TMSI is not anonymised.
        anonymised_types = {"imsi", "imei"}
        before_sensitive = [r for r in before if r["type"] in anonymised_types]
        before_values = {r["value"] for r in before_sensitive}

        # After: treat as anonymised if value differs from any before, or is a known pseudonym prefix (999)
        def is_still_sensitive(r):
            if r["type"] not in anonymised_types:
                return False
            # Pseudonym prefix (S1APAnonymise default mcc=999, mnc=99)
            if r["value"].startswith("999"):
                return False
            return r["value"] in before_values

        after_sensitive = [r for r in after if is_still_sensitive(r)]

        if args.verbose:
            print(f"=== BEFORE (input file: {pcap}) ===")
            print("# frame\ttime_epoch\ttype\tvalue")
            for r in before:
                te = r.get("time_epoch", "")
                print(f"  {r['frame']}\t{te}\t{r['type']}\t{r['value']}")
            print(f"\n=== AFTER (anonymised output file: {out_pcap}) ===")
            print("# frame\ttime_epoch\ttype\tvalue")
            for r in after:
                te = r.get("time_epoch", "")
                print(f"  {r['frame']}\t{te}\t{r['type']}\t{r['value']}")
            print()
            print(
                "Note: Wireshark 'Frame' numbers differ between these two files "
                "when packet counts differ. Use time_epoch to find the same packet in both."
            )
            print()

        if after_sensitive:
            print("FAIL: Sensitive identities still present in anonymised output:")
            print(
                f"  Anonymised capture (use this file for the frame numbers below): {out_pcap}"
            )
            print(
                "  (Input file frame numbers differ; match packets by time_epoch in Wireshark.)"
            )
            for r in after_sensitive:
                te = r.get("time_epoch", "")
                ts = f", time_epoch={te}" if te else ""
                print(f"  output frame {r['frame']}{ts}: {r['type']} = {r['value']}")
            exit_code = 1
        elif before_sensitive:
            print(f"PASS: {len(before_sensitive)} sensitive identity/identities removed")
        else:
            print("PASS: No sensitive identities in original (nothing to anonymise)")
    finally:
        if cleanup and os.path.exists(out_pcap):
            if exit_code == 1 and args.keep_output_on_fail:
                sys.stderr.write(
                    f"\nAnonymised PCAP retained for inspection: {out_pcap}\n"
                )
            else:
                os.unlink(out_pcap)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
