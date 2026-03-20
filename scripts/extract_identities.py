#!/usr/bin/env python3
"""
Extract identities (IMSI, TMSI, IMEI, etc.) from S1AP/NGAP PCAP or PCAPNG files.

Uses tshark (Wireshark CLI) to dissect packets and extract identity fields.
Text output columns are: frame, time_epoch, type, value (time_epoch helps match
packets across different capture files).

Output is suitable for comparing before and after SignalBridge anonymisation:
  - Before: should list all identities found
  - After: should list none (or only non-anonymised identifiers like RAN IDs)

Usage:
  python3 scripts/extract_identities.py capture.pcap
  python3 scripts/extract_identities.py before.pcap > before.txt
  python3 scripts/extract_identities.py after.pcap > after.txt
  diff before.txt after.txt

Example comparison workflow:
  ./build/signalbridge -i capture.pcap -o anonymised.pcap -c config_with_anonymisation.yaml
  python3 scripts/extract_identities.py capture.pcap > before.txt
  python3 scripts/extract_identities.py anonymised.pcap > after.txt
  diff before.txt after.txt   # Identities should be absent in after.txt
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


# tshark fields for identity extraction (S1AP/NGAP, 4G and 5G NAS)
# Use only fields that exist in common tshark versions
IDENTITY_FIELDS = [
    ("imsi", "e212.imsi"),
    ("tmsi", "nas_eps.emm.m_tmsi"),
    ("imei", "nas_eps.emm.imei"),
]

# Fields that may appear in S1AP/NGAP layer (RAN IDs - not typically anonymised)
RAN_ID_FIELDS = [
    ("ran_ue_ngap_id", "ngap.RAN_UE_NGAP_ID"),
    ("amf_ue_ngap_id", "ngap.AMF_UE_NGAP_ID"),
    ("enb_ue_s1ap_id", "s1ap.ENB_UE_S1AP_ID"),
    ("mme_ue_s1ap_id", "s1ap.MME_UE_S1AP_ID"),
]


def run_tshark(pcap_path: str, fields: list[tuple[str, str]]) -> str:
    """Run tshark and return tab-separated output.

    Columns: frame.number, frame.time_epoch, then one column per *fields* entry.
    time_epoch matches Wireshark's packet list time and correlates the same
    logical packet across input vs anonymised output (timestamps are preserved).
    """
    field_names = [f[1] for f in fields]
    cmd = [
        "tshark",
        "-r", pcap_path,
        "-Y", "s1ap || ngap",
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
    ]
    for fn in field_names:
        cmd.extend(["-e", fn])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0 and result.stderr:
            sys.stderr.write(f"tshark: {result.stderr}\n")
        return result.stdout
    except FileNotFoundError:
        sys.stderr.write("Error: tshark not found. Install Wireshark (includes tshark).\n")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        sys.stderr.write("Error: tshark timed out.\n")
        sys.exit(1)


def parse_tshark_output(
    output: str,
    fields: list[tuple[str, str]],
) -> list[dict]:
    """Parse tshark tab-separated output into list of identity records."""
    records = []
    field_names = [f[1] for f in fields]
    prefix_cols = 2  # frame.number, frame.time_epoch

    for line in output.strip().splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < prefix_cols + 1:
            continue
        frame_num = parts[0].strip()
        time_epoch = parts[1].strip() if len(parts) > 1 else ""
        values = parts[prefix_cols : prefix_cols + len(field_names)]

        for i, (ftype, fname) in enumerate(fields):
            val = values[i].strip() if i < len(values) else ""
            if val and val != "":
                # Handle multiple values (e.g. "1,1" from multiple IEs)
                for v in val.replace(" ", "").split(","):
                    if v:
                        records.append({
                            "frame": frame_num,
                            "time_epoch": time_epoch,
                            "type": ftype,
                            "field": fname,
                            "value": v,
                        })
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Extract identities from S1AP/NGAP PCAP/PCAPNG for anonymisation comparison.",
        epilog=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "pcap",
        help="Path to PCAP or PCAPNG file",
    )
    parser.add_argument(
        "-j", "--json",
        action="store_true",
        help="Output JSON instead of human-readable text",
    )
    parser.add_argument(
        "-a", "--include-ran-ids",
        action="store_true",
        help="Include RAN IDs (eNB/AMF UE IDs) in output (not anonymised by default)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress stderr (e.g. tshark warnings)",
    )
    args = parser.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.stderr.write(f"Error: File not found: {pcap}\n")
        sys.exit(1)

    fields = IDENTITY_FIELDS.copy()
    if args.include_ran_ids:
        fields.extend(RAN_ID_FIELDS)

    if args.quiet:
        sys.stderr = open("/dev/null", "w")

    output = run_tshark(str(pcap), fields)
    records = parse_tshark_output(output, fields)

    if args.json:
        print(json.dumps(records, indent=2))
    else:
        if not records:
            print(f"# No identities found in {pcap}")
            print("# (Either no S1AP/NGAP packets, or all NAS is encrypted)")
        else:
            print(f"# Identities in {pcap} ({len(records)} found)")
            print("# frame\ttime_epoch\ttype\tvalue")
            for r in records:
                te = r.get("time_epoch", "")
                print(f"{r['frame']}\t{te}\t{r['type']}\t{r['value']}")

    return 0 if records else 1


if __name__ == "__main__":
    sys.exit(main())
