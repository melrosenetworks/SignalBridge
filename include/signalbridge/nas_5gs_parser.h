/*
 * SignalBridge - 5G NAS (5GS) mobile identity parser
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 *
 * Parses 5G NAS (TS 24.501) Identity Response, extracts SUCI/SUPI (IMSI)
 * for anonymisation. Supports null-scheme SUCI and plain SUPI format IMSI.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace signalbridge {

struct Nas5gsIdentity {
    std::string imsi;           // Decoded IMSI digits (MCC+MNC+MSIN)
    std::vector<uint8_t> bytes; // Raw identity bytes for replacement
    bool valid{false};
};

// Extract IMSI from 5G NAS payload (Identity Response 0x5c).
// nas_payload: NAS bytes starting after security header (i.e. message type byte first).
// Returns identities found (SUCI with null scheme, or SUPI format IMSI).
std::vector<Nas5gsIdentity> extract_5gs_mobile_identities(const uint8_t* nas_payload, size_t len);

// Encode IMSI to 5G SUCI format (null scheme). MCC+MNC+MSIN structure preserved.
// Input: full IMSI string. Output: bytes matching original length for replacement.
// Returns empty if encoding fails or length mismatch.
std::vector<uint8_t> encode_5gs_suci_imsi(const std::string& imsi, size_t expected_len);

// Encode IMSI to 5G SUPI format (same as EPS - odd/even + type 001 + TBCD).
std::vector<uint8_t> encode_5gs_supi_imsi(const std::string& imsi);

}  // namespace signalbridge
