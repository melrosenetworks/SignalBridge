/*
 * SignalBridge - NAS IMSI discovery for anonymisation
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 *
 * Build-time selection: SIGNALBRIDGE_USE_ASN1C_NAS=ON (default) uses the asn1c
 * entry point (see nas_identity_asn1c.cc; delegates to manual until wired).
 * OFF selects manual parsing only (S1-SEE + 5GS helpers).
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace signalbridge {

enum class NasImsiWireEncoding {
    EpsMobileIdentityTbcd,
    FiveGsSupiImsi,
    FiveGsSuciImsi,
};

struct NasImsiWireOccurrence {
    std::string imsi_digits;
    std::vector<uint8_t> wire_bytes;
    NasImsiWireEncoding encoding{NasImsiWireEncoding::EpsMobileIdentityTbcd};
};

// Manual path: S1-SEE nas_parser + decodeStructuredNas + 5GS extract_5gs_mobile_identities.
void nas_collect_imsi_occurrences_manual(const uint8_t* nas_bytes, size_t len,
                                         std::vector<NasImsiWireOccurrence>& out);

#if defined(SIGNALBRIDGE_USE_ASN1C_NAS)
// asn1c path: generated PER decoders (TS 24.301 / 24.501) — placeholder delegates to manual until wired.
void nas_collect_imsi_occurrences_asn1c(const uint8_t* nas_bytes, size_t len,
                                        std::vector<NasImsiWireOccurrence>& out);
#endif

inline void nas_collect_imsi_occurrences(const uint8_t* nas_bytes, size_t len,
                                         std::vector<NasImsiWireOccurrence>& out) {
    out.clear();
#if defined(SIGNALBRIDGE_USE_ASN1C_NAS)
    nas_collect_imsi_occurrences_asn1c(nas_bytes, len, out);
#else
    nas_collect_imsi_occurrences_manual(nas_bytes, len, out);
#endif
}

}  // namespace signalbridge
