/*
 * SignalBridge - Manual NAS IMSI discovery (S1-SEE + 5GS helpers)
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/nas_identity_provider.h"
#include "signalbridge/nas_5gs_parser.h"
#include "nas_parser.h"

namespace signalbridge {

void nas_collect_imsi_occurrences_manual(const uint8_t* nas_bytes, size_t len,
                                         std::vector<NasImsiWireOccurrence>& out) {
    out.clear();
    if (!nas_bytes || len < 3) return;

    auto identities = nas_parser::extractMobileIdentity(nas_bytes, len);
    if (identities.empty()) {
        identities = nas_parser::decodeStructuredNas(nas_bytes, len);
    }
    for (const auto& id : identities) {
        if (id.identity_type != nas_parser::MobileIdentityType::IMSI || !id.valid) continue;
        if (id.identity_string.empty()) continue;
        NasImsiWireOccurrence w;
        w.imsi_digits = id.identity_string;
        w.wire_bytes = id.identity_bytes;
        w.encoding = NasImsiWireEncoding::EpsMobileIdentityTbcd;
        out.push_back(std::move(w));
    }

    auto ids_5gs = extract_5gs_mobile_identities(nas_bytes, len);
    for (const auto& id : ids_5gs) {
        if (!id.valid || id.imsi.empty() || id.bytes.empty()) continue;
        NasImsiWireOccurrence w;
        w.imsi_digits = id.imsi;
        w.wire_bytes = id.bytes;
        w.encoding = (id.bytes[0] == 0x01 && id.bytes.size() >= 8)
                         ? NasImsiWireEncoding::FiveGsSuciImsi
                         : NasImsiWireEncoding::FiveGsSupiImsi;
        out.push_back(std::move(w));
    }
}

}  // namespace signalbridge
