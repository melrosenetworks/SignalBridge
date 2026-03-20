/*
 * SignalBridge - NAS IMSI discovery via asn1c-generated decoders (placeholder)
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 *
 * When SIGNALBRIDGE_USE_ASN1C_NAS is enabled, this TU is linked. Replace the
 * body of nas_collect_imsi_occurrences_asn1c with PER decode of Rel-17 NAS
 * ASN.1 (TS 24.301 / 24.501) once generated sources are added — see
 * docs/ASN1C_NAS.md and scripts/generate_nas_asn1c.sh.
 */

#if defined(SIGNALBRIDGE_USE_ASN1C_NAS)

#include "signalbridge/nas_identity_provider.h"

namespace signalbridge {

void nas_collect_imsi_occurrences_asn1c(const uint8_t* nas_bytes, size_t len,
                                        std::vector<NasImsiWireOccurrence>& out) {
    (void)nas_bytes;
    (void)len;
    out.clear();
    // TODO: map PER-decoded NAS IEs into NasImsiWireOccurrence; until then keep parity with tests:
    nas_collect_imsi_occurrences_manual(nas_bytes, len, out);
}

}  // namespace signalbridge

#endif  // SIGNALBRIDGE_USE_ASN1C_NAS
