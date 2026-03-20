/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/config.h"
#include "signalbridge/types.h"
#include <map>
#include <string>
#include <vector>

namespace signalbridge {

// Anonymises IMSI in S1AP/NAS PDUs. Replaces with unique pseudonyms (MCC/MNC + counter),
// maintains mapping for consistency (S1APAnonymise-style).
class Anonymiser {
public:
    explicit Anonymiser(const AnonymisationConfig& config);

    // Anonymise frame in place. Returns number of IMSIs replaced.
    int anonymise(SignallingFrame& frame);

    // Check if frame has encrypted NAS (should be dropped if drop_encrypted_nas).
    static bool has_encrypted_nas(const SignallingFrame& frame);

    void set_config(const AnonymisationConfig& config);

    // Write IMSI mapping (original -> anonymised) to file. Call when processing completes.
    bool write_imsi_map() const;

private:
    std::string anonymise_imsi_same_length(const std::string& imsi);
    int anonymise_imsi_in_nas(uint8_t* nas_bytes, size_t len);
    int anonymise_imsi_in_nas_legacy(uint8_t* nas_bytes, size_t len, uint8_t replacement);
    int anonymise_nas_in_packet(std::vector<uint8_t>& packet, const std::string& nas_pdu_hex);

    AnonymisationConfig config_;
    std::map<std::string, std::string> imsi_map_;
    std::map<int, int> imsi_length_to_next_counter_;
};

}  // namespace signalbridge
