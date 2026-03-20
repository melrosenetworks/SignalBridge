/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 *
 * Anonymisation follows S1APAnonymise: replace IMSI with unique pseudonyms
 * (MCC/MNC prefix + counter), maintain mapping for consistency across packets.
 */

#include "signalbridge/pipeline/anonymiser.h"
#include "signalbridge/nas_identity_provider.h"
#include "signalbridge/ngap_parser.h"
#include "signalbridge/nas_5gs_parser.h"
#include "signalbridge/pipeline/frame_extractor.h"
#include "nas_parser.h"
#include "s1ap_parser.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace signalbridge {

namespace {

// Hex string to bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::string h;
    h.reserve(hex.size());
    for (char c : hex) {
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            h += c;
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(h.size() / 2);
    auto hex2byte = [](char a, char b) -> uint8_t {
        auto d = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        return static_cast<uint8_t>((d(a) << 4) | d(b));
    };
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        bytes.push_back(hex2byte(h[i], h[i + 1]));
    }
    return bytes;
}

// Encode IMSI digits to NAS Mobile identity content (3GPP TS 24.301).
// Octet 1: high nibble odd/even+type(001), low nibble first digit.
// Octets 2..N: digits packed low/high nibbles; last octet high nibble 0xF if odd.
std::vector<uint8_t> encode_nas_imsi_identity(const std::string& digits) {
    if (digits.empty()) return {};
    for (char c : digits)
        if (c < '0' || c > '9') return {};

    bool odd = (digits.size() % 2 == 1);
    uint8_t high = static_cast<uint8_t>(odd ? 0x9 : 0x1);  // odd/even + IMSI type 001
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>((high << 4) | (digits[0] - '0')));

    for (size_t i = 1; i < digits.size(); ) {
        uint8_t d_low = static_cast<uint8_t>(digits[i] - '0');
        if (i + 1 < digits.size()) {
            uint8_t d_high = static_cast<uint8_t>(digits[i + 1] - '0');
            out.push_back(static_cast<uint8_t>((d_high << 4) | d_low));
            i += 2;
        } else {
            out.push_back(static_cast<uint8_t>((0xF << 4) | d_low));
            i += 1;
        }
    }
    return out;
}

int anonymise_s1ap_imsi(std::vector<uint8_t>& /*packet*/,
                        const s1ap_parser::S1apParseResult& /*parse_result*/,
                        uint8_t /*replacement*/) {
    return 0;
}

// Plain EPS NAS (24.301): first octet security header (0=plain) + PD 7 (EMM) => 0x07, then message type.
// S1AP NAS-PDU IE values sometimes prepend PER/padding octets (e.g. 0x17 00..00) before that 0x07.
// The old heuristic (nas[0] & 0x0F) == 7 treats 0x17 as EMM and mis-skips 6 bytes, so IMSI is never found.
bool is_plausible_eps_emm_message_type(uint8_t mt) {
    switch (mt) {
    case 0x41:  // Attach request
    case 0x42:  // Attach accept
    case 0x43:  // Attach complete
    case 0x44:  // Attach reject
    case 0x45:  // Detach request
    case 0x46:  // Detach accept
    case 0x48:  // Tracking area update request
    case 0x49:  // Tracking area update accept
    case 0x4a:  // Tracking area update reject
    case 0x4c:  // EPS authentication request
    case 0x4d:  // Service request
    case 0x4e:  // Service reject
    case 0x50:  // CS notification
    case 0x52:  // Authentication reject
    case 0x53:  // Authentication failure
    case 0x54:  // Security mode command
    case 0x55:  // Security mode reject
    case 0x56:  // Identity response
    case 0x5c:  // EMM status
    case 0x5e:  // Security mode complete
        return true;
    default:
        return false;
    }
}

// If found, sets *out_off to the offset of the plain EMM header (0x07). Returns false if not found.
bool find_embedded_eps_nas_offset(const uint8_t* data, size_t len, size_t* out_off) {
    if (!data || len < 2 || !out_off) return false;
    auto match = [](uint8_t a, uint8_t b) {
        return a == 0x07 && is_plausible_eps_emm_message_type(b);
    };
    if (match(data[0], data[1])) {
        *out_off = 0;
        return true;
    }
    constexpr size_t kMaxScan = 64;
    for (size_t i = 1; i + 1 < len && i < kMaxScan; ++i) {
        if (match(data[i], data[i + 1])) {
            *out_off = i;
            return true;
        }
    }
    return false;
}

}  // namespace

std::string Anonymiser::anonymise_imsi_same_length(const std::string& imsi) {
    auto it = imsi_map_.find(imsi);
    if (it != imsi_map_.end()) return it->second;

    std::string prefix = config_.mcc + config_.mnc;
    int imsi_len = static_cast<int>(imsi.size());
    int remaining_len = std::max(0, imsi_len - static_cast<int>(prefix.size()));

    int next_counter = imsi_length_to_next_counter_[imsi_len];
    std::string counter_str;
    if (remaining_len > 0) {
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(remaining_len) << next_counter;
        counter_str = oss.str();
    }
    std::string anonymised = (prefix + counter_str).substr(0, static_cast<size_t>(imsi_len));

    imsi_map_[imsi] = anonymised;
    imsi_length_to_next_counter_[imsi_len] = next_counter + 1;
    return anonymised;
}

int Anonymiser::anonymise_imsi_in_nas(uint8_t* nas_bytes, size_t len) {
    if (!nas_bytes || len < 3) return 0;

    int count = 0;

    std::vector<NasImsiWireOccurrence> occurrences;
    nas_collect_imsi_occurrences(nas_bytes, len, occurrences);

    for (const auto& occ : occurrences) {
        if (occ.imsi_digits.empty()) continue;

        std::string fake = anonymise_imsi_same_length(occ.imsi_digits);
        std::vector<uint8_t> new_bytes;
        if (occ.encoding == NasImsiWireEncoding::EpsMobileIdentityTbcd) {
            new_bytes = encode_nas_imsi_identity(fake);
        } else if (occ.encoding == NasImsiWireEncoding::FiveGsSuciImsi) {
            new_bytes = encode_5gs_suci_imsi(fake, occ.wire_bytes.size());
        } else {
            new_bytes = encode_5gs_supi_imsi(fake);
        }
        if (new_bytes.empty()) continue;

        const std::vector<uint8_t>* to_replace = &occ.wire_bytes;
        std::vector<uint8_t> search_bytes;
        if (occ.encoding == NasImsiWireEncoding::EpsMobileIdentityTbcd && occ.wire_bytes.empty()) {
            search_bytes = encode_nas_imsi_identity(occ.imsi_digits);
            if (search_bytes.size() != new_bytes.size()) continue;
            to_replace = &search_bytes;
        }
        if (to_replace->empty() || to_replace->size() != new_bytes.size()) continue;

        const auto& ib = *to_replace;
        auto it = std::search(nas_bytes, nas_bytes + len, ib.begin(), ib.end());
        while (it != nas_bytes + len) {
            std::copy(new_bytes.begin(), new_bytes.end(), it);
            count++;
            it = std::search(it + ib.size(), nas_bytes + len, ib.begin(), ib.end());
        }
    }
    return count;
}

int Anonymiser::anonymise_imsi_in_nas_legacy(uint8_t* nas_bytes, size_t len, uint8_t replacement) {
    if (!nas_bytes || len < 3) return 0;

    auto identities = nas_parser::extractMobileIdentity(nas_bytes, len);
    int count = 0;
    for (const auto& id : identities) {
        if (id.identity_type != nas_parser::MobileIdentityType::IMSI || !id.valid) continue;
        if (id.identity_bytes.empty()) continue;

        const auto& ib = id.identity_bytes;
        auto it = std::search(nas_bytes, nas_bytes + len, ib.begin(), ib.end());
        while (it != nas_bytes + len) {
            std::fill(it, it + ib.size(), replacement);
            count++;
            it = std::search(it + ib.size(), nas_bytes + len, ib.begin(), ib.end());
        }
    }
    return count;
}

int Anonymiser::anonymise_nas_in_packet(std::vector<uint8_t>& packet,
                                        const std::string& nas_pdu_hex) {
    std::vector<uint8_t> nas_orig = hex_to_bytes(nas_pdu_hex);
    if (nas_orig.size() < 2) return 0;

    std::vector<uint8_t> nas_anon = nas_orig;
    // Locate EPS NAS inside NAS-PDU (skip S1AP/PER prefix before plain 0x07 + EMM type).
    size_t payload_off = 0;
    size_t embedded = 0;
    if (find_embedded_eps_nas_offset(nas_orig.data(), nas_orig.size(), &embedded)) {
        payload_off = embedded;
    } else {
        // Legacy: leading length octet (e.g. 0x0d) before NAS, or full buffer is NAS/5GS.
        payload_off = ((nas_orig[0] & 0x0F) == 0x07) ? 0 : 1;
    }
    size_t payload_len = nas_orig.size() - payload_off;
    if (payload_len < 2) return 0;

    int count;
    if (!config_.mcc.empty()) {
        count = anonymise_imsi_in_nas(nas_anon.data() + payload_off, payload_len);
    } else {
        count = anonymise_imsi_in_nas_legacy(nas_anon.data() + payload_off, payload_len,
                                            config_.replacement_byte);
    }
    if (count == 0) return 0;

    auto it = packet.begin();
    while ((it = std::search(it, packet.end(), nas_orig.begin(), nas_orig.end())) != packet.end()) {
        std::copy(nas_anon.begin(), nas_anon.end(), it);
        it += nas_orig.size();
    }
    return count;
}

Anonymiser::Anonymiser(const AnonymisationConfig& config) : config_(config) {}

int Anonymiser::anonymise(SignallingFrame& frame) {
    if (!config_.enabled) return 0;

    int total = 0;
    constexpr uint32_t PPID_S1AP = 18;
    constexpr uint32_t PPID_NGAP = 60;

    // Process ALL NAS-PDUs from every SCTP chunk (frame.nas_pdu_hex may only hold the last one)
    auto sctp_results = extract_all_sctp_payloads(frame.packet.data(), frame.packet.size());
    std::set<std::string> processed_nas_hex;  // avoid re-processing identical NAS

    for (const auto& sctp_result : sctp_results) {
        if (sctp_result.ppid == PPID_S1AP) {
            auto parse_result = s1ap_parser::parseS1apPdu(sctp_result.payload.data(),
                                                         sctp_result.payload.size());
            if (!parse_result.decoded) continue;
            auto nas_it = parse_result.information_elements.find("NAS-PDU");
            if (nas_it != parse_result.information_elements.end()) {
                std::string nas_pdu_hex = nas_it->second;
                if (!nas_pdu_hex.empty() && processed_nas_hex.insert(nas_pdu_hex).second)
                    total += anonymise_nas_in_packet(frame.packet, nas_pdu_hex);
            }
            if (parse_result.procedure_code == 9) {
                auto erab_it = parse_result.information_elements.find("E-RABToBeSetupListCtxtSUReq");
                if (erab_it != parse_result.information_elements.end()) {
                    auto nas_list = s1ap_parser::extractNasPdusFromErabListCtxtSUReq(erab_it->second);
                    for (const auto& nas_hex : nas_list) {
                        if (!nas_hex.empty() && processed_nas_hex.insert(nas_hex).second)
                            total += anonymise_nas_in_packet(frame.packet, nas_hex);
                    }
                }
            }
        } else if (sctp_result.ppid == PPID_NGAP) {
            NgapParseResult parse_result = parse_ngap_pdu_full(sctp_result.payload.data(),
                                                              sctp_result.payload.size());
            if (!parse_result.decoded) continue;
            auto nas_it = parse_result.information_elements.find("NAS-PDU");
            if (nas_it != parse_result.information_elements.end()) {
                std::string nas_pdu_hex = nas_it->second;
                if (!nas_pdu_hex.empty() && processed_nas_hex.insert(nas_pdu_hex).second)
                    total += anonymise_nas_in_packet(frame.packet, nas_pdu_hex);
            }
        }
    }

    // Fallback: when packet has no SCTP structure (e.g. unit tests), use frame.nas_pdu_hex
    if (total == 0 && frame.nas_pdu_hex && !frame.nas_pdu_hex->empty() &&
        processed_nas_hex.insert(*frame.nas_pdu_hex).second) {
        total += anonymise_nas_in_packet(frame.packet, *frame.nas_pdu_hex);
    }

    return total;
}

bool Anonymiser::has_encrypted_nas(const SignallingFrame& frame) {
    return frame.has_encrypted_nas;
}

void Anonymiser::set_config(const AnonymisationConfig& config) {
    config_ = config;
}

bool Anonymiser::write_imsi_map() const {
    if (config_.imsi_map_path.empty() || imsi_map_.empty()) return true;

    std::ofstream out(config_.imsi_map_path);
    if (!out) return false;
    for (const auto& [orig, anon] : imsi_map_) {
        out << orig << " -> " << anon << "\n";
    }
    return out.good();
}

}  // namespace signalbridge
