/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 *
 * NGAP procedure code to name mapping per 3GPP TS 38.413.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace signalbridge {

// PDU type: 0=initiating (Request), 1=successful (Response), 2=unsuccessful (Failure)
enum class NgapPduType { Initiating = 0, Successful = 1, Unsuccessful = 2 };

// Full NGAP parse result (APER-decoded IEs, for anonymisation)
struct NgapParseResult {
    bool decoded{false};
    NgapPduType pdu_type{NgapPduType::Initiating};
    uint8_t procedure_code{0};
    std::string procedure_name;
    std::unordered_map<std::string, std::string> information_elements;
};

// Parse NGAP PDU (same APER structure as S1AP) and return procedure code and PDU type.
// Returns true if parsed successfully.
bool parse_ngap_pdu(const uint8_t* data, size_t len, uint8_t& procedure_code, NgapPduType& pdu_type);

// Full NGAP PDU parse: extract procedure code and all IEs (including NAS-PDU).
NgapParseResult parse_ngap_pdu_full(const uint8_t* data, size_t len);

// Extract first NGAP payload from SCTP packet (PPID 60).
std::optional<std::vector<uint8_t>> extract_ngap_from_sctp(const uint8_t* packet, size_t len);

// Return full message name (e.g. NGSetupRequest, NGSetupResponse, UplinkNASTransport)
// matching Wireshark's NGAP Packet Types.
std::string get_ngap_message_name(uint8_t procedure_code, NgapPduType pdu_type);

// Legacy: procedure name only (no Request/Response suffix)
std::string get_ngap_procedure_name(uint8_t procedure_code);

}  // namespace signalbridge
