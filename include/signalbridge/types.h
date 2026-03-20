/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace signalbridge {

// Procedure info for a single SCTP DATA chunk (S1AP/NGAP)
struct ProcedureInfo {
    uint8_t procedure_code{0};
    std::string procedure_name;
    bool is_s1ap{true};
    bool has_encrypted_nas{false};
};

// Frame extracted from a packet (S1AP or NGAP). A single packet may contain
// multiple SCTP DATA chunks; procedures holds all of them.
struct SignallingFrame {
    std::vector<uint8_t> packet;           // Full packet (Ethernet + IP + SCTP + payload)
    uint64_t timestamp_sec{0};
    uint32_t timestamp_usec{0};
    uint32_t frame_number{0};
    std::vector<ProcedureInfo> procedures;  // All S1AP/NGAP chunks in this packet

    // First procedure (backward compatibility; same as procedures[0] when non-empty)
    uint8_t procedure_code{0};
    std::string procedure_name;
    bool is_s1ap{true};
    bool has_encrypted_nas{false};

    // NAS-PDU hex from S1AP parse (avoids re-parsing in anonymiser when set)
    std::optional<std::string> nas_pdu_hex;
};

// IP addresses extracted from packet (for filtering)
struct PacketIps {
    std::string src_ip;
    std::string dst_ip;
};

}  // namespace signalbridge
