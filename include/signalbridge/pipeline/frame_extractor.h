/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/types.h"
#include <functional>
#include <optional>
#include <vector>

namespace signalbridge {

// SCTP DATA chunk payload with PPID (18=S1AP, 60=NGAP)
struct SctpPayloadResult {
    std::vector<uint8_t> payload;
    uint32_t ppid;
};

// Extract all SCTP DATA chunks with PPID 18 (S1AP) or 60 (NGAP) from a packet.
std::vector<SctpPayloadResult> extract_all_sctp_payloads(const uint8_t* packet, size_t len);

// Extracts S1AP/NGAP frames from packets. Uses S1-SEE s1ap_parser.
class FrameExtractor {
public:
    // Callback: (frame, packet_ips) -> true to continue, false to stop
    using FrameCallback = std::function<bool(const SignallingFrame&, const PacketIps&)>;

    // Process a single packet. Returns true if frame was extracted and passed to callback.
    bool process_packet(const uint8_t* data, size_t len,
                       uint64_t ts_sec, uint32_t ts_usec, uint32_t frame_num,
                       FrameCallback callback);

    // Check if packet contains S1AP (PayloadProtocolID 18)
    static bool has_s1ap(const uint8_t* data, size_t len);

    // Check if packet contains NGAP (PayloadProtocolID 60)
    static bool has_ngap(const uint8_t* data, size_t len);

    // Get protocol stack string for Prometheus (e.g. "eth_ipv4_sctp_s1ap", "eth_ipv6_sctp_ngap").
    static std::string get_protocol_stack(const uint8_t* data, size_t len, bool is_s1ap);

    // Check if packet contains SCTP (any PPID).
    static bool has_sctp(const uint8_t* data, size_t len);

    // Get SCTP-only protocol stack (e.g. "eth_ipv4_sctp") for ingest-level metrics.
    static std::string get_protocol_stack_sctp(const uint8_t* data, size_t len);
};

}  // namespace signalbridge
