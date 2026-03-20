/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/types.h"
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace signalbridge {

// UDP output: sends each frame in Wireshark Exported PDU format (tag 12 dissector name + packet).
// For Wireshark udpdump: set Payload to "exported_pdu" in capture options.
// Address format: udp://host:port (e.g. udp://127.0.0.1:50052)
class UdpOutput {
public:
    // link_type_getter returns pcap link type (1=eth, 113=sll) for dissector selection.
    static std::unique_ptr<UdpOutput> create(const std::string& address,
                                             std::function<int()> link_type_getter = nullptr);

    ~UdpOutput();

    UdpOutput(const UdpOutput&) = delete;
    UdpOutput& operator=(const UdpOutput&) = delete;

    // Send frame as UDP datagram (Exported PDU header + packet). Returns true if sent successfully.
    bool write(const SignallingFrame& frame);

    // Check if the output is valid (socket created, address resolved).
    bool is_valid() const { return valid_; }

private:
    UdpOutput(const std::string& host, uint16_t port, std::function<int()> link_type_getter);

    bool build_exported_pdu_payload(const SignallingFrame& frame, std::vector<uint8_t>& out);

    std::string host_;
    uint16_t port_;
    int sock_{-1};
    std::function<int()> link_type_getter_;
    bool valid_{false};
};

// Returns true if s starts with udp://
inline bool is_udp_url(const std::string& s) {
    return s.size() >= 9 && s.compare(0, 6, "udp://") == 0;  // e.g. udp://a:1
}

}  // namespace signalbridge
