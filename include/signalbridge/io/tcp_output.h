/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/types.h"
#include <functional>
#include <memory>
#include <string>

namespace signalbridge {

// TCP output: streams PCAP format to host:port (global header + packet records).
// Compatible with TCP input (e.g. conduit -l listening for PCAP stream).
// Address format: tcp://host:port (e.g. tcp://127.0.0.1:50051)
class TcpOutput {
public:
    // link_type_getter is called when writing the first frame (for TCP input, link type
    // is known only after the stream starts). May return -1 for default (1).
    static std::unique_ptr<TcpOutput> create(const std::string& address,
                                              std::function<int()> link_type_getter);

    ~TcpOutput();

    TcpOutput(const TcpOutput&) = delete;
    TcpOutput& operator=(const TcpOutput&) = delete;

    // Stream frame as PCAP packet record. Returns true if sent successfully.
    bool write(const SignallingFrame& frame);

    // Close the connection gracefully.
    void finish();

    // Check if the output is valid (connected, header written).
    bool is_valid() const { return valid_; }

private:
    TcpOutput(const std::string& host, uint16_t port, std::function<int()> link_type_getter);

    bool write_pcap_header(int link_type);
    bool write_pcap_packet(const SignallingFrame& frame);

    std::string host_;
    uint16_t port_;
    int sock_{-1};
    std::function<int()> link_type_getter_;
    bool valid_{false};
    bool header_written_{false};
};

// Returns true if s starts with tcp://
inline bool is_tcp_url(const std::string& s) {
    return s.size() >= 9 && s.compare(0, 6, "tcp://") == 0;  // e.g. tcp://a:1
}

}  // namespace signalbridge
