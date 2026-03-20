/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include <functional>
#include <string>

namespace signalbridge {

// TCP listener: accepts connections and reads raw PCAP stream.
// Use with: tshark -r capture.pcap -w - | nc host port
class TcpIo {
public:
    // Listen on address (e.g. "0.0.0.0:50051" or "127.0.0.1:50051"),
    // accept one connection, read PCAP bytes from the stream, invoke callback per packet.
    // Callback receives (link_type, data, len, ts_sec, ts_usec, frame_num). Returns packet count or -1 on error.
    static int listen_and_read(const std::string& address,
                               std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback);

    // Like listen_and_read but accepts multiple connections in a loop.
    // before_accept: invoked before each accept(); return false to stop. If null, runs once.
    // Returns total packets across all connections, or -1 on error.
    static int listen_and_read_loop(const std::string& address,
                                    std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback,
                                    std::function<bool()> before_accept = nullptr);

    // Parse "host:port" into host and port. Returns false if invalid.
    static bool parse_address(const std::string& address, std::string& host, uint16_t& port);
};

}  // namespace signalbridge
