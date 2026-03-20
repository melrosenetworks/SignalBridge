/*
 * Melrose Networks (Melrose Labs Ltd) - https://melrosenetworks.com
 * Date: 2026-01-04
 * Support: support@melrosenetworks.com
 * Disclaimer: Provided "as is" without warranty; use at your own risk.
 * Title: pcap_reader.h
 * Description: Header for PCAP file reader utility. Provides interface for reading
 *              network packet captures from PCAP files, extracting packet data with
 *              timestamps, and supporting both libpcap and basic file reading.
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace s1see {
namespace utils {

// PCAP packet structure
struct PcapPacket {
    uint64_t timestamp_sec;
    uint32_t timestamp_usec;
    uint32_t captured_len;
    uint32_t original_len;
    uint32_t frame_number;  // Frame number in PCAP file (1-indexed)
    std::vector<uint8_t> data;
};

// Read PCAP file and call callback for each packet
// Returns number of packets processed, or -1 on error
int read_pcap_file(const std::string& pcap_path,
                   std::function<void(const PcapPacket&)> packet_callback);

} // namespace utils
} // namespace s1see

