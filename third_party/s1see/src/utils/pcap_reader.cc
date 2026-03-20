/*
 * Melrose Networks (Melrose Labs Ltd) - https://melrosenetworks.com
 * Date: 2026-01-04
 * Support: support@melrosenetworks.com
 * Disclaimer: Provided "as is" without warranty; use at your own risk.
 * Title: pcap_reader.cc
 * Description: Implementation of PCAP file reader utility for reading network packet
 *              captures. Provides functions to parse PCAP files and extract packet
 *              data with timestamps. Supports both libpcap and basic file reading
 *              depending on build configuration.
 */

#include "s1see/utils/pcap_reader.h"
#include <fstream>
#include <iostream>

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#endif

namespace s1see {
namespace utils {

int read_pcap_file(const std::string& pcap_path,
                   std::function<void(const PcapPacket&)> packet_callback) {
#ifdef HAVE_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(pcap_path.c_str(), errbuf);
    
    if (!pcap) {
        std::cerr << "Error opening PCAP file: " << errbuf << std::endl;
        return -1;
    }
    
    int packet_count = 0;
    struct pcap_pkthdr header;
    const u_char* packet_data;
    
    while ((packet_data = pcap_next(pcap, &header)) != nullptr) {
        packet_count++;  // Increment before creating packet (1-indexed frame numbers)
        PcapPacket pkt;
        pkt.timestamp_sec = header.ts.tv_sec;
        pkt.timestamp_usec = header.ts.tv_usec;
        pkt.captured_len = header.caplen;
        pkt.original_len = header.len;
        pkt.frame_number = packet_count;  // Set frame number (1-indexed)
        pkt.data.assign(packet_data, packet_data + header.caplen);
        
        packet_callback(pkt);
    }
    
    pcap_close(pcap);
    return packet_count;
#else
    std::cerr << "libpcap not available. Cannot read PCAP files." << std::endl;
    return -1;
#endif
}

} // namespace utils
} // namespace s1see

