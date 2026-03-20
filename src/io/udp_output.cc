/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/io/udp_output.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#if defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

namespace signalbridge {

namespace {

// Wireshark Exported PDU TLV tags (wsutil/exported_pdu_tlvs.h)
constexpr uint16_t EXP_PDU_TAG_END_OF_OPT = 0;
constexpr uint16_t EXP_PDU_TAG_DISSECTOR_NAME = 12;

// pcap link types -> Wireshark dissector names for link layer
// DLT_EN10MB=1 (Ethernet), DLT_LINUX_SLL=113 (Linux cooked)
const char* dissector_for_link_type(int lt) {
    if (lt == 1) return "eth";   // DLT_EN10MB
    if (lt == 113) return "sll"; // DLT_LINUX_SLL
    return "sll";                // default
}

bool parse_udp_address(const std::string& address, std::string& host, uint16_t& port) {
    if (address.size() < 10 || address.compare(0, 6, "udp://") != 0) return false;
    std::string rest = address.substr(6);
    size_t colon = rest.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon == rest.size() - 1) return false;
    host = rest.substr(0, colon);
    try {
        int p = std::stoi(rest.substr(colon + 1));
        if (p < 1 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } catch (...) {
        return false;
    }
    return true;
}

}  // namespace

std::unique_ptr<UdpOutput> UdpOutput::create(const std::string& address,
                                             std::function<int()> link_type_getter) {
    std::string host;
    uint16_t port;
    if (!parse_udp_address(address, host, port)) {
        std::cerr << "Invalid UDP address '" << address << "', expected udp://host:port\n";
        return nullptr;
    }
    return std::unique_ptr<UdpOutput>(new UdpOutput(host, port, std::move(link_type_getter)));
}

UdpOutput::UdpOutput(const std::string& host, uint16_t port,
                     std::function<int()> link_type_getter)
    : host_(host), port_(port), link_type_getter_(std::move(link_type_getter)) {
    sock_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0) {
        std::cerr << "UDP socket: " << std::strerror(errno) << "\n";
        return;
    }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid UDP host '" << host_ << "'\n";
        close(sock_);
        sock_ = -1;
        return;
    }
    valid_ = true;
}

UdpOutput::~UdpOutput() {
    if (sock_ >= 0) {
        close(sock_);
        sock_ = -1;
    }
}

bool UdpOutput::build_exported_pdu_payload(const SignallingFrame& frame, std::vector<uint8_t>& out) {
    const char* dissector = dissector_for_link_type(
        link_type_getter_ ? link_type_getter_() : 113);
    size_t dlen = std::strlen(dissector);
    size_t pad = (4 - (dlen % 4)) % 4;  // pad value to 32-bit boundary
    out.clear();
    out.reserve(8 + dlen + pad + 4 + frame.packet.size());
    uint16_t tag12 = htobe16(EXP_PDU_TAG_DISSECTOR_NAME);
    uint16_t len12 = htobe16(static_cast<uint16_t>(dlen));
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&tag12), reinterpret_cast<uint8_t*>(&tag12) + 2);
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&len12), reinterpret_cast<uint8_t*>(&len12) + 2);
    out.insert(out.end(), dissector, dissector + dlen);
    out.insert(out.end(), pad, 0);
    uint16_t tag0 = htobe16(EXP_PDU_TAG_END_OF_OPT);
    uint16_t len0 = 0;
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&tag0), reinterpret_cast<uint8_t*>(&tag0) + 2);
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&len0), reinterpret_cast<uint8_t*>(&len0) + 2);
    out.insert(out.end(), frame.packet.begin(), frame.packet.end());
    return true;
}

bool UdpOutput::write(const SignallingFrame& frame) {
    if (!valid_ || sock_ < 0 || frame.packet.empty()) return false;

    std::vector<uint8_t> payload;
    if (!build_exported_pdu_payload(frame, payload)) return false;

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) return false;

    ssize_t sent = sendto(sock_, payload.data(), payload.size(), 0,
                          reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    return sent == static_cast<ssize_t>(payload.size());
}

}  // namespace signalbridge
