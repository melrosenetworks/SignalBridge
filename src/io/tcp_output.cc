/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/io/tcp_output.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace signalbridge {

namespace {

bool parse_tcp_address(const std::string& address, std::string& host, uint16_t& port) {
    if (address.size() < 10 || address.compare(0, 6, "tcp://") != 0) return false;
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

bool send_all(int sock, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock, p + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

}  // namespace

std::unique_ptr<TcpOutput> TcpOutput::create(const std::string& address,
                                             std::function<int()> link_type_getter) {
    std::string host;
    uint16_t port;
    if (!parse_tcp_address(address, host, port)) {
        std::cerr << "Invalid TCP address '" << address << "', expected tcp://host:port\n";
        return nullptr;
    }
    return std::unique_ptr<TcpOutput>(new TcpOutput(host, port, std::move(link_type_getter)));
}

TcpOutput::TcpOutput(const std::string& host, uint16_t port,
                     std::function<int()> link_type_getter)
    : host_(host), port_(port), link_type_getter_(std::move(link_type_getter)) {
    sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_ < 0) {
        std::cerr << "TCP socket: " << std::strerror(errno) << "\n";
        return;
    }
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    if (inet_pton(AF_INET, host_.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid TCP host '" << host_ << "'\n";
        close(sock_);
        sock_ = -1;
        return;
    }
    if (connect(sock_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "TCP connect to " << host_ << ":" << port_ << ": " << std::strerror(errno) << "\n";
        close(sock_);
        sock_ = -1;
        return;
    }
    valid_ = true;
}

TcpOutput::~TcpOutput() {
    finish();
}

bool TcpOutput::write_pcap_header(int link_type) {
    if (sock_ < 0) return false;
    struct pcap_file_header {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t linktype;
    } hdr = {};
    hdr.magic = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.linktype = (link_type >= 0) ? static_cast<uint32_t>(link_type) : 1u;
    return send_all(sock_, &hdr, sizeof(hdr));
}

bool TcpOutput::write_pcap_packet(const SignallingFrame& frame) {
    if (sock_ < 0 || frame.packet.empty()) return false;
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t caplen;
        uint32_t len;
    } pkthdr = {};
    pkthdr.ts_sec = static_cast<uint32_t>(frame.timestamp_sec);
    pkthdr.ts_usec = static_cast<uint32_t>(frame.timestamp_usec);
    pkthdr.caplen = static_cast<uint32_t>(frame.packet.size());
    pkthdr.len = pkthdr.caplen;
    if (!send_all(sock_, &pkthdr, sizeof(pkthdr))) return false;
    return send_all(sock_, frame.packet.data(), frame.packet.size());
}

bool TcpOutput::write(const SignallingFrame& frame) {
    if (!valid_ || sock_ < 0) return false;
    if (!header_written_) {
        int lt = link_type_getter_ ? link_type_getter_() : 1;
        if (!write_pcap_header(lt)) return false;
        header_written_ = true;
    }
    return write_pcap_packet(frame);
}

void TcpOutput::finish() {
    if (sock_ >= 0) {
        shutdown(sock_, SHUT_WR);
        close(sock_);
        sock_ = -1;
    }
}

}  // namespace signalbridge
