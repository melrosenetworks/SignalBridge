/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/io/pcap_io.h"
#include "signalbridge/io/tcp_io.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace signalbridge {

namespace {
}  // namespace

bool TcpIo::parse_address(const std::string& address, std::string& host, uint16_t& port) {
    size_t colon = address.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon == address.size() - 1) {
        return false;
    }
    host = address.substr(0, colon);
    try {
        int p = std::stoi(address.substr(colon + 1));
        if (p < 1 || p > 65535) return false;
        port = static_cast<uint16_t>(p);
    } catch (...) {
        return false;
    }
    return true;
}

int TcpIo::listen_and_read(const std::string& address,
                           std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback) {
    std::string host;
    uint16_t port;
    if (!parse_address(address, host, port)) {
        std::cerr << "Invalid address '" << address << "', expected host:port\n";
        return -1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "socket: " << std::strerror(errno) << "\n";
        return -1;
    }

    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt: " << std::strerror(errno) << "\n";
        close(listen_fd);
        return -1;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host == "0.0.0.0" || host.empty()) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid host '" << host << "'\n";
        close(listen_fd);
        return -1;
    }

    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind " << address << ": " << std::strerror(errno) << "\n";
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 1) < 0) {
        std::cerr << "listen: " << std::strerror(errno) << "\n";
        close(listen_fd);
        return -1;
    }

    std::cout << "Listening on " << address << " (tshark -r f.pcap -w - | nc " << (host == "0.0.0.0" ? "localhost" : host) << " " << port << ")\n";

    struct sockaddr_in client_addr = {};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
    close(listen_fd);
    if (client_fd < 0) {
        std::cerr << "accept: " << std::strerror(errno) << "\n";
        return -1;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
    std::cout << "Accepted connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";

    int count = PcapIo::read_stream_from_fd(client_fd, callback);
    close(client_fd);
    return count;
}

int TcpIo::listen_and_read_loop(const std::string& address,
                                std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback,
                                std::function<bool()> before_accept) {
    std::string host;
    uint16_t port;
    if (!parse_address(address, host, port)) {
        std::cerr << "Invalid address '" << address << "', expected host:port\n";
        return -1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "socket: " << std::strerror(errno) << "\n";
        return -1;
    }

    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "setsockopt: " << std::strerror(errno) << "\n";
        close(listen_fd);
        return -1;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host == "0.0.0.0" || host.empty()) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid host '" << host << "'\n";
        close(listen_fd);
        return -1;
    }

    if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "bind " << address << ": " << std::strerror(errno) << "\n";
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 1) < 0) {
        std::cerr << "listen: " << std::strerror(errno) << "\n";
        close(listen_fd);
        return -1;
    }

    std::cout << "Listening on " << address << " (tshark -r f.pcap -w - | nc " << (host == "0.0.0.0" ? "localhost" : host) << " " << port << ")\n";

    int total = 0;
    while (true) {
        if (before_accept && !before_accept()) {
            break;
        }

        struct sockaddr_in client_addr = {};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) {
            std::cerr << "accept: " << std::strerror(errno) << "\n";
            close(listen_fd);
            return total > 0 ? total : -1;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        std::cout << "Accepted connection from " << client_ip << ":" << ntohs(client_addr.sin_port) << "\n";

        int n = PcapIo::read_stream_from_fd(client_fd, callback);
        close(client_fd);

        if (n < 0) {
            // In loop mode, a probe or non-PCAP client must not kill the listener (common on 0.0.0.0).
            if (before_accept) {
                std::cerr << "Still listening (--loop); send PCAP/PCAPNG (e.g. "
                             "tshark -r f.pcap -w - | nc HOST PORT).\n";
                continue;
            }
            close(listen_fd);
            return total > 0 ? total : -1;
        }
        total += n;

        if (!before_accept) {
            break;  // Run once when no before_accept
        }
    }

    close(listen_fd);
    return total;
}

}  // namespace signalbridge
