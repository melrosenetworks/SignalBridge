/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/metrics/metrics_server.h"
#include "signalbridge/io/tcp_io.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace signalbridge {

namespace {

constexpr const char* HTTP_200 =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain; charset=utf-8; version=0.0.4\r\n"
    "Connection: close\r\n"
    "\r\n";

constexpr const char* HTTP_404 =
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: text/plain\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Not Found";

bool parse_address(const std::string& address, std::string& host, uint16_t& port) {
    return TcpIo::parse_address(address, host, port);
}

}  // namespace

MetricsServer::MetricsServer(Metrics& metrics) : metrics_(metrics) {}

MetricsServer::~MetricsServer() {
    stop();
}

bool MetricsServer::start(const std::string& address) {
    if (running_) {
        std::cerr << "Metrics server already running\n";
        return false;
    }

    std::string host;
    uint16_t port;
    if (!parse_address(address, host, port)) {
        std::cerr << "Invalid metrics address '" << address << "', expected host:port\n";
        return false;
    }

    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::cerr << "Metrics socket: " << std::strerror(errno) << "\n";
        return false;
    }

    int opt = 1;
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Metrics setsockopt: " << std::strerror(errno) << "\n";
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (host == "0.0.0.0" || host.empty()) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
        std::cerr << "Invalid metrics host '" << host << "'\n";
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    if (bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        std::cerr << "Metrics bind " << address << ": " << std::strerror(errno) << "\n";
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    if (listen(listen_fd_, 5) < 0) {
        std::cerr << "Metrics listen: " << std::strerror(errno) << "\n";
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    address_ = address;
    running_ = true;
    stop_requested_ = false;
    thread_ = std::make_unique<std::thread>(&MetricsServer::run, this);

    std::cout << "Prometheus metrics at http://" << address << "/metrics\n";
    return true;
}

void MetricsServer::stop() {
    if (!running_) return;
    stop_requested_ = true;
    if (listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        listen_fd_ = -1;
    }
    if (thread_ && thread_->joinable()) {
        thread_->join();
    }
    running_ = false;
}

void MetricsServer::run() {
    while (!stop_requested_) {
        int fd = listen_fd_;
        if (fd < 0) break;

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(fd, &read_fds);

        struct timeval tv = {1, 0};  // 1 second timeout
        int ret = select(fd + 1, &read_fds, nullptr, nullptr, &tv);
        if (ret < 0) {
            if (errno == EINTR || stop_requested_) break;
            std::cerr << "Metrics select: " << std::strerror(errno) << "\n";
            break;
        }
        if (ret == 0) continue;  // timeout
        if (!FD_ISSET(fd, &read_fds)) continue;

        struct sockaddr_in client_addr = {};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(fd, reinterpret_cast<struct sockaddr*>(&client_addr), &client_len);
        if (client_fd < 0) {
            if (stop_requested_) break;
            continue;
        }

        // Read request (simple: we only care about GET /metrics)
        char buf[512];
        ssize_t n = recv(client_fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            std::string request(buf);
            if (request.find("GET /metrics") == 0 || request.find("GET /metrics ") != std::string::npos ||
                request.find("GET /metrics?") != std::string::npos) {
                std::string body = metrics_.to_prometheus();
                send(client_fd, HTTP_200, std::strlen(HTTP_200), 0);
                send(client_fd, body.data(), body.size(), 0);
            } else {
                send(client_fd, HTTP_404, std::strlen(HTTP_404), 0);
            }
        }
        close(client_fd);
    }
}

}  // namespace signalbridge
