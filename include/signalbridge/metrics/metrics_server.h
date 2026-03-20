/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/metrics/metrics.h"
#include <memory>
#include <string>
#include <thread>

namespace signalbridge {

// HTTP server that exposes Prometheus metrics at GET /metrics.
// Runs in a background thread. Call stop() to shut down.
class MetricsServer {
public:
    explicit MetricsServer(Metrics& metrics);
    ~MetricsServer();

    // Start listening on address (e.g. "127.0.0.1:9090"). Returns false on error.
    bool start(const std::string& address);

    // Stop the server and join the thread.
    void stop();

    bool is_running() const { return running_; }

private:
    void run();

    Metrics& metrics_;
    std::string address_;
    int listen_fd_{-1};
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::unique_ptr<std::thread> thread_;
};

}  // namespace signalbridge
