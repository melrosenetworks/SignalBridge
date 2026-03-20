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

// Async PCAP file output: frames are queued and written by a worker thread,
// so slow disk I/O does not block processing.
class AsyncPcapOutput {
public:
    // Create output for the given path. link_type_getter is called when writing the first frame
    // (for TCP input, link type is known only after the stream starts).
    static std::unique_ptr<AsyncPcapOutput> create(const std::string& path,
                                                   std::function<int()> link_type_getter);

    ~AsyncPcapOutput();

    AsyncPcapOutput(const AsyncPcapOutput&) = delete;
    AsyncPcapOutput& operator=(const AsyncPcapOutput&) = delete;

    // Queue frame for writing. Non-blocking, returns immediately.
    bool write(const SignallingFrame& frame);

    // Signal end of stream and wait for queue to drain.
    void finish();

    // Current number of frames queued. Thread-safe.
    size_t queue_size() const;

private:
    AsyncPcapOutput(const std::string& path, std::function<int()> link_type_getter);

    std::string path_;
    std::function<int()> link_type_getter_;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace signalbridge
