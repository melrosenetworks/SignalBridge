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

class Metrics;

// Streaming HTTP/HTTPS output: batches frames (up to 1000 or 1s), compresses with gzip,
// and POSTs each batch in a single HTTP request to reduce bytes transmitted.
class HttpStreamOutput {
public:
    // Create output for the given URL (http:// or https://).
    // metrics may be null; if non-null, output bytes (pre/post compression) are reported.
    // encryption_key: when non-empty (hex-encoded 32-byte key), encrypts output with AES-256-GCM.
    // Returns nullptr if URL is invalid or curl init fails.
    static std::unique_ptr<HttpStreamOutput> create(const std::string& url, Metrics* metrics = nullptr,
                                                    const std::string& encryption_key = "");

    ~HttpStreamOutput();

    HttpStreamOutput(const HttpStreamOutput&) = delete;
    HttpStreamOutput& operator=(const HttpStreamOutput&) = delete;

    // Write a frame to the stream. Thread-safe.
    bool write(const SignallingFrame& frame);

    // Signal end of stream and wait for upload to complete.
    void finish();

    // Current number of frames queued for upload. Thread-safe.
    size_t queue_size() const;

    // Check if the output is valid (connection succeeded).
    bool is_valid() const { return valid_; }

private:
    struct Impl;

    HttpStreamOutput(const std::string& url, Metrics* metrics = nullptr,
                     const std::string& encryption_key = "");
    bool init();
    static void worker_loop(Impl* impl);

    std::string url_;
    bool valid_{false};
    std::unique_ptr<Impl> impl_;
};

// Returns true if the string looks like an HTTP(S) URL.
inline bool is_http_url(const std::string& s) {
    return s.size() >= 8 && (s.compare(0, 7, "http://") == 0 || s.compare(0, 8, "https://") == 0);
}

}  // namespace signalbridge
