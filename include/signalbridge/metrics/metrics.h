/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <tuple>

namespace signalbridge {

// Thread-safe Prometheus metrics. Counters are atomic for concurrent access.
class Metrics {
public:
    Metrics() = default;

    void packets_received_inc();
    void messages_written_add(uint64_t n) { messages_written_.fetch_add(n, std::memory_order_relaxed); }
    void messages_filtered_add(uint64_t n) { messages_filtered_.fetch_add(n, std::memory_order_relaxed); }

    void bytes_in_add(uint64_t n) { bytes_in_.fetch_add(n, std::memory_order_relaxed); }
    void bytes_out_add(uint64_t n) { bytes_out_.fetch_add(n, std::memory_order_relaxed); }

    // Call when processing begins (for rate computation). Called automatically on first packet.
    void set_processing_started();

    // Set callbacks to report queue sizes (called when rendering metrics).
    // Input queue: none by default (returns 0). Output queue: set when using HTTP streaming.
    void set_input_queue_size_callback(std::function<size_t()> cb) { input_queue_size_cb_ = std::move(cb); }
    void set_output_queue_size_callback(std::function<size_t()> cb) { output_queue_size_cb_ = std::move(cb); }

    // Increment per-message-type counter (S1AP or NGAP by procedure code). One call per message.
    void messages_by_procedure_inc(uint8_t procedure_code, const std::string& procedure_name, bool is_s1ap);

    // HTTP output bytes (pre- and post-compression). Only used when HTTP output is active.
    void output_bytes_add(uint64_t precompression, uint64_t postcompression);

    // HTTP response code from endpoint (0 = no response, e.g. connection failed). One call per HTTP request.
    void http_response_code_inc(long response_code);

    // Increment per-protocol-stack counter at ingest (e.g. "eth_ipv4_sctp_s1ap"). One call per packet.
    void packets_by_protocol_stack_inc(const std::string& stack);

    uint64_t packets_received() const { return packets_received_.load(std::memory_order_relaxed); }
    uint64_t messages_written() const { return messages_written_.load(std::memory_order_relaxed); }
    uint64_t messages_filtered() const { return messages_filtered_.load(std::memory_order_relaxed); }

    // Render metrics in Prometheus exposition format (text/plain)
    std::string to_prometheus() const;

private:
    std::atomic<uint64_t> packets_received_{0};
    std::atomic<uint64_t> messages_written_{0};
    std::atomic<uint64_t> messages_filtered_{0};
    std::atomic<uint64_t> bytes_in_{0};
    std::atomic<uint64_t> bytes_out_{0};
    std::atomic<uint64_t> output_bytes_precompression_{0};
    std::atomic<uint64_t> output_bytes_postcompression_{0};

    std::atomic<uint64_t> processing_start_ns_{0};  // steady_clock nanoseconds

    std::function<size_t()> input_queue_size_cb_;
    std::function<size_t()> output_queue_size_cb_;

    mutable std::mutex procedure_mutex_;
    mutable std::mutex protocol_stack_mutex_;
    mutable std::mutex http_response_mutex_;
    std::map<std::tuple<int, std::string, std::string>, uint64_t> procedure_counts_;
    std::map<std::string, uint64_t> protocol_stack_counts_;
    std::map<long, uint64_t> http_response_counts_;
};

}  // namespace signalbridge
