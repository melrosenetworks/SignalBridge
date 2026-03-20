/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/metrics/metrics.h"
#include <chrono>
#include <sstream>

namespace signalbridge {

namespace {

// Escape Prometheus label value: \ -> \\, " -> \"
std::string escape_label(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else out += c;
    }
    return out;
}

}  // namespace

void Metrics::packets_received_inc() {
    uint64_t expected = 0;
    if (packets_received_.compare_exchange_strong(expected, 1, std::memory_order_relaxed)) {
        set_processing_started();
    } else {
        packets_received_.fetch_add(1, std::memory_order_relaxed);
    }
}

void Metrics::set_processing_started() {
    uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count();
    uint64_t expected = 0;
    processing_start_ns_.compare_exchange_strong(expected, now_ns, std::memory_order_relaxed);
}

void Metrics::messages_by_procedure_inc(uint8_t procedure_code, const std::string& procedure_name, bool is_s1ap) {
    const std::string protocol = is_s1ap ? "s1ap" : "ngap";
    auto key = std::make_tuple(static_cast<int>(procedure_code), procedure_name, protocol);
    std::lock_guard<std::mutex> lock(procedure_mutex_);
    procedure_counts_[key]++;
}

void Metrics::output_bytes_add(uint64_t precompression, uint64_t postcompression) {
    output_bytes_precompression_.fetch_add(precompression, std::memory_order_relaxed);
    output_bytes_postcompression_.fetch_add(postcompression, std::memory_order_relaxed);
}

void Metrics::http_response_code_inc(long response_code) {
    std::lock_guard<std::mutex> lock(http_response_mutex_);
    http_response_counts_[response_code]++;
}

void Metrics::packets_by_protocol_stack_inc(const std::string& stack) {
    std::lock_guard<std::mutex> lock(protocol_stack_mutex_);
    protocol_stack_counts_[stack]++;
}

std::string Metrics::to_prometheus() const {
    std::ostringstream out;
    out << "# HELP signalbridge_packets_received_total Number of packets received from input\n";
    out << "# TYPE signalbridge_packets_received_total counter\n";
    out << "signalbridge_packets_received_total " << packets_received() << "\n";

    out << "# HELP signalbridge_messages_written_total S1AP/NGAP messages written to output\n";
    out << "# TYPE signalbridge_messages_written_total counter\n";
    out << "signalbridge_messages_written_total " << messages_written() << "\n";

    out << "# HELP signalbridge_messages_filtered_total S1AP/NGAP messages filtered (procedure/IP/encrypted NAS)\n";
    out << "# TYPE signalbridge_messages_filtered_total counter\n";
    out << "signalbridge_messages_filtered_total " << messages_filtered() << "\n";

    out << "# HELP signalbridge_bytes_in_total Bytes received from input\n";
    out << "# TYPE signalbridge_bytes_in_total counter\n";
    out << "signalbridge_bytes_in_total " << bytes_in_.load(std::memory_order_relaxed) << "\n";

    out << "# HELP signalbridge_bytes_out_total Bytes written to output (frame payload size)\n";
    out << "# TYPE signalbridge_bytes_out_total counter\n";
    out << "signalbridge_bytes_out_total " << bytes_out_.load(std::memory_order_relaxed) << "\n";

    out << "# HELP signalbridge_output_bytes_precompression_total Bytes sent to HTTP output before compression\n";
    out << "# TYPE signalbridge_output_bytes_precompression_total counter\n";
    out << "signalbridge_output_bytes_precompression_total " << output_bytes_precompression_.load(std::memory_order_relaxed) << "\n";

    out << "# HELP signalbridge_output_bytes_postcompression_total Bytes sent to HTTP output after gzip compression\n";
    out << "# TYPE signalbridge_output_bytes_postcompression_total counter\n";
    out << "signalbridge_output_bytes_postcompression_total " << output_bytes_postcompression_.load(std::memory_order_relaxed) << "\n";

    {
        std::lock_guard<std::mutex> lock(http_response_mutex_);
        if (!http_response_counts_.empty()) {
            out << "# HELP signalbridge_http_responses_total HTTP response codes from endpoint (0 = no response)\n";
            out << "# TYPE signalbridge_http_responses_total counter\n";
            for (const auto& [code, count] : http_response_counts_) {
                out << "signalbridge_http_responses_total{response_code=\"" << code << "\"} " << count << "\n";
            }
        }
    }

    // Rate gauges (messages per second)
    uint64_t start_ns = processing_start_ns_.load(std::memory_order_relaxed);
    if (start_ns > 0) {
        auto now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                          std::chrono::steady_clock::now().time_since_epoch())
                          .count();
        double elapsed_sec = static_cast<double>(now_ns - start_ns) / 1e9;
        if (elapsed_sec < 0.001) elapsed_sec = 0.001;  // avoid div by zero

        double ingest_rate = static_cast<double>(packets_received()) / elapsed_sec;
        double processed_rate = static_cast<double>(messages_written() + messages_filtered()) / elapsed_sec;
        double output_rate = static_cast<double>(messages_written()) / elapsed_sec;

        out << "# HELP signalbridge_packets_ingest_rate_ps Packets received per second\n";
        out << "# TYPE signalbridge_packets_ingest_rate_ps gauge\n";
        out << "signalbridge_packets_ingest_rate_ps " << ingest_rate << "\n";

        out << "# HELP signalbridge_messages_processed_rate_ps S1AP/NGAP messages processed (written + filtered) per second\n";
        out << "# TYPE signalbridge_messages_processed_rate_ps gauge\n";
        out << "signalbridge_messages_processed_rate_ps " << processed_rate << "\n";

        out << "# HELP signalbridge_messages_output_rate_ps S1AP/NGAP messages written to output per second\n";
        out << "# TYPE signalbridge_messages_output_rate_ps gauge\n";
        out << "signalbridge_messages_output_rate_ps " << output_rate << "\n";
    }

    // Queue sizes (input: 0 when no queue; output: HTTP streaming queue when applicable)
    out << "# HELP signalbridge_input_queue_size Number of messages in input queue\n";
    out << "# TYPE signalbridge_input_queue_size gauge\n";
    out << "signalbridge_input_queue_size " << (input_queue_size_cb_ ? input_queue_size_cb_() : 0) << "\n";

    out << "# HELP signalbridge_output_queue_size Number of messages in output queue\n";
    out << "# TYPE signalbridge_output_queue_size gauge\n";
    out << "signalbridge_output_queue_size " << (output_queue_size_cb_ ? output_queue_size_cb_() : 0) << "\n";

    out << "# HELP signalbridge_packets_by_protocol_stack_total Packets by protocol composition at ingest (e.g. eth_ipv4_sctp_s1ap)\n";
    out << "# TYPE signalbridge_packets_by_protocol_stack_total counter\n";
    out << "# HELP signalbridge_messages_by_procedure_total S1AP/NGAP messages written by procedure code\n";
    out << "# TYPE signalbridge_messages_by_procedure_total counter\n";
    {
        std::lock_guard<std::mutex> lock(protocol_stack_mutex_);
        for (const auto& [stack, count] : protocol_stack_counts_) {
            out << "signalbridge_packets_by_protocol_stack_total{stack=\"" << escape_label(stack) << "\"} " << count << "\n";
        }
    }
    {
        std::lock_guard<std::mutex> lock(procedure_mutex_);
        for (const auto& [key, count] : procedure_counts_) {
            const auto& [code, name, protocol] = key;
            out << "signalbridge_messages_by_procedure_total{procedure_code=\"" << code
                << "\",procedure_name=\"" << escape_label(name)
                << "\",protocol=\"" << protocol << "\"} " << count << "\n";
        }
    }

    return out.str();
}

}  // namespace signalbridge
