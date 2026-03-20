/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/pipeline/protocol_filter.h"
#include <cctype>

namespace signalbridge {

namespace {

std::string to_upper(const std::string& s) {
    std::string r;
    r.reserve(s.size());
    for (char c : s) r += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return r;
}

std::string get_protocol_name(const SignallingFrame& frame) {
    return frame.is_s1ap ? "S1AP" : "NGAP";
}

}  // namespace

void ProtocolFilter::rebuild_sets() {
    protocol_include_set_.clear();
    protocol_exclude_set_.clear();
    for (const auto& p : config_.protocol_include) protocol_include_set_.insert(to_upper(p));
    for (const auto& p : config_.protocol_exclude) protocol_exclude_set_.insert(to_upper(p));
}

ProtocolFilter::ProtocolFilter(const FilterConfig& config) : config_(config) {
    rebuild_sets();
}

bool ProtocolFilter::passes(const SignallingFrame& frame) const {
    std::string protocol = get_protocol_name(frame);

    if (!protocol_exclude_set_.empty() && protocol_exclude_set_.count(protocol))
        return false;

    if (!protocol_include_set_.empty() && !protocol_include_set_.count(protocol))
        return false;

    return true;
}

void ProtocolFilter::set_config(const FilterConfig& config) {
    config_ = config;
    rebuild_sets();
}

}  // namespace signalbridge
