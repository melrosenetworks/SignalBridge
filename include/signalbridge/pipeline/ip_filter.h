/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/config.h"
#include "signalbridge/types.h"
#include <unordered_set>

namespace signalbridge {

// Filters frames by source/destination IP (allow/deny lists).
class IpFilter {
public:
    explicit IpFilter(const FilterConfig& config);

    // Returns true if packet IPs pass the filter.
    bool passes(const PacketIps& ips) const;

    void set_config(const FilterConfig& config);

private:
    void rebuild_sets();

    FilterConfig config_;
    std::unordered_set<std::string> ip_allow_set_;
    std::unordered_set<std::string> ip_deny_set_;
};

}  // namespace signalbridge
