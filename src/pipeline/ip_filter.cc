/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/pipeline/ip_filter.h"

namespace signalbridge {

void IpFilter::rebuild_sets() {
    ip_allow_set_.clear();
    ip_deny_set_.clear();
    for (const auto& ip : config_.ip_allow) ip_allow_set_.insert(ip);
    for (const auto& ip : config_.ip_deny) ip_deny_set_.insert(ip);
}

IpFilter::IpFilter(const FilterConfig& config) : config_(config) {
    rebuild_sets();
}

bool IpFilter::passes(const PacketIps& ips) const {
    if (ip_deny_set_.empty() && ip_allow_set_.empty()) return true;

    if (ip_deny_set_.count(ips.src_ip) || ip_deny_set_.count(ips.dst_ip)) return false;
    if (!ip_allow_set_.empty() &&
        (!ip_allow_set_.count(ips.src_ip) || !ip_allow_set_.count(ips.dst_ip)))
        return false;

    return true;
}

void IpFilter::set_config(const FilterConfig& config) {
    config_ = config;
    rebuild_sets();
}

}  // namespace signalbridge
