/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/config.h"
#include "signalbridge/types.h"
#include <unordered_set>

namespace signalbridge {

// Filters frames by procedure code (include/exclude lists).
class ProcedureFilter {
public:
    explicit ProcedureFilter(const FilterConfig& config);

    // Returns true if frame passes the filter (should be forwarded).
    bool passes(const SignallingFrame& frame) const;

    void set_config(const FilterConfig& config);

private:
    void rebuild_sets();

    FilterConfig config_;
    std::unordered_set<int> procedure_include_set_;
    std::unordered_set<int> procedure_exclude_set_;
};

}  // namespace signalbridge
