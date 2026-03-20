/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/pipeline/procedure_filter.h"

namespace signalbridge {

void ProcedureFilter::rebuild_sets() {
    procedure_include_set_.clear();
    procedure_exclude_set_.clear();
    for (int pc : config_.procedure_include) procedure_include_set_.insert(pc);
    for (int pc : config_.procedure_exclude) procedure_exclude_set_.insert(pc);
}

ProcedureFilter::ProcedureFilter(const FilterConfig& config) : config_(config) {
    rebuild_sets();
}

bool ProcedureFilter::passes(const SignallingFrame& frame) const {
    for (const auto& proc : frame.procedures) {
        int pc = static_cast<int>(proc.procedure_code);

        if (!procedure_exclude_set_.empty() && procedure_exclude_set_.count(pc))
            continue;

        if (!procedure_include_set_.empty() && !procedure_include_set_.count(pc))
            continue;

        return true;
    }
    return false;
}

void ProcedureFilter::set_config(const FilterConfig& config) {
    config_ = config;
    rebuild_sets();
}

}  // namespace signalbridge
