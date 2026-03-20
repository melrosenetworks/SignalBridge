/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/config.h"
#include <string>

namespace signalbridge {

// Load ConduitConfig from YAML file
class ConfigLoader {
public:
    static bool load(const std::string& path, ConduitConfig& config);
};

}  // namespace signalbridge
