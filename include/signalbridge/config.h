/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include <string>
#include <vector>

namespace signalbridge {

struct FilterConfig {
    // Protocol filter: include only these (empty = all). Values: "S1AP", "NGAP"
    std::vector<std::string> protocol_include;
    // Protocol filter: exclude these
    std::vector<std::string> protocol_exclude;
    // Procedure code filter: include only these (empty = all)
    std::vector<int> procedure_include;
    // Procedure code filter: exclude these
    std::vector<int> procedure_exclude;
    // IP allow list (empty = allow all)
    std::vector<std::string> ip_allow;
    // IP deny list
    std::vector<std::string> ip_deny;
    // Drop encrypted NAS (cannot anonymise without keys)
    bool drop_encrypted_nas{true};
};

struct AnonymisationConfig {
    bool enabled{true};
    // MCC/MNC prefix for anonymised IMSIs (S1APAnonymise-style pseudonyms). Default 999/99.
    std::string mcc{"999"};
    std::string mnc{"99"};
    // Optional: write "original -> anonymised" mapping to file when processing completes
    std::string imsi_map_path;
    // Legacy: used only when mcc is empty (zero-fill mode). Prefer mcc/mnc for pseudonym mode.
    uint8_t replacement_byte{0x00};
};

struct InputConfig {
    std::string type;  // "file", "stdin", "tcp", "grpc", "kafka", "amqp", "nats"
    std::string path;  // For file
    std::string address;  // For tcp (host:port)
};

struct OutputConfig {
    std::string type;  // "file", "http", "https", "tcp", "grpc", "kafka", "amqp", "nats"
    std::string path;  // For file
    std::string address;  // For tcp/http (host:port or full https:// URL)
};

struct ConduitConfig {
    FilterConfig filter;
    AnonymisationConfig anonymisation;
    std::vector<InputConfig> inputs;
    std::vector<OutputConfig> outputs;
    // When non-empty, HTTP output is encrypted with AES-256-GCM (hex-encoded 32-byte key)
    std::string encryption_key;
};

}  // namespace signalbridge
