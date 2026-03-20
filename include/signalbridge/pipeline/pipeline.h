/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include <cstddef>

#include "signalbridge/config.h"
#include "signalbridge/pipeline/anonymiser.h"
#include "signalbridge/pipeline/frame_extractor.h"
#include "signalbridge/pipeline/ip_filter.h"
#include "signalbridge/pipeline/procedure_filter.h"
#include "signalbridge/pipeline/protocol_filter.h"
#include "signalbridge/types.h"
#include <functional>
#include <memory>

namespace signalbridge {

// Result of processing a packet (for metrics and forwarding).
struct PacketProcessResult {
    bool forwarded{false};
    size_t messages_filtered{0};       // S1AP/NGAP messages filtered (procedure/IP/encrypted NAS)
    std::string protocol_stack_sctp;   // Non-empty if packet has SCTP (e.g. "eth_ipv4_sctp")
    std::string protocol_stack_s1ap;   // Non-empty if packet has S1AP
    std::string protocol_stack_ngap;   // Non-empty if packet has NGAP
};

// Main pipeline: extract -> filter (procedure, IP, encrypted NAS) -> anonymise -> output
class Pipeline {
public:
    explicit Pipeline(const ConduitConfig& config);

    // Process a single packet. Returns result with forwarded flag and protocol info for metrics.
    PacketProcessResult process_packet(const uint8_t* data, size_t len,
                                       uint64_t ts_sec, uint32_t ts_usec, uint32_t frame_num);

    // Call when processing completes (writes IMSI map if configured).
    void finish();

    // Output callback: receives anonymised frames to write
    using OutputCallback = std::function<void(const SignallingFrame&)>;
    void set_output_callback(OutputCallback cb);

    // Hot-reload config
    void set_config(const ConduitConfig& config);

private:
    ConduitConfig config_;
    OutputCallback output_cb_;
    FrameExtractor extractor_;
    ProtocolFilter protocol_filter_;
    ProcedureFilter proc_filter_;
    IpFilter ip_filter_;
    Anonymiser anonymiser_;
};

}  // namespace signalbridge
