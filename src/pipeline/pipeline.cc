/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/pipeline/pipeline.h"
#include "signalbridge/pipeline/anonymiser.h"
#include "signalbridge/pipeline/frame_extractor.h"
#include "signalbridge/pipeline/ip_filter.h"
#include "signalbridge/pipeline/procedure_filter.h"
#include "signalbridge/pipeline/protocol_filter.h"

namespace signalbridge {

Pipeline::Pipeline(const ConduitConfig& config)
    : config_(config),
      protocol_filter_(config_.filter),
      proc_filter_(config_.filter),
      ip_filter_(config_.filter),
      anonymiser_(config_.anonymisation) {}

PacketProcessResult Pipeline::process_packet(const uint8_t* data, size_t len,
                                             uint64_t ts_sec, uint32_t ts_usec, uint32_t frame_num) {
    PacketProcessResult result;
    bool forwarded = false;
    bool has_s1ap = false;
    bool has_ngap = false;

    size_t filtered_count = 0;
    bool had_frames = extractor_.process_packet(data, len, ts_sec, ts_usec, frame_num,
        [&](const SignallingFrame& frame, const PacketIps& ips) {
            for (const auto& proc : frame.procedures) {
                if (proc.is_s1ap) has_s1ap = true;
                else has_ngap = true;
            }
            if (config_.filter.drop_encrypted_nas && frame.has_encrypted_nas) {
                filtered_count += frame.procedures.size();
                return true;  // Drop, don't forward
            }
            if (!protocol_filter_.passes(frame)) {
                filtered_count += frame.procedures.size();
                return true;
            }
            if (!proc_filter_.passes(frame)) {
                filtered_count += frame.procedures.size();
                return true;
            }
            if (!ip_filter_.passes(ips)) {
                filtered_count += frame.procedures.size();
                return true;
            }

            if (config_.anonymisation.enabled) {
                SignallingFrame out = frame;
                anonymiser_.anonymise(out);
                if (output_cb_) {
                    output_cb_(out);
                    forwarded = true;
                }
            } else {
                if (output_cb_) {
                    output_cb_(frame);
                    forwarded = true;
                }
            }
            return true;
        });

    result.forwarded = forwarded;
    result.messages_filtered = filtered_count;
    if (had_frames) {
        result.protocol_stack_sctp = FrameExtractor::get_protocol_stack_sctp(data, len);
        if (has_s1ap) result.protocol_stack_s1ap = FrameExtractor::get_protocol_stack(data, len, true);
        if (has_ngap) result.protocol_stack_ngap = FrameExtractor::get_protocol_stack(data, len, false);
    } else {
        result.protocol_stack_sctp = FrameExtractor::get_protocol_stack_sctp(data, len);
    }
    return result;
}

void Pipeline::set_output_callback(OutputCallback cb) {
    output_cb_ = std::move(cb);
}

void Pipeline::finish() {
    anonymiser_.write_imsi_map();
}

void Pipeline::set_config(const ConduitConfig& config) {
    config_ = config;
    protocol_filter_.set_config(config_.filter);
    proc_filter_.set_config(config_.filter);
    ip_filter_.set_config(config_.filter);
    anonymiser_.set_config(config_.anonymisation);
}

}  // namespace signalbridge
