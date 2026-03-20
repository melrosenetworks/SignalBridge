/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/ngap_parser.h"
#include "signalbridge/pipeline/frame_extractor.h"
#include "nas_parser.h"
#include "s1ap_parser.h"
#include <arpa/inet.h>
#include <algorithm>
#include <cstring>
#include <optional>

namespace signalbridge {

namespace {

constexpr uint8_t IP_PROTO_SCTP = 132;
constexpr uint8_t SCTP_CHUNK_DATA = 0;
constexpr uint32_t PPID_S1AP = 18;
constexpr uint32_t PPID_NGAP = 60;

// Build protocol stack string: "eth_ipv4_sctp_s1ap", "eth_ipv6_sctp_ngap", etc.
std::string build_protocol_stack(const uint8_t* packet, size_t len, bool is_s1ap) {
    if (!packet || len < 16) return "unknown";

    std::string stack;
    uint16_t proto = (packet[12] << 8) | packet[13];
    size_t off = 14;

    if (proto == 0x8100 || proto == 0x88A8) {
        stack = "eth_vlan";
        if (len < 18) return stack + "_unknown";
        proto = (packet[16] << 8) | packet[17];
        off = 18;
    } else if (proto == 0x0800 || proto == 0x86DD) {
        stack = "eth";
    } else if (len >= 16) {
        proto = (packet[14] << 8) | packet[15];
        if (proto == 0x0800 || proto == 0x86DD) {
            stack = "sll";
            off = 16;
        } else {
            return "unknown";
        }
    } else {
        return "unknown";
    }

    stack += (proto == 0x0800) ? "_ipv4" : "_ipv6";
    stack += "_sctp_";
    stack += is_s1ap ? "s1ap" : "ngap";
    return stack;
}

// Get IP offset and protocol (0x0800=IPv4, 0x86DD=IPv6) for Ethernet or Linux SLL.
// Returns (offset, protocol) or nullopt.
std::optional<std::pair<size_t, uint16_t>> get_ip_offset_and_protocol(const uint8_t* packet, size_t len) {
    if (!packet || len < 16) return std::nullopt;

    // Ethernet: 14 bytes, eth_type at 12-13
    uint16_t proto = (packet[12] << 8) | packet[13];
    size_t off = 14;
    if (proto == 0x8100 || proto == 0x88A8) {
        if (len < 18) return std::nullopt;
        proto = (packet[16] << 8) | packet[17];
        off = 18;
    }
    if (proto == 0x0800 || proto == 0x86DD) return std::make_pair(off, proto);

    // Linux SLL (cooked-mode): 16 bytes, protocol at 14-15
    if (len >= 16) {
        proto = (packet[14] << 8) | packet[15];
        if (proto == 0x0800 || proto == 0x86DD) return std::make_pair(16, proto);
    }
    return std::nullopt;
}

// Build SCTP-only protocol stack: "eth_ipv4_sctp", "eth_ipv6_sctp", etc. (no app layer).
// Returns empty string if packet is not SCTP.
std::string build_protocol_stack_sctp_only(const uint8_t* packet, size_t len) {
    if (!packet || len < 16) return "";
    auto ip_info = get_ip_offset_and_protocol(packet, len);
    if (!ip_info) return "";
    size_t offset = ip_info->first;
    uint16_t eth_type = ip_info->second;
    uint8_t protocol = 0;
    if (eth_type == 0x0800) {
        if (len < offset + 20) return "";
        uint8_t ver_ihl = packet[offset];
        if ((ver_ihl >> 4) != 4) return "";
        size_t ip_header_len = (ver_ihl & 0x0F) * 4;
        if (len < offset + ip_header_len) return "";
        protocol = packet[offset + 9];
    } else if (eth_type == 0x86DD) {
        if (len < offset + 40) return "";
        if ((packet[offset] >> 4) != 6) return "";
        protocol = packet[offset + 6];
        size_t ext_offset = offset + 40;
        int ext_limit = 0;
        while (protocol != IP_PROTO_SCTP && ext_limit < 8 && ext_offset < len) {
            if (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60) {
                if (len < ext_offset + 8) return "";
                uint8_t ext_len = packet[ext_offset + 1];
                size_t ext_header_len = (ext_len + 1) * 8;
                if (len < ext_offset + ext_header_len) return "";
                protocol = packet[ext_offset];
                ext_offset += ext_header_len;
                ext_limit++;
            } else {
                return "";
            }
        }
    } else {
        return "";
    }
    if (protocol != IP_PROTO_SCTP) return "";
    if (len < offset + 12) return "";

    std::string prefix = (offset == 18) ? "eth_vlan" : (offset == 16) ? "sll" : "eth";
    return prefix + (eth_type == 0x0800 ? "_ipv4" : "_ipv6") + "_sctp";
}

// Extract all SCTP DATA chunks with PPID 18 (S1AP) or 60 (NGAP) from a packet.
std::vector<SctpPayloadResult> extractAllSctpPayloadsByPpid(const uint8_t* packet, size_t len) {
    std::vector<SctpPayloadResult> results;
    auto ip_info = get_ip_offset_and_protocol(packet, len);
    if (!ip_info) return results;

    size_t offset = ip_info->first;
    uint16_t eth_type = ip_info->second;

    uint8_t protocol = 0;
    size_t ip_header_len = 0;

    if (eth_type == 0x0800) {
        if (len < offset + 20) return results;
        uint8_t ver_ihl = packet[offset];
        if ((ver_ihl >> 4) != 4) return results;
        ip_header_len = (ver_ihl & 0x0F) * 4;
        if (len < offset + ip_header_len) return results;
        protocol = packet[offset + 9];
        offset += ip_header_len;
    } else if (eth_type == 0x86DD) {
        if (len < offset + 40) return results;
        if ((packet[offset] >> 4) != 6) return results;
        protocol = packet[offset + 6];
        offset += 40;
        int ext_limit = 0;
        while (protocol != IP_PROTO_SCTP && ext_limit < 8 && offset < len) {
            if (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60) {
                if (len < offset + 8) return results;
                uint8_t ext_len = packet[offset + 1];
                size_t ext_header_len = (ext_len + 1) * 8;
                if (len < offset + ext_header_len) return results;
                protocol = packet[offset];
                offset += ext_header_len;
                ext_limit++;
            } else {
                break;
            }
        }
    } else {
        return results;
    }

    if (protocol != IP_PROTO_SCTP) return results;
    if (len < offset + 12) return results;
    offset += 12;

    while (offset + 4 <= len) {
        uint8_t chunk_type = packet[offset];
        uint16_t chunk_len = (packet[offset + 2] << 8) | packet[offset + 3];
        if (chunk_len < 4 || offset + chunk_len > len) break;

        if (chunk_type == SCTP_CHUNK_DATA && chunk_len >= 16) {
            uint32_t ppid = (packet[offset + 12] << 24) | (packet[offset + 13] << 16) |
                           (packet[offset + 14] << 8) | packet[offset + 15];
            if (ppid == PPID_S1AP || ppid == PPID_NGAP) {
                size_t payload_offset = offset + 16;
                size_t payload_len = chunk_len - 16;
                if (payload_len > 0 && payload_offset + payload_len <= len) {
                    std::vector<uint8_t> payload(packet + payload_offset,
                                                 packet + payload_offset + payload_len);
                    results.push_back(SctpPayloadResult{std::move(payload), ppid});
                }
            }
        }
        size_t pad = (4 - (chunk_len % 4)) % 4;
        offset += chunk_len + pad;
    }
    return results;
}

}  // namespace

std::vector<SctpPayloadResult> extract_all_sctp_payloads(const uint8_t* packet, size_t len) {
    return extractAllSctpPayloadsByPpid(packet, len);
}

namespace {

// Extract src/dst IP from packet
PacketIps extract_ips(const uint8_t* data, size_t len) {
    PacketIps ips;
    auto ip_info = get_ip_offset_and_protocol(data, len);
    if (!ip_info) return ips;

    size_t offset = ip_info->first;
    uint16_t eth_type = ip_info->second;

    if (eth_type == 0x0800) {  // IPv4
        if (len < offset + 20) return ips;
        char buf[32];
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                 data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15]);
        ips.src_ip = buf;
        snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                 data[offset + 16], data[offset + 17], data[offset + 18], data[offset + 19]);
        ips.dst_ip = buf;
    } else if (eth_type == 0x86DD) {  // IPv6
        if (len < offset + 40) return ips;
        char buf[INET6_ADDRSTRLEN];
        struct in6_addr src, dst;
        std::memcpy(&src, data + offset + 8, 16);
        std::memcpy(&dst, data + offset + 24, 16);
        if (inet_ntop(AF_INET6, &src, buf, sizeof(buf))) ips.src_ip = buf;
        if (inet_ntop(AF_INET6, &dst, buf, sizeof(buf))) ips.dst_ip = buf;
    }
    return ips;
}

}  // namespace

bool FrameExtractor::process_packet(const uint8_t* data, size_t len,
                                   uint64_t ts_sec, uint32_t ts_usec, uint32_t frame_num,
                                   FrameCallback callback) {
    auto sctp_results = extractAllSctpPayloadsByPpid(data, len);
    if (sctp_results.empty()) return false;

    SignallingFrame frame;
    frame.packet.assign(data, data + len);
    frame.timestamp_sec = ts_sec;
    frame.timestamp_usec = ts_usec;
    frame.frame_number = frame_num;

    for (const auto& sctp_result : sctp_results) {
        ProcedureInfo proc;
        proc.is_s1ap = (sctp_result.ppid == PPID_S1AP);
        const auto& payload = sctp_result.payload;

        if (sctp_result.ppid == PPID_S1AP) {
            auto parse_result = s1ap_parser::parseS1apPdu(payload.data(), payload.size());
            if (!parse_result.decoded) continue;

            proc.procedure_code = parse_result.procedure_code;
            proc.procedure_name = parse_result.procedure_name;

            auto nas_it = parse_result.information_elements.find("NAS-PDU");
            if (nas_it != parse_result.information_elements.end()) {
                frame.nas_pdu_hex = nas_it->second;
                const std::string& hex = nas_it->second;
                if (!hex.empty() && hex.size() >= 4) {
                    std::vector<uint8_t> nas_bytes;
                    nas_bytes.reserve(hex.size() / 2);
                    auto hex2byte = [](char a, char b) -> uint8_t {
                        auto d = [](char c) -> uint8_t {
                            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
                            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
                            return 0;
                        };
                        return static_cast<uint8_t>((d(a) << 4) | d(b));
                    };
                    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                        nas_bytes.push_back(hex2byte(hex[i], hex[i + 1]));
                    }
                    if (nas_bytes.size() >= 2) {
                        nas_parser::NasHeader hdr = nas_parser::parseNasHeader(nas_bytes.data() + 1, nas_bytes.size() - 1);
                        proc.has_encrypted_nas = !nas_parser::isPlainNas(hdr);
                        if (proc.has_encrypted_nas) frame.has_encrypted_nas = true;
                    }
                }
            }
        } else if (sctp_result.ppid == PPID_NGAP) {
            NgapPduType ngap_pdu_type = NgapPduType::Initiating;
            if (parse_ngap_pdu(payload.data(), payload.size(), proc.procedure_code, ngap_pdu_type)) {
                proc.procedure_name = get_ngap_message_name(proc.procedure_code, ngap_pdu_type);
            } else {
                proc.procedure_code = (payload.size() >= 2) ? payload[1] : 0;
                proc.procedure_name = get_ngap_procedure_name(proc.procedure_code);
            }
            // Extract NAS-PDU for anonymisation (same as S1AP)
            NgapParseResult ngap_parse = parse_ngap_pdu_full(payload.data(), payload.size());
            if (ngap_parse.decoded) {
                auto nas_it = ngap_parse.information_elements.find("NAS-PDU");
                if (nas_it != ngap_parse.information_elements.end()) {
                    frame.nas_pdu_hex = nas_it->second;
                    const std::string& hex = nas_it->second;
                    if (!hex.empty() && hex.size() >= 4) {
                        std::vector<uint8_t> nas_bytes;
                        nas_bytes.reserve(hex.size() / 2);
                        auto hex2byte = [](char a, char b) -> uint8_t {
                            auto d = [](char c) -> uint8_t {
                                if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
                                if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
                                if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
                                return 0;
                            };
                            return static_cast<uint8_t>((d(a) << 4) | d(b));
                        };
                        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                            nas_bytes.push_back(hex2byte(hex[i], hex[i + 1]));
                        }
                        if (nas_bytes.size() >= 2) {
                            nas_parser::NasHeader hdr = nas_parser::parseNasHeader(nas_bytes.data() + 1, nas_bytes.size() - 1);
                            proc.has_encrypted_nas = !nas_parser::isPlainNas(hdr);
                            if (proc.has_encrypted_nas) frame.has_encrypted_nas = true;
                        }
                    }
                }
            }
        } else {
            continue;
        }

        frame.procedures.push_back(proc);
    }

    if (frame.procedures.empty()) return false;

    // Set first procedure for backward compatibility
    frame.procedure_code = frame.procedures[0].procedure_code;
    frame.procedure_name = frame.procedures[0].procedure_name;
    frame.is_s1ap = frame.procedures[0].is_s1ap;

    PacketIps ips = extract_ips(data, len);
    return callback(frame, ips);
}

bool FrameExtractor::has_s1ap(const uint8_t* data, size_t len) {
    auto results = extractAllSctpPayloadsByPpid(data, len);
    for (const auto& r : results) {
        if (r.ppid == PPID_S1AP) return true;
    }
    return false;
}

bool FrameExtractor::has_ngap(const uint8_t* data, size_t len) {
    auto results = extractAllSctpPayloadsByPpid(data, len);
    for (const auto& r : results) {
        if (r.ppid == PPID_NGAP) return true;
    }
    return false;
}

std::string FrameExtractor::get_protocol_stack(const uint8_t* data, size_t len, bool is_s1ap) {
    return build_protocol_stack(data, len, is_s1ap);
}

bool FrameExtractor::has_sctp(const uint8_t* data, size_t len) {
    return !build_protocol_stack_sctp_only(data, len).empty();
}

std::string FrameExtractor::get_protocol_stack_sctp(const uint8_t* data, size_t len) {
    return build_protocol_stack_sctp_only(data, len);
}

}  // namespace signalbridge
