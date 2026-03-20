/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 *
 * NGAP procedure code to name mapping per 3GPP TS 38.413.
 * NGAP has two procedure classes: Class 1 (with response) and Class 2 (without response).
 * Both share the same procedure code space; PDU type (initiating/successful/unsuccessful)
 * distinguishes Request vs Response for Class 1 procedures.
 */

#include "signalbridge/ngap_parser.h"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

namespace signalbridge {

namespace {

constexpr uint8_t IP_PROTO_SCTP = 132;
constexpr uint8_t SCTP_CHUNK_DATA = 0;
constexpr uint32_t PPID_NGAP = 60;

// NGAP ProtocolIE-ID to name (3GPP TS 38.413). Only IEs needed for anonymisation.
std::string get_ngap_ie_name(uint16_t ie_id) {
    switch (ie_id) {
        case 26: return "NAS-PDU";
        case 85: return "RAN-UE-NGAP-ID";
        case 38: return "AMF-UE-NGAP-ID";
        default: return "IE-" + std::to_string(ie_id);
    }
}

}  // namespace

bool parse_ngap_pdu(const uint8_t* data, size_t len, uint8_t& procedure_code, NgapPduType& pdu_type) {
    if (!data || len < 2) return false;
    // APER structure (3GPP TS 38.413): byte 0 = extension(1)+choice(2)+padding(5), byte 1 = procedureCode
    uint8_t choice = (data[0] >> 5) & 0x03;
    if (choice > 2) return false;
    pdu_type = static_cast<NgapPduType>(choice);
    procedure_code = data[1];
    return true;
}

NgapParseResult parse_ngap_pdu_full(const uint8_t* data, size_t len) {
    NgapParseResult result;
    if (!data || len < 4) return result;

    size_t offset = 0;

    // CHOICE index (PDU type)
    uint8_t choice_index = (data[offset] >> 5) & 0x03;
    if (choice_index > 2) return result;
    result.pdu_type = static_cast<NgapPduType>(choice_index);
    offset++;

    // Procedure code
    result.procedure_code = data[offset];
    result.procedure_name = get_ngap_procedure_name(result.procedure_code);
    offset++;

    // Criticality (1 byte)
    if (offset >= len) {
        result.decoded = true;
        return result;
    }
    offset++;

    // protocolIEs: SEQUENCE OF ProtocolIE-Field
    if (offset >= len) {
        result.decoded = true;
        return result;
    }

    // Length determinant (APER)
    uint32_t num_ies = 0;
    uint8_t length_byte = data[offset];
    offset++;
    if (offset >= len) {
        result.decoded = true;
        return result;
    }

    if ((length_byte & 0x80) == 0) {
        num_ies = length_byte & 0x7F;
    } else {
        uint8_t second_byte = data[offset];
        offset++;
        uint8_t num_length_bytes = (length_byte & 0x7F) + 1;
        if (num_length_bytes > 4 || offset + num_length_bytes > len) {
            result.decoded = true;
            return result;
        }
        num_ies = 0;
        for (size_t i = 0; i < num_length_bytes; ++i) {
            num_ies = (num_ies << 8) | data[offset + i];
        }
        offset += num_length_bytes;
    }

    // Decode each ProtocolIE-Field
    for (uint32_t ie_idx = 0; ie_idx < num_ies && offset + 4 <= len; ++ie_idx) {
        uint16_t ie_id = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        uint8_t ie_criticality = data[offset];
        (void)ie_criticality;
        offset++;

        if (offset >= len) break;

        uint32_t value_length = 0;
        uint8_t value_length_byte = data[offset];
        offset++;

        if ((value_length_byte & 0x80) == 0) {
            value_length = value_length_byte & 0x7F;
        } else {
            uint8_t num_length_bytes = (value_length_byte & 0x7F) + 1;
            if (num_length_bytes > 4 || offset + num_length_bytes > len) break;
            value_length = 0;
            for (size_t i = 0; i < num_length_bytes; ++i) {
                value_length = (value_length << 8) | data[offset + i];
            }
            offset += num_length_bytes;
        }

        if (offset + value_length > len) break;

        std::string ie_name = get_ngap_ie_name(ie_id);
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < value_length; ++i) {
            hex << std::setw(2) << static_cast<unsigned>(data[offset + i]);
        }
        result.information_elements[ie_name] = hex.str();
        offset += value_length;
    }

    result.decoded = true;
    return result;
}

std::optional<std::vector<uint8_t>> extract_ngap_from_sctp(const uint8_t* packet, size_t len) {
    if (!packet || len < 14) return std::nullopt;

    size_t offset = 0;
    uint16_t eth_type = (packet[12] << 8) | packet[13];
    offset = 14;

    if ((eth_type == 0x8100 || eth_type == 0x88A8) && len >= offset + 4) {
        eth_type = (packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
    }

    uint8_t protocol = 0;
    if (eth_type == 0x0800) {
        if (len < offset + 20) return std::nullopt;
        uint8_t ver_ihl = packet[offset];
        if ((ver_ihl >> 4) != 4) return std::nullopt;
        size_t ip_header_len = (ver_ihl & 0x0F) * 4;
        if (len < offset + ip_header_len) return std::nullopt;
        protocol = packet[offset + 9];
        offset += ip_header_len;
    } else if (eth_type == 0x86DD) {
        if (len < offset + 40) return std::nullopt;
        if ((packet[offset] >> 4) != 6) return std::nullopt;
        protocol = packet[offset + 6];
        offset += 40;
        int ext_limit = 0;
        while (protocol != IP_PROTO_SCTP && ext_limit < 8 && offset < len) {
            if (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60) {
                if (len < offset + 8) return std::nullopt;
                uint8_t ext_len = packet[offset + 1];
                size_t ext_header_len = (ext_len + 1) * 8;
                if (len < offset + ext_header_len) return std::nullopt;
                protocol = packet[offset];
                offset += ext_header_len;
                ext_limit++;
            } else {
                break;
            }
        }
    } else {
        return std::nullopt;
    }

    if (protocol != IP_PROTO_SCTP) return std::nullopt;
    if (len < offset + 12) return std::nullopt;
    offset += 12;

    while (offset + 4 <= len) {
        uint8_t chunk_type = packet[offset];
        uint16_t chunk_len = (packet[offset + 2] << 8) | packet[offset + 3];
        if (chunk_len < 4 || offset + chunk_len > len) break;

        if (chunk_type == SCTP_CHUNK_DATA && chunk_len >= 16) {
            uint32_t ppid = (packet[offset + 12] << 24) | (packet[offset + 13] << 16) |
                            (packet[offset + 14] << 8) | packet[offset + 15];
            if (ppid == PPID_NGAP) {
                size_t payload_offset = offset + 16;
                size_t payload_len = chunk_len - 16;
                if (payload_len > 0 && payload_offset + payload_len <= len) {
                    return std::vector<uint8_t>(packet + payload_offset,
                                                 packet + payload_offset + payload_len);
                }
            }
        }
        size_t pad = (4 - (chunk_len % 4)) % 4;
        offset += chunk_len + pad;
    }
    return std::nullopt;
}

std::string get_ngap_message_name(uint8_t procedure_code, NgapPduType pdu_type) {
    // Map procedure + PDU type to message names per 3GPP TS 38.413 NGAP-Constants
    switch (procedure_code) {
        case 0:  // id-AMFConfigurationUpdate (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "AMFConfigurationUpdate";
            if (pdu_type == NgapPduType::Successful) return "AMFConfigurationUpdateAcknowledge";
            return "AMFConfigurationUpdateFailure";
        case 1: return "AMFStatusIndication";
        case 2: return "CellTrafficTrace";
        case 3: return "DeactivateTrace";
        case 4: return "DownlinkNASTransport";
        case 5: return "DownlinkNonUEAssociatedNRPPaTransport";
        case 6: return "DownlinkRANConfigurationTransfer";
        case 7: return "DownlinkRANStatusTransfer";
        case 8: return "DownlinkUEAssociatedNRPPaTransport";
        case 9: return "ErrorIndication";
        case 10:  // id-HandoverCancel (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "HandoverCancel";
            return "HandoverCancelAcknowledge";
        case 11: return "HandoverNotify";
        case 12:  // id-HandoverPreparation (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "HandoverRequired";
            if (pdu_type == NgapPduType::Successful) return "HandoverCommand";
            return "HandoverPreparationFailure";
        case 13:  // id-HandoverResourceAllocation (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "HandoverRequest";
            if (pdu_type == NgapPduType::Successful) return "HandoverRequestAcknowledge";
            return "HandoverFailure";
        case 14:  // id-InitialContextSetup (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "InitialContextSetupRequest";
            if (pdu_type == NgapPduType::Successful) return "InitialContextSetupResponse";
            return "InitialContextSetupFailure";
        case 15: return "InitialUEMessage";
        case 16: return "LocationReportingControl";
        case 17: return "LocationReportingFailureIndication";
        case 18: return "LocationReport";
        case 19: return "NASNonDeliveryIndication";
        case 20:  // id-NGReset (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "NGReset";
            return "NGResetAcknowledge";
        case 21:  // id-NGSetup (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "NGSetupRequest";
            if (pdu_type == NgapPduType::Successful) return "NGSetupResponse";
            return "NGSetupFailure";
        case 22: return "OverloadStart";
        case 23: return "OverloadStop";
        case 24: return "Paging";
        case 25:  // id-PathSwitchRequest (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "PathSwitchRequest";
            if (pdu_type == NgapPduType::Successful) return "PathSwitchRequestAcknowledge";
            return "PathSwitchRequestFailure";
        case 26:  // id-PDUSessionResourceModify (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "PDUSessionResourceModifyRequest";
            return "PDUSessionResourceModifyResponse";
        case 27: return "PDUSessionResourceModifyIndication";
        case 28:  // id-PDUSessionResourceRelease (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "PDUSessionResourceReleaseCommand";
            return "PDUSessionResourceReleaseResponse";
        case 29:  // id-PDUSessionResourceSetup (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "PDUSessionResourceSetupRequest";
            return "PDUSessionResourceSetupResponse";
        case 30: return "PDUSessionResourceNotify";
        case 31: return "PrivateMessage";
        case 32:  // id-PWSCancel (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "PWSCancelRequest";
            return "PWSCancelResponse";
        case 33: return "PWSFailureIndication";
        case 34: return "PWSRestartIndication";
        case 35:  // id-RANConfigurationUpdate (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "RANConfigurationUpdate";
            if (pdu_type == NgapPduType::Successful) return "RANConfigurationUpdateAcknowledge";
            return "RANConfigurationUpdateFailure";
        case 36: return "RerouteNASRequest";
        case 37: return "RRCInactiveTransitionReport";
        case 38: return "TraceFailureIndication";
        case 39: return "TraceStart";
        case 40:  // id-UEContextModification (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "UEContextModificationRequest";
            if (pdu_type == NgapPduType::Successful) return "UEContextModificationResponse";
            return "UEContextModificationFailure";
        case 41:  // id-UEContextRelease (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "UEContextReleaseCommand";
            return "UEContextReleaseComplete";
        case 42: return "UEContextReleaseRequest";
        case 43:  // id-UERadioCapabilityCheck (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "UERadioCapabilityCheckRequest";
            return "UERadioCapabilityCheckResponse";
        case 44: return "UERadioCapabilityInfoIndication";
        case 45: return "UETNLABindingReleaseRequest";
        case 46: return "UplinkNASTransport";
        case 47: return "UplinkNonUEAssociatedNRPPaTransport";
        case 48: return "UplinkRANConfigurationTransfer";
        case 49: return "UplinkRANStatusTransfer";
        case 50: return "UplinkUEAssociatedNRPPaTransport";
        case 51:  // id-WriteReplaceWarning (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "WriteReplaceWarningRequest";
            return "WriteReplaceWarningResponse";
        case 52: return "SecondaryRATDataUsageReport";
        case 53: return "UplinkRIMInformationTransfer";
        case 54: return "DownlinkRIMInformationTransfer";
        case 55: return "RetrieveUEInformation";
        case 56: return "UEInformationTransfer";
        case 57: return "RANCPRelocationIndication";
        case 58:  // id-UEContextResume (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "UEContextResumeRequest";
            if (pdu_type == NgapPduType::Successful) return "UEContextResumeResponse";
            return "UEContextResumeFailure";
        case 59:  // id-UEContextSuspend (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "UEContextSuspendRequest";
            return "UEContextSuspendResponse";
        case 60:  // id-UERadioCapabilityIDMapping (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "UERadioCapabilityIDMappingRequest";
            return "UERadioCapabilityIDMappingResponse";
        case 61: return "HandoverSuccess";
        case 62: return "UplinkRANEarlyStatusTransfer";
        case 63: return "DownlinkRANEarlyStatusTransfer";
        case 64: return "AMFCPRelocationIndication";
        case 65: return "ConnectionEstablishmentIndication";
        case 66:  // id-BroadcastSessionModification (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "BroadcastSessionModificationRequest";
            if (pdu_type == NgapPduType::Successful) return "BroadcastSessionModificationResponse";
            return "BroadcastSessionModificationFailure";
        case 67:  // id-BroadcastSessionRelease (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "BroadcastSessionReleaseRequest";
            return "BroadcastSessionReleaseResponse";
        case 68:  // id-BroadcastSessionSetup (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "BroadcastSessionSetupRequest";
            if (pdu_type == NgapPduType::Successful) return "BroadcastSessionSetupResponse";
            return "BroadcastSessionSetupFailure";
        case 69:  // id-DistributionSetup (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "DistributionSetupRequest";
            if (pdu_type == NgapPduType::Successful) return "DistributionSetupResponse";
            return "DistributionSetupFailure";
        case 70:  // id-DistributionRelease (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "DistributionReleaseRequest";
            return "DistributionReleaseResponse";
        case 71:  // id-MulticastSessionActivation (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "MulticastSessionActivationRequest";
            if (pdu_type == NgapPduType::Successful) return "MulticastSessionActivationResponse";
            return "MulticastSessionActivationFailure";
        case 72:  // id-MulticastSessionDeactivation (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "MulticastSessionDeactivationRequest";
            return "MulticastSessionDeactivationResponse";
        case 73:  // id-MulticastSessionUpdate (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "MulticastSessionUpdateRequest";
            if (pdu_type == NgapPduType::Successful) return "MulticastSessionUpdateResponse";
            return "MulticastSessionUpdateFailure";
        case 74: return "MulticastGroupPaging";
        case 75: return "BroadcastSessionReleaseRequired";
        case 76:  // id-TimingSynchronisationStatus (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "TimingSynchronisationStatusRequest";
            if (pdu_type == NgapPduType::Successful) return "TimingSynchronisationStatusResponse";
            return "TimingSynchronisationStatusFailure";
        case 77: return "TimingSynchronisationStatusReport";
        case 78:  // id-MTCommunicationHandling (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "MTCommunicationHandlingRequest";
            if (pdu_type == NgapPduType::Successful) return "MTCommunicationHandlingResponse";
            return "MTCommunicationHandlingFailure";
        case 79: return "RANPagingRequest";
        case 80:  // id-BroadcastSessionTransport (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "BroadcastSessionTransportRequest";
            if (pdu_type == NgapPduType::Successful) return "BroadcastSessionTransportResponse";
            return "BroadcastSessionTransportFailure";
        case 81:  // id-NGRemoval (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "NGRemovalRequest";
            if (pdu_type == NgapPduType::Successful) return "NGRemovalResponse";
            return "NGRemovalFailure";
        case 82:  // id-InventoryRequest (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "InventoryRequest";
            if (pdu_type == NgapPduType::Successful) return "InventoryResponse";
            return "InventoryFailure";
        case 83: return "InventoryReport";
        case 84:  // id-CommandRequest (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "CommandRequest";
            if (pdu_type == NgapPduType::Successful) return "CommandResponse";
            return "CommandFailure";
        case 85:  // id-AIOTSessionRelease (Class 1)
            if (pdu_type == NgapPduType::Initiating) return "AIOTSessionReleaseCommand";
            return "AIOTSessionReleaseComplete";
        case 86: return "AIOTSessionReleaseRequest";
        default: return "NGAP-" + std::to_string(procedure_code);
    }
}

std::string get_ngap_procedure_name(uint8_t procedure_code) {
    // Procedure names per 3GPP TS 38.413 NGAP-Constants (base procedure, no Request/Response)
    switch (procedure_code) {
        case 0: return "AMFConfigurationUpdate";
        case 1: return "AMFStatusIndication";
        case 2: return "CellTrafficTrace";
        case 3: return "DeactivateTrace";
        case 4: return "DownlinkNASTransport";
        case 5: return "DownlinkNonUEAssociatedNRPPaTransport";
        case 6: return "DownlinkRANConfigurationTransfer";
        case 7: return "DownlinkRANStatusTransfer";
        case 8: return "DownlinkUEAssociatedNRPPaTransport";
        case 9: return "ErrorIndication";
        case 10: return "HandoverCancel";
        case 11: return "HandoverNotification";
        case 12: return "HandoverPreparation";
        case 13: return "HandoverResourceAllocation";
        case 14: return "InitialContextSetup";
        case 15: return "InitialUEMessage";
        case 16: return "LocationReportingControl";
        case 17: return "LocationReportingFailureIndication";
        case 18: return "LocationReport";
        case 19: return "NASNonDeliveryIndication";
        case 20: return "NGReset";
        case 21: return "NGSetup";
        case 22: return "OverloadStart";
        case 23: return "OverloadStop";
        case 24: return "Paging";
        case 25: return "PathSwitchRequest";
        case 26: return "PDUSessionResourceModify";
        case 27: return "PDUSessionResourceModifyIndication";
        case 28: return "PDUSessionResourceRelease";
        case 29: return "PDUSessionResourceSetup";
        case 30: return "PDUSessionResourceNotify";
        case 31: return "PrivateMessage";
        case 32: return "PWSCancel";
        case 33: return "PWSFailureIndication";
        case 34: return "PWSRestartIndication";
        case 35: return "RANConfigurationUpdate";
        case 36: return "RerouteNASRequest";
        case 37: return "RRCInactiveTransitionReport";
        case 38: return "TraceFailureIndication";
        case 39: return "TraceStart";
        case 40: return "UEContextModification";
        case 41: return "UEContextRelease";
        case 42: return "UEContextReleaseRequest";
        case 43: return "UERadioCapabilityCheck";
        case 44: return "UERadioCapabilityInfoIndication";
        case 45: return "UETNLABindingRelease";
        case 46: return "UplinkNASTransport";
        case 47: return "UplinkNonUEAssociatedNRPPaTransport";
        case 48: return "UplinkRANConfigurationTransfer";
        case 49: return "UplinkRANStatusTransfer";
        case 50: return "UplinkUEAssociatedNRPPaTransport";
        case 51: return "WriteReplaceWarning";
        case 52: return "SecondaryRATDataUsageReport";
        case 53: return "UplinkRIMInformationTransfer";
        case 54: return "DownlinkRIMInformationTransfer";
        case 55: return "RetrieveUEInformation";
        case 56: return "UEInformationTransfer";
        case 57: return "RANCPRelocationIndication";
        case 58: return "UEContextResume";
        case 59: return "UEContextSuspend";
        case 60: return "UERadioCapabilityIDMapping";
        case 61: return "HandoverSuccess";
        case 62: return "UplinkRANEarlyStatusTransfer";
        case 63: return "DownlinkRANEarlyStatusTransfer";
        case 64: return "AMFCPRelocationIndication";
        case 65: return "ConnectionEstablishmentIndication";
        case 66: return "BroadcastSessionModification";
        case 67: return "BroadcastSessionRelease";
        case 68: return "BroadcastSessionSetup";
        case 69: return "DistributionSetup";
        case 70: return "DistributionRelease";
        case 71: return "MulticastSessionActivation";
        case 72: return "MulticastSessionDeactivation";
        case 73: return "MulticastSessionUpdate";
        case 74: return "MulticastGroupPaging";
        case 75: return "BroadcastSessionReleaseRequired";
        case 76: return "TimingSynchronisationStatus";
        case 77: return "TimingSynchronisationStatusReport";
        case 78: return "MTCommunicationHandling";
        case 79: return "RANPagingRequest";
        case 80: return "BroadcastSessionTransport";
        case 81: return "NGRemoval";
        case 82: return "InventoryRequest";
        case 83: return "InventoryReport";
        case 84: return "CommandRequest";
        case 85: return "AIOTSessionRelease";
        case 86: return "AIOTSessionReleaseRequest";
        default: return "NGAP-" + std::to_string(procedure_code);
    }
}

}  // namespace signalbridge
