/*
 * Melrose Networks (Melrose Labs Ltd) - https://melrosenetworks.com
 * Date: 2026-01-04
 * Support: support@melrosenetworks.com
 * Disclaimer: Provided "as is" without warranty; use at your own risk.
 * Title: s1ap_parser.cpp
 * Description: Manual S1AP (S1 Application Protocol) parser implementation.
 *              Parses S1AP PDUs using PER (Packed Encoding Rules) decoding,
 *              extracts identifiers (IMSI, TMSI, IMEISV), S1AP IDs, and TEIDs
 *              from S1AP messages according to 3GPP TS 36.413 specifications.
 */

#include "s1ap_parser.h"
#include "nas_parser.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <cctype>

namespace s1ap_parser {

// SCTP protocol number
constexpr uint8_t IP_PROTO_SCTP = 132;

// SCTP chunk types
constexpr uint8_t SCTP_CHUNK_DATA = 0;

std::optional<std::vector<uint8_t>> extractS1apFromSctp(
    const uint8_t* packet, size_t len) {
    
    if (!packet || len < 14) {
        return std::nullopt;
    }
    
    size_t offset = 0;
    
    // Parse Ethernet header
    if (len < 14) {
        return std::nullopt;
    }
    
    uint16_t eth_type = (packet[12] << 8) | packet[13];
    offset = 14;
    
    // Handle VLAN tagging
    if ((eth_type == 0x8100 || eth_type == 0x88A8) && len >= offset + 4) {
        eth_type = (packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
    }
    
    uint8_t protocol = 0;
    size_t ip_header_len = 0;
    
    // Parse IPv4
    if (eth_type == 0x0800) {
        if (len < offset + 20) {
            return std::nullopt;
        }
        uint8_t ver_ihl = packet[offset];
        if ((ver_ihl >> 4) != 4) {
            return std::nullopt;
        }
        ip_header_len = (ver_ihl & 0x0F) * 4;
        if (len < offset + ip_header_len) {
            return std::nullopt;
        }
        protocol = packet[offset + 9];
        offset += ip_header_len;
    }
    // Parse IPv6
    else if (eth_type == 0x86DD) {
        if (len < offset + 40) {
            return std::nullopt;
        }
        if ((packet[offset] >> 4) != 6) {
            return std::nullopt;
        }
        protocol = packet[offset + 6];  // Next Header
        offset += 40;
        
        // Parse IPv6 extension headers (simplified)
        int ext_header_limit = 0;
        while (protocol != IP_PROTO_SCTP && ext_header_limit < 8 && offset < len) {
            if (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60) {
                if (len < offset + 8) {
                    return std::nullopt;
                }
                uint8_t ext_len = packet[offset + 1];
                size_t ext_header_len = (ext_len + 1) * 8;
                if (len < offset + ext_header_len) {
                    return std::nullopt;
                }
                protocol = packet[offset];
                offset += ext_header_len;
                ext_header_limit++;
            } else {
                break;
            }
        }
    } else {
        return std::nullopt;
    }
    
    // Check if SCTP
    if (protocol != IP_PROTO_SCTP) {
        return std::nullopt;
    }
    
    // Parse SCTP header (12 bytes)
    if (len < offset + 12) {
        return std::nullopt;
    }
    offset += 12;  // Skip SCTP common header
    
    // Parse SCTP chunks
    while (offset + 4 <= len) {
        uint8_t chunk_type = packet[offset];
        uint16_t chunk_len = (packet[offset + 2] << 8) | packet[offset + 3];
        
        if (chunk_len < 4 || offset + chunk_len > len) {
            break;
        }
        
        // DATA chunk (type 0)
        if (chunk_type == SCTP_CHUNK_DATA && chunk_len >= 16) {
            // DATA chunk structure:
            // Type(1) + Flags(1) + Length(2) + TSN(4) + StreamID(2) + 
            // StreamSeq(2) + PayloadProtocolID(4) + UserData(variable)

            uint32_t payload_protocol_id = (packet[offset + 12] << 24) | (packet[offset + 13] << 16) | (packet[offset + 14] << 8) | packet[offset + 15];

            if (payload_protocol_id != 18) {return std::nullopt;} // 18 is the S1AP protocol ID

            size_t payload_offset = offset + 16;
            size_t payload_len = chunk_len - 16;
            
            if (payload_len > 0 && payload_offset + payload_len <= len) {
                std::vector<uint8_t> s1ap_payload(
                    packet + payload_offset, 
                    packet + payload_offset + payload_len
                );
                return s1ap_payload;
            }
        }
        
        // Move to next chunk (4-byte aligned)
        size_t pad = (4 - (chunk_len % 4)) % 4;
        offset += chunk_len + pad;
    }
    
    return std::nullopt;
}

std::vector<std::vector<uint8_t>> extractAllS1apFromSctp(
    const uint8_t* packet, size_t len) {
    
    std::vector<std::vector<uint8_t>> s1ap_payloads;
    
    if (!packet || len < 14) {
        return s1ap_payloads;
    }
    
    size_t offset = 0;
    
    // Parse Ethernet header
    if (len < 14) {
        return s1ap_payloads;
    }
    
    uint16_t eth_type;
    if (packet[14] == 0x08) { // hack
        eth_type = (packet[14] << 8) | packet[15];
        offset = 16;
    } else {
        eth_type = (packet[12] << 8) | packet[13];
        offset = 14;
    }
    
    // Handle VLAN tagging
    if ((eth_type == 0x8100 || eth_type == 0x88A8) && len >= offset + 4) {
        eth_type = (packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
    }
    
    uint8_t protocol = 0;
    size_t ip_header_len = 0;
    
    // Parse IPv4
    if (eth_type == 0x0800) {
        if (len < offset + 20) {
            return s1ap_payloads;
        }
        uint8_t ver_ihl = packet[offset];
        if ((ver_ihl >> 4) != 4) {
            return s1ap_payloads;
        }
        ip_header_len = (ver_ihl & 0x0F) * 4;
        if (len < offset + ip_header_len) {
            return s1ap_payloads;
        }
        protocol = packet[offset + 9];
        offset += ip_header_len;
    }
    // Parse IPv6
    else if (eth_type == 0x86DD) {
        if (len < offset + 40) {
            return s1ap_payloads;
        }
        if ((packet[offset] >> 4) != 6) {
            return s1ap_payloads;
        }
        protocol = packet[offset + 6];  // Next Header
        offset += 40;
        
        // Parse IPv6 extension headers (simplified)
        int ext_header_limit = 0;
        while (protocol != IP_PROTO_SCTP && ext_header_limit < 8 && offset < len) {
            if (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60) {
                if (len < offset + 8) {
                    return s1ap_payloads;
                }
                uint8_t ext_len = packet[offset + 1];
                size_t ext_header_len = (ext_len + 1) * 8;
                if (len < offset + ext_header_len) {
                    return s1ap_payloads;
                }
                protocol = packet[offset];
                offset += ext_header_len;
                ext_header_limit++;
            } else {
                break;
            }
        }
    } else {
        return s1ap_payloads;
    }
    
    // Check if SCTP
    if (protocol != IP_PROTO_SCTP) {
        return s1ap_payloads;
    }
    
    // Parse SCTP header (12 bytes)
    if (len < offset + 12) {
        return s1ap_payloads;
    }
    offset += 12;  // Skip SCTP common header
    
    DEBUG_LOG << "[S1AP] extractAllS1apFromSctp: Searching for all SCTP DATA chunks with PayloadProtocolID=18" << std::endl;
    
    // Parse SCTP chunks - find ALL DATA chunks with PayloadProtocolID == 18
    while (offset + 4 <= len) {
        uint8_t chunk_type = packet[offset];
        uint16_t chunk_len = (packet[offset + 2] << 8) | packet[offset + 3];
        
        if (chunk_len < 4 || offset + chunk_len > len) {
            break;
        }
        
        // DATA chunk (type 0)
        if (chunk_type == SCTP_CHUNK_DATA && chunk_len >= 16) {
            // DATA chunk structure:
            // Type(1) + Flags(1) + Length(2) + TSN(4) + StreamID(2) + 
            // StreamSeq(2) + PayloadProtocolID(4) + UserData(variable)

            uint32_t payload_protocol_id = (packet[offset + 12] << 24) | 
                                          (packet[offset + 13] << 16) | 
                                          (packet[offset + 14] << 8) | 
                                          packet[offset + 15];

            if (payload_protocol_id == 18) {  // 18 is the S1AP protocol ID
                size_t payload_offset = offset + 16;
                size_t payload_len = chunk_len - 16;
                
                if (payload_len > 0 && payload_offset + payload_len <= len) {
                    std::vector<uint8_t> s1ap_payload(
                        packet + payload_offset, 
                        packet + payload_offset + payload_len
                    );
                    s1ap_payloads.push_back(s1ap_payload);
                    DEBUG_LOG << "[S1AP] extractAllS1apFromSctp: Found S1AP payload #" 
                              << s1ap_payloads.size() << " (size: " << payload_len << " bytes)" << std::endl;
                }
            }
        }
        
        // Move to next chunk (4-byte aligned)
        size_t pad = (4 - (chunk_len % 4)) % 4;
        offset += chunk_len + pad;
    }
    
    DEBUG_LOG << "[S1AP] extractAllS1apFromSctp: Found " << s1ap_payloads.size() << " S1AP payload(s)" << std::endl;
    
    return s1ap_payloads;
}

std::pair<uint64_t, size_t> readPerInteger(
    const uint8_t* data, size_t len, size_t offset) {
    
    if (offset >= len) {
        return {0, 0};
    }
    
    // Simplified PER integer decoding
    // PER uses length determinant + value
    // For simplicity, try to read as variable-length integer
    
    uint8_t first_byte = data[offset];
    
    // Single byte (0-127)
    if ((first_byte & 0x80) == 0) {
        return {first_byte, 1};
    }
    
    // Multi-byte (simplified - actual PER is more complex)
    if (offset + 1 >= len) {
        return {0, 0};
    }
    
    // Try 2-byte
    if ((first_byte & 0xC0) == 0x80) {
        uint16_t value = ((first_byte & 0x3F) << 8) | data[offset + 1];
        return {value, 2};
    }
    
    // Try 4-byte
    if (offset + 4 <= len) {
        uint32_t value = (data[offset] << 24) | 
                        (data[offset + 1] << 16) | 
                        (data[offset + 2] << 8) | 
                        data[offset + 3];
        return {value, 4};
    }
    
    return {0, 0};
}

std::pair<std::vector<uint8_t>, size_t> readPerOctetString(
    const uint8_t* data, size_t len, size_t offset, size_t length) {
    
    if (offset + length > len) {
        return {{}, 0};
    }
    
    std::vector<uint8_t> result(data + offset, data + offset + length);
    return {result, length};
}

std::string getProcedureCodeName(uint8_t procedure_code) {
    // Map ProcedureCode to procedure name based on S1AP specification
    switch (procedure_code) {
        case 0: return "HandoverPreparation";
        case 1: return "HandoverResourceAllocation";
        case 2: return "HandoverNotification";
        case 3: return "PathSwitchRequest";
        case 4: return "HandoverCancel";
        case 5: return "E-RABSetup";
        case 6: return "E-RABModify";
        case 7: return "E-RABRelease";
        case 8: return "E-RABReleaseIndication";
        case 9: return "InitialContextSetup";
        case 10: return "Paging";
        case 11: return "downlinkNASTransport";
        case 12: return "initialUEMessage";
        case 13: return "uplinkNASTransport";
        case 14: return "Reset";
        case 15: return "ErrorIndication";
        case 16: return "NASNonDeliveryIndication";
        case 17: return "S1Setup";
        case 18: return "UEContextReleaseRequest";
        case 19: return "DownlinkS1cdma2000tunneling";
        case 20: return "UplinkS1cdma2000tunneling";
        case 21: return "UEContextModification";
        case 22: return "UECapabilityInfoIndication";
        case 23: return "UEContextRelease";
        case 24: return "eNBStatusTransfer";
        case 25: return "MMEStatusTransfer";
        case 26: return "DeactivateTrace";
        case 27: return "TraceStart";
        case 28: return "TraceFailureIndication";
        case 29: return "ENBConfigurationUpdate";
        case 30: return "MMEConfigurationUpdate";
        case 31: return "LocationReportingControl";
        case 32: return "LocationReportingFailureIndication";
        case 33: return "LocationReport";
        case 34: return "OverloadStart";
        case 35: return "OverloadStop";
        case 36: return "WriteReplaceWarning";
        case 37: return "eNBDirectInformationTransfer";
        case 38: return "MMEDirectInformationTransfer";
        case 39: return "PrivateMessage";
        case 40: return "eNBConfigurationTransfer";
        case 41: return "MMEConfigurationTransfer";
        case 42: return "CellTrafficTrace";
        case 43: return "Kill";
        case 44: return "downlinkUEAssociatedLPPaTransport";
        case 45: return "uplinkUEAssociatedLPPaTransport";
        case 46: return "downlinkNonUEAssociatedLPPaTransport";
        case 47: return "uplinkNonUEAssociatedLPPaTransport";
        default: return "Unknown";
    }
}

std::string getIeNameFromId(uint16_t ie_id) {
    // Map ProtocolIE-ID to IE name based on S1AP specification
    switch (ie_id) {
        case 0: return "MME-UE-S1AP-ID";
        case 1: return "HandoverType";
        case 2: return "Cause";
        case 3: return "SourceID";
        case 4: return "TargetID";
        case 5: return "Unknown-5";
        case 6: return "Unknown-6";
        case 7: return "Unknown-7";
        case 8: return "eNB-UE-S1AP-ID";
        case 9: return "Unknown-9";
        case 10: return "Unknown-10";
        case 11: return "Unknown-11";
        case 12: return "E-RABSubjecttoDataForwardingList";
        case 13: return "E-RABtoReleaseListHOCmd";
        case 14: return "E-RABDataForwardingItem";
        case 15: return "E-RABReleaseItemBearerRelComp";
        case 16: return "E-RABToBeSetupListBearerSUReq";
        case 17: return "E-RABToBeSetupItemBearerSUReq";
        case 18: return "E-RABAdmittedList";
        case 19: return "E-RABFailedToSetupListHOReqAck";
        case 20: return "E-RABAdmittedItem";
        case 21: return "E-RABFailedtoSetupItemHOReqAck";
        case 22: return "E-RABToBeSwitchedDLList";
        case 23: return "E-RABToBeSwitchedDLItem";
        case 24: return "E-RABToBeSetupListCtxtSUReq";
        case 25: return "TraceActivation";
        case 26: return "NAS-PDU";
        case 27: return "E-RABToBeSetupItemHOReq";
        case 28: return "E-RABSetupListBearerSURes";
        case 29: return "E-RABFailedToSetupListBearerSURes";
        case 30: return "E-RABToBeModifiedListBearerModReq";
        case 31: return "E-RABModifyListBearerModRes";
        case 32: return "E-RABFailedToModifyList";
        case 33: return "E-RABToBeReleasedList";
        case 34: return "E-RABFailedToReleaseList";
        case 35: return "E-RABItem";
        case 36: return "E-RABToBeModifiedItemBearerModReq";
        case 37: return "E-RABModifyItemBearerModRes";
        case 38: return "E-RABReleaseItem";
        case 39: return "E-RABSetupItemBearerSURes";
        case 40: return "SecurityContext";
        case 41: return "HandoverRestrictionList";
        case 42: return "Unknown-42";
        case 43: return "UEPagingID";
        case 44: return "pagingDRX";
        case 45: return "Unknown-45";
        case 46: return "TAIList";
        case 47: return "TAIItem";
        case 48: return "E-RABFailedToSetupListCtxtSURes";
        case 49: return "E-RABReleaseItemHOCmd";
        case 50: return "E-RABSetupItemCtxtSURes";
        case 51: return "E-RABSetupListCtxtSURes";
        case 52: return "E-RABToBeSetupItemCtxtSUReq";
        case 53: return "E-RABToBeSetupListHOReq";
        case 54: return "Unknown-54";
        case 55: return "GERANtoLTEHOInformationRes";
        case 56: return "Unknown-56";
        case 57: return "UTRANtoLTEHOInformationRes";
        case 58: return "CriticalityDiagnostics";
        case 59: return "Global-ENB-ID";
        case 60: return "eNBname";
        case 61: return "MMEname";
        case 62: return "Unknown-62";
        case 63: return "ServedPLMNs";
        case 64: return "SupportedTAs";
        case 65: return "TimeToWait";
        case 66: return "uEaggregateMaximumBitrate";
        case 67: return "TAI";
        case 68: return "Unknown-68";
        case 69: return "E-RABReleaseListBearerRelComp";
        case 70: return "cdma2000PDU";
        case 71: return "cdma2000RATType";
        case 72: return "cdma2000SectorID";
        case 73: return "SecurityKey";
        case 74: return "UERadioCapability";
        case 75: return "GUMMEI-ID";
        case 76: return "Unknown-76";
        case 77: return "Unknown-77";
        case 78: return "E-RABInformationListItem";
        case 79: return "Direct-Forwarding-Path-Availability";
        case 80: return "UEIdentityIndexValue";
        case 81: return "Unknown-81";
        case 82: return "Unknown-82";
        case 83: return "cdma2000HOStatus";
        case 84: return "cdma2000HORequiredIndication";
        case 85: return "Unknown-85";
        case 86: return "E-UTRAN-Trace-ID";
        case 87: return "RelativeMMECapacity";
        case 88: return "SourceMME-UE-S1AP-ID";
        case 89: return "Bearers-SubjectToStatusTransfer-Item";
        case 90: return "eNB-StatusTransfer-TransparentContainer";
        case 91: return "UE-associatedLogicalS1-ConnectionItem";
        case 92: return "ResetType";
        case 93: return "UE-associatedLogicalS1-ConnectionListResAck";
        case 94: return "E-RABToBeSwitchedULItem";
        case 95: return "E-RABToBeSwitchedULList";
        case 96: return "S-TMSI";
        case 97: return "cdma2000OneXRAND";
        case 98: return "RequestType";
        case 99: return "UE-S1AP-IDs";
        case 100: return "EUTRAN-CGI";
        case 101: return "OverloadResponse";
        case 102: return "cdma2000OneXSRVCCInfo";
        case 103: return "E-RABFailedToBeReleasedList";
        case 104: return "Source-ToTarget-TransparentContainer";
        case 105: return "ServedGUMMEIs";
        case 106: return "SubscriberProfileIDforRFP";
        case 107: return "UESecurityCapabilities";
        case 108: return "CSFallbackIndicator";
        case 109: return "CNDomain";
        case 110: return "E-RABReleasedList";
        case 111: return "MessageIdentifier";
        case 112: return "SerialNumber";
        case 113: return "WarningAreaList";
        case 114: return "RepetitionPeriod";
        case 115: return "NumberofBroadcastRequest";
        case 116: return "WarningType";
        case 117: return "WarningSecurityInfo";
        case 118: return "DataCodingScheme";
        case 119: return "WarningMessageContents";
        case 120: return "BroadcastCompletedAreaList";
        case 121: return "Inter-SystemInformationTransferTypeEDT";
        case 122: return "Inter-SystemInformationTransferTypeMDT";
        case 123: return "Target-ToSource-TransparentContainer";
        case 124: return "SRVCCOperationPossible";
        case 125: return "SRVCCHOIndication";
        case 126: return "NAS-DownlinkCount";
        case 127: return "CSG-Id";
        case 128: return "CSG-IdList";
        case 129: return "SONConfigurationTransferECT";
        case 130: return "SONConfigurationTransferMCT";
        case 131: return "TraceCollectionEntityIPAddress";
        case 132: return "MSClassmark2";
        case 133: return "MSClassmark3";
        case 134: return "RRC-Establishment-Cause";
        case 135: return "NASSecurityParametersfromE-UTRAN";
        case 136: return "NASSecurityParameterstoE-UTRAN";
        case 137: return "DefaultPagingDRX";
        case 138: return "Source-ToTarget-TransparentContainer-Secondary";
        case 139: return "Target-ToSource-TransparentContainer-Secondary";
        case 140: return "EUTRANRoundTripDelayEstimationInfo";
        case 141: return "BroadcastCancelledAreaList";
        case 142: return "ConcurrentWarningMessageIndicator";
        case 143: return "Data-Forwarding-Not-Possible";
        case 144: return "ExtendedRepetitionPeriod";
        case 145: return "CellAccessMode";
        case 146: return "CSGMembershipStatus";
        case 147: return "LPPa-PDU";
        case 148: return "Routing-ID";
        case 149: return "Time-Synchronization-Info";
        case 150: return "PS-ServiceNotAvailable";
        case 151: return "PagingPriority";
        case 152: return "x2TNLConfigurationInfo";
        case 153: return "eNBX2ExtendedTransportLayerAddresses";
        case 154: return "GUMMEIList";
        case 155: return "GW-TransportLayerAddress";
        case 156: return "Correlation-ID";
        case 157: return "SourceMME-GUMMEI";
        case 158: return "MME-UE-S1AP-ID-2";
        case 159: return "RegisteredLAI";
        case 160: return "RelayNode-Indicator";
        case 161: return "TrafficLoadReductionIndication";
        case 162: return "MDTConfiguration";
        case 163: return "MMERelaySupportIndicator";
        case 164: return "GWContextReleaseIndication";
        case 165: return "ManagementBasedMDTAllowed";
        default: return "IE_" + std::to_string(ie_id);
    }
}

std::vector<uint32_t> findTeidPatterns(const uint8_t* data, size_t len) {
    std::vector<uint32_t> teids;
    
    return teids;
    
    if (!data || len < 4) {
        return teids;
    }
    
    // Look for 4-byte patterns that could be TEIDs
    // Strategy: Look for patterns that appear after known S1AP structures
    // TEIDs in S1AP are typically:
    // - 4 bytes, big-endian
    // - Non-zero
    // - Often appear after length fields or IE identifiers
    
    // More sophisticated approach: look for patterns that could be TEIDs
    // based on context (e.g., after "gTP-TEID" field markers, though we can't
    // easily detect those without full PER decoding)
    
    // For now, use a heuristic: look for 4-byte values that:
    // 1. Are non-zero
    // 2. Are in reasonable ranges (not too small, not too large)
    // 3. Don't look like lengths or other fields
    
    for (size_t i = 0; i + 4 <= len; ++i) {
        uint32_t candidate = (data[i] << 24) | 
                             (data[i + 1] << 16) | 
                             (data[i + 2] << 8) | 
                             data[i + 3];
        
        // Filter: non-zero, reasonable range
        // TEIDs are typically >= 0x100 (256) and <= 0xFFFFFFFF
        // Very small values are likely lengths or other fields
        if (candidate >= 0x100 && candidate <= 0xFFFFFFFF) {
            // Additional heuristic: TEIDs often have certain bit patterns
            // But for now, accept any reasonable value
            if (std::find(teids.begin(), teids.end(), candidate) == teids.end()) {
                teids.push_back(candidate);
            }
        }
    }
    
    // Limit to reasonable number (avoid too many false positives)
    if (teids.size() > 10) {
        // Keep only first 10 (or could use more sophisticated filtering)
        teids.resize(10);
    }
    
    return teids;
}

S1apParseResult parseS1apPdu(const uint8_t* s1ap_bytes, size_t len) {
    S1apParseResult result;
    result.decoded = false;
    result.raw_bytes.assign(s1ap_bytes, s1ap_bytes + len);
    result.s1ap_payload.assign(s1ap_bytes, s1ap_bytes + len);
    
    if (!s1ap_bytes || len < 1) {
        return result;
    }
    
    // S1AP PDU structure (APER - Aligned PER encoding):
    // S1AP-PDU is a CHOICE of:
    //   - initiatingMessage (0)
    //   - successfulOutcome (1)
    //   - unsuccessfulOutcome (2)
    //
    // In APER, CHOICE is encoded as:
    //   1. CHOICE index (1 byte, since 3 choices: 0, 1, or 2)
    //   2. Selected message structure:
    //      - procedureCode (INTEGER) - APER length determinant + value
    //      - criticality (ENUMERATED) - APER index (1 byte: 0=reject, 1=ignore, 2=notify)
    //      - value (SEQUENCE with protocolIEs) - APER length + content
    
    size_t offset = 0;
    
    // Step 1: Decode CHOICE index (PDU type)
    if (offset >= len) {
        DEBUG_LOG << "!! offset >= len" << std::endl;
        return result;
    }
    
    uint8_t choice_index = (s1ap_bytes[offset]>>5) & 0x03;
    offset++;
    
    // Validate choice index (0, 1, or 2)
    if (choice_index > 2) {
        // Invalid choice index
        DEBUG_LOG << "!! Invalid choice index " << (int)choice_index << std::endl;
        return result;
    }
    
    result.pdu_type = static_cast<S1apPduType>(choice_index);
    
    // Step 2: Decode procedureCode (INTEGER(0..255))
    // In APER, constrained INTEGER(0..255) is encoded directly as 1 byte
    // No length determinant needed for constrained integers
    
    if (offset >= len) {
        DEBUG_LOG << "!! offset >= len" << std::endl;
        return result;
    }
    
    // Procedure code is directly the next byte (constrained to 0..255)
    result.procedure_code = s1ap_bytes[offset];
    offset++;
    
    // Map procedure code to name using helper function
    result.procedure_name = getProcedureCodeName(result.procedure_code);
    
    // Step 3: Decode criticality (ENUMERATED {reject, ignore, notify})
    // In APER, ENUMERATED with 3 values is encoded as index (constrained integer)
    // Since it's constrained to 0..2, it's encoded as 1 byte directly
    if (offset >= len) {
        // Missing criticality, but we have enough info
        result.decoded = true;
        return result;
    }
    
    // criticality: 0=reject, 1=ignore, 2=notify (we don't store this in result currently)
    // Just consume the byte
    offset++;
    
    // Step 4: Decode value (SEQUENCE with protocolIEs)
    // protocolIEs is a SEQUENCE OF ProtocolIE-Field
    // Each ProtocolIE-Field contains:
    //   - id (INTEGER - ProtocolIE-ID)
    //   - criticality (ENUMERATED)
    //   - value (OPEN TYPE - variable length)
    
    DEBUG_LOG << "[S1AP] Starting protocolIEs decoding at offset " << offset 
              << " (total length: " << len << ")" << std::endl;
    
    if (offset >= len) {
        // No protocolIEs, but we have enough info
        DEBUG_LOG << "[S1AP] No protocolIEs (offset >= len)" << std::endl;
        result.decoded = true;
        return result;
    }
    
    // Decode length determinant for SEQUENCE OF
    // In APER, length determinant for SEQUENCE OF is encoded as:
    // - If length <= 127: 1 byte with bit 7 = 0, bits 0-6 = length
    // - If length > 127: Extended format (more complex)
    // For S1AP, typically uses constrained length (0..maxProtocolIEs)
    
    uint32_t num_ies = 0;
    if (offset < len) {

        for(size_t i=0;i<len;i++) { DEBUG_LOG << std::hex << static_cast<unsigned>(s1ap_bytes[i]) << " "; }
        DEBUG_LOG << std::endl; 
        DEBUG_LOG << offset << std::endl; 

        uint8_t length_byte = s1ap_bytes[offset];
        DEBUG_LOG << "[S1AP] Length determinant byte: 0x" << std::hex 
                  << static_cast<unsigned>(length_byte) << std::dec << std::endl;
        offset++;
        uint8_t second_byte = s1ap_bytes[offset];

        offset+=2;
        
        if ((length_byte & 0x80) == 0) {
            // Short form: length is in bits 0-6
            DEBUG_LOG << "offset: " << offset << std::endl;
            num_ies = s1ap_bytes[offset];
            offset+=1;

            //num_ies = length_byte & 0x7F;
            DEBUG_LOG << "[S1AP] Short form length: " << num_ies << " IEs" << std::endl;
        } else {
            // Extended form: length is in multiple bytes
            // First byte: bit 7 = 1, bits 0-6 = number of length bytes - 1
            uint8_t num_length_bytes = ((length_byte & 0x7F)<<8) + second_byte;
            DEBUG_LOG << "[S1AP] Extended form length: " << static_cast<unsigned>(num_length_bytes) 
                      << " bytes" << std::endl;
            if (num_length_bytes > 4 || (offset) + num_length_bytes > len) {
                // Invalid extended length
                DEBUG_LOG << "[S1AP] ERROR: Invalid extended length (bytes=" 
                          << static_cast<unsigned>(num_length_bytes) << ", remaining=" 
                          << (len - offset) << ")" << std::endl;
                result.decoded = true;  // We got basic info
                //return result;
            }

            offset++;
            DEBUG_LOG << "offset: " << offset << std::endl;
            num_ies = s1ap_bytes[offset];
            offset++;
            
            // Read length bytes (big-endian)
            // num_ies = 0;
            // for (size_t i = 0; i < num_length_bytes; ++i) {
            //     num_ies = (num_ies << 8) | s1ap_bytes[offset + i];
            // }
            //offset += num_length_bytes;
            DEBUG_LOG << "[S1AP] Extended length value: " << num_ies << " IEs" << std::endl;
        }
    }
    
    DEBUG_LOG << "[S1AP] Decoding " << num_ies << " protocolIE(s) starting at offset " 
              << offset << std::endl;
    
    // Decode each ProtocolIE-Field
    for (uint32_t ie_idx = 0; ie_idx < num_ies && offset < len; ++ie_idx) {
        DEBUG_LOG << "[S1AP] IE #" << (ie_idx + 1) << "/" << num_ies 
                  << " at offset " << offset << std::endl;
        // Decode id (ProtocolIE-ID)
        // ProtocolIE-ID is INTEGER(0..65535) - constrained integer
        // In APER, constrained INTEGER(0..65535) is typically encoded as:
        // - 1 byte if value < 128 (most common for small IDs)
        // - 2 bytes if value >= 128
        // However, some implementations may use length determinant
        // For S1AP, most IE IDs are small (< 128), so try 1-byte first
        if (offset >= len) {
            break;
        }
        
        uint16_t ie_id = 0;
        // Check if first byte suggests length determinant or direct value
        // If bit 7 is set, it might be a length determinant
        // Otherwise, it's likely a direct 1-byte value
        uint8_t first_byte = s1ap_bytes[offset];
        DEBUG_LOG << "[S1AP]   IE ID first byte: 0x" << std::hex 
                  << static_cast<unsigned>(first_byte) << std::dec << std::endl;
        
        ie_id = (s1ap_bytes[offset] << 8) | s1ap_bytes[offset + 1];
        offset += 2;
        DEBUG_LOG << "[S1AP]   IE ID (2-byte): " << ie_id << std::endl;
        
        // Decode criticality (ENUMERATED {reject, ignore, notify})
        // Same as message-level criticality: 1 byte, 0=reject, 1=ignore, 2=notify
        if (offset >= len) {
            DEBUG_LOG << "[S1AP]   ERROR: No data for criticality (offset=" << offset 
                      << ", len=" << len << ")" << std::endl;
            break;
        }
        uint8_t ie_criticality = s1ap_bytes[offset];
        const char* criticality_str = (ie_criticality == 0) ? "reject" : 
                                      (ie_criticality == 1) ? "ignore" : 
                                      (ie_criticality == 2) ? "notify" : "unknown";
        DEBUG_LOG << "[S1AP]   Criticality: " << static_cast<unsigned>(ie_criticality) 
                  << " (" << criticality_str << ")" << std::endl;
        offset++;
        
        // Decode value (OPEN TYPE)
        // OPEN TYPE is encoded as: length determinant + bytes
        if (offset >= len) {
            DEBUG_LOG << "[S1AP]   ERROR: No data for value length (offset=" << offset 
                      << ", len=" << len << ")" << std::endl;
            break;
        }
        
        // Read length determinant for OPEN TYPE value
        uint32_t value_length = 0;
        uint8_t value_length_byte = s1ap_bytes[offset];
        DEBUG_LOG << "[S1AP]   Value length byte: 0x" << std::hex 
                  << static_cast<unsigned>(value_length_byte) << std::dec << std::endl;
        offset++;
        
        if ((value_length_byte & 0x80) == 0) {
            // Short form: length is in bits 0-6
            value_length = value_length_byte & 0x7F;
            DEBUG_LOG << "[S1AP]   Value length (short form): " << value_length << " bytes" << std::endl;
        } else {
            // Extended form
            uint8_t num_length_bytes = (value_length_byte & 0x7F) + 1;
            DEBUG_LOG << "[S1AP]   Value length (extended form): " 
                      << static_cast<unsigned>(num_length_bytes) << " bytes" << std::endl;
            if (num_length_bytes > 4 || offset + num_length_bytes > len) {
                DEBUG_LOG << "[S1AP]   ERROR: Invalid extended value length (bytes=" 
                          << static_cast<unsigned>(num_length_bytes) << ", remaining=" 
                          << (len - offset) << ")" << std::endl;
                break;
            }
            
            value_length = 0;
            for (size_t i = 0; i < num_length_bytes; ++i) {
                value_length = (value_length << 8) | s1ap_bytes[offset + i];
            }
            offset += num_length_bytes;
            DEBUG_LOG << "[S1AP]   Value length (extended value): " << value_length << " bytes" << std::endl;
        }
        
        // Read value bytes
        if (offset + value_length > len) {
            DEBUG_LOG << "[S1AP]   ERROR: Value length exceeds remaining data (length=" 
                      << value_length << ", remaining=" << (len - offset) << ")" << std::endl;
            break;
        }
        
        // Store IE information
        // Get IE name from ID using helper function
        std::string ie_name = getIeNameFromId(ie_id);
        
        DEBUG_LOG << "[S1AP]   IE Name: " << ie_name << std::endl;
        
        // Store value as hex string for now
        // In a full implementation, we would decode the value based on IE type
        std::ostringstream value_hex;
        value_hex << std::hex << std::setfill('0');
        size_t bytes_to_show = (value_length > 32) ? 32 : value_length;  // Show first 32 bytes max
        for (size_t i = 0; i < bytes_to_show && (offset + i) < len; ++i) {
            value_hex << std::setw(2) << static_cast<unsigned>(s1ap_bytes[offset + i]);
        }
        if (value_length > 32) {
            value_hex << "...";
        }
        
        DEBUG_LOG << "[S1AP]   Value (" << value_length << " bytes): " 
                  << value_hex.str() << std::endl;
        
        // Store full value in result
        std::ostringstream full_value_hex;
        full_value_hex << std::hex << std::setfill('0');
        for (size_t i = 0; i < value_length && (offset + i) < len; ++i) {
            full_value_hex << std::setw(2) << static_cast<unsigned>(s1ap_bytes[offset + i]);
        }
        result.information_elements[ie_name] = full_value_hex.str();
        
        offset += value_length;
        DEBUG_LOG << "[S1AP]   IE #" << (ie_idx + 1) << " decoded, new offset: " << offset << std::endl;
    }
    
    DEBUG_LOG << "[S1AP] Finished decoding protocolIEs. Total decoded: " 
              << result.information_elements.size() << " IEs" << std::endl;
    
    result.decoded = true;
    
    return result;
}

std::vector<uint32_t> extractTeidsFromS1apBytes(const uint8_t* s1ap_bytes, size_t len) {
    std::vector<uint32_t> teids;
    
    if (!s1ap_bytes || len < 4) {
        return teids;
    }
    
    // Strategy: Look for 4-byte patterns that could be TEIDs
    // This is a heuristic approach - full PER decoding would be more accurate
    // but is very complex to implement manually
    
    // TEIDs in S1AP are encoded as OCTET STRING (4 bytes) in PER
    // They appear in IEs like:
    // - gTP-TEID
    // - dL-gTP-TEID  
    // - uL-GTP-TEID
    
    // // Without full PER decoding, we use pattern matching:
    // // Look for 4-byte values that could be TEIDs
    
    // auto candidates = findTeidPatterns(s1ap_bytes, len);
    
    // // Filter and deduplicate
    // for (uint32_t candidate : candidates) {
    //     if (candidate != 0 && 
    //         candidate >= 0x100 &&  // Exclude very small values (likely lengths)
    //         candidate <= 0xFFFFFFFF &&
    //         std::find(teids.begin(), teids.end(), candidate) == teids.end()) {
    //         teids.push_back(candidate);
    //     }
    // }
    
    // // Limit results to avoid too many false positives
    // // In practice, a single S1AP message typically has 0-4 TEIDs
    // if (teids.size() > 5) {
    //     teids.resize(5);
    // }
    
    return teids;
}

std::vector<std::string> extractImsiFromS1apBytes(const uint8_t* /*s1ap_bytes*/, size_t /*len*/) {
    // IMSI in S1AP is typically in NAS messages, not directly in S1AP IEs
    // This would require PER decoding to find the NAS-PDU IE
    // Then extract IMSI from NAS (which we already do in nas_parser)
    std::vector<std::string> imsis;
    return imsis;
}

std::vector<std::string> extractTmsiFromS1apBytes(const uint8_t* s1ap_bytes, size_t len) {
    std::vector<std::string> tmsis;
    
    if (!s1ap_bytes || len < 4) {
        return tmsis;
    }
    
    // TMSI in S-TMSI.m-TMSI is 4 bytes
    // Note: Should only extract from S-TMSI.m-TMSI path, not arbitrary 4-byte values
    // Without full PER decoding, we can't reliably find S-TMSI IE
    // For now, this is a placeholder that would need PER decoding
    
    // Full PER decoding would:
    // 1. Find S-TMSI IE (IE ID 10)
    // 2. Extract m-TMSI field (4 bytes) from within S-TMSI structure
    // 3. Return only that value
    
    // Current implementation: pattern matching (not accurate)
    // TODO: Implement proper PER decoding for S-TMSI IE
    
    return tmsis;  // Return empty for now - requires PER decoding
}

std::vector<std::string> extractImeisvFromS1apBytes(const uint8_t* /*s1ap_bytes*/, size_t /*len*/) {
    // IMEISV extraction would require PER decoding to find IMEISV IE
    std::vector<std::string> imeisvs;
    return imeisvs;
}

std::pair<std::optional<uint32_t>, std::optional<uint32_t>> 
extractS1apIdsFromBytes(const uint8_t* /*s1ap_bytes*/, size_t /*len*/) {
    // MME-UE-S1AP-ID and eNB-UE-S1AP-ID extraction requires PER decoding
    return {std::nullopt, std::nullopt};
}

std::vector<std::vector<uint8_t>> extractNasPdusFromS1ap(
    const uint8_t* /*s1ap_bytes*/, size_t /*len*/) {
    // NAS PDU extraction requires PER decoding to find NAS-PDU IE
    std::vector<std::vector<uint8_t>> nas_pdus;
    return nas_pdus;
}

ERabSetupListCtxtSURes decodeERabSetupListCtxtSURes(
    const uint8_t* ie_value_bytes, size_t len) {
    
    ERabSetupListCtxtSURes result;
    result.decoded = false;
    
    if (!ie_value_bytes || len < 1) {
        return result;
    }
    
    size_t offset = 0;
    
    DEBUG_LOG << "[E-RABSetupListCtxtSURes] Starting decoding at offset " << offset 
              << " (total length: " << len << ")" << std::endl;
    
    // Step 1: Decode SEQUENCE OF length determinant
    // In APER, length determinant for SEQUENCE OF is encoded as:
    // - If length <= 127: 1 byte with bit 7 = 0, bits 0-6 = length
    // - If length > 127: Extended format
    if (offset >= len) {
        DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: No data for length" << std::endl;
        return result;
    }
    
    uint32_t num_items = 0;
    uint8_t length_byte = ie_value_bytes[offset];
    offset++;
    
    if ((length_byte & 0x80) == 0) {
        // Short form: length is in bits 0-6
        num_items = 1 + (length_byte & 0x7F);
        DEBUG_LOG << "[E-RABSetupListCtxtSURes] Short form length byte: 0x" << std::hex 
                  << static_cast<unsigned>(length_byte) << std::dec << " = " << num_items << " items" << std::endl;
        
        // Special handling: If length is 0 but there's clearly data following,
        // it might be that the stored IE value doesn't start with the SEQUENCE OF length,
        // or there's a different encoding. Check if we have enough data for at least one item.
        // E-RABSetupListCtxtSURes has constraint SIZE(1..maxNrOfE-RABs), so minimum is 1.
        // In some PER encodings, a length of 0 for a constrained type with min=1 might mean 1.
        // However, standard PER encodes SEQUENCE OF length as actual count.
        // If length is 0 but we have data, assume 1 item (heuristic for constrained types)
        // if (num_items == 0 && len > offset + 5) {  // At least 5 bytes for IE ID(2) + criticality(1) + min value length(2)
        //     DEBUG_LOG << "[E-RABSetupListCtxtSURes] WARNING: Length is 0 but data present, assuming 1 item (constrained SIZE(1..max))" << std::endl;
        //     num_items = 1;
        // }
    } else {
        // Extended form
        uint8_t num_length_bytes = (length_byte & 0x7F) + 1;
        DEBUG_LOG << "[E-RABSetupListCtxtSURes] Extended form length: " 
                  << static_cast<unsigned>(num_length_bytes) << " bytes" << std::endl;
        if (num_length_bytes > 4 || offset + num_length_bytes > len) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: Invalid extended length" << std::endl;
            return result;
        }
        
        num_items = 0;
        for (size_t i = 0; i < num_length_bytes; ++i) {
            num_items = (num_items << 8) | ie_value_bytes[offset + i];
        }
        offset += num_length_bytes;
        DEBUG_LOG << "[E-RABSetupListCtxtSURes] Extended length value: " << num_items << " items" << std::endl;
    }
    
    // Step 2: Decode each ProtocolIE-SingleContainer
    // ProtocolIE-SingleContainer is a ProtocolIE-Field containing:
    //   - id (ProtocolIE-ID) = 50 (id-E-RABSetupItemCtxtSURes)
    //   - criticality (ENUMERATED)
    //   - value (E-RABSetupItemCtxtSURes)
    for (uint32_t item_idx = 0; item_idx < num_items && offset < len; ++item_idx) {
        DEBUG_LOG << "[E-RABSetupListCtxtSURes] Decoding item #" << (item_idx + 1) 
                  << "/" << num_items << " at offset " << offset << std::endl;
        
        ERabSetupItemCtxtSURes item;
        item.has_extensions = false;
        
        // Decode ProtocolIE-Field: id (ProtocolIE-ID)
        if (offset + 2 > len) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: No data for IE ID" << std::endl;
            break;
        }
        
        uint16_t ie_id = (ie_value_bytes[offset] << 8) | ie_value_bytes[offset + 1];
        offset += 2;
        DEBUG_LOG << "[E-RABSetupListCtxtSURes]   IE ID: " << ie_id << " (expected 50)" << std::endl;
        
        if (ie_id != 50) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes]   WARNING: Unexpected IE ID, expected 50" << std::endl;
        }
        
        // Decode criticality (ENUMERATED)
        if (offset >= len) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: No data for criticality" << std::endl;
            break;
        }
        uint8_t criticality = ie_value_bytes[offset];
        offset++;
        DEBUG_LOG << "[E-RABSetupListCtxtSURes]   Criticality: " << static_cast<unsigned>(criticality) << std::endl;
        
        // Decode value length (OPEN TYPE)
        if (offset >= len) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: No data for value length" << std::endl;
            break;
        }
        
        uint32_t value_length = 0;
        uint8_t value_length_byte = ie_value_bytes[offset];
        offset++;
        
        if ((value_length_byte & 0x80) == 0) {
            // Short form
            value_length = value_length_byte & 0x7F;
            DEBUG_LOG << "[E-RABSetupListCtxtSURes]   Value length (short): " << value_length << " bytes" << std::endl;
        } else {
            // Extended form
            uint8_t num_length_bytes = (value_length_byte & 0x7F) + 1;
            if (num_length_bytes > 4 || offset + num_length_bytes > len) {
                DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: Invalid extended value length" << std::endl;
                break;
            }
            
            value_length = 0;
            for (size_t i = 0; i < num_length_bytes; ++i) {
                value_length = (value_length << 8) | ie_value_bytes[offset + i];
            }
            offset += num_length_bytes;
            DEBUG_LOG << "[E-RABSetupListCtxtSURes]   Value length (extended): " << value_length << " bytes" << std::endl;
        }
        
        if (offset + value_length > len) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: Value length exceeds remaining data" << std::endl;
            break;
        }
        
        // Step 3: Decode E-RABSetupItemCtxtSURes SEQUENCE
        // Fields: e-RAB-ID, transportLayerAddress, gTP-TEID, iE-Extensions (OPTIONAL)
        //size_t item_value_start = offset;
        size_t item_value_end = offset + value_length;
        
        // Decode e-RAB-ID (INTEGER 0..15)
        // Constrained INTEGER(0..15) in APER is encoded as 1 byte
        if (offset >= item_value_end) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: No data for e-RAB-ID" << std::endl;
            break;
        }
        item.e_rab_id = ie_value_bytes[offset];  // Full byte (value 0..15)
        offset++;
        DEBUG_LOG << "[E-RABSetupListCtxtSURes]   e-RAB-ID: " << static_cast<unsigned>(item.e_rab_id) << std::endl;
        
        // Decode transportLayerAddress (BIT STRING SIZE(1..160))
        // BIT STRING in APER: length determinant (in bits) + bits (padded to byte boundary)
        if (offset >= item_value_end) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: No data for transportLayerAddress length (offset=" 
                      << offset << ", end=" << item_value_end << ")" << std::endl;
            break;
        }
        
        uint32_t bit_string_length = 0;
        uint8_t bit_length_byte = ie_value_bytes[offset];
        DEBUG_LOG << "[E-RABSetupListCtxtSURes]   transportLayerAddress length byte: 0x" << std::hex 
                  << static_cast<unsigned>(bit_length_byte) << std::dec << " at offset " << offset << std::endl;
        offset++;
        
        if ((bit_length_byte & 0x80) == 0) {
            // Short form: length in bits 0-6
            bit_string_length = bit_length_byte & 0x7F;
            DEBUG_LOG << "[E-RABSetupListCtxtSURes]   transportLayerAddress length (short form): " 
                      << bit_string_length << " bits" << std::endl;
        } else {
            // Extended form
            uint8_t num_length_bytes = (bit_length_byte & 0x7F) + 1;
            DEBUG_LOG << "[E-RABSetupListCtxtSURes]   transportLayerAddress length (extended form): " 
                      << static_cast<unsigned>(num_length_bytes) << " bytes" << std::endl;
            if (num_length_bytes > 4 || offset + num_length_bytes > item_value_end) {
                DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: Invalid bit string length (bytes=" 
                          << static_cast<unsigned>(num_length_bytes) << ", remaining=" 
                          << (item_value_end - offset) << ")" << std::endl;
                break;
            }
            
            bit_string_length = 0;
            for (size_t i = 0; i < num_length_bytes; ++i) {
                bit_string_length = (bit_string_length << 8) | ie_value_bytes[offset + i];
            }
            offset += num_length_bytes;
            DEBUG_LOG << "[E-RABSetupListCtxtSURes]   transportLayerAddress length (extended value): " 
                      << bit_string_length << " bits" << std::endl;
        }
        
        // Calculate number of bytes needed for the bit string (round up)
        size_t bit_string_bytes = (bit_string_length + 7) / 8;
        DEBUG_LOG << "[E-RABSetupListCtxtSURes]   transportLayerAddress: " << bit_string_length 
                  << " bits = " << bit_string_bytes << " bytes (offset=" << offset 
                  << ", remaining=" << (item_value_end - offset) << ")" << std::endl;
        
        if (offset + bit_string_bytes > item_value_end) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: Bit string exceeds value boundary (needed=" 
                      << bit_string_bytes << ", remaining=" << (item_value_end - offset) << ")" << std::endl;
            break;
        }
        
        item.transport_layer_address.assign(
            ie_value_bytes + offset,
            ie_value_bytes + offset + bit_string_bytes
        );
        
        // Log the transport layer address bytes
        DEBUG_LOG << "[E-RABSetupListCtxtSURes]   transportLayerAddress bytes: ";
        for (size_t i = 0; i < bit_string_bytes && i < 16; ++i) {
            DEBUG_LOG << std::hex << std::setw(2) << std::setfill('0') 
                      << static_cast<unsigned>(item.transport_layer_address[i]) << " ";
        }
        if (bit_string_bytes > 16) {
            DEBUG_LOG << "...";
        }
        DEBUG_LOG << std::dec << std::endl;
        
        offset += bit_string_bytes;
        
        // Decode gTP-TEID (OCTET STRING SIZE(4))
        // For fixed-size OCTET STRING in PER/APER, the size is known from the ASN.1 definition,
        // so no length determinant is encoded - just the 4 bytes directly
        if (offset + 4 > item_value_end) {
            DEBUG_LOG << "[E-RABSetupListCtxtSURes] ERROR: No data for gTP-TEID (need 4 bytes, have " 
                      << (item_value_end - offset) << " remaining)" << std::endl;
            break;
        }
        
        item.gtp_teid = (static_cast<uint32_t>(ie_value_bytes[offset]) << 24) |
                        (static_cast<uint32_t>(ie_value_bytes[offset + 1]) << 16) |
                        (static_cast<uint32_t>(ie_value_bytes[offset + 2]) << 8) |
                        static_cast<uint32_t>(ie_value_bytes[offset + 3]);
        offset += 4;
        DEBUG_LOG << "[E-RABSetupListCtxtSURes]   gTP-TEID: 0x" << std::hex 
                  << item.gtp_teid << std::dec << " (" << item.gtp_teid << ")" << std::endl;
        
        // Decode iE-Extensions (OPTIONAL)
        // OPTIONAL field: presence bit (1 if present, 0 if absent)
        if (offset < item_value_end) {
            // Check if there's more data (extensions might be present)
            // In APER, OPTIONAL fields typically have a presence bit
            // For simplicity, if we have remaining bytes, assume extensions are present
            item.has_extensions = (offset < item_value_end);
            if (item.has_extensions) {
                DEBUG_LOG << "[E-RABSetupListCtxtSURes]   iE-Extensions: present (" 
                          << (item_value_end - offset) << " bytes remaining)" << std::endl;
                // Skip extensions for now (they're complex to decode)
                offset = item_value_end;
            }
        }
        
        result.items.push_back(item);
        DEBUG_LOG << "[E-RABSetupListCtxtSURes]   Item #" << (item_idx + 1) << " decoded successfully" << std::endl;
    }
    
    result.decoded = (result.items.size() == num_items);
    DEBUG_LOG << "[E-RABSetupListCtxtSURes] Decoding complete: " << result.items.size() 
              << "/" << num_items << " items decoded" << std::endl;
    
    return result;
}

// Helper function to convert hex string to bytes
namespace {
    std::vector<uint8_t> hexToBytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i < hex.length(); i += 2) {
            if (i + 1 < hex.length()) {
                std::string byte_str = hex.substr(i, 2);
                bytes.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
            }
        }
        return bytes;
    }
} // anonymous namespace

// Extract TMSI from S-TMSI IE in information_elements
std::vector<std::string> extractTmsiFromIEList(
    const std::unordered_map<std::string, std::string>& information_elements) {
    
    std::vector<std::string> tmsis;
    
    DEBUG_LOG << "[S1AP] extractTmsiFromIEList: Looking for S-TMSI IE in information_elements" << std::endl;
    
    // Look for "S-TMSI" IE name
    auto s_tmsi_it = information_elements.find("S-TMSI");
    if (s_tmsi_it == information_elements.end()) {
        DEBUG_LOG << "[S1AP] extractTmsiFromIEList: S-TMSI IE not found in information_elements" << std::endl;
        return tmsis;
    }
    
    const std::string& s_tmsi_hex = s_tmsi_it->second;
    DEBUG_LOG << "[S1AP] extractTmsiFromIEList: Found S-TMSI IE, hex value length: " 
              << s_tmsi_hex.length() << " chars (" << (s_tmsi_hex.length() / 2) << " bytes)" << std::endl;
    
    if (s_tmsi_hex.empty()) {
        DEBUG_LOG << "[S1AP] extractTmsiFromIEList: S-TMSI IE value is empty" << std::endl;
        return tmsis;
    }
    
    // S-TMSI structure: mMEC (1 byte) + m-TMSI (4 bytes)
    // Extract the last 4 bytes (8 hex characters) as m-TMSI
    // Minimum length should be 10 hex chars (5 bytes: 1 byte mMEC + 4 bytes m-TMSI)
    if (s_tmsi_hex.length() < 10) {
        DEBUG_LOG << "[S1AP] extractTmsiFromIEList: S-TMSI IE value too short (" 
                  << s_tmsi_hex.length() << " chars), expected at least 10 chars" << std::endl;
        return tmsis;
    }
    
    // Extract last 8 hex characters (4 bytes) as m-TMSI
    std::string m_tmsi_hex = s_tmsi_hex.substr(s_tmsi_hex.length() - 8);
    DEBUG_LOG << "[S1AP] extractTmsiFromIEList: Extracted m-TMSI: " << m_tmsi_hex << std::endl;
    
    // Normalize: remove any spaces, convert to uppercase
    std::string normalized;
    for (char c : m_tmsi_hex) {
        if (std::isxdigit(c)) {
            normalized += std::toupper(c);
        }
    }
    
    if (normalized.length() == 8) {
        tmsis.push_back(normalized);
        DEBUG_LOG << "[S1AP] extractTmsiFromIEList: Successfully extracted TMSI: " << normalized << std::endl;
    } else {
        DEBUG_LOG << "[S1AP] extractTmsiFromIEList: Failed to extract valid m-TMSI (normalized length: " 
                  << normalized.length() << ", expected 8)" << std::endl;
    }
    
    return tmsis;
}

// Extract IMSIs from S1AP
std::vector<std::string> extractImsisFromS1ap(const S1apParseResult& s1ap_result) {
    std::vector<std::string> imsis;
    
    DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Starting IMSI extraction from S1AP" << std::endl;
    
    // IMSI in S1AP is typically in NAS messages, not directly in S1AP IEs
    // First, try to extract NAS PDU from information_elements (decoded IEs)
    
    // Check if NAS-PDU IE is present in information_elements
    auto nas_pdu_it = s1ap_result.information_elements.find("NAS-PDU");
    if (nas_pdu_it != s1ap_result.information_elements.end()) {
        DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Found NAS-PDU IE in information_elements" << std::endl;
        
        const std::string& nas_pdu_hex = nas_pdu_it->second;
        DEBUG_LOG << "[S1AP] extractImsisFromS1ap: NAS-PDU hex value length: " << nas_pdu_hex.length() 
                  << " chars (" << (nas_pdu_hex.length() / 2) << " bytes)" << std::endl;
        
        if (!nas_pdu_hex.empty()) {
            // Convert hex string to bytes
            std::vector<uint8_t> nas_pdu_bytes = hexToBytes(nas_pdu_hex);
            DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Converted NAS-PDU to " << nas_pdu_bytes.size() << " bytes" << std::endl;
            
            // Skip first byte (length byte) before passing to NAS decoder
            if (nas_pdu_bytes.size() >= 2) {
                uint8_t length_byte = nas_pdu_bytes[0];
                DEBUG_LOG << "[S1AP] extractImsisFromS1ap: NAS-PDU length byte: 0x" << std::hex 
                          << static_cast<unsigned>(length_byte) << std::dec << " (" 
                          << static_cast<unsigned>(length_byte) << " bytes)" << std::endl;
                
                // Extract IMSI from NAS PDU (skip first byte)
                auto nas_imsis = nas_parser::extractImsiFromNas(
                    nas_pdu_bytes.data() + 1,
                    nas_pdu_bytes.size() - 1
                );
            
                DEBUG_LOG << "[S1AP] extractImsisFromS1ap: NAS-PDU from information_elements yielded " 
                          << nas_imsis.size() << " IMSI(s)" << std::endl;
                
                for (const auto& imsi : nas_imsis) {
                    DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Found IMSI: " << imsi << std::endl;
                }
                
                imsis.insert(imsis.end(), nas_imsis.begin(), nas_imsis.end());
            }
        } else {
            DEBUG_LOG << "[S1AP] extractImsisFromS1ap: NAS-PDU IE value is empty" << std::endl;
        }
    } else {
        DEBUG_LOG << "[S1AP] extractImsisFromS1ap: No NAS-PDU IE found in information_elements" << std::endl;
        
        // Fallback: Try to extract NAS PDUs from raw_bytes using parser

        if (!s1ap_result.raw_bytes.empty()) {
            DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Falling back to raw_bytes extraction (size: " 
                      << s1ap_result.raw_bytes.size() << " bytes)" << std::endl;
            
            auto nas_pdus = extractNasPdusFromS1ap(
                s1ap_result.raw_bytes.data(),
                s1ap_result.raw_bytes.size()
            );
            
            DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Extracted " << nas_pdus.size() << " NAS PDU(s) from raw_bytes" << std::endl;

            for (size_t i = 0; i < nas_pdus.size(); ++i) {
                const auto& nas_pdu = nas_pdus[i];
                DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Processing NAS PDU #" << (i + 1) 
                          << " from raw_bytes (size: " << nas_pdu.size() << " bytes)" << std::endl;
                
                auto nas_imsis = nas_parser::extractImsiFromNas(
                    nas_pdu.data(),
                    nas_pdu.size()
                );
                
                DEBUG_LOG << "[S1AP] extractImsisFromS1ap: NAS PDU #" << (i + 1) 
                          << " yielded " << nas_imsis.size() << " IMSI(s)" << std::endl;
                
                for (const auto& imsi : nas_imsis) {
                    DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Found IMSI: " << imsi << std::endl;
                }
                
                imsis.insert(imsis.end(), nas_imsis.begin(), nas_imsis.end());
            }
        } else {
            DEBUG_LOG << "[S1AP] extractImsisFromS1ap: S1AP raw_bytes is empty, no fallback possible" << std::endl;
        }

    }
    
    DEBUG_LOG << "[S1AP] extractImsisFromS1ap: Total IMSIs extracted: " << imsis.size() << std::endl;
    
    if (imsis.empty()) {
        DEBUG_LOG << "[S1AP] extractImsisFromS1ap: No IMSIs found in S1AP message" << std::endl;
    }

    return imsis;
}

// Extract NAS-PDU hex strings from E-RABToBeSetupListCtxtSUReq IE value
std::vector<std::string> extractNasPdusFromErabListCtxtSUReq(const std::string& erab_list_hex) {
    std::vector<std::string> nas_pdu_hex_list;
    if (erab_list_hex.empty()) return nas_pdu_hex_list;

    std::vector<uint8_t> bytes = hexToBytes(erab_list_hex);
    size_t len = bytes.size();
    size_t offset = 0;

    // Length determinant for SEQUENCE OF
    if (offset >= len) return nas_pdu_hex_list;
    uint8_t length_byte = bytes[offset++];
    uint64_t num_items = 0;
    if ((length_byte & 0x80) == 0) {
        num_items = length_byte & 0x7F;
    } else {
        uint8_t num_length_bytes = (length_byte & 0x7F) + 1;
        if (num_length_bytes > 4 || offset + num_length_bytes > len) return nas_pdu_hex_list;
        for (size_t i = 0; i < num_length_bytes; ++i)
            num_items = (num_items << 8) | bytes[offset + i];
        offset += num_length_bytes;
    }

    for (uint64_t item_idx = 0; item_idx < num_items && offset < len; ++item_idx) {
        size_t item_start = offset;
        uint16_t ie_id = 0;
        if (offset >= len) break;
        uint8_t first_byte = bytes[offset];
        if (first_byte & 0x80) {
            if (offset + 2 > len) break;
            ie_id = ((first_byte & 0x7F) << 8) | bytes[offset + 1];
            offset += 2;
        } else {
            ie_id = first_byte;
            offset += 1;
        }
        if (offset >= len) break;
        offset += 1;  // criticality
        if (offset >= len) break;
        uint32_t value_length = 0;
        uint8_t vl_byte = bytes[offset++];
        if ((vl_byte & 0x80) == 0) {
            value_length = vl_byte & 0x7F;
        } else {
            uint8_t n_vl = (vl_byte & 0x7F) + 1;
            if (offset + n_vl > len) break;
            for (size_t i = 0; i < n_vl; ++i)
                value_length = (value_length << 8) | bytes[offset + i];
            offset += n_vl;
        }
        if (offset + value_length > len) break;

        if (ie_id == 52) {  // E-RABToBeSetupItemCtxtSUReq
            size_t vo = offset;
            size_t vlen = value_length;
            if (vo >= offset + vlen) { offset += value_length; continue; }
            vo += 1;  // e-RAB-ID
            if (vo >= offset + vlen) { offset += value_length; continue; }
            uint8_t qos_len_byte = bytes[vo++];
            uint32_t qos_len = 0;
            if ((qos_len_byte & 0x80) == 0) {
                qos_len = qos_len_byte & 0x7F;
            } else {
                uint8_t nq = (qos_len_byte & 0x7F) + 1;
                if (vo + nq > offset + vlen) { offset += value_length; continue; }
                for (size_t i = 0; i < nq; ++i) qos_len = (qos_len << 8) | bytes[vo + i];
                vo += nq;
            }
            if (vo + qos_len > offset + vlen) { offset += value_length; continue; }
            vo += qos_len;
            if (vo >= offset + vlen) { offset += value_length; continue; }
            uint8_t transport_len_byte = bytes[vo++];
            uint32_t transport_bits = 0;
            if ((transport_len_byte & 0x80) == 0) {
                transport_bits = transport_len_byte & 0x7F;
            } else {
                uint8_t nt = (transport_len_byte & 0x7F) + 1;
                if (vo + nt > offset + vlen) { offset += value_length; continue; }
                for (size_t i = 0; i < nt; ++i) transport_bits = (transport_bits << 8) | bytes[vo + i];
                vo += nt;
            }
            size_t transport_bytes_len = (transport_bits + 7) / 8;
            if (vo + transport_bytes_len > offset + vlen) { offset += value_length; continue; }
            vo += transport_bytes_len;
            if (vo + 5 > offset + vlen) { offset += value_length; continue; }
            vo += 5;  // gTP-TEID tag+length+4
            if (vo >= offset + vlen) { offset += value_length; continue; }
            uint8_t nas_len_byte = bytes[vo++];
            uint32_t nas_pdu_len = 0;
            if ((nas_len_byte & 0x80) == 0) {
                nas_pdu_len = nas_len_byte & 0x7F;
            } else {
                uint8_t nn = (nas_len_byte & 0x7F) + 1;
                if (vo + nn > offset + vlen) { offset += value_length; continue; }
                for (size_t i = 0; i < nn; ++i) nas_pdu_len = (nas_pdu_len << 8) | bytes[vo + i];
                vo += nn;
            }
            if (vo + nas_pdu_len <= offset + vlen && nas_pdu_len > 0) {
                std::ostringstream hex;
                hex << std::hex << std::setfill('0');
                for (size_t i = 0; i < nas_pdu_len; ++i)
                    hex << std::setw(2) << static_cast<unsigned>(bytes[vo + i]);
                nas_pdu_hex_list.push_back(hex.str());
            }
        }
        offset += value_length;
    }
    return nas_pdu_hex_list;
}

// Extract TMSIs from S1AP
TmsiExtractionResult extractTmsisFromS1ap(const S1apParseResult& s1ap_result) {
    TmsiExtractionResult result;
    std::vector<std::string>& tmsis = result.tmsis;
    
    DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: Starting TMSI extraction from S1AP" << std::endl;
    
    // First, try to extract TMSI from S-TMSI IE in information_elements
    auto ie_tmsis = extractTmsiFromIEList(s1ap_result.information_elements);
    if (!ie_tmsis.empty()) {
        DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: Found " << ie_tmsis.size() 
                  << " TMSI(s) from S-TMSI IE" << std::endl;
        tmsis.insert(tmsis.end(), ie_tmsis.begin(), ie_tmsis.end());
    }
    
    // Also extract from NAS PDUs (similar to IMSI extraction)
    auto nas_pdu_it = s1ap_result.information_elements.find("NAS-PDU");
    if (nas_pdu_it != s1ap_result.information_elements.end()) {
        const std::string& nas_pdu_hex = nas_pdu_it->second;
        if (!nas_pdu_hex.empty()) {
            std::vector<uint8_t> nas_pdu_bytes = hexToBytes(nas_pdu_hex);
            if (nas_pdu_bytes.size() >= 2) {
                auto nas_tmsis = nas_parser::extractTmsiFromNas(
                    nas_pdu_bytes.data() + 1,
                    nas_pdu_bytes.size() - 1
                );
                tmsis.insert(tmsis.end(), nas_tmsis.begin(), nas_tmsis.end());
            }
        }
    }
    
    // Check if this is an InitialContextSetupRequest (procedure code 9)
    // which contains E-RABToBeSetupListCtxtSUReq with optional NAS-PDU in each item
    if (s1ap_result.procedure_code == 9 /*id-InitialContextSetup*/) {
        DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: Detected InitialContextSetupRequest procedure" << std::endl;
        
        // Look for E-RABToBeSetupListCtxtSUReq IE (ID 24)
        auto erab_list_it = s1ap_result.information_elements.find("E-RABToBeSetupListCtxtSUReq");
        if (erab_list_it != s1ap_result.information_elements.end()) {
            DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: Found E-RABToBeSetupListCtxtSUReq IE" << std::endl;
            
            const std::string& erab_list_hex = erab_list_it->second;
            DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: E-RABToBeSetupListCtxtSUReq hex value length: " 
                      << erab_list_hex.length() << " chars (" << (erab_list_hex.length() / 2) << " bytes)" << std::endl;
            
            if (!erab_list_hex.empty()) {
                // Convert hex string to bytes
                std::vector<uint8_t> erab_list_bytes = hexToBytes(erab_list_hex);
                DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: Converted E-RABToBeSetupListCtxtSUReq to " 
                          << erab_list_bytes.size() << " bytes" << std::endl;
                
                // Parse E-RABToBeSetupListCtxtSUReq structure - full implementation
                size_t offset = 0;
                size_t len = erab_list_bytes.size();
                
                uint64_t num_items = 0;
                offset += 2; // Skip IE ID and criticality
                
                if (offset < len) {
                    uint8_t length_byte = erab_list_bytes[offset];
                    offset++;
                    
                    if ((length_byte & 0x80) == 0) {
                        num_items = length_byte & 0x7F;
                    } else {
                        uint8_t num_length_bytes = (length_byte & 0x7F) + 1;
                        if (num_length_bytes <= 4 && offset + num_length_bytes <= len) {
                            num_items = 0;
                            for (size_t i = 0; i < num_length_bytes; ++i) {
                                num_items = (num_items << 8) | erab_list_bytes[offset + i];
                            }
                            offset += num_length_bytes;
                        }
                    }
                }
                
                // Process each ProtocolIE-SingleContainer
                if (num_items > 0) {
                    for (uint64_t item_idx = 0; item_idx < num_items && offset < len; ++item_idx) {
                        offset = 2; // Reset for each item
                        
                        // Read IE ID
                        if (offset >= len) break;
                        uint16_t ie_id = 0;
                        uint8_t first_byte = erab_list_bytes[offset];
                        if (first_byte & 0x80) {
                            if (offset + 1 >= len) break;
                            ie_id = ((first_byte & 0x7F) << 8) | erab_list_bytes[offset + 1];
                            offset += 2;
                        } else {
                            ie_id = first_byte;
                            offset += 1;
                        }
                        
                        if (offset >= len) break;
                        offset += 1; // Skip criticality
                        
                        // Read value length
                        if (offset >= len) break;
                        uint32_t value_length = 0;
                        uint8_t value_length_byte = erab_list_bytes[offset];
                        offset++;
                        
                        if ((value_length_byte & 0x80) == 0) {
                            value_length = value_length_byte & 0x7F;
                        } else {
                            uint8_t num_length_bytes = (value_length_byte & 0x7F) + 1;
                            if (offset + num_length_bytes > len) break;
                            for (size_t i = 0; i < num_length_bytes; ++i) {
                                value_length = (value_length << 8) | erab_list_bytes[offset + i];
                            }
                            offset += num_length_bytes;
                        }
                        
                        if (offset + value_length > len) break;
                        
                        // If this is IE ID 52 (E-RABToBeSetupItemCtxtSUReq), parse it
                        if (ie_id == 52) {
                            size_t item_offset = offset;
                            size_t item_len = value_length;
                            
                            // Skip e-RAB-ID (tag 0, 1 byte)
                            if (item_offset >= offset + item_len) break;
                            item_offset += 1;
                            
                            // Skip e-RABlevelQoSParameters (tag 1, SEQUENCE)
                            if (item_offset >= offset + item_len) break;
                            uint8_t qos_length_byte = erab_list_bytes[item_offset];
                            item_offset++;
                            uint32_t qos_len = 0;
                            if ((qos_length_byte & 0x80) == 0) {
                                qos_len = qos_length_byte & 0x7F;
                            } else {
                                uint8_t num_qos_bytes = (qos_length_byte & 0x7F) + 1;
                                if (item_offset + num_qos_bytes > offset + item_len) break;
                                for (size_t i = 0; i < num_qos_bytes; ++i) {
                                    qos_len = (qos_len << 8) | erab_list_bytes[item_offset + i];
                                }
                                item_offset += num_qos_bytes;
                            }
                            if (item_offset + qos_len > offset + item_len) break;
                            item_offset += qos_len;
                            
                            // Skip transportLayerAddress (tag 2, BIT STRING)
                            if (item_offset >= offset + item_len) break;
                            uint8_t transport_length_byte = erab_list_bytes[item_offset];
                            item_offset++;
                            uint32_t transport_bits = 0;
                            if ((transport_length_byte & 0x80) == 0) {
                                transport_bits = transport_length_byte & 0x7F;
                            } else {
                                uint8_t num_transport_bytes = (transport_length_byte & 0x7F) + 1;
                                if (item_offset + num_transport_bytes > offset + item_len) break;
                                for (size_t i = 0; i < num_transport_bytes; ++i) {
                                    transport_bits = (transport_bits << 8) | erab_list_bytes[item_offset + i];
                                }
                                item_offset += num_transport_bytes;
                            }
                            size_t transport_bytes_len = (transport_bits + 7) / 8;
                            if (item_offset + transport_bytes_len > offset + item_len) break;
                            item_offset += transport_bytes_len;
                            
                            // Skip gTP-TEID (tag 3, OCTET STRING, 4 bytes)
                            item_offset += 5; // Tag + length + 4 bytes
                            if (item_offset + 4 > offset + item_len) break;
                            uint32_t gtp_teid = (static_cast<uint32_t>(erab_list_bytes[item_offset]) << 24) |
                                                (static_cast<uint32_t>(erab_list_bytes[item_offset + 1]) << 16) |
                                                (static_cast<uint32_t>(erab_list_bytes[item_offset + 2]) << 8) |
                                                static_cast<uint32_t>(erab_list_bytes[item_offset + 3]);
                            result.teids.push_back(gtp_teid);
                            item_offset += 4;
                            
                            // Check for nAS-PDU (tag 4, OPTIONAL)
                            if (item_offset < offset + item_len) {
                                bool has_nas_pdu = true; // Assume present
                                
                                if (has_nas_pdu) {
                                    // Read NAS-PDU length determinant
                                    if (item_offset >= offset + item_len) break;
                                    uint8_t nas_length_byte = erab_list_bytes[item_offset];
                                    item_offset++;
                                    uint32_t nas_pdu_len = 0;
                                    if ((nas_length_byte & 0x80) == 0) {
                                        nas_pdu_len = nas_length_byte & 0x7F;
                                    } else {
                                        uint8_t num_nas_bytes = (nas_length_byte & 0x7F) + 1;
                                        if (item_offset + num_nas_bytes > offset + item_len) break;
                                        for (size_t i = 0; i < num_nas_bytes; ++i) {
                                            nas_pdu_len = (nas_pdu_len << 8) | erab_list_bytes[item_offset + i];
                                        }
                                        item_offset += num_nas_bytes;
                                    }
                                    
                                    if (item_offset + nas_pdu_len <= offset + item_len) {
                                        // Extract TMSI from NAS PDU
                                        auto nas_tmsis = nas_parser::extractTmsiFromNas(
                                            erab_list_bytes.data() + item_offset,
                                            nas_pdu_len
                                        );
                                        
                                        if (!nas_tmsis.empty()) {
                                            tmsis.insert(tmsis.end(), nas_tmsis.begin(), nas_tmsis.end());
                                        }
                                    }
                                }
                            }
                        }
                        
                        offset += value_length;
                    }
                }
            }
        }
    }
    
    // Check for E-RABSetupListCtxtSURes (InitialContextSetupResponse)
    auto erab_setup_list_it = s1ap_result.information_elements.find("E-RABSetupListCtxtSURes");
    if (erab_setup_list_it != s1ap_result.information_elements.end()) {
        const std::string& erab_setup_list_hex = erab_setup_list_it->second;
        if (!erab_setup_list_hex.empty()) {
            std::vector<uint8_t> erab_setup_list_bytes = hexToBytes(erab_setup_list_hex);
            ERabSetupListCtxtSURes decoded_list = 
                decodeERabSetupListCtxtSURes(
                    erab_setup_list_bytes.data(), 
                    erab_setup_list_bytes.size()
                );
            
            if (decoded_list.decoded && !decoded_list.items.empty()) {
                // Extract all TEIDs from all items in decoded_list
                for (const auto& item : decoded_list.items) {
                    result.teids.push_back(item.gtp_teid);
                }
            }
        }
    }
    
    DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: Total TMSIs extracted: " << tmsis.size() << std::endl;
    
    if (tmsis.empty()) {
        DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: No TMSIs found in S1AP message" << std::endl;
    }
    
    if (!result.teids.empty()) {
        DEBUG_LOG << "[S1AP] extractTmsisFromS1ap: Found " << result.teids.size() << " TEID(s): ";
        bool first = true;
        for (uint32_t teid : result.teids) {
            if (!first) DEBUG_LOG << ", ";
            DEBUG_LOG << "0x" << std::hex << teid << std::dec << " (" << teid << ")";
            first = false;
        }
        DEBUG_LOG << std::endl;
    }

    return result;
}

// Extract IMEISVs from S1AP
std::vector<std::string> extractImeisvsFromS1ap(const S1apParseResult& s1ap_result) {
    std::vector<std::string> imeisvs;
    
    DEBUG_LOG << "[S1AP] extractImeisvsFromS1ap: Starting IMEISV extraction from S1AP" << std::endl;
    
    // IMEISV in S1AP is typically in NAS messages, not directly in S1AP IEs
    // Check if NAS-PDU IE is present in information_elements
    auto nas_pdu_it = s1ap_result.information_elements.find("NAS-PDU");
    if (nas_pdu_it != s1ap_result.information_elements.end()) {
        const std::string& nas_pdu_hex = nas_pdu_it->second;
        if (!nas_pdu_hex.empty()) {
            std::vector<uint8_t> nas_pdu_bytes = hexToBytes(nas_pdu_hex);
            if (nas_pdu_bytes.size() >= 2) {
                auto nas_imeisvs = nas_parser::extractImeisvFromNas(
                    nas_pdu_bytes.data() + 1,
                    nas_pdu_bytes.size() - 1
                );
                imeisvs.insert(imeisvs.end(), nas_imeisvs.begin(), nas_imeisvs.end());
            }
        }
    }
    
    // Fallback: Try to extract NAS PDUs from raw_bytes
    if (imeisvs.empty() && !s1ap_result.raw_bytes.empty()) {
        auto nas_pdus = extractNasPdusFromS1ap(
            s1ap_result.raw_bytes.data(),
            s1ap_result.raw_bytes.size()
        );
        
        for (const auto& nas_pdu : nas_pdus) {
            auto nas_imeisvs = nas_parser::extractImeisvFromNas(
                nas_pdu.data(),
                nas_pdu.size()
            );
            imeisvs.insert(imeisvs.end(), nas_imeisvs.begin(), nas_imeisvs.end());
        }
    }
    
    DEBUG_LOG << "[S1AP] extractImeisvsFromS1ap: Total IMEISVs extracted: " << imeisvs.size() << std::endl;
    
    if (imeisvs.empty()) {
        DEBUG_LOG << "[S1AP] extractImeisvsFromS1ap: No IMEISVs found in S1AP message" << std::endl;
    }
    
    return imeisvs;
}

// Extract S1AP IDs from S1AP
std::pair<std::optional<uint32_t>, std::optional<uint32_t>> extractS1apIds(const S1apParseResult& s1ap_result) {
    std::optional<uint32_t> mme_ue_s1ap_id = std::nullopt;
    std::optional<uint32_t> enb_ue_s1ap_id = std::nullopt;
    
    DEBUG_LOG << "[S1AP] extractS1apIds: Starting S1AP ID extraction from information_elements" << std::endl;
    
    // First, try to extract from UE-S1AP-IDs IE (contains both IDs in one field)
    // MME-UE-S1AP-ID is in the first half (4 bytes), eNB-UE-S1AP-ID is in the second half (4 bytes)
    auto ue_s1ap_ids_it = s1ap_result.information_elements.find("UE-S1AP-IDs");
    if (ue_s1ap_ids_it != s1ap_result.information_elements.end()) {
        const std::string& ue_s1ap_ids_hex = ue_s1ap_ids_it->second;
        DEBUG_LOG << "[S1AP] extractS1apIds: Found UE-S1AP-IDs in information_elements: " << ue_s1ap_ids_hex << std::endl;
        
        if (!ue_s1ap_ids_hex.empty()) {
            try {
                // Convert hex string to bytes
                std::vector<uint8_t> bytes = hexToBytes(ue_s1ap_ids_hex);
                
                // UE-S1AP-IDs should be 8 bytes (4 bytes for MME-UE-S1AP-ID + 4 bytes for eNB-UE-S1AP-ID)
                if (bytes.size() >= 8) {
                    // Extract MME-UE-S1AP-ID from first 4 bytes (big-endian)
                    uint32_t mme_id = (static_cast<uint32_t>(bytes[0]) << 24) |
                                     (static_cast<uint32_t>(bytes[1]) << 16) |
                                     (static_cast<uint32_t>(bytes[2]) << 8) |
                                     static_cast<uint32_t>(bytes[3]);
                    mme_ue_s1ap_id = mme_id;
                    DEBUG_LOG << "[S1AP] extractS1apIds: Extracted MME-UE-S1AP-ID from UE-S1AP-IDs: " << mme_ue_s1ap_id.value() << std::endl;
                    
                    // Extract eNB-UE-S1AP-ID from next 4 bytes (big-endian)
                    // Note: eNB-UE-S1AP-ID is 24 bits, but stored in 4 bytes, so we take all 4 bytes
                    uint32_t enb_id = (static_cast<uint32_t>(bytes[4]) << 24) |
                                     (static_cast<uint32_t>(bytes[5]) << 16) |
                                     (static_cast<uint32_t>(bytes[6]) << 8) |
                                     static_cast<uint32_t>(bytes[7]);
                    enb_ue_s1ap_id = enb_id;
                    DEBUG_LOG << "[S1AP] extractS1apIds: Extracted eNB-UE-S1AP-ID from UE-S1AP-IDs: " << enb_ue_s1ap_id.value() << std::endl;
                } else {
                    DEBUG_LOG << "[S1AP] extractS1apIds: UE-S1AP-IDs has insufficient bytes (" << bytes.size() << "), expected 8" << std::endl;
                }
            } catch (const std::exception& e) {
                DEBUG_LOG << "[S1AP] extractS1apIds: Failed to parse UE-S1AP-IDs: " << e.what() << std::endl;
            }
        }
    } else {
        DEBUG_LOG << "[S1AP] extractS1apIds: UE-S1AP-IDs not found in information_elements, trying individual IEs" << std::endl;
    }
    
    // If UE-S1AP-IDs was not found or failed, try individual IEs
    // Try to extract MME-UE-S1AP-ID from information_elements
    if (!mme_ue_s1ap_id.has_value()) {
        auto mme_id_it = s1ap_result.information_elements.find("MME-UE-S1AP-ID");
        if (mme_id_it != s1ap_result.information_elements.end()) {
            const std::string& mme_id_hex = mme_id_it->second;
            DEBUG_LOG << "[S1AP] extractS1apIds: Found MME-UE-S1AP-ID in information_elements: " << mme_id_hex << std::endl;
            
            if (!mme_id_hex.empty()) {
                try {
                    // Parse hex string to uint32_t
                    // Remove "0x" prefix if present
                    std::string hex_str = mme_id_hex;
                    if (hex_str.length() > 2 && hex_str.substr(0, 2) == "0x") {
                        hex_str = hex_str.substr(2);
                    }
                    mme_ue_s1ap_id = static_cast<uint32_t>(std::stoul(hex_str, nullptr, 16));
                    DEBUG_LOG << "[S1AP] extractS1apIds: Parsed MME-UE-S1AP-ID: " << mme_ue_s1ap_id.value() << std::endl;
                } catch (const std::exception& e) {
                    DEBUG_LOG << "[S1AP] extractS1apIds: Failed to parse MME-UE-S1AP-ID: " << e.what() << std::endl;
                }
            }
        } else {
            DEBUG_LOG << "[S1AP] extractS1apIds: MME-UE-S1AP-ID not found in information_elements" << std::endl;
        }
    }
    
    // Try to extract eNB-UE-S1AP-ID from information_elements
    if (!enb_ue_s1ap_id.has_value()) {
        auto enb_id_it = s1ap_result.information_elements.find("eNB-UE-S1AP-ID");
        if (enb_id_it != s1ap_result.information_elements.end()) {
            const std::string& enb_id_hex = enb_id_it->second;
            DEBUG_LOG << "[S1AP] extractS1apIds: Found eNB-UE-S1AP-ID in information_elements: " << enb_id_hex << std::endl;
            
            if (!enb_id_hex.empty()) {
                try {
                    // Parse hex string to uint32_t
                    // Remove "0x" prefix if present
                    std::string hex_str = enb_id_hex;
                    if (hex_str.length() > 2 && hex_str.substr(0, 2) == "0x") {
                        hex_str = hex_str.substr(2);
                    }
                    enb_ue_s1ap_id = static_cast<uint32_t>(std::stoul(hex_str, nullptr, 16));
                    DEBUG_LOG << "[S1AP] extractS1apIds: Parsed eNB-UE-S1AP-ID: " << enb_ue_s1ap_id.value() << std::endl;
                } catch (const std::exception& e) {
                    DEBUG_LOG << "[S1AP] extractS1apIds: Failed to parse eNB-UE-S1AP-ID: " << e.what() << std::endl;
                }
            }
        } else {
            DEBUG_LOG << "[S1AP] extractS1apIds: eNB-UE-S1AP-ID not found in information_elements" << std::endl;
        }
    }
    
    DEBUG_LOG << "[S1AP] extractS1apIds: Final result - MME-UE-S1AP-ID: " 
              << (mme_ue_s1ap_id.has_value() ? std::to_string(mme_ue_s1ap_id.value()) : "N/A")
              << ", eNB-UE-S1AP-ID: " 
              << (enb_ue_s1ap_id.has_value() ? std::to_string(enb_ue_s1ap_id.value()) : "N/A") << std::endl;
    
    return {mme_ue_s1ap_id, enb_ue_s1ap_id};
}

} // namespace s1ap_parser

