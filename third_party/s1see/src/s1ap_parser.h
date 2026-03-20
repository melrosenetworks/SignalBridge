/*
 * Melrose Networks (Melrose Labs Ltd) - https://melrosenetworks.com
 * Date: 2026-01-04
 * Support: support@melrosenetworks.com
 * Disclaimer: Provided "as is" without warranty; use at your own risk.
 * Title: s1ap_parser.h
 * Description: Manual S1AP (S1 Application Protocol) parser header for extracting
 *              identifiers and TEIDs from S1AP messages. Based on 3GPP TS 36.413
 *              (S1AP) specifications. Uses PER (Packed Encoding Rules) decoding
 *              to parse S1AP Information Elements and extract UE identifiers.
 */

#ifndef S1AP_PARSER_H
#define S1AP_PARSER_H

// Debug logging control
// Define ENABLE_DEBUG_LOGGING at compile time to enable debug output
#ifndef DEBUG_LOG
    #ifdef ENABLE_DEBUG_LOGGING
        #include <iostream>
        #include <iomanip>
        #define DEBUG_LOG std::cout
    #else
        #include <iosfwd>
        // Null stream that discards output
        namespace s1ap_parser {
            class NullStream {
            public:
                template<typename T>
                NullStream& operator<<(const T&) { return *this; }
                // Handle std::endl and other stream manipulators
                typedef std::basic_ostream<char, std::char_traits<char> > CoutType;
                typedef CoutType& (*StandardEndLine)(CoutType&);
                NullStream& operator<<(StandardEndLine) { return *this; }
            };
            inline NullStream null_stream;
        }
        #define DEBUG_LOG s1ap_parser::null_stream
    #endif
#endif

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <cstddef>
#include <optional>

namespace s1ap_parser {

// S1AP PDU Types
enum class S1apPduType {
    INITIATING_MESSAGE = 0,
    SUCCESSFUL_OUTCOME = 1,
    UNSUCCESSFUL_OUTCOME = 2
};

// S1AP Procedure Codes (from 3GPP TS 36.413)
enum class S1apProcedureCode : uint8_t {
    HANDOVER_PREPARATION = 0,
    HANDOVER_RESOURCE_ALLOCATION = 1,
    HANDOVER_NOTIFICATION = 2,
    PATH_SWITCH_REQUEST = 3,
    HANDOVER_CANCEL = 4,
    E_RAB_SETUP = 5,
    E_RAB_MODIFY = 6,
    E_RAB_RELEASE = 7,
    E_RAB_RELEASE_INDICATION = 8,
    INITIAL_CONTEXT_SETUP = 9,
    PAGING = 10,
    DOWNLINK_NAS_TRANSPORT = 11,
    INITIAL_UE_MESSAGE = 12,
    UPLINK_NAS_TRANSPORT = 13,
    RESET = 14,
    ERROR_INDICATION = 15,
    NAS_NON_DELIVERY_INDICATION = 16,
    S1_SETUP = 17,
    UE_CONTEXT_RELEASE_REQUEST = 18,
    DOWNLINK_S1CDMA2000_TUNNELING = 19,
    UPLINK_S1CDMA2000_TUNNELING = 20,
    UE_CONTEXT_MODIFICATION = 21,
    UE_CAPABILITY_INFO_INDICATION = 22,
    UE_CONTEXT_RELEASE = 23,
    ENB_STATUS_TRANSFER = 24,
    MME_STATUS_TRANSFER = 25,
    DEACTIVATE_TRACE = 26,
    TRACE_START = 27,
    TRACE_FAILURE_INDICATION = 28,
    ENB_CONFIGURATION_UPDATE = 29,
    MME_CONFIGURATION_UPDATE = 30,
    LOCATION_REPORTING_CONTROL = 31,
    LOCATION_REPORTING_FAILURE_INDICATION = 32,
    LOCATION_REPORT = 33,
    OVERLOAD_START = 34,
    OVERLOAD_STOP = 35,
    WRITE_REPLACE_WARNING = 36,
    ENB_DIRECT_INFORMATION_TRANSFER = 37,
    MME_DIRECT_INFORMATION_TRANSFER = 38,
    PRIVATE_MESSAGE = 39,
    ENB_CONFIGURATION_TRANSFER = 40,
    MME_CONFIGURATION_TRANSFER = 41,
    CELL_TRAFFIC_TRACE = 42,
    KILL = 43,
    DOWNLINK_UE_ASSOCIATED_LPPA_TRANSPORT = 44,
    UPLINK_UE_ASSOCIATED_LPPA_TRANSPORT = 45,
    DOWNLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT = 46,
    UPLINK_NON_UE_ASSOCIATED_LPPA_TRANSPORT = 47
};

// S1AP Information Element IDs (from 3GPP TS 36.413)
enum class S1apIeId : uint16_t {
    MME_UE_S1AP_ID = 0,
    HANDOVER_TYPE = 1,
    CAUSE = 2,
    SOURCE_ID = 3,
    TARGET_ID = 4,
    UNKNOWN_5 = 5,  // WS extension
    UNKNOWN_6 = 6,  // WS extension
    UNKNOWN_7 = 7,  // WS extension
    ENB_UE_S1AP_ID = 8,
    UNKNOWN_9 = 9,  // WS extension
    UNKNOWN_10 = 10,  // WS extension
    UNKNOWN_11 = 11,  // WS extension
    E_RAB_SUBJECT_TO_DATA_FORWARDING_LIST = 12,
    E_RAB_TO_RELEASE_LIST_HO_CMD = 13,
    E_RAB_DATA_FORWARDING_ITEM = 14,
    E_RAB_RELEASE_ITEM_BEARER_REL_COMP = 15,
    E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ = 16,
    E_RAB_TO_BE_SETUP_ITEM_BEARER_SU_REQ = 17,
    E_RAB_ADMITTED_LIST = 18,
    E_RAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK = 19,
    E_RAB_ADMITTED_ITEM = 20,
    E_RAB_FAILED_TO_SETUP_ITEM_HO_REQ_ACK = 21,
    E_RAB_TO_BE_SWITCHED_DL_LIST = 22,
    E_RAB_TO_BE_SWITCHED_DL_ITEM = 23,
    E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ = 24,
    TRACE_ACTIVATION = 25,
    NAS_PDU = 26,
    E_RAB_TO_BE_SETUP_ITEM_HO_REQ = 27,
    E_RAB_SETUP_LIST_BEARER_SU_RES = 28,
    E_RAB_FAILED_TO_SETUP_LIST_BEARER_SU_RES = 29,
    E_RAB_TO_BE_MODIFIED_LIST_BEARER_MOD_REQ = 30,
    E_RAB_MODIFY_LIST_BEARER_MOD_RES = 31,
    E_RAB_FAILED_TO_MODIFY_LIST = 32,
    E_RAB_TO_BE_RELEASED_LIST = 33,
    E_RAB_FAILED_TO_RELEASE_LIST = 34,
    E_RAB_ITEM = 35,
    E_RAB_TO_BE_MODIFIED_ITEM_BEARER_MOD_REQ = 36,
    E_RAB_MODIFY_ITEM_BEARER_MOD_RES = 37,
    E_RAB_RELEASE_ITEM = 38,
    E_RAB_SETUP_ITEM_BEARER_SU_RES = 39,
    SECURITY_CONTEXT = 40,
    HANDOVER_RESTRICTION_LIST = 41,
    UNKNOWN_42 = 42,  // WS extension
    UE_PAGING_ID = 43,
    PAGING_DRX = 44,
    UNKNOWN_45 = 45,  // WS extension
    TAI_LIST = 46,
    TAI_ITEM = 47,
    E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES = 48,
    E_RAB_RELEASE_ITEM_HO_CMD = 49,
    E_RAB_SETUP_ITEM_CTXT_SU_RES = 50,
    E_RAB_SETUP_LIST_CTXT_SU_RES = 51,
    E_RAB_TO_BE_SETUP_ITEM_CTXT_SU_REQ = 52,
    E_RAB_TO_BE_SETUP_LIST_HO_REQ = 53,
    UNKNOWN_54 = 54,  // WS extension
    GERAN_TO_LTE_HO_INFORMATION_RES = 55,
    UNKNOWN_56 = 56,  // WS extension
    UTRAN_TO_LTE_HO_INFORMATION_RES = 57,
    CRITICALITY_DIAGNOSTICS = 58,
    GLOBAL_ENB_ID = 59,
    ENB_NAME = 60,
    MME_NAME = 61,
    UNKNOWN_62 = 62,  // WS extension
    SERVED_PLMNS = 63,
    SUPPORTED_TAS = 64,
    TIME_TO_WAIT = 65,
    UE_AGGREGATE_MAXIMUM_BITRATE = 66,
    TAI = 67,
    UNKNOWN_68 = 68,  // WS extension
    E_RAB_RELEASE_LIST_BEARER_REL_COMP = 69,
    CDMA2000_PDU = 70,
    CDMA2000_RAT_TYPE = 71,
    CDMA2000_SECTOR_ID = 72,
    SECURITY_KEY = 73,
    UE_RADIO_CAPABILITY = 74,
    GUMMEI_ID = 75,
    UNKNOWN_76 = 76,  // WS extension
    UNKNOWN_77 = 77,  // WS extension
    E_RAB_INFORMATION_LIST_ITEM = 78,
    DIRECT_FORWARDING_PATH_AVAILABILITY = 79,
    UE_IDENTITY_INDEX_VALUE = 80,
    UNKNOWN_81 = 81,  // WS extension
    UNKNOWN_82 = 82,  // WS extension
    CDMA2000_HO_STATUS = 83,
    CDMA2000_HO_REQUIRED_INDICATION = 84,
    UNKNOWN_85 = 85,  // WS extension
    E_UTRAN_TRACE_ID = 86,
    RELATIVE_MME_CAPACITY = 87,
    SOURCE_MME_UE_S1AP_ID = 88,
    BEARERS_SUBJECT_TO_STATUS_TRANSFER_ITEM = 89,
    ENB_STATUS_TRANSFER_TRANSPARENT_CONTAINER = 90,
    UE_ASSOCIATED_LOGICAL_S1_CONNECTION_ITEM = 91,
    RESET_TYPE = 92,
    UE_ASSOCIATED_LOGICAL_S1_CONNECTION_LIST_RES_ACK = 93,
    E_RAB_TO_BE_SWITCHED_UL_ITEM = 94,
    E_RAB_TO_BE_SWITCHED_UL_LIST = 95,
    S_TMSI = 96,
    CDMA2000_ONE_X_RAND = 97,
    REQUEST_TYPE = 98,
    UE_S1AP_IDS = 99,
    EUTRAN_CGI = 100,
    OVERLOAD_RESPONSE = 101,
    CDMA2000_ONE_X_SRVCC_INFO = 102,
    E_RAB_FAILED_TO_BE_RELEASED_LIST = 103,
    SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 104,
    SERVED_GUMMEIS = 105,
    SUBSCRIBER_PROFILE_ID_FOR_RFP = 106,
    UE_SECURITY_CAPABILITIES = 107,
    CS_FALLBACK_INDICATOR = 108,
    CN_DOMAIN = 109,
    E_RAB_RELEASED_LIST = 110,
    MESSAGE_IDENTIFIER = 111,
    SERIAL_NUMBER = 112,
    WARNING_AREA_LIST = 113,
    REPETITION_PERIOD = 114,
    NUMBER_OF_BROADCAST_REQUEST = 115,
    WARNING_TYPE = 116,
    WARNING_SECURITY_INFO = 117,
    DATA_CODING_SCHEME = 118,
    WARNING_MESSAGE_CONTENTS = 119,
    BROADCAST_COMPLETED_AREA_LIST = 120,
    INTER_SYSTEM_INFORMATION_TRANSFER_TYPE_EDT = 121,
    INTER_SYSTEM_INFORMATION_TRANSFER_TYPE_MDT = 122,
    TARGET_TO_SOURCE_TRANSPARENT_CONTAINER = 123,
    SRVCC_OPERATION_POSSIBLE = 124,
    SRVCC_HO_INDICATION = 125,
    NAS_DOWNLINK_COUNT = 126,
    CSG_ID = 127,
    CSG_ID_LIST = 128,
    SON_CONFIGURATION_TRANSFER_ECT = 129,
    SON_CONFIGURATION_TRANSFER_MCT = 130,
    TRACE_COLLECTION_ENTITY_IP_ADDRESS = 131,
    MS_CLASSMARK2 = 132,
    MS_CLASSMARK3 = 133,
    RRC_ESTABLISHMENT_CAUSE = 134,
    NAS_SECURITY_PARAMETERS_FROM_E_UTRAN = 135,
    NAS_SECURITY_PARAMETERS_TO_E_UTRAN = 136,
    DEFAULT_PAGING_DRX = 137,
    SOURCE_TO_TARGET_TRANSPARENT_CONTAINER_SECONDARY = 138,
    TARGET_TO_SOURCE_TRANSPARENT_CONTAINER_SECONDARY = 139,
    EUTRAN_ROUND_TRIP_DELAY_ESTIMATION_INFO = 140,
    BROADCAST_CANCELLED_AREA_LIST = 141,
    CONCURRENT_WARNING_MESSAGE_INDICATOR = 142,
    DATA_FORWARDING_NOT_POSSIBLE = 143,
    EXTENDED_REPETITION_PERIOD = 144,
    CELL_ACCESS_MODE = 145,
    CSG_MEMBERSHIP_STATUS = 146,
    LPPA_PDU = 147,
    ROUTING_ID = 148,
    TIME_SYNCHRONIZATION_INFO = 149,
    PS_SERVICE_NOT_AVAILABLE = 150,
    PAGING_PRIORITY = 151,
    X2_TNL_CONFIGURATION_INFO = 152,
    ENB_X2_EXTENDED_TRANSPORT_LAYER_ADDRESSES = 153,
    GUMMEI_LIST = 154,
    GW_TRANSPORT_LAYER_ADDRESS = 155,
    CORRELATION_ID = 156,
    SOURCE_MME_GUMMEI = 157,
    MME_UE_S1AP_ID_2 = 158,
    REGISTERED_LAI = 159,
    RELAY_NODE_INDICATOR = 160,
    TRAFFIC_LOAD_REDUCTION_INDICATION = 161,
    MDT_CONFIGURATION = 162,
    MME_RELAY_SUPPORT_INDICATOR = 163,
    GW_CONTEXT_RELEASE_INDICATION = 164,
    MANAGEMENT_BASED_MDT_ALLOWED = 165
};

// S1AP Result Structure (for parsing)
struct S1apParseResult {
    bool decoded;
    S1apPduType pdu_type;
    uint8_t procedure_code;
    std::string procedure_name;
    std::unordered_map<std::string, std::string> information_elements;
    std::vector<uint8_t> raw_bytes;
    std::vector<uint8_t> s1ap_payload;  // Extracted S1AP PDU bytes
};

// S1AP Result Structure (for correlation - simplified version)
// struct S1apResult {
//     std::string pdu_type;
//     uint8_t procedure_code;
//     std::unordered_map<std::string, std::string> information_elements;
//     std::vector<uint8_t> raw_bytes;
// };

// struct S1apResult {
//     bool decoded;
//     std::string pdu_type;
//     uint8_t procedure_code;
//     std::string procedure_name;
//     std::unordered_map<std::string, std::string> information_elements;
//     std::vector<uint8_t> raw_bytes;
// };

// Extract S1AP payload from SCTP packet
// Parses Ethernet/IP/SCTP headers and extracts SCTP DATA chunk payload
// Returns the first SCTP DATA chunk with PayloadProtocolID == 18 (S1AP)
std::optional<std::vector<uint8_t>> extractS1apFromSctp(
    const uint8_t* packet, size_t len);

// Extract all S1AP payloads from SCTP packet
// Parses Ethernet/IP/SCTP headers and extracts all SCTP DATA chunks with PayloadProtocolID == 18
// Returns a vector of S1AP payloads (one per DATA chunk)
std::vector<std::vector<uint8_t>> extractAllS1apFromSctp(
    const uint8_t* packet, size_t len);

// Parse S1AP PDU using PER decoding
// This is a simplified parser that extracts key IEs without full PER decoding
S1apParseResult parseS1apPdu(const uint8_t* s1ap_bytes, size_t len);

// Extract TEIDs from S1AP PDU bytes
// Searches for 4-byte TEID values in the S1AP structure
std::vector<uint32_t> extractTeidsFromS1apBytes(const uint8_t* s1ap_bytes, size_t len);

// Extract IMSI from S1AP IEs (not from NAS)
std::vector<std::string> extractImsiFromS1apBytes(const uint8_t* s1ap_bytes, size_t len);

// Extract TMSI from S1AP IEs (S-TMSI.m-TMSI only)
std::vector<std::string> extractTmsiFromS1apBytes(const uint8_t* s1ap_bytes, size_t len);

// Extract IMEISV from S1AP IEs
std::vector<std::string> extractImeisvFromS1apBytes(const uint8_t* s1ap_bytes, size_t len);

// Extract MME-UE-S1AP-ID and eNB-UE-S1AP-ID from bytes
std::pair<std::optional<uint32_t>, std::optional<uint32_t>> 
extractS1apIdsFromBytes(const uint8_t* s1ap_bytes, size_t len);

// Result structure for TMSI extraction
struct TmsiExtractionResult {
    std::vector<std::string> tmsis;
    std::vector<uint32_t> teids;  // All TEIDs found in decoded_list.items
};

// Extract identifiers from S1apParseResult (uses parsed information_elements)
std::vector<std::string> extractTmsiFromIEList(
    const std::unordered_map<std::string, std::string>& information_elements);
TmsiExtractionResult extractTmsisFromS1ap(const S1apParseResult& s1ap_result);
std::vector<std::string> extractImsisFromS1ap(const S1apParseResult& s1ap_result);
std::vector<std::string> extractImeisvsFromS1ap(const S1apParseResult& s1ap_result);

// Extract NAS-PDU hex strings from E-RABToBeSetupListCtxtSUReq IE (procedure 9)
std::vector<std::string> extractNasPdusFromErabListCtxtSUReq(const std::string& erab_list_hex);
std::pair<std::optional<uint32_t>, std::optional<uint32_t>> extractS1apIds(const S1apParseResult& s1ap_result);

// Extract NAS PDU from S1AP
std::vector<std::vector<uint8_t>> extractNasPdusFromS1ap(
    const uint8_t* s1ap_bytes, size_t len);

// Helper: Read PER-encoded integer (variable length)
// Returns value and number of bytes read
std::pair<uint64_t, size_t> readPerInteger(const uint8_t* data, size_t len, size_t offset);

// Helper: Read PER-encoded octet string
// Returns bytes and number of bytes read
std::pair<std::vector<uint8_t>, size_t> readPerOctetString(
    const uint8_t* data, size_t len, size_t offset, size_t length);

// Helper: Find pattern in bytes (for TEID extraction)
std::vector<uint32_t> findTeidPatterns(const uint8_t* data, size_t len);

// Helper: Get IE name from ProtocolIE-ID
std::string getIeNameFromId(uint16_t ie_id);

// Helper: Get procedure code name from ProcedureCode
std::string getProcedureCodeName(uint8_t procedure_code);

// E-RAB Setup Item structure for Context Setup Response
struct ERabSetupItemCtxtSURes {
    uint8_t e_rab_id;                    // E-RAB-ID (0..15)
    std::vector<uint8_t> transport_layer_address;  // TransportLayerAddress (BIT STRING, converted to bytes)
    uint32_t gtp_teid;                    // GTP-TEID (4 bytes, big-endian)
    bool has_extensions;                  // Whether iE-Extensions is present
};

// E-RAB Setup List structure for Context Setup Response
struct ERabSetupListCtxtSURes {
    std::vector<ERabSetupItemCtxtSURes> items;
    bool decoded;                         // Whether decoding was successful
};

// Decode E-RABSetupListCtxtSURes IE value
// Takes the raw bytes of the IE value (after IE ID, criticality, and length)
// Returns decoded structure with all E-RAB items
ERabSetupListCtxtSURes decodeERabSetupListCtxtSURes(
    const uint8_t* ie_value_bytes, size_t len);

} // namespace s1ap_parser

#endif // S1AP_PARSER_H

