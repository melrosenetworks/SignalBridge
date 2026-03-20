/*
 * Melrose Networks (Melrose Labs Ltd) - https://melrosenetworks.com
 * Date: 2026-01-04
 * Support: support@melrosenetworks.com
 * Disclaimer: Provided "as is" without warranty; use at your own risk.
 * Title: nas_parser.h
 * Description: Manual NAS (Non-Access Stratum) message parser header for 3GPP LTE.
 *              Based on 3GPP TS 24.301 (EPS NAS) specifications. Provides functions
 *              to parse NAS PDUs and extract UE identifiers (IMSI, TMSI, IMEISV)
 *              from various NAS message types.
 */

#ifndef NAS_PARSER_H
#define NAS_PARSER_H

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
        namespace nas_parser {
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
        #define DEBUG_LOG nas_parser::null_stream
    #endif
#endif

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <iosfwd>

namespace nas_parser {

// NAS Protocol Discriminators (3GPP TS 24.301)
enum class ProtocolDiscriminator : uint8_t {
    EPS_MOBILITY_MANAGEMENT = 0x07,
    EPS_SESSION_MANAGEMENT = 0x02,
    GSM_MOBILITY_MANAGEMENT = 0x00,
    GPRS_MOBILITY_MANAGEMENT = 0x08
};

// NAS Security Header Types (3GPP TS 24.301)
enum class SecurityHeaderType : uint8_t {
    PLAIN_NAS = 0x00,           // Plain NAS message, not security protected
    INTEGRITY_PROTECTED = 0x01, // Integrity protected
    INTEGRITY_PROTECTED_AND_CIPHERED = 0x02, // Integrity protected and ciphered
    INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT = 0x03, // Integrity protected with new security context
    INTEGRITY_PROTECTED_AND_CIPHERED_AND_NEW_SECURITY_CONTEXT = 0x04 // Integrity protected and ciphered with new security context
};

// EPS Mobility Management Message Types (3GPP TS 24.301)
enum class EMMessageType : uint8_t {
    IDENTITY_REQUEST = 0x05,
    IDENTITY_RESPONSE = 0x56,  // 86 decimal
    AUTHENTICATION_REQUEST = 0x52,
    AUTHENTICATION_RESPONSE = 0x53,
    AUTHENTICATION_REJECT = 0x54,
    AUTHENTICATION_FAILURE = 0x5C,
    SECURITY_MODE_COMMAND = 0x5D,
    SECURITY_MODE_COMPLETE = 0x5E,
    SECURITY_MODE_REJECT = 0x5F,
    ATTACH_REQUEST = 0x41,
    ATTACH_ACCEPT = 0x42,
    ATTACH_REJECT = 0x43,
    ATTACH_COMPLETE = 0x44,
    DETACH_REQUEST = 0x45,
    DETACH_ACCEPT = 0x46,
    TRACKING_AREA_UPDATE_REQUEST = 0x48,
    TRACKING_AREA_UPDATE_ACCEPT = 0x49,
    TRACKING_AREA_UPDATE_REJECT = 0x4A,
    TRACKING_AREA_UPDATE_COMPLETE = 0x4B,
    SERVICE_REQUEST = 0x4C,
    EXTENDED_SERVICE_REQUEST = 0x4D,
    GUTI_REALLOCATION_COMMAND = 0x50,
    GUTI_REALLOCATION_COMPLETE = 0x51,
    EMM_STATUS = 0x60,
    EMM_INFORMATION = 0x61
};

// Mobile Identity Types (3GPP TS 24.301)
enum class MobileIdentityType : uint8_t {
    NO_IDENTITY = 0x00,
    IMSI = 0x01,
    IMEI = 0x02,
    IMEISV = 0x03,
    TMSI = 0x04,
    TMGI = 0x05,
    GUTI = 0x06
};

// NAS Message Header Structure
struct NasHeader {
    SecurityHeaderType security_header_type;
    ProtocolDiscriminator protocol_discriminator;
    uint8_t message_type;
    uint8_t eps_mobile_identity_idx;
    bool valid;
};

// Mobile Identity Structure
struct MobileIdentity {
    MobileIdentityType identity_type;
    std::vector<uint8_t> identity_bytes;  // TBCD-encoded for IMSI/IMEI/IMEISV
    std::string identity_string;           // Decoded identity string
    bool valid;
};

// Parse NAS header from raw bytes
// Returns parsed header or invalid header if parsing fails
NasHeader parseNasHeader(const uint8_t* nas_bytes, size_t len);

// Check if NAS message is plain (not security protected)
bool isPlainNas(const NasHeader& header);

// Check if NAS message is EPS Mobility Management
bool isEpsMobilityManagement(const NasHeader& header);

// Extract Mobile Identity from NAS Identity Response message
// nas_bytes: Raw NAS message bytes
// len: Length of NAS message
// Returns vector of MobileIdentity structures found
std::vector<MobileIdentity> extractMobileIdentity(const uint8_t* nas_bytes, size_t len);

// Decode TBCD-encoded IMSI/IMEI/IMEISV
// bytes: TBCD-encoded bytes (includes identity type byte as first byte)
// len: Length of bytes
// start_from_upper_nibble: If true, start decoding from upper nibble of first byte; if false, start from lower nibble
// is_odd_length: If true, IMSI has odd number of digits; if false, even number
// Returns decoded IMSI string (digits only)
// For IMSI: First byte (identity type byte):
//           - Bit 3: odd/even indicator (1=odd, 0=even)
//           - Bits 0-2: lower 3 bits (1 for IMSI)
//           - Upper nibble (bits 4-7): first digit if start_from_upper_nibble=true
//           Subsequent bytes: low nibble first, then high nibble
std::string decodeTbcdImsi(const uint8_t* bytes, size_t len, bool start_from_upper_nibble = true, bool is_odd_length = false);

// Decode TBCD-encoded TMSI
// bytes: TBCD-encoded bytes (includes identity type byte as first byte)
// len: Length of bytes
// start_from_upper_nibble: If true, start decoding from upper nibble of first byte; if false, start from lower nibble
// is_odd_length: If true, TMSI has odd number of digits; if false, even number
// Returns decoded TMSI string (hex)
// For TMSI: First byte (identity type byte):
//           - Bit 3: odd/even indicator (1=odd, 0=even)
//           - Bits 0-2: lower 3 bits (4 for TMSI)
//           - Upper nibble (bits 4-7): first digit if start_from_upper_nibble=true
//           Subsequent bytes: low nibble first, then high nibble
std::string decodeTmsi(const uint8_t* bytes, size_t len, bool start_from_upper_nibble = true, bool is_odd_length = false);

// Extract IMSI from NAS message
// Returns vector of IMSI strings (digits only)
std::vector<std::string> extractImsiFromNas(const uint8_t* nas_bytes, size_t len);

// Extract TMSI from NAS message
// Returns vector of TMSI strings (hex)
std::vector<std::string> extractTmsiFromNas(const uint8_t* nas_bytes, size_t len);

// Extract IMEISV from NAS message
// Returns vector of IMEISV strings (digits only)
std::vector<std::string> extractImeisvFromNas(const uint8_t* nas_bytes, size_t len);

// Validate IMSI string
// Returns true if IMSI is valid (5-15 digits, not all zeros)
bool isValidImsi(const std::string& imsi);

// Validate TMSI string
// Returns true if TMSI is valid (4-8 hex digits)
bool isValidTmsi(const std::string& tmsi);

// Structured NAS decoder functions

// Decode EPS Mobile Identity (GUTI/TMSI) from bytes
// Returns decoded identity string and type
// EPS Mobile Identity format:
// - Byte 0: Identity type (bits 0-2) + odd/even (bit 3) + first digit/byte (bits 4-7)
// - Bytes 1+: Identity value
std::pair<MobileIdentityType, std::string> decodeEpsMobileIdentity(const uint8_t* bytes, size_t len);

// Decode Mobile Identity (IMSI/IMEI/IMEISV) from bytes
// Returns decoded identity string and type
std::pair<MobileIdentityType, std::string> decodeMobileIdentity(const uint8_t* bytes, size_t len);

// Decode structured NAS message and extract all mobile identities
// Returns vector of MobileIdentity structures found in the message
std::vector<MobileIdentity> decodeStructuredNas(const uint8_t* nas_bytes, size_t len);

// Helper functions to get human-readable names
std::string getSecurityHeaderTypeName(SecurityHeaderType type);
std::string getProtocolDiscriminatorName(ProtocolDiscriminator pd);
std::string getMessageTypeName(uint8_t message_type, ProtocolDiscriminator pd);
std::string getMobileIdentityTypeName(MobileIdentityType type);

// Dump decoded NAS message to output stream (or std::cout)
// Prints a human-readable representation of the decoded NAS message
// Note: os parameter defaults to std::cout, but requires <iostream> to be included
void dumpNasMessage(const uint8_t* nas_bytes, size_t len, std::ostream& os);

} // namespace nas_parser

#endif // NAS_PARSER_H
