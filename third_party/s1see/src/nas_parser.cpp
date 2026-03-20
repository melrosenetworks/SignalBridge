/*
 * Melrose Networks (Melrose Labs Ltd) - https://melrosenetworks.com
 * Date: 2026-01-04
 * Support: support@melrosenetworks.com
 * Disclaimer: Provided "as is" without warranty; use at your own risk.
 * Title: nas_parser.cpp
 * Description: Manual NAS (Non-Access Stratum) message parser implementation.
 *              Parses EPS NAS messages according to 3GPP TS 24.301 specifications,
 *              extracts UE identifiers (IMSI, TMSI, IMEISV) from NAS PDUs embedded
 *              in S1AP Information Elements.
 */

#include "nas_parser.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>
#include <iostream>

namespace nas_parser {

NasHeader parseNasHeader(const uint8_t* nas_bytes, size_t len) {
    NasHeader header;
    header.valid = false;

    if (!nas_bytes || len < 1) {
        return header;
    }

    for(size_t i=0;i<len && i<20;i++) { DEBUG_LOG << std::hex << static_cast<unsigned>(nas_bytes[i]) << " "; }
    DEBUG_LOG << std::endl;

    // First byte: Security header type (upper 4 bits) and Protocol discriminator (lower 4 bits)
    uint8_t first_byte = nas_bytes[0];
    uint8_t security_header_type_val = (first_byte >> 4) & 0x0F;
    uint8_t protocol_discriminator_val = first_byte & 0x0F;

    DEBUG_LOG << "[NAS] parseNasHeader: First byte=0x" << std::hex 
              << static_cast<unsigned>(first_byte) << std::dec
              << ", security_header_type=" << static_cast<unsigned>(security_header_type_val)
              << ", protocol_discriminator=" << static_cast<unsigned>(protocol_discriminator_val) << std::endl;

    size_t payload_offset = 1; // Skip first byte

    // For security-protected messages, skip MAC (4 bytes) and sequence number (1 byte)
    if (security_header_type_val >= 1 && security_header_type_val <= 4) {
        if (len < 6) {
            DEBUG_LOG << "[NAS] parseNasHeader: Security-protected message but insufficient length" << std::endl;
            return header;
        }
        payload_offset = 6; // Skip security header (1) + MAC (4) + sequence (1)
        DEBUG_LOG << "[NAS] parseNasHeader: Security-protected message, payload starts at offset " 
                  << payload_offset << std::endl;
    } else if (security_header_type_val == 0) {
        DEBUG_LOG << "[NAS] parseNasHeader: Plain NAS message" << std::endl;
    } else {
        DEBUG_LOG << "[NAS] parseNasHeader: Unknown security header type: " 
                  << static_cast<unsigned>(security_header_type_val) << std::endl;
        // Still try to parse, might be a special case
    }

    // Message type is at payload_offset
    if (payload_offset >= len) {
        DEBUG_LOG << "[NAS] parseNasHeader: Payload offset exceeds message length" << std::endl;
        return header;
    }

    uint8_t message_type = nas_bytes[payload_offset];
    DEBUG_LOG << "[NAS] parseNasHeader: Message type=0x" << std::hex 
              << static_cast<unsigned>(message_type) << std::dec << std::endl;

    header.security_header_type = static_cast<SecurityHeaderType>(security_header_type_val);
    header.protocol_discriminator = static_cast<ProtocolDiscriminator>(protocol_discriminator_val);
    header.message_type = message_type;
    header.eps_mobile_identity_idx = payload_offset - 1; // Store offset for backward compatibility
    header.valid = true;

    return header;
}

bool isPlainNas(const NasHeader& header) {
    return header.valid && 
           header.security_header_type == SecurityHeaderType::PLAIN_NAS;
}

bool isEpsMobilityManagement(const NasHeader& header) {
    return header.valid && 
           header.protocol_discriminator == ProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT;
}

std::vector<MobileIdentity> extractMobileIdentity(const uint8_t* nas_bytes, size_t len) {
    std::vector<MobileIdentity> identities;

    DEBUG_LOG << "[NAS] extractMobileIdentity: Starting extraction (len=" << len << ")" << std::endl;

    if (!nas_bytes || len < 3) {
        DEBUG_LOG << "[NAS] extractMobileIdentity: Invalid input (nas_bytes=" 
                  << (nas_bytes ? "valid" : "null") << ", len=" << len << ")" << std::endl;
        return identities;
    }

    // Parse header
    NasHeader header = parseNasHeader(nas_bytes, len);
    if (!header.valid) {
        DEBUG_LOG << "[NAS] extractMobileIdentity: Invalid NAS header" << std::endl;
        return identities;
    }

    DEBUG_LOG << "[NAS] extractMobileIdentity: Header parsed - "
              << "security_header_type=" << static_cast<unsigned>(header.security_header_type)
              << ", protocol_discriminator=" << static_cast<unsigned>(header.protocol_discriminator)
              << ", message_type=0x" << std::hex << static_cast<unsigned>(header.message_type) << std::dec << std::endl;

    /*
    // For security-protected messages, try to extract from ciphered payload
    if (!isPlainNas(header)) {
        DEBUG_LOG << "[NAS] extractMobileIdentity: Security-protected message, attempting extraction from ciphered payload" << std::endl;
        
        // Ciphered payload starts after security header (1) + MAC (4) + sequence (1) = 6 bytes
        if (len < 6) {
            DEBUG_LOG << "[NAS] extractMobileIdentity: Message too short for security header" << std::endl;
            return identities;
        }
        
        size_t ciphered_start = 6;
        size_t ciphered_len = len - ciphered_start;
        
        if (ciphered_len < 2) {
            DEBUG_LOG << "[NAS] extractMobileIdentity: Ciphered payload too short" << std::endl;
            return identities;
        }
        
        // Try to parse the ciphered payload as if it were a plain message
        // (This is a heuristic - the actual structure is encrypted)
        const uint8_t* ciphered_data = nas_bytes + ciphered_start;
        
        // Search for mobile identity patterns in the ciphered data
        // Look for length byte followed by identity type byte
        if (ciphered_len >= 2) {
            for (size_t i = 0; i + 1 < ciphered_len; ++i) {
                // Ensure we can safely read the length byte
                if (i >= ciphered_len) break;
                
                uint8_t potential_len = ciphered_data[i];
                
                // Validate length: must be at least 5 bytes (minimum for mobile identity)
                // and we must have enough bytes remaining
                if (potential_len >= 5 && potential_len <= 15 && 
                    i + 1 < ciphered_len && 
                    i + 1 + potential_len <= ciphered_len &&
                    potential_len <= ciphered_len - (i + 1)) {  // Extra safety check
                    
                    // Ensure we can safely read the type byte
                    if (i + 1 >= ciphered_len) break;
                    
                    uint8_t potential_type_byte = ciphered_data[i + 1];
                    uint8_t lower_3_bits = potential_type_byte & 0x07;
                    
                    if (lower_3_bits == 1 || lower_3_bits == 4) {
                        // Ensure we have enough bytes for the identity
                        size_t identity_start = i + 1;
                        size_t available_bytes = ciphered_len - identity_start;
                        if (potential_len <= available_bytes) {
                            // Try to decode as mobile identity
                            auto [type, identity_str] = decodeMobileIdentity(
                                ciphered_data + identity_start, potential_len);
                            if (!identity_str.empty() && 
                                ((type == MobileIdentityType::IMSI && isValidImsi(identity_str)) ||
                                 (type == MobileIdentityType::TMSI && isValidTmsi(identity_str)))) {
                                MobileIdentity identity;
                                identity.identity_type = type;
                                identity.identity_string = identity_str;
                                identity.valid = true;
                                identities.push_back(identity);
                                DEBUG_LOG << "[NAS] extractMobileIdentity: Found " 
                                          << (type == MobileIdentityType::IMSI ? "IMSI" : "TMSI")
                                          << " in ciphered payload: " << identity_str << std::endl;
                                i += potential_len; // Skip past this identity
                            }
                        }
                    }
                }
            }
        }
        
        return identities;
    }
     */

    // Only process EPS Mobility Management messages
    if (!isEpsMobilityManagement(header)) {
        DEBUG_LOG << "[NAS] extractMobileIdentity: Not an EPS Mobility Management message" << std::endl;
        return identities;
    }

    // Only process Identity Response messages (message type 0x56 = 86 decimal)
    if (header.message_type != static_cast<uint8_t>(EMMessageType::IDENTITY_RESPONSE)) {
        DEBUG_LOG << "[NAS] extractMobileIdentity: Not an Identity Response message (type=0x" 
                  << std::hex << static_cast<unsigned>(header.message_type) << std::dec << ")" << std::endl;
        //return identities;
    }

    DEBUG_LOG << "[NAS] extractMobileIdentity: Processing Identity Response message" << std::endl;

    // Identity Response structure:
    // Byte 0: Security header + Protocol discriminator
    // Byte 1: Message type (0x56)
    // Byte 2: Mobile Identity IEI (0x02) - optional, may be omitted
    // Byte 3: Length of Mobile Identity
    // Byte 4+: Mobile Identity value

    // Find Mobile Identity IE
    // It can appear at different offsets depending on presence of optional IEs
    // For simplicity, search for the Mobile Identity pattern

    size_t offset = 3;  // Start after header
    offset = header.eps_mobile_identity_idx + 3;
    DEBUG_LOG << "[NAS] extractMobileIdentity: Starting search for Mobile Identity IE at offset " << offset << std::endl;

    // Skip optional IEs if present (they have IEI byte)
    // Mobile Identity IEI is 0x02
    while (offset < len) {
        uint8_t current_byte = nas_bytes[offset];
        DEBUG_LOG << "[NAS] extractMobileIdentity: Checking byte at offset " << offset 
                  << ": 0x" << std::hex << static_cast<unsigned>(current_byte) << std::dec << std::endl;


        uint8_t identity_len = nas_bytes[offset];
        DEBUG_LOG << "[NAS] extractMobileIdentity: Mobile Identity length: " 
                    << static_cast<unsigned>(identity_len) << " bytes" << std::endl;
        offset++;
        if (offset + identity_len > len) {
            DEBUG_LOG << "[NAS] extractMobileIdentity: ERROR: Identity length exceeds remaining data "
                        << "(length=" << static_cast<unsigned>(identity_len) 
                        << ", remaining=" << (len - offset) << ")" << std::endl;
            break;
        }

        uint8_t identity_type_byte = nas_bytes[offset];
        DEBUG_LOG << "[NAS] extractMobileIdentity: Identity type byte: 0x" << std::hex 
                  << static_cast<unsigned>(identity_type_byte) << std::dec << std::endl;
        
        // Extract identity type byte structure:
        // - Bits 0-2 (lower 3 bits): identity type indicator (1 = IMSI)
        // - Bit 3: odd/even indicator (1 = odd number of digits, 0 = even)
        // - Bits 4-7 (upper nibble): may contain first digit
        uint8_t lower_3_bits = identity_type_byte & 0x07;
        bool is_odd_length = (identity_type_byte & 0x08) != 0;
        uint8_t upper_nibble = (identity_type_byte >> 4) & 0x0F;
        
        DEBUG_LOG << "[NAS] extractMobileIdentity: Lower 3 bits: " << static_cast<unsigned>(lower_3_bits)
                  << ", odd/even (bit 3): " << (is_odd_length ? "odd" : "even")
                  << ", upper nibble: 0x" << std::hex << static_cast<unsigned>(upper_nibble) << std::dec << std::endl;
        
        // Check if it's an IMSI (lower 3 bits = 1) or TMSI (lower 3 bits = 4)
        bool is_imsi = (lower_3_bits == 1);
        bool is_tmsi = (lower_3_bits == 4);
        DEBUG_LOG << "[NAS] extractMobileIdentity: Is IMSI: " << (is_imsi ? "true" : "false") 
                  << ", Is TMSI: " << (is_tmsi ? "true" : "false") << std::endl;
        
        // Extract mobile identity bytes (including identity type byte)
        MobileIdentity identity;
        // Include identity_type_byte in the identity_bytes for decoding
        identity.identity_bytes.assign(nas_bytes + offset, nas_bytes + offset + identity_len);
        for(int i=0;i<identity_len;i++) { DEBUG_LOG << std::hex << static_cast<unsigned>(identity.identity_bytes[i]) << " "; }
        DEBUG_LOG << std::dec << std::endl; 

        if (identity_len > 0) {
            // Set identity type based on lower 3 bits
            if (is_imsi) {
                identity.identity_type = MobileIdentityType::IMSI;
                DEBUG_LOG << "[NAS] extractMobileIdentity: Identity type: IMSI" << std::endl;
            } else if (is_tmsi) {
                identity.identity_type = MobileIdentityType::TMSI;
                DEBUG_LOG << "[NAS] extractMobileIdentity: Identity type: TMSI" << std::endl;
            } else {
                // Map other values to identity types
                identity.identity_type = static_cast<MobileIdentityType>(lower_3_bits);
                DEBUG_LOG << "[NAS] extractMobileIdentity: Identity type: " 
                          << static_cast<unsigned>(lower_3_bits) << std::endl;
            }

            // Decode based on type
            if (identity.identity_type == MobileIdentityType::IMSI) {
                DEBUG_LOG << "[NAS] extractMobileIdentity: Decoding as IMSI" << std::endl;
                // For IMSI, start from upper nibble of identity type byte
                identity.identity_string = decodeTbcdImsi(
                    identity.identity_bytes.data(), 
                    identity.identity_bytes.size(),
                    true,  // start_from_upper_nibble = true for IMSI
                    is_odd_length
                );
                for(size_t i=0;i<identity.identity_string.length();i++) { DEBUG_LOG << identity.identity_string[i] << " "; }
                DEBUG_LOG << std::endl;
            } else if (identity.identity_type == MobileIdentityType::TMSI) {
                DEBUG_LOG << "[NAS] extractMobileIdentity: Decoding as TMSI" << std::endl;
                // For TMSI, start from upper nibble of identity type byte (same as IMSI)
                identity.identity_string = decodeTmsi(
                    identity.identity_bytes.data(), 
                    identity.identity_bytes.size(),
                    true,  // start_from_upper_nibble = true for TMSI
                    is_odd_length
                );
                for(size_t i=0;i<identity.identity_string.length();i++) { DEBUG_LOG << identity.identity_string[i] << " "; }
                DEBUG_LOG << std::endl;
            } else if (identity.identity_type == MobileIdentityType::IMEISV) {
                DEBUG_LOG << "[NAS] extractMobileIdentity: Decoding as IMEISV" << std::endl;
                identity.identity_string = decodeTbcdImsi(
                    identity.identity_bytes.data(), 
                    identity.identity_bytes.size(),
                    true,  // start_from_upper_nibble = true for IMEISV
                    is_odd_length
                );
            } else {
                DEBUG_LOG << "[NAS] extractMobileIdentity: Unknown identity type: " 
                          << static_cast<unsigned>(static_cast<uint8_t>(identity.identity_type)) << std::endl;
            }

            identity.valid = !identity.identity_string.empty();
            DEBUG_LOG << "[NAS] extractMobileIdentity: Decoded identity: '" << identity.identity_string 
                      << "' (valid=" << (identity.valid ? "true" : "false") << ")" << std::endl;

            if (identity.valid) {
                identities.push_back(identity);
                DEBUG_LOG << "[NAS] extractMobileIdentity: Added identity to results" << std::endl;
            }
        }

        offset += identity_len;
        
    }

    // Alternative: If no IEI found, try direct parsing (some messages omit IEI)
    // Identity Response can have Mobile Identity directly after message type
    if (identities.empty() && len >= 4) {
        DEBUG_LOG << "[NAS] extractMobileIdentity: No IEI found, trying alternative parsing (without IEI)" << std::endl;
        // Try parsing without IEI
        // Byte 2: Length of Mobile Identity
        // Byte 3+: Mobile Identity value
        size_t alt_offset = 2;
        if (alt_offset < len) {
            uint8_t identity_len = nas_bytes[alt_offset];
            DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - length at offset " << alt_offset 
                      << ": " << static_cast<unsigned>(identity_len) << std::endl;
            alt_offset++;
            if (alt_offset + identity_len <= len) {
                MobileIdentity identity;
                identity.identity_bytes.assign(nas_bytes + alt_offset, nas_bytes + alt_offset + identity_len);

                DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - identity bytes: ";
                for (size_t i = 0; i < identity.identity_bytes.size() && i < 16; ++i) {
                    DEBUG_LOG << std::hex << std::setw(2) << std::setfill('0') 
                              << static_cast<unsigned>(identity.identity_bytes[i]) << " ";
                }
                if (identity.identity_bytes.size() > 16) {
                    DEBUG_LOG << "...";
                }
                DEBUG_LOG << std::dec << std::endl;

                if (identity_len > 0) {
                    uint8_t first_byte = identity.identity_bytes[0];
                    uint8_t identity_type_val = (first_byte >> 4) & 0x0F;
                    DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - first byte: 0x" << std::hex 
                              << static_cast<unsigned>(first_byte) << std::dec
                              << ", identity_type=" << static_cast<unsigned>(identity_type_val) << std::endl;
                    identity.identity_type = static_cast<MobileIdentityType>(identity_type_val);

                    // Extract identity type byte structure for alternative parsing
                    uint8_t alt_identity_type_byte = identity.identity_bytes[0];
                    uint8_t alt_lower_3_bits = alt_identity_type_byte & 0x07;
                    bool alt_is_odd_length = (alt_identity_type_byte & 0x08) != 0;
                    bool alt_is_imsi = (alt_lower_3_bits == 1);
                    
                    if (alt_is_imsi) {
                        identity.identity_type = MobileIdentityType::IMSI;
                    } else {
                        identity.identity_type = static_cast<MobileIdentityType>(alt_lower_3_bits);
                    }
                    
                    if (alt_is_imsi) {
                        identity.identity_type = MobileIdentityType::IMSI;
                    } else if (alt_lower_3_bits == 4) {
                        identity.identity_type = MobileIdentityType::TMSI;
                    } else {
                        identity.identity_type = static_cast<MobileIdentityType>(alt_lower_3_bits);
                    }
                    
                    if (identity.identity_type == MobileIdentityType::IMSI) {
                        DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - Decoding as IMSI" << std::endl;
                        identity.identity_string = decodeTbcdImsi(
                            identity.identity_bytes.data(), 
                            identity.identity_bytes.size(),
                            true,  // start_from_upper_nibble = true for IMSI
                            alt_is_odd_length
                        );
                    } else if (identity.identity_type == MobileIdentityType::TMSI) {
                        DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - Decoding as TMSI" << std::endl;
                        identity.identity_string = decodeTmsi(
                            identity.identity_bytes.data(), 
                            identity.identity_bytes.size(),
                            true,  // start_from_upper_nibble = true for TMSI
                            alt_is_odd_length
                        );
                    } else if (identity.identity_type == MobileIdentityType::IMEISV) {
                        DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - Decoding as IMEISV" << std::endl;
                        identity.identity_string = decodeTbcdImsi(
                            identity.identity_bytes.data(), 
                            identity.identity_bytes.size(),
                            true,  // start_from_upper_nibble = true for IMEISV
                            alt_is_odd_length
                        );
                    } else {
                        DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - Unknown identity type: " 
                                  << static_cast<unsigned>(identity_type_val) << std::endl;
                    }

                    identity.valid = !identity.identity_string.empty();
                    DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - Decoded identity: '" 
                              << identity.identity_string << "' (valid=" << (identity.valid ? "true" : "false") << ")" << std::endl;

                    if (identity.valid) {
                        identities.push_back(identity);
                        DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - Added identity to results" << std::endl;
                    }
                } else {
                    DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - Invalid identity length" << std::endl;
                }
            } else {
                DEBUG_LOG << "[NAS] extractMobileIdentity: Alternative parsing - Identity length exceeds remaining data" << std::endl;
            }
        }
    }

    DEBUG_LOG << "[NAS] extractMobileIdentity: Finished extraction, found " << identities.size() << " identity(ies)" << std::endl;

    return identities;
}

std::string decodeTbcdImsi(const uint8_t* bytes, size_t len, bool start_from_upper_nibble, bool is_odd_length) {
    if (!bytes || len == 0) {
        return "";
    }

    std::vector<char> digits;

    // First byte is the identity type byte:
    // - Bits 0-2: lower 3 bits (1 for IMSI)
    // - Bit 3: odd/even indicator
    // - Bits 4-7: upper nibble (may contain first digit)
    uint8_t first_byte = bytes[0];
    uint8_t first_byte_high = (first_byte >> 4) & 0x0F;
    uint8_t first_byte_low = first_byte & 0x0F;
    
    DEBUG_LOG << "[NAS] decodeTbcdImsi: First byte: 0x" << std::hex << static_cast<unsigned>(first_byte) << std::dec
              << ", start_from_upper_nibble=" << (start_from_upper_nibble ? "true" : "false")
              << ", is_odd_length=" << (is_odd_length ? "true" : "false") << std::endl;

    if (start_from_upper_nibble) {
        // Start decoding from upper nibble of first byte (identity type byte)
        // Upper nibble contains the first digit
        if (first_byte_high <= 9) {
            digits.push_back('0' + first_byte_high);
            DEBUG_LOG << "[NAS] decodeTbcdImsi: First digit from upper nibble: " << static_cast<unsigned>(first_byte_high) << std::endl;
        }
        
    } else {
        // Start decoding from lower nibble of first byte
        if (first_byte_low <= 9) {
            digits.push_back('0' + first_byte_low);
            DEBUG_LOG << "[NAS] decodeTbcdImsi: First digit from lower nibble: " << static_cast<unsigned>(first_byte_low) << std::endl;
        }
        
        // Upper nibble may contain second digit (if it's a digit)
        if (first_byte_high <= 9) {
            digits.push_back('0' + first_byte_high);
            DEBUG_LOG << "[NAS] decodeTbcdImsi: Second digit from upper nibble: " << static_cast<unsigned>(first_byte_high) << std::endl;
        }
    }

    // Extract remaining digits from bytes 1 onwards
    // TBCD: low nibble first, then high nibble
    for (size_t i = 1; i < len; ++i) {
        uint8_t byte = bytes[i];
        uint8_t digit1 = byte & 0x0F;  // Low nibble
        uint8_t digit2 = (byte >> 4) & 0x0F;  // High nibble

        if (digit1 <= 9) {
            digits.push_back('0' + digit1);
        } else {
            // 0xF indicates padding/end
            break;
        }

        if (digit2 <= 9) {
            digits.push_back('0' + digit2);
        } else {
            // 0xF indicates padding/end
            break;
        }
    }
    
    // Handle odd/even length indicator
    // If is_odd_length is true, the last digit is in the upper nibble of the last byte
    // If is_odd_length is false, all digits are complete
    // Note: The odd/even indicator tells us if there's a half-byte at the end
    if (is_odd_length && len > 1) {
        // For odd length, the last byte's upper nibble might be padding (0xF)
        // and the lower nibble contains the last digit
        // But we've already processed it in the loop above
        // The indicator just tells us the total number of digits is odd
        DEBUG_LOG << "[NAS] decodeTbcdImsi: Odd length indicator - IMSI has odd number of digits" << std::endl;
    } else {
        DEBUG_LOG << "[NAS] decodeTbcdImsi: Even length indicator - IMSI has even number of digits" << std::endl;
    }
    
    DEBUG_LOG << "[NAS] decodeTbcdImsi: Extracted " << digits.size() << " digits so far" << std::endl;
    DEBUG_LOG << "[NAS] decodeTbcdImsi: Digits: ";
    for(size_t i=0;i<digits.size();i++) { DEBUG_LOG << digits[i] << " "; }
    DEBUG_LOG << std::endl; 

    std::string imsi(digits.begin(), digits.end());

    // Validate IMSI/IMEI/IMEISV
    // IMSI: 5-15 digits
    // IMEI: 14-15 digits  
    // IMEISV: 16 digits
    if (imsi.length() >= 5 && imsi.length() <= 16) {
        // Check if all digits
        bool all_digits = true;
        for (char c : imsi) {
            if (!std::isdigit(c)) {
                all_digits = false;
                break;
            }
        }
        if (all_digits) {
            // Reject all zeros
            bool all_zeros = true;
            for (char c : imsi) {
                if (c != '0') {
                    all_zeros = false;
                    break;
                }
            }
            if (!all_zeros) {
                return imsi;
            }
        }
    }

    return "";
}

std::string decodeTmsi(const uint8_t* bytes, size_t len, bool start_from_upper_nibble, bool is_odd_length) {
    if (!bytes || len == 0) {
        return "";
    }

    DEBUG_LOG << "[NAS] decodeTmsi: Starting TMSI decoding (len=" << len 
              << ", start_from_upper_nibble=" << (start_from_upper_nibble ? "true" : "false")
              << ", is_odd_length=" << (is_odd_length ? "true" : "false") << ")" << std::endl;

    // TMSI can be encoded in two ways:
    // 1. TBCD-encoded (similar to IMSI) - starts from identity type byte
    // 2. Direct hex encoding - just the 4 bytes as hex
    
    // First byte is the identity type byte:
    // - Bits 0-2: lower 3 bits (4 for TMSI)
    // - Bit 3: odd/even indicator
    // - Bits 4-7: upper nibble (may contain first digit/byte)
    uint8_t first_byte = bytes[0];
    uint8_t first_byte_high = (first_byte >> 4) & 0x0F;
    uint8_t first_byte_low = first_byte & 0x0F;
    
    DEBUG_LOG << "[NAS] decodeTmsi: First byte: 0x" << std::hex << static_cast<unsigned>(first_byte) << std::dec
              << " (high=0x" << std::hex << static_cast<unsigned>(first_byte_high) << std::dec
              << ", low=0x" << std::hex << static_cast<unsigned>(first_byte_low) << std::dec << ")" << std::endl;

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    if (start_from_upper_nibble) {
        // Start decoding from upper nibble of first byte (identity type byte)
        // Upper nibble contains the first byte of TMSI
        oss << std::setw(2) << static_cast<unsigned>(first_byte_high);
        DEBUG_LOG << "[NAS] decodeTmsi: First byte from upper nibble: 0x" << std::hex 
                  << static_cast<unsigned>(first_byte_high) << std::dec << std::endl;
        
        // Lower nibble contains the second byte of TMSI
        oss << std::setw(2) << static_cast<unsigned>(first_byte_low);
        DEBUG_LOG << "[NAS] decodeTmsi: Second byte from lower nibble: 0x" << std::hex 
                  << static_cast<unsigned>(first_byte_low) << std::dec << std::endl;
    } else {
        // Start decoding from lower nibble of first byte
        oss << std::setw(2) << static_cast<unsigned>(first_byte_low);
        DEBUG_LOG << "[NAS] decodeTmsi: First byte from lower nibble: 0x" << std::hex 
                  << static_cast<unsigned>(first_byte_low) << std::dec << std::endl;
        
        // Upper nibble may contain second byte
        if (first_byte_high <= 0x0F) {
            oss << std::setw(2) << static_cast<unsigned>(first_byte_high);
            DEBUG_LOG << "[NAS] decodeTmsi: Second byte from upper nibble: 0x" << std::hex 
                      << static_cast<unsigned>(first_byte_high) << std::dec << std::endl;
        }
    }

    // Extract remaining bytes from bytes 1 onwards
    // TMSI is typically 4 bytes total, so we need 2-3 more bytes after the first byte
    for (size_t i = 1; i < len && i < 4; ++i) {
        uint8_t byte = bytes[i];
        oss << std::setw(2) << static_cast<unsigned>(byte);
        DEBUG_LOG << "[NAS] decodeTmsi: Byte " << i << ": 0x" << std::hex 
                  << static_cast<unsigned>(byte) << std::dec << std::endl;
    }
    
    // Handle odd/even length indicator
    if (is_odd_length) {
        DEBUG_LOG << "[NAS] decodeTmsi: Odd length indicator - TMSI has odd number of bytes" << std::endl;
    } else {
        DEBUG_LOG << "[NAS] decodeTmsi: Even length indicator - TMSI has even number of bytes" << std::endl;
    }

    std::string tmsi = oss.str();
    std::transform(tmsi.begin(), tmsi.end(), tmsi.begin(), ::tolower);
    
    DEBUG_LOG << "[NAS] decodeTmsi: Decoded TMSI: " << tmsi << std::endl;

    if (isValidTmsi(tmsi)) {
        return tmsi;
    }

    DEBUG_LOG << "[NAS] decodeTmsi: TMSI validation failed" << std::endl;
    return "";
}

std::vector<std::string> extractImsiFromNas(const uint8_t* nas_bytes, size_t len) {
    std::vector<std::string> imsis;

    if (!nas_bytes || len < 2) {
        return imsis;
    }

    // Use structured decoder
    auto identities = decodeStructuredNas(nas_bytes, len);  // ISSUE: This is not working as expected - results in fallback    for (const auto& identity : identities) {
    for (const auto& identity : identities) {
        if (identity.identity_type == MobileIdentityType::IMSI && 
            !identity.identity_string.empty() &&
            isValidImsi(identity.identity_string)) {
            imsis.push_back(identity.identity_string);
        }
    }

    // Fallback to extractMobileIdentity if structured decoder found nothing
    // ISSUE: This is wrongly identifying some bytes as IMSIs
    if (imsis.empty()) {
        DEBUG_LOG << "[NAS] extractImsiFromNas: No IMSI found via structured decoder, trying extractMobileIdentity" << std::endl;
        auto fallback_identities = extractMobileIdentity(nas_bytes, len);
        for (const auto& identity : fallback_identities) {
            if (identity.identity_type == MobileIdentityType::IMSI && 
                !identity.identity_string.empty() &&
                isValidImsi(identity.identity_string)) {
                //imsis.push_back(identity.identity_string);
            }
        }
    }

    return imsis;
}

// Decode EPS Mobile Identity (GUTI/TMSI)
std::pair<MobileIdentityType, std::string> decodeEpsMobileIdentity(const uint8_t* bytes, size_t len) {
    if (!bytes || len < 1) {
        return {MobileIdentityType::NO_IDENTITY, ""};
    }

    uint8_t identity_type_byte = bytes[0];
    uint8_t lower_3_bits = identity_type_byte & 0x07;
    bool is_odd_length = (identity_type_byte & 0x08) != 0;
    bool start_from_upper_nibble = true; // For EPS Mobile Identity, typically start from upper nibble

    MobileIdentityType type = MobileIdentityType::NO_IDENTITY;
    if (lower_3_bits == 6) { // GUTI
        type = MobileIdentityType::GUTI;
        // GUTI contains M-TMSI (last 4 bytes)
        if (len >= 5) {
            // Extract M-TMSI (last 4 bytes of GUTI)
            std::ostringstream oss;
            oss << std::hex << std::setfill('0');
            for (size_t i = len - 4; i < len; ++i) {
                oss << std::setw(2) << static_cast<unsigned>(bytes[i]);
            }
            std::string m_tmsi = oss.str();
            std::transform(m_tmsi.begin(), m_tmsi.end(), m_tmsi.begin(), ::tolower);
            return {MobileIdentityType::TMSI, m_tmsi};
        }
    } else if (lower_3_bits == 4) { // TMSI
        type = MobileIdentityType::TMSI;
        std::string tmsi = decodeTmsi(bytes, len, start_from_upper_nibble, is_odd_length);
        return {type, tmsi};
    }

    return {type, ""};
}

// Decode Mobile Identity (IMSI/IMEI/IMEISV)
std::pair<MobileIdentityType, std::string> decodeMobileIdentity(const uint8_t* bytes, size_t len) {
    if (!bytes || len < 1) {
        return {MobileIdentityType::NO_IDENTITY, ""};
    }

    uint8_t identity_type_byte = bytes[0];
    uint8_t lower_3_bits = identity_type_byte & 0x07;
    bool is_odd_length = (identity_type_byte & 0x08) != 0;
    bool start_from_upper_nibble = true; // For IMSI/IMEI/IMEISV, typically start from upper nibble

    MobileIdentityType type = static_cast<MobileIdentityType>(lower_3_bits);
    std::string identity;

    if (lower_3_bits == 1) { // IMSI
        identity = decodeTbcdImsi(bytes, len, start_from_upper_nibble, is_odd_length);
    } else if (lower_3_bits == 2) { // IMEI
        identity = decodeTbcdImsi(bytes, len, start_from_upper_nibble, is_odd_length);
    } else if (lower_3_bits == 3) { // IMEISV
        identity = decodeTbcdImsi(bytes, len, start_from_upper_nibble, is_odd_length);
    } else if (lower_3_bits == 4) { // TMSI
        identity = decodeTmsi(bytes, len, start_from_upper_nibble, is_odd_length);
    }

    return {type, identity};
}

// Decode structured NAS message
std::vector<MobileIdentity> decodeStructuredNas(const uint8_t* nas_bytes, size_t len) {
    std::vector<MobileIdentity> identities;

    if (!nas_bytes || len < 2) {
        return identities;
    }

    // Parse header
    NasHeader header = parseNasHeader(nas_bytes, len);
    if (!header.valid) {
        DEBUG_LOG << "[NAS] decodeStructuredNas: Invalid NAS header" << std::endl;
        return identities;
    }

    DEBUG_LOG << "[NAS] decodeStructuredNas: Message type=0x" << std::hex 
              << static_cast<unsigned>(header.message_type) << std::dec
              << ", protocol=" << static_cast<unsigned>(header.protocol_discriminator)
              << ", security_header=" << static_cast<unsigned>(header.security_header_type) << std::endl;

    // For security-protected messages, we can't fully decode without keys
    // But we can try to extract identities from the ciphered payload using patterns
    if (header.security_header_type != SecurityHeaderType::PLAIN_NAS) {
        DEBUG_LOG << "[NAS] decodeStructuredNas: Security-protected message, attempting to extract from ciphered payload" << std::endl;
        
        // Ciphered payload starts after security header (1 byte) + MAC (4 bytes) + sequence (1 byte) = 6 bytes
        if (len < 6) {
            DEBUG_LOG << "[NAS] decodeStructuredNas: Message too short for security header" << std::endl;
            return identities;
        }
        
        size_t ciphered_start = 6;
        size_t ciphered_len = len - ciphered_start;
        
        if (ciphered_len < 1) {
            DEBUG_LOG << "[NAS] decodeStructuredNas: No ciphered payload" << std::endl;
            return identities;
        }
        
        const uint8_t* ciphered_data = nas_bytes + ciphered_start;
        
        // Search for known TMSI pattern: 0x50 0x0b 0xf6 followed by TMSI 7 bytes after 0xf6
        // Pattern: 0x50 (offset i), 0x0b (offset i+1), 0xf6 (offset i+2)
        // TMSI starts 7 bytes after 0xf6, so at offset i+2+7 = i+9
        const uint8_t tmsi_pattern[] = {0x50, 0x0b, 0xf6};
        const size_t pattern_len = sizeof(tmsi_pattern);
        const size_t tmsi_offset = 7;  // Bytes after the last byte of pattern (0xf6)
        const size_t tmsi_len = 4;
        
        // Check if we have enough bytes for pattern + offset + TMSI
        size_t min_required = pattern_len + tmsi_offset + tmsi_len;
        if (ciphered_len >= min_required) {
            for (size_t i = 0; i <= ciphered_len - min_required; ++i) {
            // Check if pattern matches
            bool pattern_match = true;
            for (size_t j = 0; j < pattern_len; ++j) {
                if (ciphered_data[i + j] != tmsi_pattern[j]) {
                    pattern_match = false;
                    break;
                }
            }
            
            if (pattern_match) {
                DEBUG_LOG << "[NAS] decodeStructuredNas: Found TMSI pattern 0x50 0x0b 0xf6 at offset " 
                          << (ciphered_start + i) << std::endl;
                
                // Extract TMSI starting 7 bytes after the last byte of pattern (0xf6)
                // Pattern ends at i + pattern_len - 1, so TMSI starts at i + (pattern_len - 1) + tmsi_offset
                size_t tmsi_start = i + (pattern_len - 1) + tmsi_offset;
                if (tmsi_start + tmsi_len <= ciphered_len) {
                    // Convert 4 bytes to hex string
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0');
                    for (size_t k = 0; k < tmsi_len; ++k) {
                        oss << std::setw(2) << static_cast<unsigned>(ciphered_data[tmsi_start + k]);
                    }
                    std::string tmsi = oss.str();
                    std::transform(tmsi.begin(), tmsi.end(), tmsi.begin(), ::tolower);
                    
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Extracted TMSI from pattern: " << tmsi 
                              << " (from offset " << (ciphered_start + tmsi_start) << ")" << std::endl;
                    
                    if (isValidTmsi(tmsi)) {
                        MobileIdentity identity;
                        identity.identity_type = MobileIdentityType::TMSI;
                        identity.identity_string = tmsi;
                        identity.valid = true;
                        identities.push_back(identity);
                    }
                }
            }
        }
        }
        
        // If we found identities via pattern, return them
        if (!identities.empty()) {
            return identities;
        }
        
        // Try to parse the ciphered payload as if it were a plain NAS message
        // Sometimes the ciphered payload contains a plain NAS message structure
        // Check if it starts with a plain NAS header (security header type 0)
        // Only do this once (not recursively) to avoid infinite loops
        if (ciphered_len >= 2) {
            uint8_t first_byte = ciphered_data[0];
            uint8_t security_header_type_val = (first_byte >> 4) & 0x0F;
            uint8_t protocol_discriminator_val = first_byte & 0x0F;
            
            // If it looks like a plain NAS message (security header type 0, protocol 7)
            if (security_header_type_val == 0 && protocol_discriminator_val == 7) {
                DEBUG_LOG << "[NAS] decodeStructuredNas: Ciphered payload appears to be plain NAS, attempting to parse as plain message" << std::endl;
                
                // Parse as plain NAS message directly (offset 1 after header, then message type)
                size_t plain_offset = 1;
                if (plain_offset >= ciphered_len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Plain message too short" << std::endl;
                } else {
                    uint8_t plain_message_type = ciphered_data[plain_offset];
                    plain_offset++; // Skip message type
                    
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Plain message type=0x" << std::hex 
                              << static_cast<unsigned>(plain_message_type) << std::dec << std::endl;
                    
                    // Handle Security Mode Complete (0x5e)
                    if (plain_message_type == static_cast<uint8_t>(EMMessageType::SECURITY_MODE_COMPLETE)) {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: Decoding Security Mode Complete from ciphered payload" << std::endl;
                        
                        // Parse optional IEs
                        while (plain_offset < ciphered_len) {
                            if (plain_offset >= ciphered_len) break;
                            uint8_t iei = ciphered_data[plain_offset];
                            DEBUG_LOG << "[NAS] decodeStructuredNas: Parsing IE at offset " << plain_offset 
                                      << ", IEI=0x" << std::hex << static_cast<unsigned>(iei) << std::dec << std::endl;
                            plain_offset++;
                            
                            if (plain_offset >= ciphered_len) break;
                            
                            uint8_t ie_len = ciphered_data[plain_offset];
                            DEBUG_LOG << "[NAS] decodeStructuredNas: IE length=" << static_cast<unsigned>(ie_len) << std::endl;
                            plain_offset++;
                            
                            if (plain_offset + ie_len > ciphered_len) {
                                DEBUG_LOG << "[NAS] decodeStructuredNas: IE length exceeds remaining data" << std::endl;
                                break;
                            }
                            
                            // MS Identity IE (IEI 0x23) - contains IMSI/IMEI/IMEISV
                            if (iei == 0x23) {
                                DEBUG_LOG << "[NAS] decodeStructuredNas: Found MS Identity IE (0x23), decoding with length " 
                                          << static_cast<unsigned>(ie_len) << std::endl;
                                auto [type, identity_str] = decodeMobileIdentity(
                                    ciphered_data + plain_offset, ie_len);
                                DEBUG_LOG << "[NAS] decodeStructuredNas: decodeMobileIdentity returned type=" 
                                          << static_cast<unsigned>(type) << ", identity_str='" << identity_str << "'" << std::endl;
                                if (!identity_str.empty()) {
                                    MobileIdentity identity;
                                    identity.identity_type = type;
                                    identity.identity_string = identity_str;
                                    identity.valid = true;
                                    identities.push_back(identity);
                                    DEBUG_LOG << "[NAS] decodeStructuredNas: Found MS Identity in ciphered payload: " 
                                              << identity_str << " (type=" 
                                              << static_cast<unsigned>(type) << ")" << std::endl;
                                } else {
                                    DEBUG_LOG << "[NAS] decodeStructuredNas: decodeMobileIdentity returned empty string" << std::endl;
                                }
                            }
                            
                            plain_offset += ie_len;
                        }
                    }
                }
                
                if (!identities.empty()) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Found " << identities.size() 
                              << " identity(ies) from ciphered plain NAS message" << std::endl;
                    return identities;
                }
            }
        }
        
        DEBUG_LOG << "[NAS] decodeStructuredNas: Could not extract identities from ciphered payload" << std::endl;
        return identities;
    }

    // Calculate payload offset
    // For plain NAS: offset = 1 (after header byte)
    // For security-protected: offset = 6 (after header + MAC + sequence)
    size_t offset = 1;
    if (header.security_header_type != SecurityHeaderType::PLAIN_NAS) {
        offset = 6; // Skip security header (1) + MAC (4) + sequence (1)
    }

    if (offset >= len) {
        DEBUG_LOG << "[NAS] decodeStructuredNas: Payload offset exceeds message length" << std::endl;
        return identities;
    }

    // Handle EMM messages
    if (header.protocol_discriminator == ProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT) {
        uint8_t message_type = header.message_type;
        
        // Message type is already at offset, so skip it
        offset++;
        if (offset >= len) {
            DEBUG_LOG << "[NAS] decodeStructuredNas: Message type byte exceeds message length" << std::endl;
            return identities;
        }

        // Decode based on message type
        switch (message_type) {
            case static_cast<uint8_t>(EMMessageType::ATTACH_REQUEST): {
                DEBUG_LOG << "[NAS] decodeStructuredNas: Decoding Attach Request" << std::endl;
                // Attach Request structure per 3GPP TS 24.301:
                // - EPS attach type (bits 0-2, bit 3 is reserved)
                // - NAS key set identifier (bits 4-6)
                // - Type of security context flag (TSC) (bit 7)
                // - EPS mobile identity (variable, LV format: 1 byte length + value, mandatory)
                // - UE network capability (variable, LV format, mandatory)
                // - ESM message container (variable, LV-E format, mandatory)
                // - Optional IEs follow
                
                offset++;
                
                // Decode EPS mobile identity (LV format: 1 byte length + value, mandatory)
                if (offset >= len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Attach Request too short for eps_mobile_identity length" << std::endl;
                    break;
                }
                uint8_t eps_mobile_identity_len = nas_bytes[offset];
                offset++;
                
                if (offset + eps_mobile_identity_len > len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: EPS mobile identity length exceeds remaining data" << std::endl;
                    break;
                }
                
                // Check identity type to determine if it's IMSI
                DEBUG_LOG << "[NAS] decodeStructuredNas: eps_mobile_identity_len: " 
                                      << static_cast<unsigned>(eps_mobile_identity_len) << std::endl;
                if (eps_mobile_identity_len > 0) {
                    uint8_t identity_type_byte = nas_bytes[offset];
                    uint8_t lower_3_bits = identity_type_byte & 0x07;
                    
                    // EPS mobile identity can be IMSI (type 1), GUTI (type 6), or IMEI (type 2)
                    if (lower_3_bits == 1) { // IMSI
                        auto [type, identity_str] = decodeMobileIdentity(
                            nas_bytes + offset, eps_mobile_identity_len);
                        if (!identity_str.empty() && type == MobileIdentityType::IMSI) {
                            MobileIdentity identity;
                            identity.identity_type = type;
                            identity.identity_string = identity_str;
                            identity.identity_bytes.assign(nas_bytes + offset,
                                                          nas_bytes + offset + eps_mobile_identity_len);
                            identity.valid = true;
                            identities.push_back(identity);
                            DEBUG_LOG << "[NAS] decodeStructuredNas: Found IMSI in Attach Request: " 
                                      << identity_str << std::endl;
                        }
                    } else {
                        // For GUTI/TMSI, use decodeEpsMobileIdentity
                        auto [type, identity_str] = decodeEpsMobileIdentity(
                            nas_bytes + offset, eps_mobile_identity_len);
                        if (!identity_str.empty()) {
                            MobileIdentity identity;
                            identity.identity_type = type;
                            identity.identity_string = identity_str;
                            identity.identity_bytes.assign(nas_bytes + offset,
                                                          nas_bytes + offset + eps_mobile_identity_len);
                            identity.valid = true;
                            identities.push_back(identity);
                            DEBUG_LOG << "[NAS] decodeStructuredNas: Found EPS mobile identity: " 
                                      << identity_str << " (type=" 
                                      << static_cast<unsigned>(type) << ")" << std::endl;
                        }
                    }
                }
                break;
            }
            
            case static_cast<uint8_t>(EMMessageType::ATTACH_ACCEPT): {
                DEBUG_LOG << "[NAS] decodeStructuredNas: Decoding Attach Accept" << std::endl;
                // Attach Accept structure per 3GPP TS 24.301:
                // Mandatory fields (no IEI):
                // - EPS attach result (1 byte, V format)
                // - T3412 value (1 byte, V format)
                // - TAI list (variable, LV format: 1 byte length + value)
                // - ESM message container (variable, LV-E format: 2 byte length + value)
                // Optional IEs follow (TLV format: IEI + Length + Value)
                
                // Skip EPS attach result (1 byte, mandatory)
                if (offset >= len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Attach Accept too short for eps_attach_result" << std::endl;
                    break;
                }
                uint8_t eps_attach_result = nas_bytes[offset];
                DEBUG_LOG << "[NAS] decodeStructuredNas: EPS attach result: 0x" << std::hex 
                          << static_cast<unsigned>(eps_attach_result) << std::dec << std::endl;
                offset++;
                
                // Skip T3412 value (1 byte, mandatory)
                if (offset >= len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Attach Accept too short for t3412_value" << std::endl;
                    break;
                }
                uint8_t t3412_value = nas_bytes[offset];
                DEBUG_LOG << "[NAS] decodeStructuredNas: T3412 value: 0x" << std::hex 
                          << static_cast<unsigned>(t3412_value) << std::dec << std::endl;
                offset++;
                
                // Skip TAI list (LV format: 1 byte length + variable value, mandatory)
                if (offset >= len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Attach Accept too short for tai_list length" << std::endl;
                    break;
                }
                uint8_t tai_list_len = nas_bytes[offset];
                DEBUG_LOG << "[NAS] decodeStructuredNas: TAI list length: " 
                          << static_cast<unsigned>(tai_list_len) << std::endl;
                offset++;
                if (offset + tai_list_len > len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: TAI list length exceeds remaining data" << std::endl;
                    break;
                }
                offset += tai_list_len;
                
                // Skip ESM message container (LV-E format: 2 byte length + variable value, mandatory)
                if (offset + 1 >= len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: Attach Accept too short for esm_message_container length" << std::endl;
                    break;
                }
                uint16_t esm_len = (static_cast<uint16_t>(nas_bytes[offset]) << 8) | nas_bytes[offset + 1];
                DEBUG_LOG << "[NAS] decodeStructuredNas: ESM message container length: " << esm_len << std::endl;
                offset += 2;
                if (offset + esm_len > len) {
                    DEBUG_LOG << "[NAS] decodeStructuredNas: ESM message container length exceeds remaining data" << std::endl;
                    break;
                }
                offset += esm_len;
                
                // Parse optional IEs (TLV format: IEI + Length + Value)
                // According to 3GPP TS 24.301, optional IEs can appear in any order
                while (offset < len) {
                    // Check if we have at least IEI byte
                    if (offset >= len) break;
                    
                    uint8_t iei = nas_bytes[offset];
                    offset++;
                    
                    // Check if IEI indicates end of message or padding
                    // IEI values 0x00-0x0F are reserved, but 0x00 can indicate padding/end
                    if (iei == 0x00) {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: Found padding/end marker (IEI=0x00)" << std::endl;
                        break;
                    }
                    
                    // Check if we have length byte
                    if (offset >= len) {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: Missing length byte for IEI 0x" 
                                  << std::hex << static_cast<unsigned>(iei) << std::dec << std::endl;
                        break;
                    }
                    
                    uint8_t ie_len = nas_bytes[offset];
                    offset++;
                    
                    // Validate length
                    if (offset + ie_len > len) {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: IE length exceeds remaining data for IEI 0x" 
                                  << std::hex << static_cast<unsigned>(iei) << std::dec 
                                  << " (length=" << static_cast<unsigned>(ie_len) 
                                  << ", remaining=" << (len - offset) << ")" << std::endl;
                        break;
                    }
                    
                    // Handle identity-related IEs
                    // Additional GUTI (IEI 0x50) - per spec table
                    if (iei == 0x50) {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: Found Additional GUTI IE (0x50)" << std::endl;
                        auto [type, identity_str] = decodeEpsMobileIdentity(
                            nas_bytes + offset, ie_len);
                        if (!identity_str.empty()) {
                            MobileIdentity identity;
                            identity.identity_type = type;
                            identity.identity_string = identity_str;
                            identity.valid = true;
                            identities.push_back(identity);
                            DEBUG_LOG << "[NAS] decodeStructuredNas: Found GUTI/TMSI: " 
                                      << identity_str << std::endl;
                        }
                    }
                    // MS Identity IE (IEI 0x23) - contains IMSI/IMEI/IMEISV - per spec table
                    else if (iei == 0x23) {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: Found MS Identity IE (0x23)" << std::endl;
                        auto [type, identity_str] = decodeMobileIdentity(
                            nas_bytes + offset, ie_len);
                        if (!identity_str.empty()) {
                            MobileIdentity identity;
                            identity.identity_type = type;
                            identity.identity_string = identity_str;
                            identity.valid = true;
                            identities.push_back(identity);
                            DEBUG_LOG << "[NAS] decodeStructuredNas: Found MS Identity: " 
                                      << identity_str << " (type=" 
                                      << static_cast<unsigned>(type) << ")" << std::endl;
                        }
                    }
                    // Other optional IEs - log for debugging but don't extract identities
                    // Per spec table: 0x19 (Old P-TMSI signature), 0x52 (Last visited registered TAI),
                    // 0x5C (DRX parameter), 0x31 (MS network capability), 0x5E (T3412 extended value),
                    // 0x6E (Extended DRX parameters), etc.
                    else {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: Optional IE with IEI 0x" 
                                  << std::hex << std::setw(2) << std::setfill('0') 
                                  << static_cast<unsigned>(iei) << std::dec 
                                  << ", length " << static_cast<unsigned>(ie_len) 
                                  << " (not identity-related, skipping)" << std::endl;
                    }
                    
                    offset += ie_len;
                }
                break;
            }
            
            case static_cast<uint8_t>(EMMessageType::IDENTITY_RESPONSE): {
                DEBUG_LOG << "[NAS] decodeStructuredNas: Decoding Identity Response" << std::endl;
                // Identity Response structure:
                // - Mobile Identity IE (type 0x02, optional IEI)
                //   If IEI is present, it's 0x02, followed by length, then value
                //   If IEI is omitted, it's directly the length, then value
                
                // Check if IEI is present (0x02)
                if (offset < len && nas_bytes[offset] == 0x02) {
                    offset++; // Skip IEI
                }
                
                if (offset < len) {
                    uint8_t mobile_identity_len = nas_bytes[offset];
                    offset++;
                    if (offset + mobile_identity_len <= len) {
                        auto [type, identity_str] = decodeMobileIdentity(
                            nas_bytes + offset, mobile_identity_len);
                        if (!identity_str.empty()) {
                            MobileIdentity identity;
                            identity.identity_type = type;
                            identity.identity_string = identity_str;
                            identity.valid = true;
                            identities.push_back(identity);
                            DEBUG_LOG << "[NAS] decodeStructuredNas: Found Mobile Identity: " 
                                      << identity_str << " (type=" 
                                      << static_cast<unsigned>(type) << ")" << std::endl;
                        }
                    }
                }
                break;
            }
            
            case static_cast<uint8_t>(EMMessageType::EXTENDED_SERVICE_REQUEST): {
                DEBUG_LOG << "[NAS] decodeStructuredNas: Decoding Extended Service Request" << std::endl;
                // Extended Service Request structure:
                // - service_type (1 byte)
                // - m-TMSI (EPS Mobile Identity, variable)
                // Optional IEs follow
                
                if (offset + 1 < len) {
                    offset++; // Skip service_type
                }
                
                // Decode m-TMSI (EPS Mobile Identity)
                if (offset < len) {
                    uint8_t m_tmsi_len = nas_bytes[offset];
                    offset++;
                    if (offset + m_tmsi_len <= len) {
                        auto [type, identity_str] = decodeEpsMobileIdentity(
                            nas_bytes + offset, m_tmsi_len);
                        if (!identity_str.empty()) {
                            MobileIdentity identity;
                            identity.identity_type = type;
                            identity.identity_string = identity_str;
                            identity.valid = true;
                            identities.push_back(identity);
                            DEBUG_LOG << "[NAS] decodeStructuredNas: Found m-TMSI: " 
                                      << identity_str << std::endl;
                        }
                        offset += m_tmsi_len;
                    }
                }
                break;
            }
            
            case static_cast<uint8_t>(EMMessageType::SECURITY_MODE_COMPLETE): {
                DEBUG_LOG << "[NAS] decodeStructuredNas: Decoding Security Mode Complete" << std::endl;
                // Security Mode Complete structure:
                // - IMEISV (optional, IEI 0x23)
                // Format: IEI (1 byte) + Length (1 byte) + Value (variable)
                
                // Parse optional IEs
                while (offset < len) {
                    uint8_t iei = nas_bytes[offset];
                    offset++;
                    
                    if (offset >= len) break;
                    
                    uint8_t ie_len = nas_bytes[offset];
                    offset++;
                    
                    if (offset + ie_len > len) {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: IE length exceeds remaining data" << std::endl;
                        break;
                    }
                    
                    // MS Identity IE (IEI 0x23) - contains IMSI/IMEI/IMEISV
                    if (iei == 0x23) {
                        auto [type, identity_str] = decodeMobileIdentity(
                            nas_bytes + offset, ie_len);
                        if (!identity_str.empty()) {
                            MobileIdentity identity;
                            identity.identity_type = type;
                            identity.identity_string = identity_str;
                            identity.valid = true;
                            identities.push_back(identity);
                            DEBUG_LOG << "[NAS] decodeStructuredNas: Found MS Identity: " 
                                      << identity_str << " (type=" 
                                      << static_cast<unsigned>(type) << ")" << std::endl;
                        }
                    }
                    // Unknown IE - skip it
                    else {
                        DEBUG_LOG << "[NAS] decodeStructuredNas: Unknown IE with IEI 0x" 
                                  << std::hex << static_cast<unsigned>(iei) << std::dec 
                                  << ", length " << static_cast<unsigned>(ie_len) << std::endl;
                    }
                    
                    offset += ie_len;
                }
                break;
            }
            
            default:
                DEBUG_LOG << "[NAS] decodeStructuredNas: Unhandled EMM message type: 0x" 
                          << std::hex << static_cast<unsigned>(message_type) << std::dec << std::endl;
                break;
        }
    }

    return identities;
}

std::vector<std::string> extractTmsiFromNas(const uint8_t* nas_bytes, size_t len) {
    std::vector<std::string> tmsis;

    if (!nas_bytes || len < 2) {
        return tmsis;
    }

    // Use structured decoder
    auto identities = decodeStructuredNas(nas_bytes, len);
    for (const auto& identity : identities) {
        if ((identity.identity_type == MobileIdentityType::TMSI || 
             identity.identity_type == MobileIdentityType::GUTI) &&
            !identity.identity_string.empty() &&
            isValidTmsi(identity.identity_string)) {
            tmsis.push_back(identity.identity_string);
        }
    }

    // Fallback to extractMobileIdentity if structured decoder found nothing
    if (tmsis.empty()) {
        DEBUG_LOG << "[NAS] extractTmsiFromNas: No TMSI found via structured decoder, trying extractMobileIdentity" << std::endl;
        auto fallback_identities = extractMobileIdentity(nas_bytes, len);
        for (const auto& identity : fallback_identities) {
            if (identity.identity_type == MobileIdentityType::TMSI && 
                !identity.identity_string.empty() &&
                isValidTmsi(identity.identity_string)) {
                //tmsis.push_back(identity.identity_string);
            }
        }
    }

    return tmsis;
}

std::vector<std::string> extractImeisvFromNas(const uint8_t* nas_bytes, size_t len) {
    std::vector<std::string> imeisvs;

    if (!nas_bytes || len < 2) {
        return imeisvs;
    }

    // Use structured decoder
    auto identities = decodeStructuredNas(nas_bytes, len);
    for (const auto& identity : identities) {
        if (identity.identity_type == MobileIdentityType::IMEISV && 
            !identity.identity_string.empty()) {
            imeisvs.push_back(identity.identity_string);
        }
    }

    // Fallback to extractMobileIdentity if structured decoder found nothing
    if (imeisvs.empty()) {
        DEBUG_LOG << "[NAS] extractImeisvFromNas: No IMEISV found via structured decoder, trying extractMobileIdentity" << std::endl;
        auto fallback_identities = extractMobileIdentity(nas_bytes, len);
        for (const auto& identity : fallback_identities) {
            if (identity.identity_type == MobileIdentityType::IMEISV && 
                !identity.identity_string.empty()) {
                imeisvs.push_back(identity.identity_string);
            }
        }
    }

    return imeisvs;
}

bool isValidImsi(const std::string& imsi) {
    if (imsi.length() < 5 || imsi.length() > 15) {
        return false;
    }

    // Check if all digits
    for (char c : imsi) {
        if (!std::isdigit(c)) {
            return false;
        }
    }

    // Reject all zeros
    bool all_zeros = true;
    for (char c : imsi) {
        if (c != '0') {
            all_zeros = false;
            break;
        }
    }

    return !all_zeros;
}

bool isValidTmsi(const std::string& tmsi) {
    if (tmsi.length() < 4 || tmsi.length() > 8) {
        return false;
    }

    // Check if all hex digits
    for (char c : tmsi) {
        if (!std::isxdigit(c)) {
            return false;
        }
    }

    return true;
}

std::string getSecurityHeaderTypeName(SecurityHeaderType type) {
    switch (type) {
        case SecurityHeaderType::PLAIN_NAS:
            return "Plain NAS (not security protected)";
        case SecurityHeaderType::INTEGRITY_PROTECTED:
            return "Integrity Protected";
        case SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED:
            return "Integrity Protected and Ciphered";
        case SecurityHeaderType::INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT:
            return "Integrity Protected with New Security Context";
        case SecurityHeaderType::INTEGRITY_PROTECTED_AND_CIPHERED_AND_NEW_SECURITY_CONTEXT:
            return "Integrity Protected and Ciphered with New Security Context";
        default:
            return "Unknown";
    }
}

std::string getProtocolDiscriminatorName(ProtocolDiscriminator pd) {
    switch (pd) {
        case ProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT:
            return "EPS Mobility Management (EMM)";
        case ProtocolDiscriminator::EPS_SESSION_MANAGEMENT:
            return "EPS Session Management (ESM)";
        case ProtocolDiscriminator::GSM_MOBILITY_MANAGEMENT:
            return "GSM Mobility Management";
        case ProtocolDiscriminator::GPRS_MOBILITY_MANAGEMENT:
            return "GPRS Mobility Management";
        default:
            return "Unknown";
    }
}

std::string getMessageTypeName(uint8_t message_type, ProtocolDiscriminator pd) {
    if (pd == ProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT) {
        switch (message_type) {
            case static_cast<uint8_t>(EMMessageType::IDENTITY_REQUEST):
                return "Identity Request";
            case static_cast<uint8_t>(EMMessageType::IDENTITY_RESPONSE):
                return "Identity Response";
            case static_cast<uint8_t>(EMMessageType::AUTHENTICATION_REQUEST):
                return "Authentication Request";
            case static_cast<uint8_t>(EMMessageType::AUTHENTICATION_RESPONSE):
                return "Authentication Response";
            case static_cast<uint8_t>(EMMessageType::AUTHENTICATION_REJECT):
                return "Authentication Reject";
            case static_cast<uint8_t>(EMMessageType::AUTHENTICATION_FAILURE):
                return "Authentication Failure";
            case static_cast<uint8_t>(EMMessageType::SECURITY_MODE_COMMAND):
                return "Security Mode Command";
            case static_cast<uint8_t>(EMMessageType::SECURITY_MODE_COMPLETE):
                return "Security Mode Complete";
            case static_cast<uint8_t>(EMMessageType::SECURITY_MODE_REJECT):
                return "Security Mode Reject";
            case static_cast<uint8_t>(EMMessageType::ATTACH_REQUEST):
                return "Attach Request";
            case static_cast<uint8_t>(EMMessageType::ATTACH_ACCEPT):
                return "Attach Accept";
            case static_cast<uint8_t>(EMMessageType::ATTACH_REJECT):
                return "Attach Reject";
            case static_cast<uint8_t>(EMMessageType::ATTACH_COMPLETE):
                return "Attach Complete";
            case static_cast<uint8_t>(EMMessageType::DETACH_REQUEST):
                return "Detach Request";
            case static_cast<uint8_t>(EMMessageType::DETACH_ACCEPT):
                return "Detach Accept";
            case static_cast<uint8_t>(EMMessageType::TRACKING_AREA_UPDATE_REQUEST):
                return "Tracking Area Update Request";
            case static_cast<uint8_t>(EMMessageType::TRACKING_AREA_UPDATE_ACCEPT):
                return "Tracking Area Update Accept";
            case static_cast<uint8_t>(EMMessageType::TRACKING_AREA_UPDATE_REJECT):
                return "Tracking Area Update Reject";
            case static_cast<uint8_t>(EMMessageType::TRACKING_AREA_UPDATE_COMPLETE):
                return "Tracking Area Update Complete";
            case static_cast<uint8_t>(EMMessageType::SERVICE_REQUEST):
                return "Service Request";
            case static_cast<uint8_t>(EMMessageType::EXTENDED_SERVICE_REQUEST):
                return "Extended Service Request";
            case static_cast<uint8_t>(EMMessageType::GUTI_REALLOCATION_COMMAND):
                return "GUTI Reallocation Command";
            case static_cast<uint8_t>(EMMessageType::GUTI_REALLOCATION_COMPLETE):
                return "GUTI Reallocation Complete";
            case static_cast<uint8_t>(EMMessageType::EMM_STATUS):
                return "EMM Status";
            case static_cast<uint8_t>(EMMessageType::EMM_INFORMATION):
                return "EMM Information";
            default:
                return "Unknown EMM Message";
        }
    } else if (pd == ProtocolDiscriminator::EPS_SESSION_MANAGEMENT) {
        return "ESM Message (type 0x" + 
               std::to_string(static_cast<unsigned>(message_type)) + ")";
    } else {
        return "Unknown Protocol Message (type 0x" + 
               std::to_string(static_cast<unsigned>(message_type)) + ")";
    }
}

std::string getMobileIdentityTypeName(MobileIdentityType type) {
    switch (type) {
        case MobileIdentityType::NO_IDENTITY:
            return "No Identity";
        case MobileIdentityType::IMSI:
            return "IMSI";
        case MobileIdentityType::IMEI:
            return "IMEI";
        case MobileIdentityType::IMEISV:
            return "IMEISV";
        case MobileIdentityType::TMSI:
            return "TMSI";
        case MobileIdentityType::TMGI:
            return "TMGI";
        case MobileIdentityType::GUTI:
            return "GUTI";
        default:
            return "Unknown";
    }
}

void dumpNasMessage(const uint8_t* nas_bytes, size_t len, std::ostream& os) {
    if (!nas_bytes || len == 0) {
        os << "NAS Message: [Invalid - null or empty]" << std::endl;
        return;
    }

    os << "========================================" << std::endl;
    os << "NAS Message Decode" << std::endl;
    os << "========================================" << std::endl;
    os << "Length: " << len << " bytes" << std::endl;
    
    // Parse header
    NasHeader header = parseNasHeader(nas_bytes, len);
    if (!header.valid) {
        os << "Header: [Invalid - failed to parse]" << std::endl;
        os << "Raw bytes (hex): ";
        for (size_t i = 0; i < len && i < 32; ++i) {
            os << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<unsigned>(nas_bytes[i]) << " ";
        }
        if (len > 32) os << "...";
        os << std::dec << std::endl;
        return;
    }

    // Header information
    os << "\n--- Header ---" << std::endl;
    os << "Security Header Type: " << getSecurityHeaderTypeName(header.security_header_type) 
       << " (" << static_cast<unsigned>(header.security_header_type) << ")" << std::endl;
    os << "Protocol Discriminator: " << getProtocolDiscriminatorName(header.protocol_discriminator)
       << " (0x" << std::hex << static_cast<unsigned>(header.protocol_discriminator) << std::dec << ")" << std::endl;
    os << "Message Type: " << getMessageTypeName(header.message_type, header.protocol_discriminator)
       << " (0x" << std::hex << std::setw(2) << std::setfill('0') 
       << static_cast<unsigned>(header.message_type) << std::dec << ")" << std::endl;

    // Extract identities
    os << "\n--- Identities ---" << std::endl;
    auto identities = decodeStructuredNas(nas_bytes, len);
    
    if (identities.empty()) {
        // Try fallback extraction
        identities = extractMobileIdentity(nas_bytes, len);
    }

    if (identities.empty()) {
        os << "No identities found" << std::endl;
    } else {
        for (size_t i = 0; i < identities.size(); ++i) {
            const auto& identity = identities[i];
            os << "Identity #" << (i + 1) << ":" << std::endl;
            os << "  Type: " << getMobileIdentityTypeName(identity.identity_type) << std::endl;
            os << "  Value: " << identity.identity_string << std::endl;
            os << "  Valid: " << (identity.valid ? "Yes" : "No") << std::endl;
        }
    }

    // Extract specific identity types
    auto imsis = extractImsiFromNas(nas_bytes, len);
    auto tmsis = extractTmsiFromNas(nas_bytes, len);
    auto imeisvs = extractImeisvFromNas(nas_bytes, len);

    if (!imsis.empty() || !tmsis.empty() || !imeisvs.empty()) {
        os << "\n--- Extracted Identities ---" << std::endl;
        if (!imsis.empty()) {
            os << "IMSI(s): ";
            for (size_t i = 0; i < imsis.size(); ++i) {
                os << imsis[i];
                if (i < imsis.size() - 1) os << ", ";
            }
            os << std::endl;
        }
        if (!tmsis.empty()) {
            os << "TMSI(s): ";
            for (size_t i = 0; i < tmsis.size(); ++i) {
                os << tmsis[i];
                if (i < tmsis.size() - 1) os << ", ";
            }
            os << std::endl;
        }
        if (!imeisvs.empty()) {
            os << "IMEISV(s): ";
            for (size_t i = 0; i < imeisvs.size(); ++i) {
                os << imeisvs[i];
                if (i < imeisvs.size() - 1) os << ", ";
            }
            os << std::endl;
        }
    }

    // Raw bytes (first 64 bytes)
    os << "\n--- Raw Bytes (first 64) ---" << std::endl;
    size_t dump_len = (len < 64) ? len : 64;
    for (size_t i = 0; i < dump_len; ++i) {
        os << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<unsigned>(nas_bytes[i]) << " ";
        if ((i + 1) % 16 == 0) {
            os << std::endl;
        }
    }
    if (len > 64) {
        os << "... (" << (len - 64) << " more bytes)" << std::endl;
    }
    os << std::dec << std::endl;
    os << "========================================" << std::endl;
}

} // namespace nas_parser

