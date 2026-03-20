/*
 * SignalBridge - 5G NAS (5GS) mobile identity parser
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 *
 * Parses 5G NAS (TS 24.501) Identity Response, extracts SUCI/SUPI (IMSI).
 * Supports null-scheme SUCI and plain SUPI format IMSI.
 */

#include "signalbridge/nas_5gs_parser.h"
#include <algorithm>
#include <cctype>

namespace signalbridge {

namespace {

// 5G Identity Response message type (TS 24.501)
constexpr uint8_t k5gIdentityResponse = 0x5c;

// SUPI format: IMSI
constexpr uint8_t kSupiFormatImsi = 0x01;

// Protection scheme: null (no encryption)
constexpr uint8_t kProtectionSchemeNull = 0x00;

// Decode TBCD digits (low nibble first, then high). Last nibble 0xF = padding.
std::string decode_tbcd(const uint8_t* bytes, size_t len, bool first_digit_upper_nibble) {
    if (!bytes || len == 0) return {};
    std::string digits;
    for (size_t i = 0; i < len; ++i) {
        uint8_t lo = bytes[i] & 0x0F;
        uint8_t hi = (bytes[i] >> 4) & 0x0F;
        if (i == 0 && first_digit_upper_nibble) {
            if (hi <= 9) digits += static_cast<char>('0' + hi);
            if (lo <= 9) digits += static_cast<char>('0' + lo);
        } else {
            if (lo <= 9) digits += static_cast<char>('0' + lo);
            else if (lo == 0x0F) break;
            if (hi <= 9) digits += static_cast<char>('0' + hi);
            else if (hi == 0x0F) break;
        }
    }
    return digits;
}

// Encode digits to TBCD (low nibble first).
std::vector<uint8_t> encode_tbcd(const std::string& digits) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i < digits.size(); ) {
        uint8_t d1 = static_cast<uint8_t>(digits[i] - '0');
        if (i + 1 < digits.size()) {
            uint8_t d2 = static_cast<uint8_t>(digits[i + 1] - '0');
            out.push_back(static_cast<uint8_t>((d2 << 4) | d1));
            i += 2;
        } else {
            out.push_back(static_cast<uint8_t>((0xF << 4) | d1));
            i += 1;
        }
    }
    return out;
}

bool is_valid_imsi(const std::string& s) {
    if (s.size() < 5 || s.size() > 15) return false;
    for (char c : s) if (c < '0' || c > '9') return false;
    return s.find_first_not_of('0') != std::string::npos;
}

}  // namespace

std::vector<Nas5gsIdentity> extract_5gs_mobile_identities(const uint8_t* nas_payload, size_t len) {
    std::vector<Nas5gsIdentity> result;
    if (!nas_payload || len < 4) return result;

    // nas_payload can be: (a) full NAS with byte0=security+PD, or (b) payload only (msg type first)
    size_t offset = 0;
    uint8_t msg_type;
    if ((nas_payload[0] & 0x0F) == 0x07) {
        // First byte looks like PD 7 (5GMM) - assume full NAS
        offset = 1;
        if (offset >= len) return result;
        msg_type = nas_payload[offset];
        offset++;
    } else {
        msg_type = nas_payload[0];
        offset = 1;
    }

    if (msg_type != k5gIdentityResponse) return result;

    // 5G Identity Response: 5GMM cause (1 byte) + 5G mobile identity (optional)
    if (offset >= len) return result;
    offset++;  // skip 5GMM cause

    if (offset >= len) return result;
    uint8_t identity_len = nas_payload[offset];
    offset++;

    if (offset + identity_len > len || identity_len < 2) return result;

    const uint8_t* ident = nas_payload + offset;
    uint8_t first = ident[0];

    // SUPI format IMSI (plain, same as EPS): odd/even + type 001 + first digit + TBCD
    uint8_t lower3 = first & 0x07;
    if (lower3 == 1) {
        bool odd = (first & 0x08) != 0;
        std::string imsi = decode_tbcd(ident, identity_len, true);
        if (is_valid_imsi(imsi)) {
            Nas5gsIdentity id;
            id.imsi = imsi;
            id.bytes.assign(ident, ident + identity_len);
            id.valid = true;
            result.push_back(id);
        }
        return result;
    }

    // SUCI (SUPI type IMSI): supi_format(1) + mcc_mnc(3) + routing(2) + protection(1) + hn_key(1) + scheme_output
    if (identity_len < 8) return result;
    uint8_t supi_format = ident[0];
    if ((supi_format & 0x0F) != kSupiFormatImsi) return result;

    // MCC digit 2-1 (low=digit2, high=digit1), MCC digit 3 + MNC digit 3 (low=MCC3, high=MNC3 or F), MNC digit 2-1
    uint8_t mcc_d2_1 = ident[1];
    uint8_t mcc3_mnc3 = ident[2];
    uint8_t mnc_d2_1 = ident[3];
    std::string mcc_mnc;
    mcc_mnc += static_cast<char>('0' + (mcc_d2_1 >> 4));   // digit 1
    mcc_mnc += static_cast<char>('0' + (mcc_d2_1 & 0x0F)); // digit 2
    mcc_mnc += static_cast<char>('0' + (mcc3_mnc3 & 0x0F)); // digit 3
    mcc_mnc += static_cast<char>('0' + (mnc_d2_1 >> 4));   // MNC digit 1
    mcc_mnc += static_cast<char>('0' + (mnc_d2_1 & 0x0F)); // MNC digit 2
    if ((mcc3_mnc3 >> 4) != 0x0F)
        mcc_mnc += static_cast<char>('0' + (mcc3_mnc3 >> 4)); // MNC digit 3

    uint8_t protection = ident[6] & 0x0F;
    if (protection != kProtectionSchemeNull) return result;  // Cannot decode encrypted

    // Scheme output = MSIN in TBCD (bytes 8+)
    size_t scheme_output_len = identity_len - 8;
    if (scheme_output_len == 0) return result;
    std::string msin = decode_tbcd(ident + 8, scheme_output_len, false);
    std::string imsi = mcc_mnc + msin;
    if (is_valid_imsi(imsi)) {
        Nas5gsIdentity id;
        id.imsi = imsi;
        id.bytes.assign(ident, ident + identity_len);
        id.valid = true;
        result.push_back(id);
    }
    return result;
}

std::vector<uint8_t> encode_5gs_supi_imsi(const std::string& imsi) {
    if (imsi.empty()) return {};
    for (char c : imsi) if (c < '0' || c > '9') return {};

    bool odd = (imsi.size() % 2 == 1);
    uint8_t high = static_cast<uint8_t>(odd ? 0x9 : 0x1);
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>((high << 4) | (imsi[0] - '0')));
    auto rest = encode_tbcd(imsi.substr(1));
    out.insert(out.end(), rest.begin(), rest.end());
    return out;
}

std::vector<uint8_t> encode_5gs_suci_imsi(const std::string& imsi, size_t expected_len) {
    if (imsi.size() < 5 || imsi.size() > 15) return {};
    for (char c : imsi) if (c < '0' || c > '9') return {};

    // MCC (3) + MNC (2 or 3) + MSIN. TS 24.501: MCC digit 2-1, MCC digit 3 + MNC digit 3, MNC digit 2-1
    std::string mcc = imsi.substr(0, 3);
    bool mnc_3_digit = (imsi.size() >= 14);
    std::string mnc = mnc_3_digit ? imsi.substr(3, 3) : imsi.substr(3, 2);
    std::string msin = imsi.substr(3 + mnc.size());

    std::vector<uint8_t> out;
    out.push_back(kSupiFormatImsi);
    out.push_back(static_cast<uint8_t>((mcc[1] - '0') | ((mcc[0] - '0') << 4)));  // digit 2-1
    out.push_back(static_cast<uint8_t>((mcc[2] - '0') | ((mnc_3_digit ? (mnc[2] - '0') : 0x0F) << 4)));
    out.push_back(static_cast<uint8_t>((mnc[0] - '0') | ((mnc[1] - '0') << 4)));
    out.push_back(0);
    out.push_back(0);
    out.push_back(kProtectionSchemeNull);
    out.push_back(0);
    auto msin_bytes = encode_tbcd(msin);
    out.insert(out.end(), msin_bytes.begin(), msin_bytes.end());

    if (out.size() != expected_len) return {};
    return out;
}

}  // namespace signalbridge
