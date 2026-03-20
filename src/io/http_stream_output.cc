/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/io/http_stream_output.h"
#include "signalbridge/metrics/metrics.h"
#include "signalbridge/types.h"
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <zlib.h>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace {

// Simple base64 encode for binary packet data
std::string base64_encode(const uint8_t* data, size_t len) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out += b64[(n >> 18) & 63];
        out += b64[(n >> 12) & 63];
        out += (i + 1 < len) ? b64[(n >> 6) & 63] : '=';
        out += (i + 2 < len) ? b64[n & 63] : '=';
    }
    return out;
}

std::string frame_to_json(const signalbridge::SignallingFrame& frame) {
    nlohmann::json j;
    j["packet"] = base64_encode(frame.packet.data(), frame.packet.size());
    j["timestamp_sec"] = frame.timestamp_sec;
    j["timestamp_usec"] = frame.timestamp_usec;
    j["frame_number"] = frame.frame_number;
    j["procedure_code"] = frame.procedure_code;
    j["procedure_name"] = frame.procedure_name;
    j["protocol"] = frame.is_s1ap ? "s1ap" : "ngap";
    j["has_encrypted_nas"] = frame.has_encrypted_nas;
    if (frame.procedures.size() > 1) {
        nlohmann::json procs = nlohmann::json::array();
        for (const auto& p : frame.procedures) {
            procs.push_back({{"procedure_code", p.procedure_code},
                            {"procedure_name", p.procedure_name},
                            {"protocol", p.is_s1ap ? "s1ap" : "ngap"}});
        }
        j["procedures"] = procs;
    }
    return j.dump() + "\n";
}

// Gzip compress data. Returns empty vector on failure.
std::vector<uint8_t> gzip_compress(const std::string& data) {
    z_stream strm{};
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return {};

    strm.avail_in = static_cast<uInt>(data.size());
    strm.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data.data()));

    std::vector<uint8_t> out;
    out.resize(deflateBound(&strm, static_cast<uLong>(data.size())));
    strm.avail_out = static_cast<uInt>(out.size());
    strm.next_out = out.data();

    int ret = deflate(&strm, Z_FINISH);
    deflateEnd(&strm);
    if (ret != Z_STREAM_END) return {};

    out.resize(strm.total_out);
    return out;
}

// Decode hex string to bytes. Returns empty vector if invalid.
std::vector<uint8_t> hex_decode(const std::string& hex) {
    if (hex.size() % 2 != 0) return {};
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto hi = hex[i];
        auto lo = hex[i + 1];
        if (!std::isxdigit(static_cast<unsigned char>(hi)) ||
            !std::isxdigit(static_cast<unsigned char>(lo)))
            return {};
        int h = (hi >= 'a') ? (hi - 'a' + 10) : (hi >= 'A') ? (hi - 'A' + 10) : (hi - '0');
        int l = (lo >= 'a') ? (lo - 'a' + 10) : (lo >= 'A') ? (lo - 'A' + 10) : (lo - '0');
        out.push_back(static_cast<uint8_t>((h << 4) | l));
    }
    return out;
}

// AES-256-GCM encrypt. Returns [iv(12)][ciphertext][tag(16)] or empty on failure.
std::vector<uint8_t> aes_256_gcm_encrypt(const uint8_t* key, size_t key_len,
                                         const uint8_t* plain, size_t plain_len) {
    if (key_len != 32) return {};

    constexpr size_t kIVLen = 12;
    constexpr size_t kTagLen = 16;
    std::vector<uint8_t> iv(kIVLen);
    if (RAND_bytes(iv.data(), static_cast<int>(kIVLen)) != 1) return {};

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    std::vector<uint8_t> out;
    out.resize(kIVLen + plain_len + kTagLen);
    std::copy(iv.begin(), iv.end(), out.begin());

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int len;
    if (EVP_EncryptUpdate(ctx, out.data() + kIVLen, &len,
                          plain, static_cast<int>(plain_len)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }

    int cipher_len = len;
    if (EVP_EncryptFinal_ex(ctx, out.data() + kIVLen + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    cipher_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagLen),
                            out.data() + kIVLen + cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    EVP_CIPHER_CTX_free(ctx);

    out.resize(kIVLen + cipher_len + kTagLen);
    return out;
}

}  // namespace

namespace signalbridge {

static constexpr size_t kMaxBatchSize = 1000;
static constexpr auto kBatchTimeout = std::chrono::seconds(1);

struct HttpStreamOutput::Impl {
    std::queue<SignallingFrame> batch;
    std::chrono::steady_clock::time_point batch_first_item_time;
    mutable std::mutex mutex;
    std::condition_variable cv;
    bool done{false};
    std::thread worker;
    std::string url_;
    std::vector<uint8_t> encryption_key;  // 32 bytes when encryption enabled
    CURL* curl{nullptr};
    struct curl_slist* headers{nullptr};
    bool worker_finished{false};
    CURLcode result{CURLE_OK};
    Metrics* metrics{nullptr};
};

static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)userdata;
    return size * nmemb;  // consume all
}

void HttpStreamOutput::worker_loop(Impl* impl) {
    while (true) {
        std::vector<SignallingFrame> to_send;
        {
            std::unique_lock<std::mutex> lock(impl->mutex);
            auto pred = [impl] {
                return impl->done || impl->batch.size() >= kMaxBatchSize;
            };
            if (impl->batch.empty()) {
                impl->cv.wait(lock, [impl] { return impl->done || !impl->batch.empty(); });
                if (impl->done && impl->batch.empty()) break;
            }
            if (!impl->batch.empty()) {
                auto deadline = impl->batch_first_item_time + kBatchTimeout;
                impl->cv.wait_until(lock, deadline, pred);
                while (!impl->batch.empty() && to_send.size() < kMaxBatchSize) {
                    to_send.push_back(std::move(impl->batch.front()));
                    impl->batch.pop();
                }
            }
            if (impl->done && impl->batch.empty() && to_send.empty()) break;
        }

        if (to_send.empty()) continue;

        size_t estimated_size = 0;
        for (const auto& f : to_send) {
            estimated_size += f.packet.size() * 2 + 256;  // base64 ~4/3 + metadata
        }
        estimated_size = std::min(estimated_size, size_t(16 * 1024 * 1024));
        std::string plain;
        plain.reserve(estimated_size);
        for (const auto& f : to_send) {
            plain += frame_to_json(f);
        }
        std::vector<uint8_t> compressed = gzip_compress(plain);
        if (compressed.empty()) {
            std::cerr << "Error: gzip compression failed for batch of " << to_send.size() << " frames, dropping\n";
            continue;
        }
        uint64_t pre = static_cast<uint64_t>(plain.size());
        uint64_t post = static_cast<uint64_t>(compressed.size());
        if (impl->metrics) impl->metrics->output_bytes_add(pre, post);

        const void* payload = compressed.data();
        curl_off_t payload_size = static_cast<curl_off_t>(compressed.size());
        std::vector<uint8_t> encrypted;

        if (!impl->encryption_key.empty()) {
            encrypted = aes_256_gcm_encrypt(impl->encryption_key.data(), impl->encryption_key.size(),
                                            compressed.data(), compressed.size());
            if (encrypted.empty()) {
                std::cerr << "Error: AES-256-GCM encryption failed for batch of " << to_send.size() << " frames, dropping\n";
                continue;
            }
            payload = encrypted.data();
            payload_size = static_cast<curl_off_t>(encrypted.size());
        }

        curl_easy_setopt(impl->curl, CURLOPT_POSTFIELDSIZE_LARGE, payload_size);
        curl_easy_setopt(impl->curl, CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(impl->curl, CURLOPT_READFUNCTION, nullptr);
        curl_easy_setopt(impl->curl, CURLOPT_READDATA, nullptr);

        CURLcode res = curl_easy_perform(impl->curl);
        long response_code = 0;
        if (res == CURLE_OK) {
            curl_easy_getinfo(impl->curl, CURLINFO_RESPONSE_CODE, &response_code);
        }
        if (impl->metrics) impl->metrics->http_response_code_inc(response_code);
        if (res != CURLE_OK) {
            impl->result = res;
            std::cerr << "Error: HTTP POST failed: " << curl_easy_strerror(res) << "\n";
        }
        // Reset for next request - POSTFIELDS will be set again
        curl_easy_setopt(impl->curl, CURLOPT_POSTFIELDS, nullptr);
    }
    impl->worker_finished = true;
}

std::unique_ptr<HttpStreamOutput> HttpStreamOutput::create(const std::string& url, Metrics* metrics,
                                                           const std::string& encryption_key) {
    auto out = std::unique_ptr<HttpStreamOutput>(new HttpStreamOutput(url, metrics, encryption_key));
    if (!out->init()) return nullptr;
    return out;
}

HttpStreamOutput::HttpStreamOutput(const std::string& url, Metrics* metrics,
                                   const std::string& encryption_key) : url_(url) {
    impl_ = std::make_unique<Impl>();
    impl_->metrics = metrics;
    if (!encryption_key.empty()) {
        impl_->encryption_key = hex_decode(encryption_key);
        if (impl_->encryption_key.size() != 32) {
            impl_->encryption_key.clear();
            std::cerr << "Warning: encryption_key must be 64 hex chars (32 bytes), disabling encryption\n";
        }
    }
}

bool HttpStreamOutput::init() {
    impl_->curl = curl_easy_init();
    if (!impl_->curl) return false;

    if (impl_->encryption_key.empty()) {
        impl_->headers = curl_slist_append(nullptr, "Content-Type: application/x-ndjson");
        impl_->headers = curl_slist_append(impl_->headers, "Content-Encoding: gzip");
    } else {
        impl_->headers = curl_slist_append(nullptr, "Content-Type: application/octet-stream");
        impl_->headers = curl_slist_append(impl_->headers, "X-Encryption: aes-256-gcm");
        impl_->headers = curl_slist_append(impl_->headers, "X-Content-Encoding: gzip");
    }
    curl_easy_setopt(impl_->curl, CURLOPT_URL, url_.c_str());
    curl_easy_setopt(impl_->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(impl_->curl, CURLOPT_WRITEFUNCTION, &write_callback);
    curl_easy_setopt(impl_->curl, CURLOPT_HTTPHEADER, impl_->headers);
    curl_easy_setopt(impl_->curl, CURLOPT_TIMEOUT, 0L);
    curl_easy_setopt(impl_->curl, CURLOPT_CONNECTTIMEOUT, 10L);

    valid_ = true;
    return true;
}

HttpStreamOutput::~HttpStreamOutput() {
    finish();
    if (impl_) {
        if (impl_->headers) {
            curl_slist_free_all(impl_->headers);
            impl_->headers = nullptr;
        }
        if (impl_->curl) {
            curl_easy_cleanup(impl_->curl);
            impl_->curl = nullptr;
        }
    }
}

size_t HttpStreamOutput::queue_size() const {
    if (!impl_) return 0;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->batch.size();
}

bool HttpStreamOutput::write(const SignallingFrame& frame) {
    if (!valid_ || !impl_) return false;

    if (!impl_->worker.joinable()) {
        impl_->worker = std::thread([this]() {
            worker_loop(impl_.get());
        });
    }

    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->batch.empty()) {
            impl_->batch_first_item_time = std::chrono::steady_clock::now();
        }
        impl_->batch.push(frame);
    }
    impl_->cv.notify_one();
    return true;
}

void HttpStreamOutput::finish() {
    if (!impl_) return;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->done = true;
    }
    impl_->cv.notify_one();
    if (impl_->worker.joinable()) impl_->worker.join();
}

}  // namespace signalbridge
