/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/io/pcap_io.h"
#include "s1see/utils/pcap_reader.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <map>
#include <unistd.h>
#include <vector>

#ifdef HAVE_PCAP
#include <pcap/pcap.h>
#include <cstdio>
#endif

namespace signalbridge {

namespace {

constexpr size_t PCAP_GLOBAL_HEADER_SIZE = 24;
constexpr size_t PCAP_PACKET_HEADER_SIZE = 16;
constexpr size_t STREAM_BUF_SIZE = 65536;

// Buffered stream reader for partial reads (e.g. from TCP socket).
// Returns true if n bytes available and consumed, false on error/EOF.
class StreamBuffer {
public:
    bool ensure(size_t n) {
        while (size_ < n) {
            if (pos_ > 0) {
                std::memmove(buf_.data(), buf_.data() + pos_, size_);
                pos_ = 0;
            }
            if (size_ >= buf_.size()) return false;  // need more than buffer
            ssize_t r = ::read(fd_, buf_.data() + size_, buf_.size() - size_);
            if (r <= 0) return false;
            size_ += static_cast<size_t>(r);
        }
        return true;
    }

    const uint8_t* peek() const { return buf_.data() + pos_; }
    void consume(size_t n) {
        pos_ += n;
        size_ -= n;
    }

    explicit StreamBuffer(int fd) : fd_(fd), buf_(STREAM_BUF_SIZE), pos_(0), size_(0) {}

private:
    int fd_;
    std::vector<uint8_t> buf_;
    size_t pos_;
    size_t size_;
};

bool read_exact(int fd, uint8_t* buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = ::read(fd, buf + total, n - total);
        if (r <= 0) return false;
        total += static_cast<size_t>(r);
    }
    return true;
}

int parse_pcap_stream(int fd,
                      std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback) {
    uint8_t global_header[PCAP_GLOBAL_HEADER_SIZE];
    if (!read_exact(fd, global_header, PCAP_GLOBAL_HEADER_SIZE)) {
        return -1;
    }

    uint32_t magic;
    std::memcpy(&magic, global_header, 4);
    const bool swap = (magic == 0xd4c3b2a1);
    if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1) {
        std::cerr << "Invalid PCAP magic: 0x" << std::hex << magic << std::dec << "\n";
        return -1;
    }

    uint32_t linktype;
    std::memcpy(&linktype, global_header + 20, 4);
    if (swap) linktype = __builtin_bswap32(linktype);
    int link_type = static_cast<int>(linktype);

    uint32_t frame_num = 0;
    while (true) {
        uint8_t pkt_header[PCAP_PACKET_HEADER_SIZE];
        if (!read_exact(fd, pkt_header, PCAP_PACKET_HEADER_SIZE)) {
            break;
        }

        uint32_t ts_sec, ts_usec, caplen, origlen;
        std::memcpy(&ts_sec, pkt_header + 0, 4);
        std::memcpy(&ts_usec, pkt_header + 4, 4);
        std::memcpy(&caplen, pkt_header + 8, 4);
        std::memcpy(&origlen, pkt_header + 12, 4);
        if (swap) {
            ts_sec = __builtin_bswap32(ts_sec);
            ts_usec = __builtin_bswap32(ts_usec);
            caplen = __builtin_bswap32(caplen);
            origlen = __builtin_bswap32(origlen);
        }

        if (caplen > 65535 * 2) {
            std::cerr << "Invalid packet caplen: " << caplen << "\n";
            return -1;
        }

        std::vector<uint8_t> packet(caplen);
        if (!read_exact(fd, packet.data(), caplen)) {
            std::cerr << "Truncated packet data\n";
            return -1;
        }

        frame_num++;
callback(link_type, packet.data(), caplen, ts_sec, ts_usec, frame_num);
    }

    return static_cast<int>(frame_num);
}

// PCAPNG block type constants
constexpr uint32_t PCAPNG_SHB = 0x0A0D0D0A;
constexpr uint32_t PCAPNG_IDB = 0x00000001;
constexpr uint32_t PCAPNG_EPB = 0x00000006;

int parse_pcapng_stream(StreamBuffer& sb,
                        std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback) {
    std::map<uint32_t, int> iface_to_linktype;
    int frame_num = 0;
    int default_link_type = 1;

    while (true) {
        if (!sb.ensure(8)) break;  // block type + block total length
        const uint8_t* p = sb.peek();
        uint32_t block_type;
        uint32_t block_len;
        std::memcpy(&block_type, p, 4);
        std::memcpy(&block_len, p + 4, 4);
        if (block_len < 12) {
            std::cerr << "Invalid PCAPNG block length: " << block_len << "\n";
            return -1;
        }
        if (!sb.ensure(block_len)) break;

        p = sb.peek();
        if (block_type == PCAPNG_SHB) {
            sb.consume(block_len);
            continue;
        }
        if (block_type == PCAPNG_IDB) {
            if (block_len >= 20) {
                uint16_t linktype;
                std::memcpy(&linktype, p + 8, 2);
                uint32_t iface_id = static_cast<uint32_t>(iface_to_linktype.size());
                iface_to_linktype[iface_id] = static_cast<int>(linktype);
            }
            sb.consume(block_len);
            continue;
        }
        if (block_type == PCAPNG_EPB) {
            if (block_len < 28) {
                sb.consume(block_len);
                continue;
            }
            uint32_t iface_id;
            uint32_t ts_high, ts_low, caplen, origlen;
            std::memcpy(&iface_id, p + 8, 4);
            std::memcpy(&ts_high, p + 12, 4);
            std::memcpy(&ts_low, p + 16, 4);
            std::memcpy(&caplen, p + 20, 4);
            std::memcpy(&origlen, p + 24, 4);

            if (caplen > 65535 * 2) {
                std::cerr << "Invalid PCAPNG packet caplen: " << caplen << "\n";
                return -1;
            }
            // EPB: 8 (type+len) + 20 (iface,ts_high,ts_low,caplen,origlen) = 28, then packet, then 4 (trailing len)
            size_t data_offset = 28;
            size_t available = (block_len > 32) ? (block_len - 32) : 0;  // -28 (hdr) -4 (trailing)
            size_t packet_len = (caplen <= available) ? caplen : available;
            if (packet_len == 0 || data_offset + packet_len > block_len - 4) {
                sb.consume(block_len);
                continue;
            }

            int link_type = default_link_type;
            auto it = iface_to_linktype.find(iface_id);
            if (it != iface_to_linktype.end()) link_type = it->second;

            uint64_t ts_us = (static_cast<uint64_t>(ts_high) << 32) | ts_low;
            uint64_t ts_sec = ts_us / 1000000;
            uint32_t ts_usec = static_cast<uint32_t>(ts_us % 1000000);

            frame_num++;
            callback(link_type, p + data_offset, packet_len, ts_sec, ts_usec, frame_num);
            sb.consume(block_len);
            continue;
        }
        sb.consume(block_len);
    }
    return frame_num;
}

int parse_pcap_stream_buffered(StreamBuffer& sb,
                               std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback) {
    if (!sb.ensure(PCAP_GLOBAL_HEADER_SIZE)) return -1;
    const uint8_t* gh = sb.peek();
    uint32_t magic;
    std::memcpy(&magic, gh, 4);
    const bool swap = (magic == 0xd4c3b2a1);
    if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1) {
        std::cerr << "Invalid PCAP magic: 0x" << std::hex << magic << std::dec << "\n";
        return -1;
    }
    uint32_t linktype;
    std::memcpy(&linktype, gh + 20, 4);
    if (swap) linktype = __builtin_bswap32(linktype);
    int link_type = static_cast<int>(linktype);
    sb.consume(PCAP_GLOBAL_HEADER_SIZE);

    uint32_t frame_num = 0;
    while (true) {
        if (!sb.ensure(PCAP_PACKET_HEADER_SIZE)) break;
        const uint8_t* ph = sb.peek();
        uint32_t ts_sec, ts_usec, caplen, origlen;
        std::memcpy(&ts_sec, ph + 0, 4);
        std::memcpy(&ts_usec, ph + 4, 4);
        std::memcpy(&caplen, ph + 8, 4);
        std::memcpy(&origlen, ph + 12, 4);
        if (swap) {
            ts_sec = __builtin_bswap32(ts_sec);
            ts_usec = __builtin_bswap32(ts_usec);
            caplen = __builtin_bswap32(caplen);
            origlen = __builtin_bswap32(origlen);
        }
        if (caplen > 65535 * 2) {
            std::cerr << "Invalid packet caplen: " << caplen << "\n";
            return -1;
        }
        sb.consume(PCAP_PACKET_HEADER_SIZE);
        if (!sb.ensure(caplen)) break;
        const uint8_t* packet = sb.peek();
        frame_num++;
callback(link_type, packet, caplen, ts_sec, ts_usec, frame_num);
        sb.consume(caplen);
    }
    return static_cast<int>(frame_num);
}

}  // namespace

bool PcapWriter::is_pcapng_path(const std::string& path) {
    return path.size() >= 7 && path.compare(path.size() - 7, 7, ".pcapng") == 0;
}

PcapWriter::PcapWriter(const std::string& path) : path_(path), use_pcapng_(is_pcapng_path(path)) {}

void PcapWriter::write_pcap_header(int link_type) {
    struct pcap_file_header {
        uint32_t magic;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t linktype;
    } hdr = {};
    hdr.magic = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = 0;
    hdr.sigfigs = 0;
    hdr.snaplen = 65535;
    hdr.linktype = (link_type >= 0) ? static_cast<uint32_t>(link_type) : 1u;
    ofs_.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
}

void PcapWriter::write_pcapng_header(int link_type) {
    link_type_ = (link_type >= 0) ? link_type : 1;
    // Section Header Block: type 0x0A0D0D0A, length 28, magic 0x1A2B3C4D, version 1.0, section length -1
    uint32_t shb_type = 0x0A0D0D0A;
    uint32_t shb_len = 28;
    uint32_t shb_magic = 0x1A2B3C4D;
    uint16_t shb_major = 1, shb_minor = 0;
    uint64_t shb_section_len = 0xFFFFFFFFFFFFFFFFu;
    ofs_.write(reinterpret_cast<const char*>(&shb_type), 4);
    ofs_.write(reinterpret_cast<const char*>(&shb_len), 4);
    ofs_.write(reinterpret_cast<const char*>(&shb_magic), 4);
    ofs_.write(reinterpret_cast<const char*>(&shb_major), 2);
    ofs_.write(reinterpret_cast<const char*>(&shb_minor), 2);
    ofs_.write(reinterpret_cast<const char*>(&shb_section_len), 8);
    ofs_.write(reinterpret_cast<const char*>(&shb_len), 4);

    // Interface Description Block: type 1, length 20, linktype, reserved 0, snaplen 65535
    uint32_t idb_type = 0x00000001;
    uint32_t idb_len = 20;
    uint16_t idb_linktype = static_cast<uint16_t>(link_type_);
    uint16_t idb_reserved = 0;
    uint32_t idb_snaplen = 65535;
    ofs_.write(reinterpret_cast<const char*>(&idb_type), 4);
    ofs_.write(reinterpret_cast<const char*>(&idb_len), 4);
    ofs_.write(reinterpret_cast<const char*>(&idb_linktype), 2);
    ofs_.write(reinterpret_cast<const char*>(&idb_reserved), 2);
    ofs_.write(reinterpret_cast<const char*>(&idb_snaplen), 4);
    ofs_.write(reinterpret_cast<const char*>(&idb_len), 4);
}

bool PcapWriter::open(int link_type) {
    if (ofs_.is_open()) return true;
    ofs_.open(path_, std::ios::binary | std::ios::trunc);
    if (!ofs_) return false;

    if (use_pcapng_) {
        write_pcapng_header(link_type);
    } else {
        write_pcap_header(link_type);
    }
    header_written_ = ofs_.good();
    link_type_ = (link_type >= 0) ? link_type : 1;
    return header_written_;
}

bool PcapWriter::write_pcap_frame(const SignallingFrame& frame) {
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t caplen;
        uint32_t len;
    } pkthdr = {};
    pkthdr.ts_sec = static_cast<uint32_t>(frame.timestamp_sec);
    pkthdr.ts_usec = static_cast<uint32_t>(frame.timestamp_usec);
    pkthdr.caplen = static_cast<uint32_t>(frame.packet.size());
    pkthdr.len = pkthdr.caplen;

    ofs_.write(reinterpret_cast<const char*>(&pkthdr), sizeof(pkthdr));
    ofs_.write(reinterpret_cast<const char*>(frame.packet.data()), frame.packet.size());
    return ofs_.good();
}

bool PcapWriter::write_pcapng_frame(const SignallingFrame& frame) {
    uint32_t caplen = static_cast<uint32_t>(frame.packet.size());
    uint32_t origlen = caplen;
    uint32_t pad = (4 - (caplen % 4)) % 4;
    uint32_t block_len = 32 + caplen + pad;  // EPB header 32 + data + padding

    uint32_t epb_type = 0x00000006;
    uint32_t iface_id = 0;
    uint64_t ts_us = static_cast<uint64_t>(frame.timestamp_sec) * 1000000 + frame.timestamp_usec;
    uint32_t ts_high = static_cast<uint32_t>(ts_us >> 32);
    uint32_t ts_low = static_cast<uint32_t>(ts_us & 0xFFFFFFFFu);

    ofs_.write(reinterpret_cast<const char*>(&epb_type), 4);
    ofs_.write(reinterpret_cast<const char*>(&block_len), 4);
    ofs_.write(reinterpret_cast<const char*>(&iface_id), 4);
    ofs_.write(reinterpret_cast<const char*>(&ts_high), 4);
    ofs_.write(reinterpret_cast<const char*>(&ts_low), 4);
    ofs_.write(reinterpret_cast<const char*>(&caplen), 4);
    ofs_.write(reinterpret_cast<const char*>(&origlen), 4);
    ofs_.write(reinterpret_cast<const char*>(frame.packet.data()), frame.packet.size());
    for (uint32_t i = 0; i < pad; ++i) ofs_.put(0);
    ofs_.write(reinterpret_cast<const char*>(&block_len), 4);
    return ofs_.good();
}

bool PcapWriter::write_frame(const SignallingFrame& frame) {
    if (!ofs_.is_open() || !header_written_) return false;
    return use_pcapng_ ? write_pcapng_frame(frame) : write_pcap_frame(frame);
}

void PcapWriter::close() {
    if (ofs_.is_open()) {
        ofs_.flush();
        ofs_.close();
    }
    header_written_ = false;
}

int PcapIo::get_link_type(const std::string& path) {
#ifdef HAVE_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(path.c_str(), errbuf);
    if (!pcap) return -1;
    int lt = pcap_datalink(pcap);
    pcap_close(pcap);
    return lt;
#else
    std::ifstream f(path, std::ios::binary);
    if (!f) return -1;
    uint8_t hdr[24];
    if (!f.read(reinterpret_cast<char*>(hdr), 24) || f.gcount() != 24) return -1;
    uint32_t magic;
    std::memcpy(&magic, hdr, 4);
    if (magic != 0xa1b2c3d4 && magic != 0xd4c3b2a1) return -1;
    uint32_t linktype;
    std::memcpy(&linktype, hdr + 20, 4);
    if (magic == 0xd4c3b2a1) linktype = __builtin_bswap32(linktype);
    return static_cast<int>(linktype);
#endif
}

int PcapIo::read_file_with_link_type(const std::string& path,
                                      std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback) {
#ifdef HAVE_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(path.c_str(), errbuf);
    if (!pcap) {
        std::cerr << "Error opening PCAP/PCAPNG file: " << errbuf << "\n";
        return -1;
    }
    int link_type = pcap_datalink(pcap);
    int frame_num = 0;
    struct pcap_pkthdr header;
    const u_char* packet_data;
    while ((packet_data = pcap_next(pcap, &header)) != nullptr) {
        frame_num++;
callback(link_type, packet_data, header.caplen,
                 static_cast<uint64_t>(header.ts.tv_sec),
                 static_cast<uint32_t>(header.ts.tv_usec),
                 static_cast<uint32_t>(frame_num));
    }
    pcap_close(pcap);
    return frame_num;
#else
    (void)path;
    (void)callback;
    return -1;
#endif
}

int PcapIo::read_stdin(std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback) {
#ifdef HAVE_PCAP
    FILE* fp = fdopen(STDIN_FILENO, "rb");
    if (!fp) {
        std::cerr << "Failed to open stdin\n";
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_fopen_offline(fp, errbuf);
    if (!pcap) {
        std::cerr << "Failed to read PCAP/PCAPNG from stdin: " << errbuf << "\n";
        return -1;
    }
    int link_type = pcap_datalink(pcap);
    int frame_num = 0;
    struct pcap_pkthdr header;
    const u_char* packet_data;
    while ((packet_data = pcap_next(pcap, &header)) != nullptr) {
        frame_num++;
callback(link_type, packet_data, header.caplen,
                 static_cast<uint64_t>(header.ts.tv_sec),
                 static_cast<uint32_t>(header.ts.tv_usec),
                 static_cast<uint32_t>(frame_num));
    }
    pcap_close(pcap);
    return frame_num;
#else
    return parse_pcap_stream(STDIN_FILENO, std::move(callback));
#endif
}

int PcapIo::read_stream_from_fd(int fd,
                                std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback) {
    StreamBuffer sb(fd);
    if (!sb.ensure(4)) {
        std::cerr << "Stream ended before PCAP/PCAPNG header (peer closed or sent no data).\n";
        return -1;
    }
    const uint8_t* magic = sb.peek();
    uint32_t m;
    std::memcpy(&m, magic, 4);
    if (m == PCAPNG_SHB) {
        return parse_pcapng_stream(sb, std::move(callback));
    }
    if (m == 0xa1b2c3d4 || m == 0xd4c3b2a1) {
        return parse_pcap_stream_buffered(sb, std::move(callback));
    }
    std::cerr << "Unknown stream format, magic: 0x" << std::hex << m << std::dec << "\n";
    return -1;
}

int PcapIo::read_file(const std::string& path,
                      std::function<void(const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback) {
#ifdef HAVE_PCAP
    return s1see::utils::read_pcap_file(path, [&](const s1see::utils::PcapPacket& pkt) {
        callback(pkt.data.data(), pkt.data.size(),
                 pkt.timestamp_sec, pkt.timestamp_usec, pkt.frame_number);
    });
#else
    (void)path;
    (void)callback;
    return -1;
#endif
}

bool PcapIo::write_frame(const std::string& path, const SignallingFrame& frame, bool append, int link_type) {
#ifdef HAVE_PCAP
    std::ofstream ofs;
    if (append) {
        ofs.open(path, std::ios::binary | std::ios::app);
    } else {
        ofs.open(path, std::ios::binary | std::ios::trunc);
    }
    if (!ofs) return false;

    if (!append) {
        // Write PCAP global header (microsecond resolution), preserving input link type
        struct pcap_file_header {
            uint32_t magic;
            uint16_t version_major;
            uint16_t version_minor;
            int32_t thiszone;
            uint32_t sigfigs;
            uint32_t snaplen;
            uint32_t linktype;
        } hdr = {};
        hdr.magic = 0xa1b2c3d4;
        hdr.version_major = 2;
        hdr.version_minor = 4;
        hdr.thiszone = 0;
        hdr.sigfigs = 0;
        hdr.snaplen = 65535;
        hdr.linktype = (link_type >= 0) ? static_cast<uint32_t>(link_type) : 1u;  // default DLT_EN10MB
        ofs.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    }

    // Use fixed 16-byte pcap packet header (pcap_pkthdr is 280 bytes on macOS)
    struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t caplen;
        uint32_t len;
    } pkthdr = {};
    pkthdr.ts_sec = static_cast<uint32_t>(frame.timestamp_sec);
    pkthdr.ts_usec = static_cast<uint32_t>(frame.timestamp_usec);
    pkthdr.caplen = static_cast<uint32_t>(frame.packet.size());
    pkthdr.len = pkthdr.caplen;

    ofs.write(reinterpret_cast<const char*>(&pkthdr), sizeof(pkthdr));
    ofs.write(reinterpret_cast<const char*>(frame.packet.data()), frame.packet.size());
    ofs.flush();

    return ofs.good();
#else
    (void)path;
    (void)frame;
    (void)append;
    return false;
#endif
}

}  // namespace signalbridge
