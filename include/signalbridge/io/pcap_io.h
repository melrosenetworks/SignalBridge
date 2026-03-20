/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#pragma once

#include "signalbridge/types.h"
#include <fstream>
#include <functional>
#include <string>

namespace signalbridge {

// PCAP file input/output
class PcapIo {
public:
    // Read PCAP/PCAPNG file, call callback for each packet
    // Returns packet count or -1 on error
    static int read_file(const std::string& path,
                         std::function<void(const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback);

    // Read PCAP/PCAPNG file with link_type in callback (for TCP stream processing)
    static int read_file_with_link_type(const std::string& path,
                                        std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback);

    // Read PCAP/PCAPNG from stdin (e.g. tshark -r f -w - | signalbridge --stdin -o out.pcap)
    // Callback receives (link_type, data, len, ts_sec, ts_usec, frame_num). Returns packet count or -1 on error.
    static int read_stdin(std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback);

    // Read PCAP/PCAPNG stream from fd (e.g. TCP socket). Processes packets as they arrive, no temp files.
    // Supports both classic PCAP and PCAPNG. Returns packet count or -1 on error.
    static int read_stream_from_fd(int fd,
                                   std::function<void(int link_type, const uint8_t*, size_t, uint64_t, uint32_t, uint32_t)> callback);

    // Get link type from PCAP file (reads global header). Returns -1 on error.
    static int get_link_type(const std::string& path);

    // Write frame to PCAP file (creates/appends). link_type used only when creating (append=false).
    static bool write_frame(const std::string& path, const SignallingFrame& frame, bool append = true,
                           int link_type = 1);
};

// Stateful PCAP/PCAPNG writer that keeps the file open for efficient multi-frame output.
// Format is inferred from path: .pcapng -> PCAPNG, otherwise PCAP.
class PcapWriter {
public:
    explicit PcapWriter(const std::string& path);

    // Open file and write global header. link_type used for dissection (default DLT_EN10MB).
    bool open(int link_type = 1);

    // Write a frame. open() must have been called successfully.
    bool write_frame(const SignallingFrame& frame);

    // Close the file.
    void close();

    bool is_open() const { return ofs_.is_open(); }

    // True if path indicates PCAPNG output
    static bool is_pcapng_path(const std::string& path);

private:
    void write_pcap_header(int link_type);
    void write_pcapng_header(int link_type);
    bool write_pcap_frame(const SignallingFrame& frame);
    bool write_pcapng_frame(const SignallingFrame& frame);

    std::string path_;
    std::ofstream ofs_;
    bool header_written_{false};
    bool use_pcapng_{false};
    int link_type_{1};
};

}  // namespace signalbridge
