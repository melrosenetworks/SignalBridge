/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/config/config_loader.h"
#include "signalbridge/io/async_pcap_output.h"
#include "signalbridge/io/http_stream_output.h"
#include "signalbridge/io/tcp_output.h"
#include "signalbridge/io/udp_output.h"
#include "signalbridge/io/pcap_io.h"
#include "signalbridge/io/tcp_io.h"
#include "signalbridge/metrics/metrics.h"
#include "signalbridge/metrics/metrics_server.h"
#include "signalbridge/pipeline/pipeline.h"
#include <chrono>
#include <csignal>
#include <ctime>
#include <iostream>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>

namespace {

static volatile sig_atomic_t g_stop_requested = 0;

void sigint_handler(int) {
    g_stop_requested = 1;
}

void run_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " run [options]\n"
              << "       " << prog << " run -i <input.pcap> [-o <output>]\n"
              << "       " << prog << " run -l <host:port> [-o <output>] [--loop]\n"
              << "       " << prog << " run --stdin [-o <output>]\n"
              << "       " << prog << " run -c <config.yaml>  # inputs/outputs from config\n"
              << "\n"
              << "Options:\n"
              << "  -i, --input <file>     Input PCAP/PCAPNG file\n"
              << "  -l, --listen <addr>   Listen on host:port for PCAP stream (e.g. 0.0.0.0:50051)\n"
              << "  -o, --output <dest>    Output: PCAP file path, tcp://host:port, udp://host:port, or http(s):// endpoint\n"
              << "  -c, --config <file>   Config YAML (inputs/outputs from config when omitted)\n"
              << "  -m, --metrics <addr>  Prometheus metrics address (default: 127.0.0.1:9090)\n"
              << "  --stdin               Read PCAP from stdin (e.g. tshark -r f -w - | ...)\n"
              << "  --loop                TCP: accept multiple connections, reload config between (hot-reload)\n"
              << "\n"
              << "Examples:\n"
              << "  " << prog << " run -i capture.pcap -o anonymised.pcap\n"
              << "  " << prog << " run -c config/conduit.yaml\n"
              << "  tshark -r capture.pcap -w - | " << prog << " run --stdin -o anonymised.pcap\n"
              << "  " << prog << " run -l 0.0.0.0:50051 -o out.pcap -c config.yaml --loop\n";
}

void validate_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " validate -c <config.yaml>\n"
              << "\n"
              << "Validates the config file and reports any errors.\n";
}

void main_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " <command> [options]\n"
              << "\n"
              << "Commands:\n"
              << "  run       Run the pipeline (default if no command given)\n"
              << "  validate  Validate config file\n"
              << "\n"
              << "Use " << prog << " run [--help] or " << prog << " validate [--help] for command-specific options.\n";
}

std::time_t get_file_mtime(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return 0;
    return st.st_mtime;
}

std::string resolve_output(const signalbridge::ConduitConfig& config, const std::string& cli_output) {
    if (!cli_output.empty()) return cli_output;
    for (const auto& out : config.outputs) {
        if (out.type == "file" && !out.path.empty()) return out.path;
        if (out.type == "tcp" && !out.address.empty()) return "tcp://" + out.address;
        if (out.type == "udp" && !out.address.empty()) return "udp://" + out.address;
        if (out.type == "http" || out.type == "https") {
            std::string url = !out.address.empty() ? out.address : out.path;
            if (!url.empty()) return url;
        }
    }
    return "";
}

std::string resolve_input_file(const signalbridge::ConduitConfig& config, const std::string& cli_input) {
    if (!cli_input.empty()) return cli_input;
    for (const auto& in : config.inputs) {
        if (in.type == "file" && !in.path.empty()) return in.path;
    }
    return "";
}

std::string resolve_listen_address(const signalbridge::ConduitConfig& config, const std::string& cli_listen) {
    if (!cli_listen.empty()) return cli_listen;
    for (const auto& in : config.inputs) {
        if ((in.type == "tcp" || in.type == "tcp_listen") && !in.address.empty()) return in.address;
    }
    return "";
}

bool resolve_stdin(const signalbridge::ConduitConfig& config, bool cli_stdin) {
    if (cli_stdin) return true;
    for (const auto& in : config.inputs) {
        if (in.type == "stdin") return true;
    }
    return false;
}

int cmd_validate(int argc, char* argv[], const char* prog) {
    std::string config_path;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) config_path = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            validate_usage(prog);
            return 0;
        }
    }

    if (config_path.empty()) {
        std::cerr << "Error: -c/--config required for validate\n";
        validate_usage(prog);
        return 1;
    }

    signalbridge::ConduitConfig config;
    if (!signalbridge::ConfigLoader::load(config_path, config)) {
        std::cerr << "Error: Invalid config file\n";
        return 1;
    }

    std::cout << "Config OK: " << config_path << "\n";
    return 0;
}

int cmd_run(int argc, char* argv[], const char* prog) {
    std::string input_path;
    std::string listen_address;
    std::string output_path;
    std::string config_path;
    std::string metrics_address;
    bool use_stdin = false;
    bool tcp_loop = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-i" || arg == "--input") {
            if (i + 1 < argc) input_path = argv[++i];
        } else if (arg == "-l" || arg == "--listen") {
            if (i + 1 < argc) listen_address = argv[++i];
        } else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) output_path = argv[++i];
        } else if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) config_path = argv[++i];
        } else if (arg == "-m" || arg == "--metrics") {
            if (i + 1 < argc) metrics_address = argv[++i];
        } else if (arg == "--stdin") {
            use_stdin = true;
        } else if (arg == "--loop") {
            tcp_loop = true;
        } else if (arg == "-h" || arg == "--help") {
            run_usage(prog);
            return 0;
        }
    }

    signalbridge::ConduitConfig config;
    if (!config_path.empty()) {
        if (!signalbridge::ConfigLoader::load(config_path, config)) {
            std::cerr << "Warning: Could not load config from " << config_path << ", using defaults\n";
        }
    }

    // Resolve input from config when CLI not specified
    input_path = resolve_input_file(config, input_path);
    listen_address = resolve_listen_address(config, listen_address);
    use_stdin = resolve_stdin(config, use_stdin);

    if (!use_stdin && input_path.empty() && listen_address.empty()) {
        std::cerr << "Error: -i/--input, -l/--listen, --stdin required, or specify inputs in config (-c)\n";
        run_usage(prog);
        return 1;
    }

    output_path = resolve_output(config, output_path);
    if (output_path.empty()) {
        std::cerr << "Error: -o/--output required, or specify outputs in config (-c)\n";
        run_usage(prog);
        return 1;
    }

    signalbridge::Pipeline pipeline(config);
    signalbridge::Metrics metrics;
    std::unique_ptr<signalbridge::MetricsServer> metrics_server;
    std::string metrics_addr = metrics_address.empty() ? "127.0.0.1:9090" : metrics_address;
    metrics_server = std::make_unique<signalbridge::MetricsServer>(metrics);
    if (!metrics_server->start(metrics_addr)) {
        std::cerr << "Warning: Could not start metrics server, continuing without metrics\n";
        metrics_server.reset();
    }

    int output_link_type = 1;
    if (!input_path.empty()) {
        output_link_type = signalbridge::PcapIo::get_link_type(input_path);
        if (output_link_type < 0) output_link_type = 1;
    }
    std::unique_ptr<signalbridge::HttpStreamOutput> http_output;
    std::unique_ptr<signalbridge::TcpOutput> tcp_output;
    std::unique_ptr<signalbridge::UdpOutput> udp_output;
    std::unique_ptr<signalbridge::AsyncPcapOutput> pcap_output;

    if (signalbridge::is_http_url(output_path)) {
        http_output = signalbridge::HttpStreamOutput::create(output_path, &metrics,
                                                             config.encryption_key);
        if (!http_output || !http_output->is_valid()) {
            std::cerr << "Error: Failed to create HTTP stream output for " << output_path << "\n";
            return 1;
        }
        metrics.set_output_queue_size_callback([&]() { return http_output->queue_size(); });
        pipeline.set_output_callback([&](const signalbridge::SignallingFrame& frame) {
            if (http_output->write(frame)) {
                metrics.messages_written_add(frame.procedures.size());
                metrics.bytes_out_add(frame.packet.size());
                for (const auto& proc : frame.procedures) {
                    metrics.messages_by_procedure_inc(proc.procedure_code, proc.procedure_name, proc.is_s1ap);
                }
            }
        });
    } else if (signalbridge::is_tcp_url(output_path)) {
        tcp_output = signalbridge::TcpOutput::create(output_path,
                                                     [&]() { return output_link_type; });
        if (!tcp_output || !tcp_output->is_valid()) {
            std::cerr << "Error: Failed to create TCP output for " << output_path << "\n";
            return 1;
        }
        pipeline.set_output_callback([&](const signalbridge::SignallingFrame& frame) {
            if (tcp_output->write(frame)) {
                metrics.messages_written_add(frame.procedures.size());
                metrics.bytes_out_add(frame.packet.size());
                for (const auto& proc : frame.procedures) {
                    metrics.messages_by_procedure_inc(proc.procedure_code, proc.procedure_name, proc.is_s1ap);
                }
            }
        });
    } else if (signalbridge::is_udp_url(output_path)) {
        udp_output = signalbridge::UdpOutput::create(output_path,
                                                     [&]() { return output_link_type; });
        if (!udp_output || !udp_output->is_valid()) {
            std::cerr << "Error: Failed to create UDP output for " << output_path << "\n";
            return 1;
        }
        pipeline.set_output_callback([&](const signalbridge::SignallingFrame& frame) {
            if (udp_output->write(frame)) {
                metrics.messages_written_add(frame.procedures.size());
                metrics.bytes_out_add(frame.packet.size());
                for (const auto& proc : frame.procedures) {
                    metrics.messages_by_procedure_inc(proc.procedure_code, proc.procedure_name, proc.is_s1ap);
                }
            }
        });
    } else {
        pcap_output = signalbridge::AsyncPcapOutput::create(
            output_path, [&]() { return output_link_type; });
        if (!pcap_output) {
            std::cerr << "Error: Failed to create output for " << output_path << "\n";
            return 1;
        }
        metrics.set_output_queue_size_callback([&]() { return pcap_output->queue_size(); });
        pipeline.set_output_callback([&](const signalbridge::SignallingFrame& frame) {
            if (pcap_output->write(frame)) {
                metrics.messages_written_add(frame.procedures.size());
                metrics.bytes_out_add(frame.packet.size());
                for (const auto& proc : frame.procedures) {
                    metrics.messages_by_procedure_inc(proc.procedure_code, proc.procedure_name, proc.is_s1ap);
                }
            }
        });
    }

    auto process_packet = [&](const uint8_t* data, size_t len, uint64_t ts_sec, uint32_t ts_usec, uint32_t frame_num) {
        metrics.packets_received_inc();
        metrics.bytes_in_add(len);
        auto result = pipeline.process_packet(data, len, ts_sec, ts_usec, frame_num);
        metrics.messages_filtered_add(result.messages_filtered);
        if (!result.protocol_stack_sctp.empty())
            metrics.packets_by_protocol_stack_inc(result.protocol_stack_sctp);
        if (!result.protocol_stack_s1ap.empty())
            metrics.packets_by_protocol_stack_inc(result.protocol_stack_s1ap);
        if (!result.protocol_stack_ngap.empty())
            metrics.packets_by_protocol_stack_inc(result.protocol_stack_ngap);
    };

    int count = 0;
    if (use_stdin) {
        auto process_packet_stdin = [&](int link_type, const uint8_t* data, size_t len, uint64_t ts_sec, uint32_t ts_usec, uint32_t frame_num) {
            output_link_type = link_type;
            process_packet(data, len, ts_sec, ts_usec, frame_num);
        };
        count = signalbridge::PcapIo::read_stdin(process_packet_stdin);
    } else if (!listen_address.empty()) {
        auto process_packet_tcp = [&](int link_type, const uint8_t* data, size_t len, uint64_t ts_sec, uint32_t ts_usec, uint32_t frame_num) {
            output_link_type = link_type;
            process_packet(data, len, ts_sec, ts_usec, frame_num);
        };

        if (tcp_loop) {
            signal(SIGINT, sigint_handler);
            if (!config_path.empty()) {
                std::time_t last_mtime = get_file_mtime(config_path);
                auto before_accept = [&]() {
                    if (g_stop_requested) return false;
                    std::time_t mtime = get_file_mtime(config_path);
                    if (mtime != last_mtime && mtime != 0) {
                        signalbridge::ConduitConfig new_config;
                        if (signalbridge::ConfigLoader::load(config_path, new_config)) {
                            config = new_config;
                            pipeline.set_config(config);
                            last_mtime = mtime;
                            std::cout << "Config reloaded from " << config_path << "\n";
                        }
                    }
                    return true;
                };
                count = signalbridge::TcpIo::listen_and_read_loop(listen_address, process_packet_tcp, before_accept);
            } else {
                auto before_accept = []() { return !g_stop_requested; };
                count = signalbridge::TcpIo::listen_and_read_loop(listen_address, process_packet_tcp, before_accept);
            }
        } else {
            count = signalbridge::TcpIo::listen_and_read_loop(listen_address, process_packet_tcp, nullptr);
        }
    } else {
        count = signalbridge::PcapIo::read_file(input_path, process_packet);
    }

    if (count < 0) {
        std::string source = !input_path.empty() ? input_path : (!listen_address.empty() ? "TCP " + listen_address : "stdin");
        std::cerr << "Error: Failed to read " << source << "\n";
        return 1;
    }

    pipeline.finish();
    if (http_output) http_output->finish();
    if (tcp_output) tcp_output->finish();
    if (pcap_output) pcap_output->finish();

    if (metrics_server) {
        std::cout << "Metrics available for 2s at http://" << metrics_addr << "/metrics\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
        metrics_server->stop();
    }

    std::cout << "Processed " << count << " packets, wrote " << metrics.messages_written() << " messages to " << output_path << "\n";
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    const char* prog = argv[0];
    std::string cmd = "run";

    if (argc >= 2 && argv[1][0] != '-') {
        cmd = argv[1];
        argc--;
        argv++;
    }

    if (cmd == "validate") {
        return cmd_validate(argc, argv, prog);
    }
    if (cmd == "run") {
        return cmd_run(argc, argv, prog);
    }
    if (cmd == "help" || cmd == "-h" || cmd == "--help") {
        main_usage(prog);
        return 0;
    }

    std::cerr << "Unknown command: " << cmd << "\n";
    main_usage(prog);
    return 1;
}
