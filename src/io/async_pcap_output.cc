/*
 * SignalBridge - S1AP/NGAP signalling anonymisation and forwarding
 * Copyright (c) 2026 Melrose Networks (Melrose Labs Ltd)
 */

#include "signalbridge/io/async_pcap_output.h"
#include "signalbridge/io/pcap_io.h"
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <queue>
#include <thread>

namespace signalbridge {

struct AsyncPcapOutput::Impl {
    std::queue<SignallingFrame> queue;
    mutable std::mutex mutex;
    std::condition_variable cv;
    bool done{false};
    std::thread worker;
};

std::unique_ptr<AsyncPcapOutput> AsyncPcapOutput::create(const std::string& path,
                                                         std::function<int()> link_type_getter) {
    auto out = std::unique_ptr<AsyncPcapOutput>(new AsyncPcapOutput(path, std::move(link_type_getter)));
    return out;
}

AsyncPcapOutput::AsyncPcapOutput(const std::string& path, std::function<int()> link_type_getter)
    : path_(path), link_type_getter_(std::move(link_type_getter)), impl_(std::make_unique<Impl>()) {}

AsyncPcapOutput::~AsyncPcapOutput() {
    finish();
}

bool AsyncPcapOutput::write(const SignallingFrame& frame) {
    if (!impl_) return false;

    if (!impl_->worker.joinable()) {
        impl_->worker = std::thread([this]() {
            PcapWriter writer(path_);
            for (;;) {
                SignallingFrame frame;
                {
                    std::unique_lock<std::mutex> lock(impl_->mutex);
                    impl_->cv.wait(lock, [this]() {
                        return impl_->done || !impl_->queue.empty();
                    });
                    if (impl_->queue.empty()) {
                        if (impl_->done) break;
                        continue;
                    }
                    frame = std::move(impl_->queue.front());
                    impl_->queue.pop();
                }
                int lt = link_type_getter_ ? link_type_getter_() : 1;
                if (!writer.is_open() && !writer.open(lt)) {
                    std::cerr << "Error: Failed to open output file " << path_ << ", frame dropped\n";
                    continue;
                }
                writer.write_frame(frame);
            }
            writer.close();
        });
    }

    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->queue.push(frame);
    }
    impl_->cv.notify_one();
    return true;
}

size_t AsyncPcapOutput::queue_size() const {
    if (!impl_) return 0;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->queue.size();
}

void AsyncPcapOutput::finish() {
    if (!impl_) return;

    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        impl_->done = true;
    }
    impl_->cv.notify_one();
    if (impl_->worker.joinable()) impl_->worker.join();
}

}  // namespace signalbridge
