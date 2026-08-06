#pragma once

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>
#include "atlas/packet/packet.hpp"

namespace atlas::forwarding {

class WorkerPool {
public:
    explicit WorkerPool(std::size_t thread_count = std::thread::hardware_concurrency());
    ~WorkerPool();

    // Enqueue packet processing task
    void enqueue(std::function<void()> task);

    // Stop worker threads
    void stop();

    [[nodiscard]] std::size_t active_workers() const { return worker_count_; }

private:
    void worker_loop();

    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> task_queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stopping_{false};
    std::size_t worker_count_{0};
};

} // namespace atlas::forwarding
