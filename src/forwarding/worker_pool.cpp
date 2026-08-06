#include "atlas/forwarding/worker_pool.hpp"

namespace atlas::forwarding {

WorkerPool::WorkerPool(std::size_t thread_count)
    : worker_count_(thread_count == 0 ? 1 : thread_count) {
    for (std::size_t i = 0; i < worker_count_; ++i) {
        workers_.emplace_back(&WorkerPool::worker_loop, this);
    }
}

WorkerPool::~WorkerPool() {
    stop();
}

void WorkerPool::enqueue(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        task_queue_.push(std::move(task));
    }
    cv_.notify_one();
}

void WorkerPool::stop() {
    if (stopping_.exchange(true)) {
        return;
    }
    cv_.notify_all();
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void WorkerPool::worker_loop() {
    while (true) {
        std::function<void()> task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] {
                return stopping_ || !task_queue_.empty();
            });

            if (task_queue_.empty()) {
                if (stopping_) {
                    return;
                }
                continue;
            }

            task = std::move(task_queue_.front());
            task_queue_.pop();
        }
        if (task) {
            task();
        }
    }
}

} // namespace atlas::forwarding
