#include <gtest/gtest.h>
#include "atlas/forwarding/worker_pool.hpp"
#include <atomic>

using namespace atlas::forwarding;

TEST(WorkerPoolTest, ConcurrentTaskExecution) {
    WorkerPool pool(4);
    EXPECT_EQ(pool.active_workers(), 4);

    std::atomic<int> counter{0};
    for (int i = 0; i < 100; ++i) {
        pool.enqueue([&counter]() {
            counter.fetch_add(1);
        });
    }

    pool.stop();
    EXPECT_EQ(counter.load(), 100);
}
