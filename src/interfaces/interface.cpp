#include "atlas/interfaces/interface.hpp"

namespace atlas::interfaces {

void FakeInterface::inject_rx(std::vector<std::byte> frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    rx_queue_.push(std::move(frame));
}

std::vector<std::vector<std::byte>> FakeInterface::get_tx_history() {
    std::lock_guard<std::mutex> lock(mutex_);
    return tx_history_;
}

std::vector<std::byte> FakeInterface::read() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (rx_queue_.empty()) return {};
    auto frame = rx_queue_.front();
    rx_queue_.pop();
    return frame;
}

std::optional<std::vector<std::byte>> FakeInterface::try_read() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (rx_queue_.empty()) return std::nullopt;
    auto frame = rx_queue_.front();
    rx_queue_.pop();
    return frame;
}

bool FakeInterface::write(std::span<const std::byte> frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    tx_history_.emplace_back(frame.begin(), frame.end());
    return true;
}

} // namespace atlas::interfaces
