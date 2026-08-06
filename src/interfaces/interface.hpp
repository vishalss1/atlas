#pragma once

#include <string>
#include <vector>
#include <span>
#include <optional>
#include <queue>
#include <mutex>
#include "packet/address.hpp"

namespace atlas::interfaces {

class Interface {
public:
    virtual ~Interface() = default;

    [[nodiscard]] virtual std::string name() const = 0;
    [[nodiscard]] virtual packet::MacAddr mac_address() const = 0;
    [[nodiscard]] virtual packet::Ipv4Prefix ip_prefix() const = 0;
    [[nodiscard]] virtual bool is_nat_outside() const = 0;

    virtual std::vector<std::byte> read() = 0;
    virtual std::optional<std::vector<std::byte>> try_read() = 0;
    virtual bool write(std::span<const std::byte> frame) = 0;
};

// FakeInterface for unit tests and offline testing
class FakeInterface : public Interface {
    std::string name_;
    packet::MacAddr mac_;
    packet::Ipv4Prefix ip_;
    bool nat_outside_{false};

    std::queue<std::vector<std::byte>> rx_queue_;
    std::vector<std::vector<std::byte>> tx_history_;
    std::mutex mutex_;

public:
    FakeInterface(std::string name, packet::MacAddr mac, packet::Ipv4Prefix ip, bool nat_outside = false)
        : name_(std::move(name)), mac_(mac), ip_(ip), nat_outside_(nat_outside) {}

    [[nodiscard]] std::string name() const override { return name_; }
    [[nodiscard]] packet::MacAddr mac_address() const override { return mac_; }
    [[nodiscard]] packet::Ipv4Prefix ip_prefix() const override { return ip_; }
    [[nodiscard]] bool is_nat_outside() const override { return nat_outside_; }

    void inject_rx(std::vector<std::byte> frame);
    std::vector<std::vector<std::byte>> get_tx_history();

    std::vector<std::byte> read() override;
    std::optional<std::vector<std::byte>> try_read() override;
    bool write(std::span<const std::byte> frame) override;
};

} // namespace atlas::interfaces
