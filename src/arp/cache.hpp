#pragma once

#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>
#include "packet/address.hpp"

namespace atlas::arp {

enum class EntryState : std::uint8_t {
    Pending,
    Resolved
};

struct ArpEntry {
    packet::MacAddr mac{};
    std::chrono::steady_clock::time_point expires_at{};
    EntryState state{EntryState::Pending};
};

class ArpCache {
public:
    explicit ArpCache(std::chrono::seconds ttl = std::chrono::seconds(300))
        : default_ttl_(ttl) {}

    void put_resolved(packet::Ipv4Addr ip, packet::MacAddr mac, std::chrono::seconds ttl = std::chrono::seconds(0));
    void put_pending(packet::Ipv4Addr ip, std::chrono::seconds pending_ttl = std::chrono::seconds(3));

    [[nodiscard]] std::optional<ArpEntry> get(packet::Ipv4Addr ip) const;
    void remove(packet::Ipv4Addr ip);
    void clear();
    void sweep_expired(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    [[nodiscard]] std::size_t size() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<packet::Ipv4Addr, ArpEntry> cache_;
    std::chrono::seconds default_ttl_;
};

} // namespace atlas::arp
