#pragma once

#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>
#include "atlas/packet/address_v6.hpp"
#include "atlas/packet/address.hpp"

namespace atlas::ndp {

struct NdpEntry {
    packet::MacAddr mac{};
    std::chrono::steady_clock::time_point expires_at{};
    bool resolved{true};
};

class NdpCache {
public:
    explicit NdpCache(std::chrono::seconds ttl = std::chrono::seconds(300))
        : default_ttl_(ttl) {}

    void put(packet::Ipv6Addr ip, packet::MacAddr mac, std::chrono::seconds ttl = std::chrono::seconds(0));
    [[nodiscard]] std::optional<NdpEntry> get(packet::Ipv6Addr ip) const;
    void remove(packet::Ipv6Addr ip);
    void clear();
    void sweep_expired(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    [[nodiscard]] std::size_t size() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<packet::Ipv6Addr, NdpEntry> cache_;
    std::chrono::seconds default_ttl_;
};

} // namespace atlas::ndp
