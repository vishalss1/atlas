#include "atlas/arp/cache.hpp"

namespace atlas::arp {

void ArpCache::put_resolved(packet::Ipv4Addr ip, packet::MacAddr mac, std::chrono::seconds ttl) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto duration = (ttl.count() > 0) ? ttl : default_ttl_;
    cache_[ip] = ArpEntry{
        .mac = mac,
        .expires_at = std::chrono::steady_clock::now() + duration,
        .state = EntryState::Resolved
    };
}

void ArpCache::put_pending(packet::Ipv4Addr ip, std::chrono::seconds pending_ttl) {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_[ip] = ArpEntry{
        .mac = packet::MacAddr{},
        .expires_at = std::chrono::steady_clock::now() + pending_ttl,
        .state = EntryState::Pending
    };
}

std::optional<ArpEntry> ArpCache::get(packet::Ipv4Addr ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = cache_.find(ip);
    if (it == cache_.end()) {
        return std::nullopt;
    }
    if (std::chrono::steady_clock::now() > it->second.expires_at) {
        return std::nullopt;
    }
    return it->second;
}

void ArpCache::remove(packet::Ipv4Addr ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.erase(ip);
}

void ArpCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

void ArpCache::sweep_expired(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = cache_.begin(); it != cache_.end();) {
        if (now > it->second.expires_at) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

std::size_t ArpCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

} // namespace atlas::arp
