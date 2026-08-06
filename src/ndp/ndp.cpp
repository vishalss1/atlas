#include "atlas/ndp/ndp.hpp"

namespace atlas::ndp {

void NdpCache::put(packet::Ipv6Addr ip, packet::MacAddr mac, std::chrono::seconds ttl) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto actual_ttl = (ttl.count() > 0) ? ttl : default_ttl_;
    cache_[ip] = NdpEntry{
        .mac = mac,
        .expires_at = std::chrono::steady_clock::now() + actual_ttl,
        .resolved = true
    };
}

std::optional<NdpEntry> NdpCache::get(packet::Ipv6Addr ip) const {
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

void NdpCache::remove(packet::Ipv6Addr ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.erase(ip);
}

void NdpCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    cache_.clear();
}

void NdpCache::sweep_expired(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = cache_.begin(); it != cache_.end(); ) {
        if (now > it->second.expires_at) {
            it = cache_.erase(it);
        } else {
            ++it;
        }
    }
}

std::size_t NdpCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cache_.size();
}

} // namespace atlas::ndp
