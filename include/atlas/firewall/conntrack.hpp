#pragma once

#include <cstdint>
#include <array>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>
#include <string>
#include "atlas/packet/address.hpp"
#include "atlas/packet/packet.hpp"

namespace atlas::firewall {

enum class ConnState : std::uint8_t {
    New,
    Established,
    Related,
    Invalid
};

enum class TcpState : std::uint8_t {
    SynSent,
    SynRecv,
    Established,
    FinWait,
    Closed
};

struct FiveTuple {
    packet::Ipv4Addr src_ip;
    packet::Ipv4Addr dst_ip;
    std::uint16_t    src_port{0};
    std::uint16_t    dst_port{0};
    std::uint8_t     protocol{0};

    bool operator==(const FiveTuple& other) const noexcept {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port &&
               protocol == other.protocol;
    }
};

} // namespace atlas::firewall

namespace std {
template <>
struct hash<atlas::firewall::FiveTuple> {
    std::size_t operator()(const atlas::firewall::FiveTuple& key) const noexcept {
        std::size_t h1 = std::hash<atlas::packet::Ipv4Addr>{}(key.src_ip);
        std::size_t h2 = std::hash<atlas::packet::Ipv4Addr>{}(key.dst_ip);
        std::size_t h3 = std::hash<std::uint16_t>{}(key.src_port);
        std::size_t h4 = std::hash<std::uint16_t>{}(key.dst_port);
        std::size_t h5 = std::hash<std::uint8_t>{}(key.protocol);
        return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
    }
};
} // namespace std

namespace atlas::firewall {

struct ConnEntry {
    FiveTuple orig_tuple;
    FiveTuple reply_tuple;
    TcpState  tcp_state{TcpState::SynSent};
    std::chrono::steady_clock::time_point last_seen;
};

class ConntrackTable {
public:
    explicit ConntrackTable(std::chrono::seconds timeout = std::chrono::seconds(120))
        : timeout_(timeout) {}

    // Track a packet, updating connection state or creating new flow entry
    ConnState track_packet(const packet::Packet& pkt);

    // Sweep expired connections
    void sweep_expired(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    [[nodiscard]] std::size_t size() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<FiveTuple, ConnEntry> flows_;
    std::chrono::seconds timeout_;
};

} // namespace atlas::firewall
