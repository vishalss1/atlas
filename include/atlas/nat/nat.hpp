#pragma once

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <chrono>
#include <optional>
#include <span>
#include "atlas/packet/address.hpp"
#include "atlas/packet/packet.hpp"

namespace atlas::nat {

struct NatSessionKey {
    packet::Ipv4Addr inside_ip{};
    std::uint16_t inside_port{0};
    std::uint8_t proto{0};

    bool operator==(const NatSessionKey& other) const noexcept {
        return inside_ip == other.inside_ip &&
               inside_port == other.inside_port &&
               proto == other.proto;
    }
};

struct NatInboundKey {
    packet::Ipv4Addr outside_ip{};
    std::uint16_t outside_port{0};
    std::uint8_t proto{0};

    bool operator==(const NatInboundKey& other) const noexcept {
        return outside_ip == other.outside_ip &&
               outside_port == other.outside_port &&
               proto == other.proto;
    }
};

struct Session {
    packet::Ipv4Addr inside_ip{};
    std::uint16_t inside_port{0};
    packet::Ipv4Addr outside_ip{};
    std::uint16_t outside_port{0};
    std::uint8_t proto{0};
    std::chrono::steady_clock::time_point last_seen{};
};

// Recomputes L4 (TCP/UDP) checksum over pseudo-header and L4 payload
std::uint16_t compute_l4_checksum(
    packet::Ipv4Addr src_ip,
    packet::Ipv4Addr dst_ip,
    std::uint8_t protocol,
    std::span<std::byte> l4_payload
);

} // namespace atlas::nat

namespace std {
template <>
struct hash<atlas::nat::NatSessionKey> {
    std::size_t operator()(const atlas::nat::NatSessionKey& k) const noexcept {
        std::size_t h1 = std::hash<atlas::packet::Ipv4Addr>{}(k.inside_ip);
        std::size_t h2 = std::hash<std::uint16_t>{}(k.inside_port);
        std::size_t h3 = std::hash<std::uint8_t>{}(k.proto);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};

template <>
struct hash<atlas::nat::NatInboundKey> {
    std::size_t operator()(const atlas::nat::NatInboundKey& k) const noexcept {
        std::size_t h1 = std::hash<atlas::packet::Ipv4Addr>{}(k.outside_ip);
        std::size_t h2 = std::hash<std::uint16_t>{}(k.outside_port);
        std::size_t h3 = std::hash<std::uint8_t>{}(k.proto);
        return h1 ^ (h2 << 1) ^ (h3 << 2);
    }
};
} // namespace std

namespace atlas::nat {

class NatEngine {
public:
    explicit NatEngine(
        bool enabled = true,
        std::uint16_t port_start = 1024,
        std::uint16_t port_end = 65535,
        std::chrono::seconds tcp_timeout = std::chrono::seconds(300),
        std::chrono::seconds udp_timeout = std::chrono::seconds(60)
    ) : enabled_(enabled),
        port_start_(port_start),
        port_end_(port_end),
        tcp_timeout_(tcp_timeout),
        udp_timeout_(udp_timeout),
        next_port_cursor_(port_start) {}

    void set_enabled(bool enabled) noexcept { enabled_ = enabled; }
    [[nodiscard]] bool is_enabled() const noexcept { return enabled_; }

    // Translates outbound packet leaving a public interface (rewrites src IP & port, recomputes IPv4 & L4 checksums)
    bool translate_outbound(packet::Packet& pkt, packet::Ipv4Addr public_outside_ip);

    // Translates inbound return packet arriving on a public interface (rewrites dst IP & port, recomputes IPv4 & L4 checksums)
    bool translate_inbound(packet::Packet& pkt);

    void sweep_expired(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    void clear();

    [[nodiscard]] std::size_t session_count() const;

private:
    bool enabled_{true};
    std::uint16_t port_start_{1024};
    std::uint16_t port_end_{65535};
    std::chrono::seconds tcp_timeout_{300};
    std::chrono::seconds udp_timeout_{60};
    std::uint16_t next_port_cursor_{1024};

    mutable std::mutex mutex_;
    std::unordered_map<NatSessionKey, Session> outbound_map_;
    std::unordered_map<NatInboundKey, Session> inbound_map_;
    std::unordered_set<std::uint32_t> allocated_ports_; // Packed (proto << 16) | port

    std::uint16_t allocate_port(std::uint8_t proto, std::uint16_t preferred_port);
    void free_port(std::uint8_t proto, std::uint16_t port);
};

} // namespace atlas::nat
