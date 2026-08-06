#include "atlas/nat/nat.hpp"
#include "atlas/ipv4/ipv4.hpp"
#include <cstring>
#include <spdlog/spdlog.h>

namespace atlas::nat {

std::uint16_t compute_l4_checksum(
    packet::Ipv4Addr src_ip,
    packet::Ipv4Addr dst_ip,
    std::uint8_t protocol,
    std::span<std::byte> l4_payload
) {
    std::uint32_t sum = 0;

    // Pseudo-header: Src IP (4 bytes), Dst IP (4 bytes), Reserved(1 byte) + Protocol(1 byte), L4 Length (2 bytes)
    sum += (src_ip.value >> 16) & 0xFFFF;
    sum += src_ip.value & 0xFFFF;
    sum += (dst_ip.value >> 16) & 0xFFFF;
    sum += dst_ip.value & 0xFFFF;
    sum += static_cast<std::uint16_t>(protocol);
    sum += static_cast<std::uint16_t>(l4_payload.size());

    // L4 Payload (with checksum field zeroed before computing)
    const auto* ptr = reinterpret_cast<const std::uint8_t*>(l4_payload.data());
    std::size_t len = l4_payload.size();

    for (std::size_t i = 0; i < len - 1; i += 2) {
        std::uint16_t word = (static_cast<std::uint16_t>(ptr[i]) << 8) | ptr[i + 1];
        sum += word;
    }

    if (len % 2 != 0) {
        std::uint16_t word = static_cast<std::uint16_t>(ptr[len - 1]) << 8;
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    auto checksum = static_cast<std::uint16_t>(~sum);
    return (checksum == 0) ? 0xFFFF : checksum;
}

std::uint16_t NatEngine::allocate_port(std::uint8_t proto, std::uint16_t preferred_port) {
    std::uint32_t packed_pref = (static_cast<std::uint32_t>(proto) << 16) | preferred_port;
    if (preferred_port >= port_start_ && preferred_port <= port_end_) {
        if (allocated_ports_.find(packed_pref) == allocated_ports_.end()) {
            allocated_ports_.insert(packed_pref);
            return preferred_port;
        }
    }

    // Scan for available port in range
    std::uint16_t range_size = port_end_ - port_start_ + 1;
    for (std::uint16_t i = 0; i < range_size; ++i) {
        std::uint16_t port = port_start_ + ((next_port_cursor_ - port_start_ + i) % range_size);
        std::uint32_t packed = (static_cast<std::uint32_t>(proto) << 16) | port;
        if (allocated_ports_.find(packed) == allocated_ports_.end()) {
            allocated_ports_.insert(packed);
            next_port_cursor_ = port_start_ + ((port - port_start_ + 1) % range_size);
            return port;
        }
    }

    return 0; // Pool exhausted
}

void NatEngine::free_port(std::uint8_t proto, std::uint16_t port) {
    std::uint32_t packed = (static_cast<std::uint32_t>(proto) << 16) | port;
    allocated_ports_.erase(packed);
}

bool NatEngine::translate_outbound(packet::Packet& pkt, packet::Ipv4Addr public_outside_ip) {
    if (!enabled_ || !pkt.ipv4.has_value()) {
        return false;
    }

    std::uint8_t proto = pkt.ipv4->protocol;
    if (proto != 6 && proto != 17) {
        return false; // SNAT only handles TCP (6) and UDP (17)
    }

    if (!pkt.l4.has_value()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    NatSessionKey out_key{
        .inside_ip = pkt.ipv4->src_addr,
        .inside_port = pkt.l4->src_port,
        .proto = proto
    };

    auto it = outbound_map_.find(out_key);
    Session session;

    if (it != outbound_map_.end()) {
        session = it->second;
        session.last_seen = now;
        outbound_map_[out_key] = session;

        NatInboundKey in_key{
            .outside_ip = session.outside_ip,
            .outside_port = session.outside_port,
            .proto = proto
        };
        inbound_map_[in_key] = session;
    } else {
        std::uint16_t out_port = allocate_port(proto, pkt.l4->src_port);
        if (out_port == 0) {
            spdlog::warn("[nat] Dynamic port pool exhausted for proto {}", proto);
            return false;
        }

        session = Session{
            .inside_ip = pkt.ipv4->src_addr,
            .inside_port = pkt.l4->src_port,
            .outside_ip = public_outside_ip,
            .outside_port = out_port,
            .proto = proto,
            .last_seen = now
        };

        outbound_map_[out_key] = session;
        NatInboundKey in_key{
            .outside_ip = public_outside_ip,
            .outside_port = out_port,
            .proto = proto
        };
        inbound_map_[in_key] = session;

        spdlog::info("[nat] Created outbound NAPT session: {}:{} -> {}:{}",
            session.inside_ip.to_string(), session.inside_port,
            session.outside_ip.to_string(), session.outside_port);
    }

    // Rewrite Packet Headers
    pkt.ipv4->src_addr = session.outside_ip;
    pkt.l4->src_port = session.outside_port;

    // Recompute IPv4 Header Checksum
    ipv4::recompute_checksum(*pkt.ipv4);

    // Rewrite L4 Payload & Checksum if payload exists
    if (!pkt.payload.empty()) {
        auto* raw_l4 = const_cast<std::byte*>(pkt.payload.data());
        auto* raw_u8 = reinterpret_cast<std::uint8_t*>(raw_l4);

        // Rewrite Src Port bytes in L4 header
        raw_u8[0] = static_cast<std::uint8_t>((session.outside_port >> 8) & 0xFF);
        raw_u8[1] = static_cast<std::uint8_t>(session.outside_port & 0xFF);

        // Zero L4 checksum field before computing
        std::size_t cksum_offset = (proto == 6) ? 16 : 6;
        if (pkt.payload.size() >= cksum_offset + 2) {
            raw_u8[cksum_offset] = 0;
            raw_u8[cksum_offset + 1] = 0;

            std::span<std::byte> l4_span(raw_l4, pkt.payload.size());
            std::uint16_t new_l4_cksum = compute_l4_checksum(
                pkt.ipv4->src_addr,
                pkt.ipv4->dst_addr,
                proto,
                l4_span
            );

            raw_u8[cksum_offset] = static_cast<std::uint8_t>((new_l4_cksum >> 8) & 0xFF);
            raw_u8[cksum_offset + 1] = static_cast<std::uint8_t>(new_l4_cksum & 0xFF);
        }
    }

    return true;
}

bool NatEngine::translate_inbound(packet::Packet& pkt) {
    if (!enabled_ || !pkt.ipv4.has_value() || !pkt.l4.has_value()) {
        return false;
    }

    std::uint8_t proto = pkt.ipv4->protocol;
    if (proto != 6 && proto != 17) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    NatInboundKey in_key{
        .outside_ip = pkt.ipv4->dst_addr,
        .outside_port = pkt.l4->dst_port,
        .proto = proto
    };

    auto it = inbound_map_.find(in_key);
    if (it == inbound_map_.end()) {
        return false; // No conntrack session found for return packet
    }

    auto session = it->second;
    session.last_seen = std::chrono::steady_clock::now();
    inbound_map_[in_key] = session;

    // Rewrite Packet Headers (Destination -> Inside IP & Port)
    pkt.ipv4->dst_addr = session.inside_ip;
    pkt.l4->dst_port = session.inside_port;

    // Recompute IPv4 Header Checksum
    ipv4::recompute_checksum(*pkt.ipv4);

    // Rewrite L4 Payload & Checksum if payload exists
    if (!pkt.payload.empty()) {
        auto* raw_l4 = const_cast<std::byte*>(pkt.payload.data());
        auto* raw_u8 = reinterpret_cast<std::uint8_t*>(raw_l4);

        // Rewrite Dst Port bytes in L4 header
        raw_u8[2] = static_cast<std::uint8_t>((session.inside_port >> 8) & 0xFF);
        raw_u8[3] = static_cast<std::uint8_t>(session.inside_port & 0xFF);

        std::size_t cksum_offset = (proto == 6) ? 16 : 6;
        if (pkt.payload.size() >= cksum_offset + 2) {
            raw_u8[cksum_offset] = 0;
            raw_u8[cksum_offset + 1] = 0;

            std::span<std::byte> l4_span(raw_l4, pkt.payload.size());
            std::uint16_t new_l4_cksum = compute_l4_checksum(
                pkt.ipv4->src_addr,
                pkt.ipv4->dst_addr,
                proto,
                l4_span
            );

            raw_u8[cksum_offset] = static_cast<std::uint8_t>((new_l4_cksum >> 8) & 0xFF);
            raw_u8[cksum_offset + 1] = static_cast<std::uint8_t>(new_l4_cksum & 0xFF);
        }
    }

    return true;
}

void NatEngine::sweep_expired(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = outbound_map_.begin(); it != outbound_map_.end();) {
        auto timeout = (it->second.proto == 6) ? tcp_timeout_ : udp_timeout_;
        if (now - it->second.last_seen > timeout) {
            NatInboundKey in_key{
                .outside_ip = it->second.outside_ip,
                .outside_port = it->second.outside_port,
                .proto = it->second.proto
            };
            free_port(it->second.proto, it->second.outside_port);
            inbound_map_.erase(in_key);
            it = outbound_map_.erase(it);
        } else {
            ++it;
        }
    }
}

void NatEngine::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    outbound_map_.clear();
    inbound_map_.clear();
    allocated_ports_.clear();
}

std::size_t NatEngine::session_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return outbound_map_.size();
}

} // namespace atlas::nat
