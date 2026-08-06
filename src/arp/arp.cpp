#include "atlas/arp/arp.hpp"
#include "atlas/ethernet/ethernet.hpp"
#include "atlas/interfaces/interface.hpp"
#include <cstring>
#include <winsock2.h>

namespace atlas::arp {

packet::Result<ArpHeader> parse_arp(std::span<const std::byte> payload) {
    if (payload.size() < sizeof(ArpHeader)) {
        return std::string("ARP payload too short");
    }

    ArpHeader hdr{};
    const auto* raw = reinterpret_cast<const std::uint8_t*>(payload.data());

    std::uint16_t raw_htype = (static_cast<std::uint16_t>(raw[0]) << 8) | raw[1];
    std::uint16_t raw_ptype = (static_cast<std::uint16_t>(raw[2]) << 8) | raw[3];
    hdr.htype = raw_htype;
    hdr.ptype = raw_ptype;
    hdr.hlen  = raw[4];
    hdr.plen  = raw[5];
    hdr.opcode = (static_cast<std::uint16_t>(raw[6]) << 8) | raw[7];

    std::memcpy(hdr.sender_mac.bytes.data(), raw + 8, 6);
    std::uint32_t s_ip = (static_cast<std::uint32_t>(raw[14]) << 24) |
                         (static_cast<std::uint32_t>(raw[15]) << 16) |
                         (static_cast<std::uint32_t>(raw[16]) << 8)  |
                         raw[17];
    hdr.sender_ip = packet::Ipv4Addr{s_ip};

    std::memcpy(hdr.target_mac.bytes.data(), raw + 18, 6);
    std::uint32_t t_ip = (static_cast<std::uint32_t>(raw[24]) << 24) |
                         (static_cast<std::uint32_t>(raw[25]) << 16) |
                         (static_cast<std::uint32_t>(raw[26]) << 8)  |
                         raw[27];
    hdr.target_ip = packet::Ipv4Addr{t_ip};

    if (hdr.htype != 1 || hdr.ptype != 0x0800 || hdr.hlen != 6 || hdr.plen != 4) {
        return std::string("Unsupported ARP format (requires Ethernet/IPv4)");
    }

    return hdr;
}

static std::vector<std::byte> build_arp_payload(
    std::uint16_t opcode,
    packet::MacAddr sender_mac,
    packet::Ipv4Addr sender_ip,
    packet::MacAddr target_mac,
    packet::Ipv4Addr target_ip
) {
    std::vector<std::byte> payload(28);
    auto* raw = reinterpret_cast<std::uint8_t*>(payload.data());

    raw[0] = 0x00; raw[1] = 0x01; // Hardware: Ethernet
    raw[2] = 0x08; raw[3] = 0x00; // Protocol: IPv4
    raw[4] = 6;    raw[5] = 4;    // Lengths

    raw[6] = static_cast<std::uint8_t>((opcode >> 8) & 0xFF);
    raw[7] = static_cast<std::uint8_t>(opcode & 0xFF);

    std::memcpy(raw + 8, sender_mac.bytes.data(), 6);
    raw[14] = static_cast<std::uint8_t>((sender_ip.value >> 24) & 0xFF);
    raw[15] = static_cast<std::uint8_t>((sender_ip.value >> 16) & 0xFF);
    raw[16] = static_cast<std::uint8_t>((sender_ip.value >> 8) & 0xFF);
    raw[17] = static_cast<std::uint8_t>(sender_ip.value & 0xFF);

    std::memcpy(raw + 18, target_mac.bytes.data(), 6);
    raw[24] = static_cast<std::uint8_t>((target_ip.value >> 24) & 0xFF);
    raw[25] = static_cast<std::uint8_t>((target_ip.value >> 16) & 0xFF);
    raw[26] = static_cast<std::uint8_t>((target_ip.value >> 8) & 0xFF);
    raw[27] = static_cast<std::uint8_t>(target_ip.value & 0xFF);

    return payload;
}

std::vector<std::byte> build_arp_request(
    packet::MacAddr sender_mac,
    packet::Ipv4Addr sender_ip,
    packet::Ipv4Addr target_ip
) {
    packet::MacAddr bcast_mac{std::array<std::byte, 6>{
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}
    }};
    packet::MacAddr zero_mac{};

    auto payload = build_arp_payload(1, sender_mac, sender_ip, zero_mac, target_ip);
    return ethernet::build(sender_mac, bcast_mac, 0x0806, payload);
}

std::vector<std::byte> build_arp_reply(
    packet::MacAddr sender_mac,
    packet::Ipv4Addr sender_ip,
    packet::MacAddr target_mac,
    packet::Ipv4Addr target_ip
) {
    auto payload = build_arp_payload(2, sender_mac, sender_ip, target_mac, target_ip);
    return ethernet::build(sender_mac, target_mac, 0x0806, payload);
}

std::vector<std::byte> build_gratuitous_arp(
    packet::MacAddr sender_mac,
    packet::Ipv4Addr sender_ip
) {
    packet::MacAddr bcast_mac{std::array<std::byte, 6>{
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}
    }};

    auto payload = build_arp_payload(2, sender_mac, sender_ip, bcast_mac, sender_ip);
    return ethernet::build(sender_mac, bcast_mac, 0x0806, payload);
}

packet::Result<packet::MacAddr> ArpEngine::resolve(packet::Ipv4Addr target_ip, const packet::Packet& pkt) {
    auto entry = cache_.get(target_ip);
    if (entry.has_value() && entry->state == EntryState::Resolved) {
        return entry->mac;
    }

    // Pending or missing entry -> Queue packet
    std::lock_guard<std::mutex> lock(queue_mutex_);
    auto& queue = pending_queue_[target_ip];
    if (queue.size() < kMaxQueuePerIp) {
        queue.push_back(pkt);
    }
    if (!entry.has_value()) {
        cache_.put_pending(target_ip);
    }

    return std::string("Pending ARP resolution for ") + target_ip.to_string();
}

std::vector<packet::Packet> ArpEngine::process_arp_packet(
    const ArpHeader& arp,
    interfaces::Interface& ingress_iface
) {
    std::vector<packet::Packet> flushed_packets;

    // Update ARP cache with sender details
    cache_.put_resolved(arp.sender_ip, arp.sender_mac);

    // Flush any pending queued packets for sender_ip
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        auto it = pending_queue_.find(arp.sender_ip);
        if (it != pending_queue_.end()) {
            flushed_packets = std::move(it->second);
            pending_queue_.erase(it);
        }
    }

    // Handle ARP Request for local interface IP
    if (arp.opcode == 1 && arp.target_ip == ingress_iface.ip_prefix().addr) {
        auto reply_frame = build_arp_reply(
            ingress_iface.mac_address(),
            ingress_iface.ip_prefix().addr,
            arp.sender_mac,
            arp.sender_ip
        );
        ingress_iface.write(reply_frame);
    }

    return flushed_packets;
}

std::size_t ArpEngine::pending_queue_size(packet::Ipv4Addr ip) const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    auto it = pending_queue_.find(ip);
    if (it != pending_queue_.end()) {
        return it->second.size();
    }
    return 0;
}

} // namespace atlas::arp
