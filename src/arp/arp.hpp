#pragma once

#include <cstdint>
#include <vector>
#include <span>
#include <unordered_map>
#include <mutex>
#include "packet/address.hpp"
#include "packet/packet.hpp"
#include "packet/result.hpp"
#include "arp/cache.hpp"

namespace atlas::interfaces {
class Interface;
}

namespace atlas::arp {

#pragma pack(push, 1)
struct ArpHeader {
    std::uint16_t htype{1};      // 1 = Ethernet (Host byte order)
    std::uint16_t ptype{0x0800}; // 0x0800 = IPv4 (Host byte order)
    std::uint8_t  hlen{6};       // Hardware size = 6
    std::uint8_t  plen{4};       // Protocol size = 4
    std::uint16_t opcode{1};     // 1 = Request, 2 = Reply (Host byte order)
    packet::MacAddr  sender_mac{};
    packet::Ipv4Addr sender_ip{};
    packet::MacAddr  target_mac{};
    packet::Ipv4Addr target_ip{};
};
#pragma pack(pop)

// Parse raw payload into ArpHeader
packet::Result<ArpHeader> parse_arp(std::span<const std::byte> payload);

// Build raw ARP Ethernet frame (Ethertype 0x0806)
std::vector<std::byte> build_arp_request(
    packet::MacAddr sender_mac,
    packet::Ipv4Addr sender_ip,
    packet::Ipv4Addr target_ip
);

std::vector<std::byte> build_arp_reply(
    packet::MacAddr sender_mac,
    packet::Ipv4Addr sender_ip,
    packet::MacAddr target_mac,
    packet::Ipv4Addr target_ip
);

std::vector<std::byte> build_gratuitous_arp(
    packet::MacAddr sender_mac,
    packet::Ipv4Addr sender_ip
);

class ArpEngine {
public:
    explicit ArpEngine(std::chrono::seconds cache_ttl = std::chrono::seconds(300))
        : cache_(cache_ttl) {}

    // Resolve target_ip to MAC. If resolved, returns MacAddr.
    // If pending/absent, queues pkt and returns error ("Pending ARP resolution").
    packet::Result<packet::MacAddr> resolve(packet::Ipv4Addr target_ip, const packet::Packet& pkt);

    // Process incoming ARP reply/request packet. Returns queued packets that were waiting for this IP.
    std::vector<packet::Packet> process_arp_packet(
        const ArpHeader& arp,
        interfaces::Interface& ingress_iface
    );

    ArpCache& cache() noexcept { return cache_; }
    const ArpCache& cache() const noexcept { return cache_; }

    [[nodiscard]] std::size_t pending_queue_size(packet::Ipv4Addr ip) const;

private:
    ArpCache cache_;
    mutable std::mutex queue_mutex_;
    std::unordered_map<packet::Ipv4Addr, std::vector<packet::Packet>> pending_queue_;
    static constexpr std::size_t kMaxQueuePerIp = 64;
};

} // namespace atlas::arp
