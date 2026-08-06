#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <optional>
#include <chrono>
#include <string>
#include "atlas/packet/address.hpp"

namespace atlas::interfaces {
class Interface;
}

namespace atlas::packet {

using PacketID = std::uint64_t;

enum class Verdict : std::uint8_t {
    Forward,
    Drop,
    LocalDeliver
};

struct EthernetHeader {
    std::array<std::byte, 6> dst_mac{};
    std::array<std::byte, 6> src_mac{};
    std::uint16_t ethertype{0}; // Host byte order
};

struct IPv4Header {
    std::uint8_t  version_ihl{0x45};
    std::uint8_t  tos{0};
    std::uint16_t total_length{0}; // Host byte order
    std::uint16_t id{0};
    std::uint16_t flags_fragment{0}; // Host byte order
    std::uint8_t  ttl{64};
    std::uint8_t  protocol{0};
    std::uint16_t checksum{0};    // Host byte order
    Ipv4Addr      src_addr{};
    Ipv4Addr      dst_addr{};
};

struct L4Info {
    std::uint8_t  protocol{0};   // TCP/UDP/ICMP
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
    std::uint8_t  tcp_flags{0};
};

struct Packet {
    PacketID id{0};
    std::chrono::steady_clock::time_point timestamp{std::chrono::steady_clock::now()};

    const interfaces::Interface* ingress_iface = nullptr;
    const interfaces::Interface* egress_iface  = nullptr;

    std::span<const std::byte> raw{}; // Original raw frame view
    std::optional<EthernetHeader> eth{};
    std::optional<IPv4Header>     ipv4{};
    std::span<const std::byte>    payload{}; // L4+ payload view
    std::optional<L4Info>         l4{};

    // Pipeline traversal state
    Ipv4Addr    next_hop{};
    MacAddr     next_hop_mac{};
    Verdict     verdict = Verdict::Forward;
    std::string drop_reason{};
};

} // namespace atlas::packet
