#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>
#include <string>
#include "atlas/packet/address_v6.hpp"
#include "atlas/packet/result.hpp"

namespace atlas::ipv6 {

struct IPv6Header {
    std::uint8_t  version{6};      // 4 bits
    std::uint8_t  traffic_class{0};// 8 bits
    std::uint32_t flow_label{0};   // 20 bits
    std::uint16_t payload_length{0};
    std::uint8_t  next_header{59}; // 59 = No Next Header, 58 = ICMPv6, 6 = TCP, 17 = UDP
    std::uint8_t  hop_limit{64};
    packet::Ipv6Addr src_addr{};
    packet::Ipv6Addr dst_addr{};
};

struct IPv6ParseOutput {
    IPv6Header header;
    std::span<const std::byte> payload;
};

// Parses 40-byte IPv6 fixed header
packet::Result<IPv6ParseOutput, std::string> parse(std::span<const std::byte> raw);

// Builds raw 40-byte IPv6 header + payload frame
std::vector<std::byte> build(const IPv6Header& hdr, std::span<const std::byte> payload);

} // namespace atlas::ipv6
