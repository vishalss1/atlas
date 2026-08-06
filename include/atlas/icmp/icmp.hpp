#pragma once

#include <cstdint>
#include <cstddef>
#include <span>
#include <vector>
#include <string>
#include "atlas/packet/address.hpp"
#include "atlas/packet/result.hpp"

namespace atlas::icmp {

struct IcmpHeader {
    std::uint8_t  type{0};
    std::uint8_t  code{0};
    std::uint16_t checksum{0};
    std::uint32_t rest_of_header{0}; // ID & Sequence number for Echo
};

struct IcmpParseOutput {
    IcmpHeader header;
    std::span<const std::byte> payload;
};

// Computes 16-bit 1's complement ICMP checksum
std::uint16_t compute_checksum(std::span<const std::byte> data);

// Parses raw ICMP payload span
packet::Result<IcmpParseOutput, std::string> parse_icmp(std::span<const std::byte> raw);

// Constructs ICMP Echo Reply (Type 0, Code 0)
std::vector<std::byte> build_echo_reply(
    const IcmpHeader& request_hdr,
    std::span<const std::byte> echo_data
);

// Constructs ICMP Time Exceeded (Type 11, Code 0 - TTL Expired in Transit)
std::vector<std::byte> build_time_exceeded(std::span<const std::byte> orig_ip_frame);

// Constructs ICMP Destination Unreachable (Type 3, Code - Network/Host Unreachable)
std::vector<std::byte> build_dest_unreachable(
    std::span<const std::byte> orig_ip_frame,
    std::uint8_t code = 0 // 0 = Network Unreachable, 1 = Host Unreachable, 3 = Port Unreachable
);

} // namespace atlas::icmp
