#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>
#include <string>
#include "atlas/packet/address.hpp"
#include "atlas/packet/packet.hpp"
#include "atlas/packet/result.hpp"

namespace atlas::ethernet {

struct EthernetParseOutput {
    packet::EthernetHeader header;
    std::span<const std::byte> payload;
};

// Parses an Ethernet II frame. Returns header + payload span.
packet::Result<EthernetParseOutput, std::string> parse(std::span<const std::byte> raw);

// Constructs a raw Ethernet II frame byte vector.
std::vector<std::byte> build(
    packet::MacAddr src,
    packet::MacAddr dst,
    std::uint16_t ethertype,
    std::span<const std::byte> payload
);

} // namespace atlas::ethernet
