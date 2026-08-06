#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include "atlas/packet/address.hpp"
#include "atlas/packet/packet.hpp"
#include "atlas/packet/result.hpp"

namespace atlas::ipv4 {

struct IPv4ParseOutput {
    packet::IPv4Header header;
    std::span<const std::byte> payload;
};

// Calculates 16-bit ones-complement Internet Checksum over a byte range
std::uint16_t compute_checksum(std::span<const std::byte> header_bytes);

// Parses an IPv4 header from payload bytes.
packet::Result<IPv4ParseOutput, std::string> parse(std::span<const std::byte> raw);

// Validates IPv4 header fields and checksum.
bool validate(const packet::IPv4Header& header, std::size_t raw_len);

// Decrements TTL by 1. Returns false if TTL drops to 0.
bool decrement_ttl(packet::IPv4Header& header);

// Recomputes IPv4 header checksum in place.
void recompute_checksum(packet::IPv4Header& header);

} // namespace atlas::ipv4
