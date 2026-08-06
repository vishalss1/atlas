#include "atlas/ipv4/ipv4.hpp"
#include <cstring>
#include <vector>

namespace atlas::ipv4 {

std::uint16_t compute_checksum(std::span<const std::byte> bytes) {
    std::uint32_t sum = 0;
    std::size_t len = bytes.size();
    const auto* ptr = reinterpret_cast<const std::uint8_t*>(bytes.data());

    while (len > 1) {
        std::uint16_t word = (static_cast<std::uint16_t>(ptr[0]) << 8) | static_cast<std::uint16_t>(ptr[1]);
        sum += word;
        ptr += 2;
        len -= 2;
    }

    if (len == 1) {
        std::uint16_t word = (static_cast<std::uint16_t>(ptr[0]) << 8);
        sum += word;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<std::uint16_t>(~sum & 0xFFFF);
}

packet::Result<IPv4ParseOutput, std::string> parse(std::span<const std::byte> raw) {
    if (raw.size() < 20) {
        return packet::Result<IPv4ParseOutput, std::string>("IPv4 payload too short (< 20 bytes)");
    }

    const auto* u8 = reinterpret_cast<const std::uint8_t*>(raw.data());

    packet::IPv4Header hdr;
    hdr.version_ihl = u8[0];
    hdr.tos         = u8[1];
    hdr.total_length = (static_cast<std::uint16_t>(u8[2]) << 8) | static_cast<std::uint16_t>(u8[3]);
    hdr.id           = (static_cast<std::uint16_t>(u8[4]) << 8) | static_cast<std::uint16_t>(u8[5]);
    hdr.flags_fragment = (static_cast<std::uint16_t>(u8[6]) << 8) | static_cast<std::uint16_t>(u8[7]);
    hdr.ttl          = u8[8];
    hdr.protocol     = u8[9];
    hdr.checksum     = (static_cast<std::uint16_t>(u8[10]) << 8) | static_cast<std::uint16_t>(u8[11]);

    hdr.src_addr = packet::Ipv4Addr{
        (static_cast<std::uint32_t>(u8[12]) << 24) |
        (static_cast<std::uint32_t>(u8[13]) << 16) |
        (static_cast<std::uint32_t>(u8[14]) << 8)  |
        static_cast<std::uint32_t>(u8[15])
    };

    hdr.dst_addr = packet::Ipv4Addr{
        (static_cast<std::uint32_t>(u8[16]) << 24) |
        (static_cast<std::uint32_t>(u8[17]) << 16) |
        (static_cast<std::uint32_t>(u8[18]) << 8)  |
        static_cast<std::uint32_t>(u8[19])
    };

    std::uint8_t version = (hdr.version_ihl >> 4) & 0x0F;
    std::uint8_t ihl     = hdr.version_ihl & 0x0F;

    if (version != 4) {
        return packet::Result<IPv4ParseOutput, std::string>("Non-IPv4 version field: " + std::to_string(version));
    }

    if (ihl < 5) {
        return packet::Result<IPv4ParseOutput, std::string>("Invalid IHL (< 5): " + std::to_string(ihl));
    }

    std::size_t header_len = static_cast<std::size_t>(ihl) * 4;
    if (raw.size() < header_len) {
        return packet::Result<IPv4ParseOutput, std::string>("Raw data shorter than IHL header length");
    }

    if (hdr.total_length < header_len || hdr.total_length > raw.size()) {
        return packet::Result<IPv4ParseOutput, std::string>("Invalid IPv4 total length: " + std::to_string(hdr.total_length));
    }

    // Check fragments (MF flag or Fragment Offset != 0)
    std::uint16_t frag_offset = hdr.flags_fragment & 0x1FFF;
    bool more_frags = (hdr.flags_fragment & 0x2000) != 0;
    if (frag_offset != 0 || more_frags) {
        return packet::Result<IPv4ParseOutput, std::string>("Fragmented IPv4 packets not supported in v1");
    }

    // Validate Checksum
    std::uint16_t calc_cksum = compute_checksum(raw.subspan(0, header_len));
    if (calc_cksum != 0) {
        return packet::Result<IPv4ParseOutput, std::string>("IPv4 header checksum verification failed");
    }

    IPv4ParseOutput out{
        .header = hdr,
        .payload = raw.subspan(header_len, hdr.total_length - header_len)
    };

    return packet::Result<IPv4ParseOutput, std::string>(out);
}

bool validate(const packet::IPv4Header& header, std::size_t raw_len) {
    std::uint8_t version = (header.version_ihl >> 4) & 0x0F;
    std::uint8_t ihl     = header.version_ihl & 0x0F;
    std::size_t header_len = static_cast<std::size_t>(ihl) * 4;

    if (version != 4 || ihl < 5 || raw_len < header_len || header.total_length < header_len || header.ttl == 0) {
        return false;
    }
    return true;
}

bool decrement_ttl(packet::IPv4Header& header) {
    if (header.ttl <= 1) {
        header.ttl = 0;
        return false;
    }
    header.ttl--;
    return true;
}

void recompute_checksum(packet::IPv4Header& header) {
    std::uint8_t ihl = header.version_ihl & 0x0F;
    std::size_t header_len = static_cast<std::size_t>(ihl) * 4;
    if (header_len < 20) header_len = 20;

    std::vector<std::byte> hdr_bytes(header_len, std::byte{0});

    hdr_bytes[0] = static_cast<std::byte>(header.version_ihl);
    hdr_bytes[1] = static_cast<std::byte>(header.tos);
    hdr_bytes[2] = static_cast<std::byte>((header.total_length >> 8) & 0xFF);
    hdr_bytes[3] = static_cast<std::byte>(header.total_length & 0xFF);
    hdr_bytes[4] = static_cast<std::byte>((header.id >> 8) & 0xFF);
    hdr_bytes[5] = static_cast<std::byte>(header.id & 0xFF);
    hdr_bytes[6] = static_cast<std::byte>((header.flags_fragment >> 8) & 0xFF);
    hdr_bytes[7] = static_cast<std::byte>(header.flags_fragment & 0xFF);
    hdr_bytes[8] = static_cast<std::byte>(header.ttl);
    hdr_bytes[9] = static_cast<std::byte>(header.protocol);
    hdr_bytes[10] = std::byte{0}; // Checksum cleared for calculation
    hdr_bytes[11] = std::byte{0};

    hdr_bytes[12] = static_cast<std::byte>((header.src_addr.value >> 24) & 0xFF);
    hdr_bytes[13] = static_cast<std::byte>((header.src_addr.value >> 16) & 0xFF);
    hdr_bytes[14] = static_cast<std::byte>((header.src_addr.value >> 8) & 0xFF);
    hdr_bytes[15] = static_cast<std::byte>(header.src_addr.value & 0xFF);

    hdr_bytes[16] = static_cast<std::byte>((header.dst_addr.value >> 24) & 0xFF);
    hdr_bytes[17] = static_cast<std::byte>((header.dst_addr.value >> 16) & 0xFF);
    hdr_bytes[18] = static_cast<std::byte>((header.dst_addr.value >> 8) & 0xFF);
    hdr_bytes[19] = static_cast<std::byte>(header.dst_addr.value & 0xFF);

    header.checksum = compute_checksum(hdr_bytes);
}

} // namespace atlas::ipv4
