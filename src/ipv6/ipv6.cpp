#include "atlas/ipv6/ipv6.hpp"
#include <cstring>

namespace atlas::ipv6 {

packet::Result<IPv6ParseOutput, std::string> parse(std::span<const std::byte> raw) {
    if (raw.size() < 40) {
        return std::string("IPv6 header too short (< 40 bytes)");
    }

    const auto* u8 = reinterpret_cast<const std::uint8_t*>(raw.data());

    std::uint8_t version = (u8[0] >> 4) & 0x0F;
    if (version != 6) {
        return std::string("Invalid IPv6 version field");
    }

    std::uint8_t tc = static_cast<std::uint8_t>(((u8[0] & 0x0F) << 4) | ((u8[1] >> 4) & 0x0F));
    std::uint32_t flow = ((static_cast<std::uint32_t>(u8[1] & 0x0F) << 16) |
                          (static_cast<std::uint32_t>(u8[2]) << 8) |
                          static_cast<std::uint32_t>(u8[3]));
    std::uint16_t plen = static_cast<std::uint16_t>((static_cast<std::uint16_t>(u8[4]) << 8) | u8[5]);
    std::uint8_t nh = u8[6];
    std::uint8_t hl = u8[7];

    packet::Ipv6Addr src{};
    packet::Ipv6Addr dst{};
    std::memcpy(src.bytes.data(), raw.data() + 8, 16);
    std::memcpy(dst.bytes.data(), raw.data() + 24, 16);

    IPv6Header hdr{
        .version = version,
        .traffic_class = tc,
        .flow_label = flow,
        .payload_length = plen,
        .next_header = nh,
        .hop_limit = hl,
        .src_addr = src,
        .dst_addr = dst
    };

    IPv6ParseOutput out{
        .header = hdr,
        .payload = raw.subspan(40)
    };

    return out;
}

std::vector<std::byte> build(const IPv6Header& hdr, std::span<const std::byte> payload) {
    std::vector<std::byte> frame(40 + payload.size());
    auto* u8 = reinterpret_cast<std::uint8_t*>(frame.data());

    u8[0] = static_cast<std::uint8_t>(0x60 | ((hdr.traffic_class >> 4) & 0x0F));
    u8[1] = static_cast<std::uint8_t>(((hdr.traffic_class & 0x0F) << 4) | ((hdr.flow_label >> 16) & 0x0F));
    u8[2] = static_cast<std::uint8_t>((hdr.flow_label >> 8) & 0xFF);
    u8[3] = static_cast<std::uint8_t>(hdr.flow_label & 0xFF);

    std::uint16_t plen = static_cast<std::uint16_t>(payload.size());
    u8[4] = static_cast<std::uint8_t>((plen >> 8) & 0xFF);
    u8[5] = static_cast<std::uint8_t>(plen & 0xFF);
    u8[6] = hdr.next_header;
    u8[7] = hdr.hop_limit;

    std::memcpy(frame.data() + 8, hdr.src_addr.bytes.data(), 16);
    std::memcpy(frame.data() + 24, hdr.dst_addr.bytes.data(), 16);

    if (!payload.empty()) {
        std::memcpy(frame.data() + 40, payload.data(), payload.size());
    }

    return frame;
}

} // namespace atlas::ipv6
