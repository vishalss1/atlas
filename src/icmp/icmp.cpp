#include "atlas/icmp/icmp.hpp"
#include <cstring>
#include <algorithm>

namespace atlas::icmp {

std::uint16_t compute_checksum(std::span<const std::byte> data) {
    std::uint32_t sum = 0;
    const auto* ptr = reinterpret_cast<const std::uint8_t*>(data.data());
    std::size_t len = data.size();

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

    return static_cast<std::uint16_t>(~sum);
}

packet::Result<IcmpParseOutput, std::string> parse_icmp(std::span<const std::byte> raw) {
    if (raw.size() < 8) {
        return std::string("ICMP payload too short (< 8 bytes)");
    }

    const auto* u8 = reinterpret_cast<const std::uint8_t*>(raw.data());

    // Validate Checksum
    std::uint16_t cksum = compute_checksum(raw);
    if (cksum != 0) {
        return std::string("ICMP checksum mismatch");
    }

    IcmpHeader hdr{
        .type = u8[0],
        .code = u8[1],
        .checksum = static_cast<std::uint16_t>((static_cast<std::uint16_t>(u8[2]) << 8) | u8[3]),
        .rest_of_header = (static_cast<std::uint32_t>(u8[4]) << 24) |
                          (static_cast<std::uint32_t>(u8[5]) << 16) |
                          (static_cast<std::uint32_t>(u8[6]) << 8)  |
                          static_cast<std::uint32_t>(u8[7])
    };

    IcmpParseOutput out{
        .header = hdr,
        .payload = raw.subspan(8)
    };

    return out;
}

std::vector<std::byte> build_echo_reply(
    const IcmpHeader& request_hdr,
    std::span<const std::byte> echo_data
) {
    std::vector<std::byte> reply(8 + echo_data.size());
    auto* u8 = reinterpret_cast<std::uint8_t*>(reply.data());

    u8[0] = 0; // Type 0 = Echo Reply
    u8[1] = 0; // Code 0
    u8[2] = 0; // Checksum placeholder
    u8[3] = 0;
    u8[4] = static_cast<std::uint8_t>((request_hdr.rest_of_header >> 24) & 0xFF);
    u8[5] = static_cast<std::uint8_t>((request_hdr.rest_of_header >> 16) & 0xFF);
    u8[6] = static_cast<std::uint8_t>((request_hdr.rest_of_header >> 8) & 0xFF);
    u8[7] = static_cast<std::uint8_t>(request_hdr.rest_of_header & 0xFF);

    if (!echo_data.empty()) {
        std::memcpy(reply.data() + 8, echo_data.data(), echo_data.size());
    }

    std::uint16_t cksum = compute_checksum(reply);
    u8[2] = static_cast<std::uint8_t>((cksum >> 8) & 0xFF);
    u8[3] = static_cast<std::uint8_t>(cksum & 0xFF);

    return reply;
}

std::vector<std::byte> build_time_exceeded(std::span<const std::byte> orig_ip_frame) {
    // ICMP error message payload includes original IPv4 header + 8 bytes of original payload
    std::size_t payload_len = std::min<std::size_t>(orig_ip_frame.size(), 28);
    std::vector<std::byte> msg(8 + payload_len);
    auto* u8 = reinterpret_cast<std::uint8_t*>(msg.data());

    u8[0] = 11; // Type 11 = Time Exceeded
    u8[1] = 0;  // Code 0 = TTL Expired in Transit
    u8[2] = 0;
    u8[3] = 0;
    u8[4] = 0; u8[5] = 0; u8[6] = 0; u8[7] = 0; // Unused 4 bytes

    if (payload_len > 0) {
        std::memcpy(msg.data() + 8, orig_ip_frame.data(), payload_len);
    }

    std::uint16_t cksum = compute_checksum(msg);
    u8[2] = static_cast<std::uint8_t>((cksum >> 8) & 0xFF);
    u8[3] = static_cast<std::uint8_t>(cksum & 0xFF);

    return msg;
}

std::vector<std::byte> build_dest_unreachable(
    std::span<const std::byte> orig_ip_frame,
    std::uint8_t code
) {
    std::size_t payload_len = std::min<std::size_t>(orig_ip_frame.size(), 28);
    std::vector<std::byte> msg(8 + payload_len);
    auto* u8 = reinterpret_cast<std::uint8_t*>(msg.data());

    u8[0] = 3;    // Type 3 = Destination Unreachable
    u8[1] = code; // Code
    u8[2] = 0;
    u8[3] = 0;
    u8[4] = 0; u8[5] = 0; u8[6] = 0; u8[7] = 0; // Unused

    if (payload_len > 0) {
        std::memcpy(msg.data() + 8, orig_ip_frame.data(), payload_len);
    }

    std::uint16_t cksum = compute_checksum(msg);
    u8[2] = static_cast<std::uint8_t>((cksum >> 8) & 0xFF);
    u8[3] = static_cast<std::uint8_t>(cksum & 0xFF);

    return msg;
}

} // namespace atlas::icmp
