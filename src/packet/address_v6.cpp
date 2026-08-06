#include "atlas/packet/address_v6.hpp"
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>

namespace atlas::packet {

std::string Ipv6Addr::to_string() const {
    std::ostringstream ss;
    const auto* u8 = reinterpret_cast<const std::uint8_t*>(bytes.data());
    for (std::size_t i = 0; i < 16; i += 2) {
        std::uint16_t word = (static_cast<std::uint16_t>(u8[i]) << 8) | u8[i + 1];
        ss << std::hex << word;
        if (i < 14) {
            ss << ":";
        }
    }
    return ss.str();
}

Ipv6Addr Ipv6Addr::from_string(const std::string& str) {
    Ipv6Addr addr{};
    auto* u8 = reinterpret_cast<std::uint8_t*>(addr.bytes.data());

    auto double_colon = str.find("::");
    if (double_colon != std::string::npos) {
        std::string left = str.substr(0, double_colon);
        std::string right = str.substr(double_colon + 2);

        std::vector<std::uint16_t> left_words;
        std::vector<std::uint16_t> right_words;

        std::stringstream ss_left(left);
        std::string seg;
        while (std::getline(ss_left, seg, ':')) {
            if (!seg.empty()) {
                left_words.push_back(static_cast<std::uint16_t>(std::stoul(seg, nullptr, 16)));
            }
        }

        std::stringstream ss_right(right);
        while (std::getline(ss_right, seg, ':')) {
            if (!seg.empty()) {
                right_words.push_back(static_cast<std::uint16_t>(std::stoul(seg, nullptr, 16)));
            }
        }

        std::size_t zero_words = 8 - (left_words.size() + right_words.size());
        std::size_t idx = 0;

        for (auto w : left_words) {
            u8[idx++] = static_cast<std::uint8_t>((w >> 8) & 0xFF);
            u8[idx++] = static_cast<std::uint8_t>(w & 0xFF);
        }
        for (std::size_t z = 0; z < zero_words; ++z) {
            u8[idx++] = 0;
            u8[idx++] = 0;
        }
        for (auto w : right_words) {
            u8[idx++] = static_cast<std::uint8_t>((w >> 8) & 0xFF);
            u8[idx++] = static_cast<std::uint8_t>(w & 0xFF);
        }
    } else {
        std::stringstream ss(str);
        std::string segment;
        std::size_t idx = 0;
        while (std::getline(ss, segment, ':') && idx < 16) {
            if (segment.empty()) continue;
            std::uint16_t word = static_cast<std::uint16_t>(std::stoul(segment, nullptr, 16));
            u8[idx++] = static_cast<std::uint8_t>((word >> 8) & 0xFF);
            u8[idx++] = static_cast<std::uint8_t>(word & 0xFF);
        }
    }

    return addr;
}

bool Ipv6Prefix::contains(const Ipv6Addr& ip) const noexcept {
    if (prefix_length == 0) return true;
    std::size_t full_bytes = prefix_length / 8;
    std::uint8_t rem_bits = prefix_length % 8;

    for (std::size_t i = 0; i < full_bytes; ++i) {
        if (addr.bytes[i] != ip.bytes[i]) return false;
    }
    if (rem_bits > 0 && full_bytes < 16) {
        std::uint8_t mask = static_cast<std::uint8_t>(0xFF << (8 - rem_bits));
        std::uint8_t a = static_cast<std::uint8_t>(addr.bytes[full_bytes]) & mask;
        std::uint8_t b = static_cast<std::uint8_t>(ip.bytes[full_bytes]) & mask;
        return a == b;
    }
    return true;
}

Ipv6Prefix Ipv6Prefix::from_string(const std::string& str) {
    auto slash_pos = str.find('/');
    if (slash_pos == std::string::npos) {
        return Ipv6Prefix{Ipv6Addr::from_string(str), 128};
    }
    std::string ip_part = str.substr(0, slash_pos);
    std::string len_part = str.substr(slash_pos + 1);
    return Ipv6Prefix{
        .addr = Ipv6Addr::from_string(ip_part),
        .prefix_length = static_cast<std::uint8_t>(std::stoul(len_part))
    };
}

} // namespace atlas::packet
