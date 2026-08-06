#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace atlas::packet {

struct Ipv6Addr {
    std::array<std::byte, 16> bytes{};

    bool operator==(const Ipv6Addr& other) const noexcept {
        return bytes == other.bytes;
    }

    [[nodiscard]] std::string to_string() const;
    static Ipv6Addr from_string(const std::string& str);
};

struct Ipv6Prefix {
    Ipv6Addr addr{};
    std::uint8_t prefix_length{128};

    bool operator==(const Ipv6Prefix& other) const noexcept {
        return addr == other.addr && prefix_length == other.prefix_length;
    }

    [[nodiscard]] bool contains(const Ipv6Addr& ip) const noexcept;
    static Ipv6Prefix from_string(const std::string& str);
};

} // namespace atlas::packet

namespace std {
template <>
struct hash<atlas::packet::Ipv6Addr> {
    std::size_t operator()(const atlas::packet::Ipv6Addr& key) const noexcept {
        std::size_t h = 0;
        for (std::size_t i = 0; i < 16; ++i) {
            h ^= std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(key.bytes[i])) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }
        return h;
    }
};
} // namespace std
