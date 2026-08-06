#pragma once

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <tuple>
#include <stdexcept>
#include <fmt/format.h>

namespace atlas::packet {

struct Ipv4Addr {
    std::uint32_t value{0}; // Host byte order

    constexpr auto operator<=>(const Ipv4Addr&) const = default;

    [[nodiscard]] std::string to_string() const {
        return fmt::format("{}.{}.{}.{}",
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8)  & 0xFF,
            value         & 0xFF);
    }

    [[nodiscard]] static Ipv4Addr from_string(const std::string& str) {
        std::uint32_t a = 0, b = 0, c = 0, d = 0;
        char dot1 = 0, dot2 = 0, dot3 = 0;
        std::istringstream iss(str);
        if (!(iss >> a >> dot1 >> b >> dot2 >> c >> dot3 >> d) ||
            dot1 != '.' || dot2 != '.' || dot3 != '.' ||
            a > 255 || b > 255 || c > 255 || d > 255) {
            throw std::invalid_argument("Invalid IPv4 address string: " + str);
        }
        return Ipv4Addr{(a << 24) | (b << 16) | (c << 8) | d};
    }
};

struct MacAddr {
    std::array<std::byte, 6> bytes{};

    constexpr auto operator<=>(const MacAddr&) const = default;

    [[nodiscard]] std::string to_string() const {
        return fmt::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            static_cast<unsigned int>(bytes[0]),
            static_cast<unsigned int>(bytes[1]),
            static_cast<unsigned int>(bytes[2]),
            static_cast<unsigned int>(bytes[3]),
            static_cast<unsigned int>(bytes[4]),
            static_cast<unsigned int>(bytes[5]));
    }

    [[nodiscard]] static MacAddr from_string(const std::string& str) {
        MacAddr mac{};
        unsigned int b[6];
        if (sscanf_s(str.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
                     &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6 &&
            sscanf_s(str.c_str(), "%02x-%02x-%02x-%02x-%02x-%02x",
                     &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
            throw std::invalid_argument("Invalid MAC address string: " + str);
        }
        for (int i = 0; i < 6; ++i) {
            mac.bytes[i] = static_cast<std::byte>(b[i]);
        }
        return mac;
    }
};

struct Ipv4Prefix {
    Ipv4Addr addr{};
    std::uint8_t length{0}; // CIDR prefix length (0..32)

    constexpr auto operator<=>(const Ipv4Prefix&) const = default;

    [[nodiscard]] std::uint32_t mask() const noexcept {
        if (length == 0) return 0;
        if (length >= 32) return 0xFFFFFFFF;
        return 0xFFFFFFFF << (32 - length);
    }

    [[nodiscard]] bool contains(Ipv4Addr target) const noexcept {
        if (length == 0) return true;
        std::uint32_t m = mask();
        return (addr.value & m) == (target.value & m);
    }

    [[nodiscard]] std::string to_string() const {
        return fmt::format("{}/{}", addr.to_string(), length);
    }

    [[nodiscard]] static Ipv4Prefix from_string(const std::string& str) {
        auto slash_pos = str.find('/');
        if (slash_pos == std::string::npos) {
            return Ipv4Prefix{Ipv4Addr::from_string(str), 32};
        }
        std::string ip_part = str.substr(0, slash_pos);
        int len = std::stoi(str.substr(slash_pos + 1));
        if (len < 0 || len > 32) {
            throw std::invalid_argument("Invalid prefix length: " + str);
        }
        return Ipv4Prefix{Ipv4Addr::from_string(ip_part), static_cast<std::uint8_t>(len)};
    }
};

} // namespace atlas::packet
