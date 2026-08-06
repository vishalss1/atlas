#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include "packet/address.hpp"

namespace atlas::config {

struct InterfaceConfig {
    packet::Ipv4Prefix address{};
    std::string device{};
    bool nat_outside{false};
};

struct RouteConfig {
    packet::Ipv4Prefix destination{};
    packet::Ipv4Addr gateway{};
    std::string interface{};
};

struct PortRange {
    std::uint16_t start{1024};
    std::uint16_t end{65535};
};

struct NatConfig {
    bool enabled{false};
    packet::Ipv4Addr outside_ip{};
    PortRange port_range{1024, 65535};
    std::uint32_t tcp_timeout_sec{300};
    std::uint32_t udp_timeout_sec{60};
};

struct RuleConfig {
    std::string action{"drop"};     // "allow" or "drop"
    std::string protocol{"all"};    // "tcp", "udp", "icmp", "all"
    std::string dir{"in"};          // "in", "out", "both"
    std::string src_addr{};
    std::string dst_addr{};
    std::uint16_t src_port{0};
    std::uint16_t dst_port{0};
};

struct FirewallConfig {
    std::string default_policy{"drop"};
    std::vector<RuleConfig> rules{};
};

struct ArpConfig {
    std::uint32_t cache_ttl_sec{300};
};

struct LoggingConfig {
    std::string level{"info"};
};

struct Config {
    std::unordered_map<std::string, InterfaceConfig> interfaces{};
    std::vector<RouteConfig> routes{};
    NatConfig nat{};
    FirewallConfig firewall{};
    ArpConfig arp{};
    LoggingConfig logging{};
};

Config load(const std::string& path);

} // namespace atlas::config
