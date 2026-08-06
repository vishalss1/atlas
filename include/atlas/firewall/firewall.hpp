#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include "atlas/packet/address.hpp"
#include "atlas/packet/packet.hpp"

namespace atlas::firewall {

enum class Action : std::uint8_t {
    Allow,
    Drop
};

enum class Direction : std::uint8_t {
    In,
    Out,
    Both
};

struct PortRange {
    std::uint16_t start{0};
    std::uint16_t end{0};

    [[nodiscard]] bool contains(std::uint16_t port) const noexcept {
        if (start == 0 && end == 0) return true;
        return port >= start && port <= end;
    }
};

struct Rule {
    Action action{Action::Drop};
    std::string protocol{"all"}; // "tcp", "udp", "icmp", "all"
    std::optional<packet::Ipv4Prefix> src_addr;
    std::optional<packet::Ipv4Prefix> dst_addr;
    std::optional<PortRange> src_port;
    std::optional<PortRange> dst_port;
    Direction dir{Direction::Both};
};

class Firewall {
public:
    explicit Firewall(Action default_policy = Action::Drop)
        : default_policy_(default_policy) {}

    void add_rule(Rule rule);
    void clear();
    void set_default_policy(Action policy) noexcept { default_policy_ = policy; }

    [[nodiscard]] Action default_policy() const noexcept { return default_policy_; }
    [[nodiscard]] const std::vector<Rule>& rules() const noexcept { return rules_; }

    // Evaluates a packet against the rule set top-down. First match wins. Fallback to default policy.
    [[nodiscard]] Action evaluate(const packet::Packet& pkt, Direction dir) const;

private:
    Action default_policy_;
    std::vector<Rule> rules_;

    [[nodiscard]] bool match_rule(const Rule& rule, const packet::Packet& pkt, Direction dir) const;
};

} // namespace atlas::firewall
