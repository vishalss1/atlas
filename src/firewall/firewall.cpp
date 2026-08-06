#include "atlas/firewall/firewall.hpp"
#include <algorithm>

namespace atlas::firewall {

static std::string to_lower(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return str;
}

void Firewall::add_rule(Rule rule) {
    rule.protocol = to_lower(rule.protocol);
    rules_.push_back(std::move(rule));
}

void Firewall::clear() {
    rules_.clear();
}

bool Firewall::match_rule(const Rule& rule, const packet::Packet& pkt, Direction dir) const {
    // 1. Direction Check
    if (rule.dir != Direction::Both && rule.dir != dir) {
        return false;
    }

    if (!pkt.ipv4.has_value()) {
        return false;
    }

    const auto& ip = *pkt.ipv4;

    // 2. Protocol Check
    std::string proto_lower = to_lower(rule.protocol);
    if (proto_lower != "all") {
        if (proto_lower == "tcp" && ip.protocol != 6) return false;
        if (proto_lower == "udp" && ip.protocol != 17) return false;
        if (proto_lower == "icmp" && ip.protocol != 1) return false;
    }

    // 3. Source IP Prefix Check
    if (rule.src_addr.has_value()) {
        if (!rule.src_addr->contains(ip.src_addr)) {
            return false;
        }
    }

    // 4. Destination IP Prefix Check
    if (rule.dst_addr.has_value()) {
        if (!rule.dst_addr->contains(ip.dst_addr)) {
            return false;
        }
    }

    // 5. Source Port Check (if L4 info available)
    if (rule.src_port.has_value()) {
        if (!pkt.l4.has_value() || !rule.src_port->contains(pkt.l4->src_port)) {
            return false;
        }
    }

    // 6. Destination Port Check (if L4 info available)
    if (rule.dst_port.has_value()) {
        if (!pkt.l4.has_value() || !rule.dst_port->contains(pkt.l4->dst_port)) {
            return false;
        }
    }

    return true;
}

Action Firewall::evaluate(const packet::Packet& pkt, Direction dir) const {
    for (const auto& rule : rules_) {
        if (match_rule(rule, pkt, dir)) {
            return rule.action;
        }
    }
    return default_policy_;
}

} // namespace atlas::firewall
