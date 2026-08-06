#include "config.hpp"
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>

namespace atlas::config {

using json = nlohmann::json;

static std::uint32_t parse_duration_sec(const std::string& str, std::uint32_t default_val) {
    if (str.empty()) return default_val;
    if (str.back() == 's' || str.back() == 'S') {
        return static_cast<std::uint32_t>(std::stoul(str.substr(0, str.size() - 1)));
    }
    return static_cast<std::uint32_t>(std::stoul(str));
}

Config load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open configuration file: " + path);
    }

    json j;
    try {
        file >> j;
    } catch (const json::parse_error& e) {
        throw std::runtime_error("JSON parse error in " + path + ": " + e.what());
    }

    Config cfg;

    // Interfaces
    if (j.contains("interfaces") && j["interfaces"].is_object()) {
        for (auto& [name, iface_j] : j["interfaces"].items()) {
            InterfaceConfig ic;
            if (iface_j.contains("address")) {
                ic.address = packet::Ipv4Prefix::from_string(iface_j["address"].get<std::string>());
            }
            if (iface_j.contains("device")) {
                ic.device = iface_j["device"].get<std::string>();
            }
            if (iface_j.contains("nat_outside")) {
                ic.nat_outside = iface_j["nat_outside"].get<bool>();
            }
            cfg.interfaces[name] = ic;
        }
    }

    // Routes
    if (j.contains("routes") && j["routes"].is_array()) {
        for (auto& r_j : j["routes"]) {
            RouteConfig rc;
            if (r_j.contains("destination")) {
                rc.destination = packet::Ipv4Prefix::from_string(r_j["destination"].get<std::string>());
            }
            if (r_j.contains("gateway") && !r_j["gateway"].get<std::string>().empty()) {
                rc.gateway = packet::Ipv4Addr::from_string(r_j["gateway"].get<std::string>());
            }
            if (r_j.contains("interface")) {
                rc.interface = r_j["interface"].get<std::string>();
            }

            // Validation: interface must exist
            if (!rc.interface.empty() && cfg.interfaces.find(rc.interface) == cfg.interfaces.end()) {
                throw std::runtime_error("Route specifies non-existent interface: " + rc.interface);
            }
            cfg.routes.push_back(rc);
        }
    }

    // NAT
    if (j.contains("nat") && j["nat"].is_object()) {
        auto& nat_j = j["nat"];
        if (nat_j.contains("enabled")) cfg.nat.enabled = nat_j["enabled"].get<bool>();
        if (nat_j.contains("outside_ip") && !nat_j["outside_ip"].get<std::string>().empty()) {
            cfg.nat.outside_ip = packet::Ipv4Addr::from_string(nat_j["outside_ip"].get<std::string>());
        }
        if (nat_j.contains("port_range") && nat_j["port_range"].is_object()) {
            cfg.nat.port_range.start = static_cast<std::uint16_t>(nat_j["port_range"].value("start", 1024));
            cfg.nat.port_range.end   = static_cast<std::uint16_t>(nat_j["port_range"].value("end", 65535));
            if (cfg.nat.port_range.start > cfg.nat.port_range.end) {
                throw std::runtime_error("Invalid NAT port_range: start > end");
            }
        }
        if (nat_j.contains("timeouts") && nat_j["timeouts"].is_object()) {
            if (nat_j["timeouts"].contains("tcp")) {
                cfg.nat.tcp_timeout_sec = parse_duration_sec(nat_j["timeouts"]["tcp"].get<std::string>(), 300);
            }
            if (nat_j["timeouts"].contains("udp")) {
                cfg.nat.udp_timeout_sec = parse_duration_sec(nat_j["timeouts"]["udp"].get<std::string>(), 60);
            }
        }
    }

    // Firewall
    if (j.contains("firewall") && j["firewall"].is_object()) {
        auto& fw_j = j["firewall"];
        if (fw_j.contains("default")) cfg.firewall.default_policy = fw_j["default"].get<std::string>();
        if (fw_j.contains("rules") && fw_j["rules"].is_array()) {
            for (auto& r_j : fw_j["rules"]) {
                RuleConfig rule;
                if (r_j.contains("action")) rule.action = r_j["action"].get<std::string>();
                if (r_j.contains("protocol")) rule.protocol = r_j["protocol"].get<std::string>();
                if (r_j.contains("dir")) rule.dir = r_j["dir"].get<std::string>();
                if (r_j.contains("src_port")) rule.src_port = static_cast<uint16_t>(std::stoi(r_j["src_port"].get<std::string>()));
                if (r_j.contains("dst_port")) rule.dst_port = static_cast<uint16_t>(std::stoi(r_j["dst_port"].get<std::string>()));
                cfg.firewall.rules.push_back(rule);
            }
        }
    }

    // ARP
    if (j.contains("arp") && j["arp"].is_object()) {
        if (j["arp"].contains("cache_ttl")) {
            cfg.arp.cache_ttl_sec = parse_duration_sec(j["arp"]["cache_ttl"].get<std::string>(), 300);
        }
    }

    // Logging
    if (j.contains("logging") && j["logging"].is_object()) {
        if (j["logging"].contains("level")) cfg.logging.level = j["logging"]["level"].get<std::string>();
    }

    return cfg;
}

} // namespace atlas::config
