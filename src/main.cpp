#include <iostream>
#include <spdlog/spdlog.h>
#include "atlas/config/config.hpp"
#include "atlas/interfaces/manager.hpp"
#include "atlas/routing/routing.hpp"
#include "atlas/arp/arp.hpp"
#include "atlas/firewall/firewall.hpp"
#include "atlas/nat/nat.hpp"
#include "atlas/forwarding/forwarding.hpp"

int main(int argc, char* argv[]) {
    spdlog::info("Atlas Software Router v0.1.0 starting...");

    std::string config_path = "config.json";
    if (argc > 1) {
        config_path = argv[1];
    }

    try {
        spdlog::info("Loading configuration from {}", config_path);
        auto cfg = atlas::config::load(config_path);
        spdlog::info("Config loaded successfully. Interfaces: {}, Routes: {}",
                     cfg.interfaces.size(), cfg.routes.size());

        // Initialize Routing Table
        atlas::routing::RouteTable route_table;
        for (const auto& r : cfg.routes) {
            route_table.add_route(atlas::routing::Route{
                .destination = r.destination,
                .gateway = r.gateway,
                .interface_name = r.interface
            });
        }

        // Initialize ARP Engine
        atlas::arp::ArpEngine arp_engine(std::chrono::seconds(cfg.arp.cache_ttl_sec));

        // Initialize Firewall Policy Engine
        atlas::firewall::Action default_act = (cfg.firewall.default_policy == "allow") ?
                                              atlas::firewall::Action::Allow :
                                              atlas::firewall::Action::Drop;
        atlas::firewall::Firewall firewall(default_act);
        for (const auto& r : cfg.firewall.rules) {
            atlas::firewall::Direction dir = atlas::firewall::Direction::Both;
            if (r.dir == "in") dir = atlas::firewall::Direction::In;
            else if (r.dir == "out") dir = atlas::firewall::Direction::Out;

            atlas::firewall::Action act = (r.action == "allow") ?
                                          atlas::firewall::Action::Allow :
                                          atlas::firewall::Action::Drop;

            std::optional<atlas::packet::Ipv4Prefix> src_p;
            if (!r.src_addr.empty()) src_p = atlas::packet::Ipv4Prefix::from_string(r.src_addr);

            std::optional<atlas::packet::Ipv4Prefix> dst_p;
            if (!r.dst_addr.empty()) dst_p = atlas::packet::Ipv4Prefix::from_string(r.dst_addr);

            std::optional<atlas::firewall::PortRange> src_pr;
            if (r.src_port > 0) src_pr = atlas::firewall::PortRange{r.src_port, r.src_port};

            std::optional<atlas::firewall::PortRange> dst_pr;
            if (r.dst_port > 0) dst_pr = atlas::firewall::PortRange{r.dst_port, r.dst_port};

            firewall.add_rule(atlas::firewall::Rule{
                .action = act,
                .protocol = r.protocol,
                .src_addr = src_p,
                .dst_addr = dst_p,
                .src_port = src_pr,
                .dst_port = dst_pr,
                .dir = dir
            });
        }

        // Initialize NAT Engine
        atlas::nat::NatEngine nat_engine(
            cfg.nat.enabled,
            cfg.nat.port_range.start,
            cfg.nat.port_range.end,
            std::chrono::seconds(cfg.nat.tcp_timeout_sec),
            std::chrono::seconds(cfg.nat.udp_timeout_sec)
        );

        // Initialize Interface Manager
        atlas::interfaces::InterfaceManager iface_manager;
        spdlog::info("Interface Manager & Pipeline Forwarder initialized.");

        // Initialize Forwarder composition root
        atlas::forwarding::Forwarder forwarder(route_table, arp_engine, iface_manager, &firewall, &nat_engine);

        spdlog::info("Atlas Software Router initialized successfully.");
    } catch (const std::exception& e) {
        spdlog::error("Initialization error: {}", e.what());
        return 1;
    }

    return 0;
}
