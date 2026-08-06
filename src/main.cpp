#include <iostream>
#include <spdlog/spdlog.h>
#include "config/config.hpp"
#include "interfaces/manager.hpp"
#include "routing/routing.hpp"
#include "arp/arp.hpp"
#include "forwarding/forwarding.hpp"

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

        // Initialize Interface Manager
        atlas::interfaces::InterfaceManager iface_manager;
        spdlog::info("Interface Manager & Pipeline Forwarder initialized.");

        // Initialize Forwarder composition root
        atlas::forwarding::Forwarder forwarder(route_table, arp_engine, iface_manager);

        spdlog::info("Atlas Software Router initialized successfully.");
    } catch (const std::exception& e) {
        spdlog::error("Initialization error: {}", e.what());
        return 1;
    }

    return 0;
}
