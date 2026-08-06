#pragma once

#include <vector>
#include <optional>
#include <string>
#include "atlas/packet/address.hpp"

namespace atlas::routing {

struct Route {
    packet::Ipv4Prefix destination;   // e.g. 192.168.1.0/24
    packet::Ipv4Addr   gateway;       // 0.0.0.0 if direct / on-link
    std::string        interface_name; // interface name
    bool               is_default{false};
};

class RouteTable {
public:
    RouteTable() = default;

    void add_route(Route route);
    void clear();

    // Performs Longest Prefix Match (LPM). Returns best matching route or std::nullopt.
    [[nodiscard]] std::optional<Route> lookup(packet::Ipv4Addr dst) const;

    // Returns true if dst matches any IP assigned to our local interfaces.
    [[nodiscard]] bool is_local(packet::Ipv4Addr dst, const std::vector<packet::Ipv4Addr>& local_ips) const;

    [[nodiscard]] const std::vector<Route>& routes() const noexcept { return routes_; }
    [[nodiscard]] std::size_t size() const noexcept { return routes_.size(); }

private:
    std::vector<Route> routes_;
};

} // namespace atlas::routing
