#include "atlas/routing/routing.hpp"
#include <algorithm>

namespace atlas::routing {

void RouteTable::add_route(Route route) {
    if (route.destination.length == 0) {
        route.is_default = true;
    }
    routes_.push_back(std::move(route));
}

void RouteTable::clear() {
    routes_.clear();
}

std::optional<Route> RouteTable::lookup(packet::Ipv4Addr dst) const {
    const Route* best_match = nullptr;
    int max_prefix_length = -1;

    for (const auto& route : routes_) {
        if (route.destination.contains(dst)) {
            int len = static_cast<int>(route.destination.length);
            if (len > max_prefix_length) {
                max_prefix_length = len;
                best_match = &route;
            }
        }
    }

    if (best_match != nullptr) {
        return *best_match;
    }
    return std::nullopt;
}

bool RouteTable::is_local(packet::Ipv4Addr dst, const std::vector<packet::Ipv4Addr>& local_ips) const {
    return std::any_of(local_ips.begin(), local_ips.end(), [dst](packet::Ipv4Addr ip) {
        return ip == dst;
    });
}

} // namespace atlas::routing
