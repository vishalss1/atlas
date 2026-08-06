#pragma once

#include <atomic>
#include <vector>
#include "packet/packet.hpp"
#include "routing/routing.hpp"
#include "arp/arp.hpp"
#include "interfaces/manager.hpp"

namespace atlas::forwarding {

class Forwarder {
public:
    Forwarder(
        routing::RouteTable& route_table,
        arp::ArpEngine& arp_engine,
        interfaces::InterfaceManager& iface_manager
    ) : route_table_(route_table),
        arp_engine_(arp_engine),
        iface_manager_(iface_manager) {}

    // Orchestrates the 14-stage non-throwing packet pipeline
    void forward(packet::Packet& pkt);

    [[nodiscard]] packet::PacketID next_packet_id() noexcept {
        return next_packet_id_.fetch_add(1, std::memory_order_relaxed);
    }

private:
    routing::RouteTable& route_table_;
    arp::ArpEngine& arp_engine_;
    interfaces::InterfaceManager& iface_manager_;
    std::atomic<packet::PacketID> next_packet_id_{1};
};

} // namespace atlas::forwarding
