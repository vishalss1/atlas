#pragma once

#include <atomic>
#include <vector>
#include "atlas/packet/packet.hpp"
#include "atlas/routing/routing.hpp"
#include "atlas/arp/arp.hpp"
#include "atlas/interfaces/manager.hpp"
#include "atlas/firewall/firewall.hpp"
#include "atlas/nat/nat.hpp"

namespace atlas::forwarding {

class Forwarder {
public:
    Forwarder(
        routing::RouteTable& route_table,
        arp::ArpEngine& arp_engine,
        interfaces::InterfaceManager& iface_manager,
        firewall::Firewall* firewall = nullptr,
        nat::NatEngine* nat_engine = nullptr
    ) : route_table_(route_table),
        arp_engine_(arp_engine),
        iface_manager_(iface_manager),
        firewall_(firewall),
        nat_engine_(nat_engine) {}

    // Orchestrates the 14-stage non-throwing packet pipeline
    void forward(packet::Packet& pkt);

    [[nodiscard]] packet::PacketID next_packet_id() noexcept {
        return next_packet_id_.fetch_add(1, std::memory_order_relaxed);
    }

private:
    routing::RouteTable& route_table_;
    arp::ArpEngine& arp_engine_;
    interfaces::InterfaceManager& iface_manager_;
    firewall::Firewall* firewall_{nullptr};
    nat::NatEngine* nat_engine_{nullptr};
    std::atomic<packet::PacketID> next_packet_id_{1};
};

} // namespace atlas::forwarding
