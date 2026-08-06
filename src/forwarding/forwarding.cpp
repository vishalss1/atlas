#include "atlas/forwarding/forwarding.hpp"
#include "atlas/ethernet/ethernet.hpp"
#include "atlas/ipv4/ipv4.hpp"
#include "atlas/interfaces/interface.hpp"
#include <spdlog/spdlog.h>

namespace atlas::forwarding {

void Forwarder::forward(packet::Packet& pkt) {
    if (pkt.id == 0) {
        pkt.id = next_packet_id();
    }

    if (!pkt.ingress_iface) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = "Null ingress interface";
        spdlog::debug("[pkt:{}] Dropped: Null ingress interface", pkt.id);
        return;
    }

    // Stage 2: Parse Ethernet Header
    auto eth_res = ethernet::parse(pkt.raw);
    if (!eth_res.ok()) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = eth_res.error();
        spdlog::debug("[pkt:{}] Dropped: Ethernet parse failed - {}", pkt.id, pkt.drop_reason);
        return;
    }

    auto [eth_hdr, eth_payload] = eth_res.get();
    pkt.eth = eth_hdr;
    pkt.payload = eth_payload;

    // Stage 3: Filter MAC Address (ours, broadcast, or drop)
    static const packet::MacAddr bcast_mac{std::array<std::byte, 6>{
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF},
        std::byte{0xFF}, std::byte{0xFF}, std::byte{0xFF}
    }};
    bool is_mac_for_us = (eth_hdr.dst_mac == pkt.ingress_iface->mac_address().bytes);
    bool is_bcast = (eth_hdr.dst_mac == bcast_mac.bytes);

    if (!is_mac_for_us && !is_bcast) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = "MAC address filtering drop";
        spdlog::debug("[pkt:{}] Dropped: MAC address not destined for us or broadcast", pkt.id);
        return;
    }

    // Handle ARP Frame (Ethertype 0x0806)
    if (eth_hdr.ethertype == 0x0806) {
        auto arp_res = arp::parse_arp(eth_payload);
        if (!arp_res.ok()) {
            pkt.verdict = packet::Verdict::Drop;
            pkt.drop_reason = arp_res.error();
            spdlog::debug("[pkt:{}] Dropped: Malformed ARP packet - {}", pkt.id, pkt.drop_reason);
            return;
        }

        auto* mutable_ingress = const_cast<interfaces::Interface*>(pkt.ingress_iface);
        auto flushed_pkts = arp_engine_.process_arp_packet(arp_res.get(), *mutable_ingress);
        pkt.verdict = packet::Verdict::LocalDeliver;
        spdlog::debug("[pkt:{}] Processed ARP packet from {}", pkt.id, arp_res.get().sender_ip.to_string());

        // Resume flushed pending packets (Stage 13 & 14)
        for (auto& pending_pkt : flushed_pkts) {
            spdlog::debug("[pkt:{}] Resuming pending packet resolution -> egress: {}", pending_pkt.id, pending_pkt.egress_iface->name());
            
            // Re-resolve MAC from cache
            auto mac_res = arp_engine_.resolve(pending_pkt.next_hop, pending_pkt);
            if (mac_res.ok()) {
                pending_pkt.next_hop_mac = mac_res.get();
                // Stage 13: Build Frame
                std::vector<std::byte> updated_pending_payload(pending_pkt.payload.begin(), pending_pkt.payload.end());
                if (pending_pkt.ipv4 && updated_pending_payload.size() >= 12) {
                    auto* raw_ipv4 = reinterpret_cast<std::uint8_t*>(updated_pending_payload.data());
                    raw_ipv4[8] = pending_pkt.ipv4->ttl;
                    raw_ipv4[10] = static_cast<std::uint8_t>((pending_pkt.ipv4->checksum >> 8) & 0xFF);
                    raw_ipv4[11] = static_cast<std::uint8_t>(pending_pkt.ipv4->checksum & 0xFF);
                }
                auto outgoing_frame = ethernet::build(
                    pending_pkt.egress_iface->mac_address(),
                    pending_pkt.next_hop_mac,
                    0x0800,
                    updated_pending_payload
                );
                // Stage 14: Transmit
                auto* mutable_egress = const_cast<interfaces::Interface*>(pending_pkt.egress_iface);
                mutable_egress->write(outgoing_frame);
                pending_pkt.verdict = packet::Verdict::Forward;
            }
        }
        return;
    }

    // Reject non-IPv4 frames
    if (eth_hdr.ethertype != 0x0800) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = "Unsupported Ethertype";
        spdlog::debug("[pkt:{}] Dropped: Unsupported Ethertype 0x{:04x}", pkt.id, eth_hdr.ethertype);
        return;
    }

    // Stage 4: Parse IPv4 Header
    auto ipv4_res = ipv4::parse(eth_payload);
    if (!ipv4_res.ok()) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = ipv4_res.error();
        spdlog::debug("[pkt:{}] Dropped: IPv4 parse failed - {}", pkt.id, pkt.drop_reason);
        return;
    }
    auto parse_out = ipv4_res.get();
    pkt.ipv4 = parse_out.header;

    // Stage 5: Validate Packet (checksum, ihl, total length, ttl > 0)
    if (!ipv4::validate(*pkt.ipv4, eth_payload.size())) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = "IPv4 header validation failed";
        spdlog::debug("[pkt:{}] Dropped: IPv4 checksum/header validation failed", pkt.id);
        return;
    }

    // Stage 6: Decrement TTL
    if (!ipv4::decrement_ttl(*pkt.ipv4)) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = "TTL expired (TTL <= 1)";
        spdlog::debug("[pkt:{}] Dropped: TTL expired", pkt.id);
        return;
    }

    // Stage 7: Recalculate IPv4 Checksum
    ipv4::recompute_checksum(*pkt.ipv4);

    // Stage 8: Routing Table Lookup (LPM)
    auto route = route_table_.lookup(pkt.ipv4->dst_addr);
    if (!route.has_value()) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = "No route to host";
        spdlog::debug("[pkt:{}] Dropped: No route to destination {}", pkt.id, pkt.ipv4->dst_addr.to_string());
        return;
    }

    // Determine egress interface & next hop IP
    auto* egress = iface_manager_.get_interface(route->interface_name);
    if (!egress) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = "Egress interface not found: " + route->interface_name;
        spdlog::debug("[pkt:{}] Dropped: Egress interface {} missing", pkt.id, route->interface_name);
        return;
    }
    pkt.egress_iface = egress;
    pkt.next_hop = (route->gateway.value != 0) ? route->gateway : pkt.ipv4->dst_addr;

    // Stage 9: Local Delivery Check
    std::vector<packet::Ipv4Addr> local_ips;
    for (const auto& iface_ptr : iface_manager_.get_all()) {
        local_ips.push_back(iface_ptr->ip_prefix().addr);
    }
    if (route_table_.is_local(pkt.ipv4->dst_addr, local_ips)) {
        pkt.verdict = packet::Verdict::LocalDeliver;
        spdlog::debug("[pkt:{}] Local delivery for {}", pkt.id, pkt.ipv4->dst_addr.to_string());
        return;
    }

    // Stage 10: Firewall Evaluation
    if (firewall_) {
        firewall::Direction f_dir = egress->is_nat_outside() ? firewall::Direction::Out : firewall::Direction::In;
        if (firewall_->evaluate(pkt, f_dir) == firewall::Action::Drop) {
            pkt.verdict = packet::Verdict::Drop;
            pkt.drop_reason = "Firewall policy drop";
            spdlog::info("[pkt:{}] Dropped by firewall policy", pkt.id);
            return;
        }
    }

    // Stage 11: NAT Translation
    if (nat_engine_ && nat_engine_->is_enabled()) {
        if (pkt.ingress_iface->is_nat_outside()) {
            nat_engine_->translate_inbound(pkt);
        } else if (egress->is_nat_outside()) {
            nat_engine_->translate_outbound(pkt, egress->ip_prefix().addr);
        }
    }

    // Stage 12: ARP Resolution
    auto arp_res = arp_engine_.resolve(pkt.next_hop, pkt);
    if (!arp_res.ok()) {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = arp_res.error();
        spdlog::debug("[pkt:{}] Queued in ARP pending queue for next hop {}", pkt.id, pkt.next_hop.to_string());
        return;
    }
    pkt.next_hop_mac = arp_res.get();

    // Stage 13: Build Outgoing Ethernet Frame
    std::vector<std::byte> updated_payload(eth_payload.begin(), eth_payload.end());
    if (pkt.ipv4 && updated_payload.size() >= 20) {
        auto* raw_ipv4 = reinterpret_cast<std::uint8_t*>(updated_payload.data());
        raw_ipv4[8] = pkt.ipv4->ttl;
        raw_ipv4[10] = static_cast<std::uint8_t>((pkt.ipv4->checksum >> 8) & 0xFF);
        raw_ipv4[11] = static_cast<std::uint8_t>(pkt.ipv4->checksum & 0xFF);
        raw_ipv4[12] = static_cast<std::uint8_t>((pkt.ipv4->src_addr.value >> 24) & 0xFF);
        raw_ipv4[13] = static_cast<std::uint8_t>((pkt.ipv4->src_addr.value >> 16) & 0xFF);
        raw_ipv4[14] = static_cast<std::uint8_t>((pkt.ipv4->src_addr.value >> 8) & 0xFF);
        raw_ipv4[15] = static_cast<std::uint8_t>(pkt.ipv4->src_addr.value & 0xFF);
        raw_ipv4[16] = static_cast<std::uint8_t>((pkt.ipv4->dst_addr.value >> 24) & 0xFF);
        raw_ipv4[17] = static_cast<std::uint8_t>((pkt.ipv4->dst_addr.value >> 16) & 0xFF);
        raw_ipv4[18] = static_cast<std::uint8_t>((pkt.ipv4->dst_addr.value >> 8) & 0xFF);
        raw_ipv4[19] = static_cast<std::uint8_t>(pkt.ipv4->dst_addr.value & 0xFF);
    }

    auto outgoing_frame = ethernet::build(
        pkt.egress_iface->mac_address(),
        pkt.next_hop_mac,
        0x0800,
        updated_payload
    );

    // Stage 14: Transmit
    auto* mutable_egress = const_cast<interfaces::Interface*>(pkt.egress_iface);
    if (mutable_egress->write(outgoing_frame)) {
        pkt.verdict = packet::Verdict::Forward;
        spdlog::debug("[pkt:{}] Forwarded frame via {} -> next hop {}", pkt.id, pkt.egress_iface->name(), pkt.next_hop.to_string());
    } else {
        pkt.verdict = packet::Verdict::Drop;
        pkt.drop_reason = "Egress transmit failure";
        spdlog::warn("[pkt:{}] Transmit failure on {}", pkt.id, pkt.egress_iface->name());
    }
}

} // namespace atlas::forwarding
