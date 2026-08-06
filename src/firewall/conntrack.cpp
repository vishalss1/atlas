#include "atlas/firewall/conntrack.hpp"

namespace atlas::firewall {

ConnState ConntrackTable::track_packet(const packet::Packet& pkt) {
    if (!pkt.ipv4.has_value() || !pkt.l4.has_value()) {
        return ConnState::Invalid;
    }

    FiveTuple forward_tuple{
        .src_ip = pkt.ipv4->src_addr,
        .dst_ip = pkt.ipv4->dst_addr,
        .src_port = pkt.l4->src_port,
        .dst_port = pkt.l4->dst_port,
        .protocol = pkt.l4->protocol
    };

    FiveTuple reverse_tuple{
        .src_ip = pkt.ipv4->dst_addr,
        .dst_ip = pkt.ipv4->src_addr,
        .src_port = pkt.l4->dst_port,
        .dst_port = pkt.l4->src_port,
        .protocol = pkt.l4->protocol
    };

    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    // Check if forward flow exists
    auto it_fwd = flows_.find(forward_tuple);
    if (it_fwd != flows_.end()) {
        it_fwd->second.last_seen = now;

        if (pkt.l4->protocol == 6) { // TCP
            std::uint8_t flags = pkt.l4->tcp_flags;
            if (flags & 0x01) { // FIN
                it_fwd->second.tcp_state = TcpState::FinWait;
            } else if (flags & 0x10) { // ACK
                it_fwd->second.tcp_state = TcpState::Established;
            }
        }
        return ConnState::Established;
    }

    // Check if reverse flow exists (return traffic)
    auto it_rev = flows_.find(reverse_tuple);
    if (it_rev != flows_.end()) {
        it_rev->second.last_seen = now;

        if (pkt.l4->protocol == 6) {
            std::uint8_t flags = pkt.l4->tcp_flags;
            if (flags & 0x10) { // ACK -> Connection Established
                it_rev->second.tcp_state = TcpState::Established;
            }
        }
        return ConnState::Established;
    }

    // New Connection
    ConnEntry new_entry{
        .orig_tuple = forward_tuple,
        .reply_tuple = reverse_tuple,
        .tcp_state = (pkt.l4->protocol == 6) ? TcpState::SynSent : TcpState::Established,
        .last_seen = now
    };

    flows_[forward_tuple] = new_entry;
    flows_[reverse_tuple] = new_entry;

    return ConnState::New;
}

void ConntrackTable::sweep_expired(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = flows_.begin(); it != flows_.end(); ) {
        if (now - it->second.last_seen > timeout_) {
            it = flows_.erase(it);
        } else {
            ++it;
        }
    }
}

std::size_t ConntrackTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return flows_.size();
}

} // namespace atlas::firewall
