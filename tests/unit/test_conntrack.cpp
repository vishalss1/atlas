#include <gtest/gtest.h>
#include "atlas/firewall/conntrack.hpp"

using namespace atlas::firewall;
using namespace atlas::packet;

TEST(ConntrackTest, NewAndEstablishedFlowTracking) {
    ConntrackTable ct(std::chrono::seconds(60));

    Packet pkt1;
    pkt1.ipv4 = IPv4Header{
        .src_addr = Ipv4Addr::from_string("192.168.1.50"),
        .dst_addr = Ipv4Addr::from_string("8.8.8.8")
    };
    pkt1.l4 = L4Info{
        .protocol = 6, // TCP
        .src_port = 5000,
        .dst_port = 80,
        .tcp_flags = 0x02 // SYN
    };

    EXPECT_EQ(ct.track_packet(pkt1), ConnState::New);

    // Return ACK packet from 8.8.8.8:80 -> 192.168.1.50:5000
    Packet pkt2;
    pkt2.ipv4 = IPv4Header{
        .src_addr = Ipv4Addr::from_string("8.8.8.8"),
        .dst_addr = Ipv4Addr::from_string("192.168.1.50")
    };
    pkt2.l4 = L4Info{
        .protocol = 6,
        .src_port = 80,
        .dst_port = 5000,
        .tcp_flags = 0x12 // SYN-ACK
    };

    EXPECT_EQ(ct.track_packet(pkt2), ConnState::Established);
}
