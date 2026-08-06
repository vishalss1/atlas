#include <gtest/gtest.h>
#include "atlas/nat/nat.hpp"

using namespace atlas::nat;
using namespace atlas::packet;

TEST(NatTest, OutboundAndInboundTranslation) {
    NatEngine nat(true, 1024, 65535);

    auto inside_ip = Ipv4Addr::from_string("192.168.1.50");
    auto outside_ip = Ipv4Addr::from_string("203.0.113.10");
    auto dest_ip = Ipv4Addr::from_string("8.8.8.8");

    // 1. Build Outbound Packet (TCP 192.168.1.50:5000 -> 8.8.8.8:80)
    std::vector<std::byte> payload(20, std::byte{0});
    auto* raw_l4 = reinterpret_cast<std::uint8_t*>(payload.data());
    raw_l4[0] = 0x13; raw_l4[1] = 0x88; // Src Port = 5000
    raw_l4[2] = 0x00; raw_l4[3] = 0x50; // Dst Port = 80

    Packet outbound_pkt;
    outbound_pkt.ipv4 = IPv4Header{
        .protocol = 6,
        .src_addr = inside_ip,
        .dst_addr = dest_ip
    };
    outbound_pkt.l4 = L4Info{
        .protocol = 6,
        .src_port = 5000,
        .dst_port = 80
    };
    outbound_pkt.payload = payload;

    // 2. Perform Outbound Translation
    ASSERT_TRUE(nat.translate_outbound(outbound_pkt, outside_ip));
    EXPECT_EQ(outbound_pkt.ipv4->src_addr, outside_ip);
    EXPECT_EQ(outbound_pkt.l4->src_port, 5000); // Preserves port 5000 if available
    EXPECT_EQ(nat.session_count(), 1);

    // 3. Build Inbound Return Packet (TCP 8.8.8.8:80 -> 203.0.113.10:5000)
    std::vector<std::byte> return_payload(20, std::byte{0});
    auto* return_l4 = reinterpret_cast<std::uint8_t*>(return_payload.data());
    return_l4[0] = 0x00; return_l4[1] = 0x50; // Src Port = 80
    return_l4[2] = 0x13; return_l4[3] = 0x88; // Dst Port = 5000

    Packet return_pkt;
    return_pkt.ipv4 = IPv4Header{
        .protocol = 6,
        .src_addr = dest_ip,
        .dst_addr = outside_ip
    };
    return_pkt.l4 = L4Info{
        .protocol = 6,
        .src_port = 80,
        .dst_port = 5000
    };
    return_pkt.payload = return_payload;

    // 4. Perform Inbound Return Translation
    ASSERT_TRUE(nat.translate_inbound(return_pkt));
    EXPECT_EQ(return_pkt.ipv4->dst_addr, inside_ip);
    EXPECT_EQ(return_pkt.l4->dst_port, 5000);
}
