#include <gtest/gtest.h>
#include "atlas/forwarding/forwarding.hpp"
#include "atlas/interfaces/interface.hpp"
#include "atlas/ethernet/ethernet.hpp"
#include "atlas/ipv4/ipv4.hpp"

using namespace atlas;

TEST(ForwardingTest, EndToEndPacketForwarding) {
    // 1. Setup Fake Interfaces
    auto iface1 = std::make_unique<interfaces::FakeInterface>(
        "eth0",
        packet::MacAddr::from_string("00:11:22:33:44:01"),
        packet::Ipv4Prefix::from_string("192.168.1.1/24")
    );
    auto iface2 = std::make_unique<interfaces::FakeInterface>(
        "eth1",
        packet::MacAddr::from_string("00:11:22:33:44:02"),
        packet::Ipv4Prefix::from_string("10.0.0.1/24")
    );

    interfaces::InterfaceManager iface_manager;
    auto* eth0_ptr = iface1.get();
    auto* eth1_ptr = iface2.get();
    iface_manager.add_interface(std::move(iface1));
    iface_manager.add_interface(std::move(iface2));

    // 2. Setup Route Table
    routing::RouteTable route_table;
    route_table.add_route(routing::Route{
        .destination = packet::Ipv4Prefix::from_string("10.0.0.0/24"),
        .gateway = packet::Ipv4Addr::from_string("0.0.0.0"), // On-link direct
        .interface_name = "eth1"
    });

    // 3. Setup ARP Engine & Pre-populate ARP Cache for next hop
    arp::ArpEngine arp_engine;
    auto target_ip = packet::Ipv4Addr::from_string("10.0.0.50");
    auto target_mac = packet::MacAddr::from_string("AA:BB:CC:DD:EE:FF");
    arp_engine.cache().put_resolved(target_ip, target_mac);

    // 4. Construct Forwarder
    forwarding::Forwarder forwarder(route_table, arp_engine, iface_manager);

    // 5. Build Synthetic IPv4 Packet entering eth0 destined for 10.0.0.50
    packet::IPv4Header ip_hdr{
        .version_ihl = 0x45,
        .tos = 0,
        .total_length = 20,
        .id = 1234,
        .flags_fragment = 0,
        .ttl = 64,
        .protocol = 17, // UDP
        .checksum = 0,
        .src_addr = packet::Ipv4Addr::from_string("192.168.1.100"),
        .dst_addr = target_ip
    };
    ipv4::recompute_checksum(ip_hdr);

    std::vector<std::byte> ipv4_bytes(20);
    auto* raw_ip = reinterpret_cast<std::uint8_t*>(ipv4_bytes.data());
    raw_ip[0] = ip_hdr.version_ihl;
    raw_ip[1] = ip_hdr.tos;
    raw_ip[2] = (ip_hdr.total_length >> 8) & 0xFF;
    raw_ip[3] = ip_hdr.total_length & 0xFF;
    raw_ip[4] = (ip_hdr.id >> 8) & 0xFF;
    raw_ip[5] = ip_hdr.id & 0xFF;
    raw_ip[6] = (ip_hdr.flags_fragment >> 8) & 0xFF;
    raw_ip[7] = ip_hdr.flags_fragment & 0xFF;
    raw_ip[8] = ip_hdr.ttl;
    raw_ip[9] = ip_hdr.protocol;
    raw_ip[10] = (ip_hdr.checksum >> 8) & 0xFF;
    raw_ip[11] = ip_hdr.checksum & 0xFF;
    raw_ip[12] = (ip_hdr.src_addr.value >> 24) & 0xFF;
    raw_ip[13] = (ip_hdr.src_addr.value >> 16) & 0xFF;
    raw_ip[14] = (ip_hdr.src_addr.value >> 8) & 0xFF;
    raw_ip[15] = ip_hdr.src_addr.value & 0xFF;
    raw_ip[16] = (ip_hdr.dst_addr.value >> 24) & 0xFF;
    raw_ip[17] = (ip_hdr.dst_addr.value >> 16) & 0xFF;
    raw_ip[18] = (ip_hdr.dst_addr.value >> 8) & 0xFF;
    raw_ip[19] = ip_hdr.dst_addr.value & 0xFF;

    auto frame_bytes = ethernet::build(
        packet::MacAddr::from_string("00:11:22:33:44:99"),
        eth0_ptr->mac_address(),
        0x0800,
        ipv4_bytes
    );

    packet::Packet pkt;
    pkt.ingress_iface = eth0_ptr;
    pkt.raw = frame_bytes;

    // 6. Forward packet through pipeline
    forwarder.forward(pkt);

    // 7. Verify Verdict and Egress Output
    EXPECT_EQ(pkt.verdict, packet::Verdict::Forward);
    EXPECT_EQ(pkt.egress_iface, eth1_ptr);

    // Check frame written to eth1 FakeInterface
    auto tx_history = eth1_ptr->get_tx_history();
    ASSERT_EQ(tx_history.size(), 1);
    auto egress_frame = tx_history[0];
    auto eth_res = ethernet::parse(egress_frame);
    ASSERT_TRUE(eth_res.ok());

    auto [out_hdr, out_payload] = eth_res.get();
    EXPECT_EQ(out_hdr.dst_mac, target_mac.bytes);
    EXPECT_EQ(out_hdr.src_mac, eth1_ptr->mac_address().bytes);

    // Verify TTL decremented to 63
    auto out_ip_res = ipv4::parse(out_payload);
    ASSERT_TRUE(out_ip_res.ok());
    EXPECT_EQ(out_ip_res.get().header.ttl, 63);
}
