#include <gtest/gtest.h>
#include <cstring>
#include "atlas/packet/address.hpp"
#include "atlas/packet/packet.hpp"
#include "atlas/interfaces/interface.hpp"
#include "atlas/interfaces/manager.hpp"
#include "atlas/routing/routing.hpp"
#include "atlas/arp/arp.hpp"
#include "atlas/firewall/firewall.hpp"
#include "atlas/nat/nat.hpp"
#include "atlas/forwarding/forwarding.hpp"
#include "atlas/ethernet/ethernet.hpp"
#include "atlas/ipv4/ipv4.hpp"

using namespace atlas;

static std::vector<std::byte> build_ipv4_packet(
    std::uint8_t proto,
    packet::Ipv4Addr src,
    packet::Ipv4Addr dst,
    std::uint8_t ttl,
    std::span<const std::byte> l4_payload
) {
    packet::IPv4Header hdr{
        .version_ihl = 0x45,
        .tos = 0,
        .total_length = static_cast<std::uint16_t>(20 + l4_payload.size()),
        .id = 0x1234,
        .flags_fragment = 0,
        .ttl = ttl,
        .protocol = proto,
        .checksum = 0,
        .src_addr = src,
        .dst_addr = dst
    };
    ipv4::recompute_checksum(hdr);

    std::vector<std::byte> raw(20 + l4_payload.size());
    raw[0] = static_cast<std::byte>(hdr.version_ihl);
    raw[1] = static_cast<std::byte>(hdr.tos);
    raw[2] = static_cast<std::byte>((hdr.total_length >> 8) & 0xFF);
    raw[3] = static_cast<std::byte>(hdr.total_length & 0xFF);
    raw[4] = static_cast<std::byte>((hdr.id >> 8) & 0xFF);
    raw[5] = static_cast<std::byte>(hdr.id & 0xFF);
    raw[6] = static_cast<std::byte>((hdr.flags_fragment >> 8) & 0xFF);
    raw[7] = static_cast<std::byte>(hdr.flags_fragment & 0xFF);
    raw[8] = static_cast<std::byte>(hdr.ttl);
    raw[9] = static_cast<std::byte>(hdr.protocol);
    raw[10] = static_cast<std::byte>((hdr.checksum >> 8) & 0xFF);
    raw[11] = static_cast<std::byte>(hdr.checksum & 0xFF);
    raw[12] = static_cast<std::byte>((hdr.src_addr.value >> 24) & 0xFF);
    raw[13] = static_cast<std::byte>((hdr.src_addr.value >> 16) & 0xFF);
    raw[14] = static_cast<std::byte>((hdr.src_addr.value >> 8) & 0xFF);
    raw[15] = static_cast<std::byte>(hdr.src_addr.value & 0xFF);
    raw[16] = static_cast<std::byte>((hdr.dst_addr.value >> 24) & 0xFF);
    raw[17] = static_cast<std::byte>((hdr.dst_addr.value >> 16) & 0xFF);
    raw[18] = static_cast<std::byte>((hdr.dst_addr.value >> 8) & 0xFF);
    raw[19] = static_cast<std::byte>(hdr.dst_addr.value & 0xFF);

    if (!l4_payload.empty()) {
        std::memcpy(raw.data() + 20, l4_payload.data(), l4_payload.size());
    }
    return raw;
}

class PipelineIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Setup Topology: eth0 (LAN 192.168.1.1/24), eth1 (WAN 203.0.113.1/24, nat_outside: true)
        auto eth0 = std::make_unique<interfaces::FakeInterface>(
            "eth0",
            packet::MacAddr{std::array<std::byte, 6>{std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55}}},
            packet::Ipv4Prefix::from_string("192.168.1.1/24"),
            false
        );
        eth0_ptr = eth0.get();
        iface_manager.add_interface(std::move(eth0));

        auto eth1 = std::make_unique<interfaces::FakeInterface>(
            "eth1",
            packet::MacAddr{std::array<std::byte, 6>{std::byte{0x00}, std::byte{0xAA}, std::byte{0xBB}, std::byte{0xCC}, std::byte{0xDD}, std::byte{0xEE}}},
            packet::Ipv4Prefix::from_string("203.0.113.1/24"),
            true // NAT Outside
        );
        eth1_ptr = eth1.get();
        iface_manager.add_interface(std::move(eth1));

        // Setup Routing: Connected LAN route + Default WAN route
        route_table.add_route(routing::Route{
            .destination = packet::Ipv4Prefix::from_string("192.168.1.0/24"),
            .gateway = packet::Ipv4Addr{},
            .interface_name = "eth0"
        });

        route_table.add_route(routing::Route{
            .destination = packet::Ipv4Prefix::from_string("0.0.0.0/0"),
            .gateway = packet::Ipv4Addr::from_string("203.0.113.254"),
            .interface_name = "eth1"
        });

        // Pre-populate ARP cache for WAN Gateway (203.0.113.254) and LAN Host (192.168.1.50)
        wan_gw_mac = packet::MacAddr{std::array<std::byte, 6>{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}, std::byte{0x00}, std::byte{0x01}}};
        lan_host_mac = packet::MacAddr{std::array<std::byte, 6>{std::byte{0xAA}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55}}};

        arp_engine.cache().put_resolved(packet::Ipv4Addr::from_string("203.0.113.254"), wan_gw_mac);
        arp_engine.cache().put_resolved(packet::Ipv4Addr::from_string("192.168.1.50"), lan_host_mac);

        // Setup Firewall: Default Allow, block port 23 (Telnet)
        firewall.set_default_policy(firewall::Action::Allow);
        firewall.add_rule(firewall::Rule{
            .action = firewall::Action::Drop,
            .protocol = "tcp",
            .dst_port = firewall::PortRange{23, 23},
            .dir = firewall::Direction::Out
        });
    }

    interfaces::InterfaceManager iface_manager;
    routing::RouteTable route_table;
    arp::ArpEngine arp_engine{std::chrono::seconds(300)};
    firewall::Firewall firewall;
    nat::NatEngine nat_engine{true};
    interfaces::FakeInterface* eth0_ptr{nullptr};
    interfaces::FakeInterface* eth1_ptr{nullptr};
    packet::MacAddr wan_gw_mac{};
    packet::MacAddr lan_host_mac{};
};

TEST_F(PipelineIntegrationTest, FullOutboundSNATAndInboundReturnFlow) {
    forwarding::Forwarder forwarder(route_table, arp_engine, iface_manager, &firewall, &nat_engine);

    // 1. LAN Host (192.168.1.50:6000) sends TCP packet to WAN Server (8.8.8.8:80) via router eth0
    std::vector<std::byte> l4_payload(20, std::byte{0});
    auto* raw_l4 = reinterpret_cast<std::uint8_t*>(l4_payload.data());
    raw_l4[0] = 0x17; raw_l4[1] = 0x70; // Src Port = 6000
    raw_l4[2] = 0x00; raw_l4[3] = 0x50; // Dst Port = 80

    auto ip_payload = build_ipv4_packet(
        6, // TCP
        packet::Ipv4Addr::from_string("192.168.1.50"),
        packet::Ipv4Addr::from_string("8.8.8.8"),
        64,
        l4_payload
    );

    auto frame_bytes = ethernet::build(
        lan_host_mac,
        eth0_ptr->mac_address(),
        0x0800,
        ip_payload
    );

    // Ingress on eth0
    eth0_ptr->inject_rx(frame_bytes);
    auto ingress_opt = eth0_ptr->try_read();
    ASSERT_TRUE(ingress_opt.has_value());

    packet::Packet pkt;
    pkt.id = forwarder.next_packet_id();
    pkt.raw = *ingress_opt;
    pkt.ingress_iface = eth0_ptr;

    // Process through 14-stage forwarder pipeline
    forwarder.forward(pkt);

    // Assert Forward verdict
    EXPECT_EQ(pkt.verdict, packet::Verdict::Forward);
    EXPECT_EQ(pkt.egress_iface->name(), "eth1");

    // Verify translated frame transmitted on eth1 (WAN)
    auto tx_history = eth1_ptr->get_tx_history();
    ASSERT_EQ(tx_history.size(), 1);

    auto egress_eth_res = ethernet::parse(tx_history[0]);
    ASSERT_TRUE(egress_eth_res.ok());
    auto [out_eth_hdr, out_ip_bytes] = egress_eth_res.get();

    // Verify MAC Rewriting (Destination = WAN Gateway MAC, Source = Router eth1 MAC)
    EXPECT_EQ(out_eth_hdr.dst_mac, wan_gw_mac.bytes);
    EXPECT_EQ(out_eth_hdr.src_mac, eth1_ptr->mac_address().bytes);

    // Verify IPv4 Header (SNAT: Source IP rewritten to router WAN IP 203.0.113.1, TTL decremented to 63)
    auto out_ip_res = ipv4::parse(out_ip_bytes);
    ASSERT_TRUE(out_ip_res.ok());
    auto out_ip_hdr = out_ip_res.get().header;
    EXPECT_EQ(out_ip_hdr.src_addr, packet::Ipv4Addr::from_string("203.0.113.1"));
    EXPECT_EQ(out_ip_hdr.dst_addr, packet::Ipv4Addr::from_string("8.8.8.8"));
    EXPECT_EQ(out_ip_hdr.ttl, 63);

    // 2. Simulate Return Traffic from WAN Server (8.8.8.8:80 -> 203.0.113.1:6000) arriving on eth1
    std::vector<std::byte> return_l4(20, std::byte{0});
    auto* return_raw = reinterpret_cast<std::uint8_t*>(return_l4.data());
    return_raw[0] = 0x00; return_raw[1] = 0x50; // Src Port = 80
    return_raw[2] = 0x17; return_raw[3] = 0x70; // Dst Port = 6000

    auto return_ip = build_ipv4_packet(
        6,
        packet::Ipv4Addr::from_string("8.8.8.8"),
        packet::Ipv4Addr::from_string("203.0.113.1"),
        64,
        return_l4
    );

    auto return_frame = ethernet::build(
        wan_gw_mac,
        eth1_ptr->mac_address(),
        0x0800,
        return_ip
    );

    eth1_ptr->inject_rx(return_frame);
    auto return_opt = eth1_ptr->try_read();
    ASSERT_TRUE(return_opt.has_value());

    packet::Packet return_pkt;
    return_pkt.id = forwarder.next_packet_id();
    return_pkt.raw = *return_opt;
    return_pkt.ingress_iface = eth1_ptr;

    forwarder.forward(return_pkt);

    // Assert Return packet translated back to LAN Host (192.168.1.50) and egressed on eth0
    EXPECT_EQ(return_pkt.verdict, packet::Verdict::Forward);
    EXPECT_EQ(return_pkt.egress_iface->name(), "eth0");

    auto lan_tx_history = eth0_ptr->get_tx_history();
    ASSERT_EQ(lan_tx_history.size(), 1);

    auto lan_eth_res = ethernet::parse(lan_tx_history[0]);
    ASSERT_TRUE(lan_eth_res.ok());
    auto [lan_eth_hdr, lan_ip_bytes] = lan_eth_res.get();

    EXPECT_EQ(lan_eth_hdr.dst_mac, lan_host_mac.bytes);
    auto lan_ip_res = ipv4::parse(lan_ip_bytes);
    ASSERT_TRUE(lan_ip_res.ok());
    EXPECT_EQ(lan_ip_res.get().header.dst_addr, packet::Ipv4Addr::from_string("192.168.1.50"));
}

TEST_F(PipelineIntegrationTest, FirewallBlockedPortDropped) {
    forwarding::Forwarder forwarder(route_table, arp_engine, iface_manager, &firewall, &nat_engine);

    // Send Telnet (TCP port 23) packet from LAN host
    std::vector<std::byte> l4_payload(20, std::byte{0});
    auto* raw_l4 = reinterpret_cast<std::uint8_t*>(l4_payload.data());
    raw_l4[0] = 0x13; raw_l4[1] = 0x88; // Src Port = 5000
    raw_l4[2] = 0x00; raw_l4[3] = 0x17; // Dst Port = 23 (Telnet)

    auto ip_payload = build_ipv4_packet(
        6,
        packet::Ipv4Addr::from_string("192.168.1.50"),
        packet::Ipv4Addr::from_string("8.8.8.8"),
        64,
        l4_payload
    );

    auto frame_bytes = ethernet::build(
        lan_host_mac,
        eth0_ptr->mac_address(),
        0x0800,
        ip_payload
    );

    eth0_ptr->inject_rx(frame_bytes);
    auto ingress_opt = eth0_ptr->try_read();
    ASSERT_TRUE(ingress_opt.has_value());

    packet::Packet pkt;
    pkt.id = forwarder.next_packet_id();
    pkt.raw = *ingress_opt;
    pkt.ingress_iface = eth0_ptr;

    forwarder.forward(pkt);

    // Assert Drop verdict due to Firewall policy
    EXPECT_EQ(pkt.verdict, packet::Verdict::Drop);
    EXPECT_EQ(pkt.drop_reason, "Firewall policy drop");
    EXPECT_EQ(eth1_ptr->get_tx_history().size(), 0);
}
