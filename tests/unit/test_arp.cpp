#include <gtest/gtest.h>
#include "arp/arp.hpp"
#include "arp/cache.hpp"

using namespace atlas::arp;
using namespace atlas::packet;

TEST(ArpTest, CacheStoreAndRetrieve) {
    ArpCache cache(std::chrono::seconds(10));
    auto ip = Ipv4Addr::from_string("192.168.1.10");
    auto mac = MacAddr::from_string("00:11:22:33:44:55");

    EXPECT_FALSE(cache.get(ip).has_value());

    cache.put_resolved(ip, mac);
    auto entry = cache.get(ip);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->state, EntryState::Resolved);
    EXPECT_EQ(entry->mac, mac);
}

TEST(ArpTest, CacheExpirySweep) {
    ArpCache cache(std::chrono::seconds(10));
    auto ip = Ipv4Addr::from_string("192.168.1.10");
    auto mac = MacAddr::from_string("00:11:22:33:44:55");

    cache.put_resolved(ip, mac, std::chrono::seconds(1));
    EXPECT_EQ(cache.size(), 1);

    // Sweep with future time
    cache.sweep_expired(std::chrono::steady_clock::now() + std::chrono::seconds(5));
    EXPECT_EQ(cache.size(), 0);
}

TEST(ArpTest, ParseAndBuildArpRequest) {
    auto sender_mac = MacAddr::from_string("00:11:22:33:44:55");
    auto sender_ip = Ipv4Addr::from_string("192.168.1.1");
    auto target_ip = Ipv4Addr::from_string("192.168.1.2");

    auto frame = build_arp_request(sender_mac, sender_ip, target_ip);
    ASSERT_GE(frame.size(), 42); // 14 byte Eth + 28 byte ARP

    // Skip Ethernet header (14 bytes)
    std::span<const std::byte> payload(frame.data() + 14, frame.size() - 14);
    auto res = parse_arp(payload);
    ASSERT_TRUE(res.ok());

    auto arp = res.get();
    EXPECT_EQ(arp.opcode, 1);
    EXPECT_EQ(arp.sender_mac, sender_mac);
    EXPECT_EQ(arp.sender_ip, sender_ip);
    EXPECT_EQ(arp.target_ip, target_ip);
}
