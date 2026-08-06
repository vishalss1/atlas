#include <gtest/gtest.h>
#include "atlas/ipv6/ipv6.hpp"

using namespace atlas::ipv6;
using namespace atlas::packet;

TEST(IPv6Test, ParseAndBuildIPv6Header) {
    IPv6Header hdr{
        .version = 6,
        .traffic_class = 0,
        .flow_label = 0x12345,
        .payload_length = 8,
        .next_header = 17, // UDP
        .hop_limit = 64,
        .src_addr = Ipv6Addr::from_string("2001:db8::1"),
        .dst_addr = Ipv6Addr::from_string("2001:db8::2")
    };

    std::vector<std::byte> payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0x05}, std::byte{0x06}, std::byte{0x07}, std::byte{0x08}};

    auto frame = build(hdr, payload);
    ASSERT_EQ(frame.size(), 48);

    auto parse_res = parse(frame);
    ASSERT_TRUE(parse_res.ok()) << parse_res.error();

    auto parsed = parse_res.get();
    EXPECT_EQ(parsed.header.version, 6);
    EXPECT_EQ(parsed.header.flow_label, 0x12345);
    EXPECT_EQ(parsed.header.next_header, 17);
    EXPECT_EQ(parsed.header.hop_limit, 64);
    EXPECT_EQ(parsed.header.src_addr, Ipv6Addr::from_string("2001:db8::1"));
    EXPECT_EQ(parsed.header.dst_addr, Ipv6Addr::from_string("2001:db8::2"));
    EXPECT_EQ(parsed.payload.size(), 8);
}

TEST(IPv6Test, PrefixContainsCheck) {
    auto prefix = Ipv6Prefix::from_string("2001:db8::/32");
    auto ip1 = Ipv6Addr::from_string("2001:db8:1:2::1");
    auto ip2 = Ipv6Addr::from_string("2001:db9::1");

    EXPECT_TRUE(prefix.contains(ip1));
    EXPECT_FALSE(prefix.contains(ip2));
}
