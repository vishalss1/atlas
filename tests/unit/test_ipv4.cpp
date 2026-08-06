#include <gtest/gtest.h>
#include "ipv4/ipv4.hpp"

using namespace atlas;

TEST(IPv4Test, ParseAndValidateIPv4Header) {
    // Construct a reference 20-byte IPv4 Header
    packet::IPv4Header hdr{
        .version_ihl = 0x45, // Version 4, IHL 5 (20 bytes)
        .tos = 0,
        .total_length = 20,
        .id = 0x1234,
        .flags_fragment = 0,
        .ttl = 64,
        .protocol = 17, // UDP
        .checksum = 0,
        .src_addr = packet::Ipv4Addr::from_string("192.168.1.10"),
        .dst_addr = packet::Ipv4Addr::from_string("10.0.0.1")
    };

    ipv4::recompute_checksum(hdr);
    EXPECT_NE(hdr.checksum, 0);

    // Serialize to raw byte array
    std::vector<std::byte> raw(20);
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

    auto result = ipv4::parse(raw);
    ASSERT_TRUE(result.ok()) << result.error();

    auto parsed = result.get().header;
    EXPECT_EQ(parsed.src_addr.to_string(), "192.168.1.10");
    EXPECT_EQ(parsed.dst_addr.to_string(), "10.0.0.1");
    EXPECT_EQ(parsed.ttl, 64);
    EXPECT_EQ(parsed.protocol, 17);
}

TEST(IPv4Test, TTLDecrement) {
    packet::IPv4Header hdr{.ttl = 64};
    EXPECT_TRUE(ipv4::decrement_ttl(hdr));
    EXPECT_EQ(hdr.ttl, 63);

    hdr.ttl = 1;
    EXPECT_FALSE(ipv4::decrement_ttl(hdr));
    EXPECT_EQ(hdr.ttl, 0);
}

TEST(IPv4Test, RejectBadChecksum) {
    std::vector<std::byte> raw(20, std::byte{0x00});
    raw[0] = std::byte{0x45}; // IPv4, IHL=5
    raw[2] = std::byte{0x00};
    raw[3] = std::byte{0x14}; // Total length = 20
    raw[10] = std::byte{0xFF}; // Corrupted checksum
    raw[11] = std::byte{0xFF};

    auto result = ipv4::parse(raw);
    EXPECT_FALSE(result.ok());
}
