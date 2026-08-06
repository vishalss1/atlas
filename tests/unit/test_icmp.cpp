#include <gtest/gtest.h>
#include "atlas/icmp/icmp.hpp"

using namespace atlas::icmp;

TEST(IcmpTest, EchoReplyGeneration) {
    IcmpHeader req{
        .type = 8,
        .code = 0,
        .checksum = 0,
        .rest_of_header = 0x12345678 // Identifier & Sequence
    };

    std::vector<std::byte> payload = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};

    auto reply = build_echo_reply(req, payload);
    ASSERT_GE(reply.size(), 12);

    auto parse_res = parse_icmp(reply);
    ASSERT_TRUE(parse_res.ok()) << parse_res.error();

    auto parsed = parse_res.get();
    EXPECT_EQ(parsed.header.type, 0); // Echo Reply
    EXPECT_EQ(parsed.header.code, 0);
    EXPECT_EQ(parsed.header.rest_of_header, 0x12345678);
    EXPECT_EQ(parsed.payload.size(), 4);
}

TEST(IcmpTest, TimeExceededGeneration) {
    std::vector<std::byte> dummy_ip_frame(28, std::byte{0x45});

    auto msg = build_time_exceeded(dummy_ip_frame);
    ASSERT_GE(msg.size(), 36);

    auto parse_res = parse_icmp(msg);
    ASSERT_TRUE(parse_res.ok()) << parse_res.error();

    auto parsed = parse_res.get();
    EXPECT_EQ(parsed.header.type, 11); // Time Exceeded
    EXPECT_EQ(parsed.header.code, 0);   // TTL Expired
    EXPECT_EQ(parsed.payload.size(), 28);
}

TEST(IcmpTest, DestUnreachableGeneration) {
    std::vector<std::byte> dummy_ip_frame(28, std::byte{0x45});

    auto msg = build_dest_unreachable(dummy_ip_frame, 0);
    ASSERT_GE(msg.size(), 36);

    auto parse_res = parse_icmp(msg);
    ASSERT_TRUE(parse_res.ok()) << parse_res.error();

    auto parsed = parse_res.get();
    EXPECT_EQ(parsed.header.type, 3); // Dest Unreachable
    EXPECT_EQ(parsed.header.code, 0); // Network Unreachable
    EXPECT_EQ(parsed.payload.size(), 28);
}
