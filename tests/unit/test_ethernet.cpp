#include <gtest/gtest.h>
#include "atlas/ethernet/ethernet.hpp"

using namespace atlas;

TEST(EthernetTest, ParseValidEthernetFrame) {
    packet::MacAddr src = packet::MacAddr::from_string("00:11:22:33:44:55");
    packet::MacAddr dst = packet::MacAddr::from_string("66:77:88:99:aa:bb");
    std::uint16_t ethertype = 0x0800; // IPv4

    std::vector<std::byte> payload = { std::byte{0x01}, std::byte{0x02}, std::byte{0x03} };
    std::vector<std::byte> frame = ethernet::build(src, dst, ethertype, payload);

    auto result = ethernet::parse(frame);
    ASSERT_TRUE(result.ok()) << result.error();

    auto output = result.get();
    EXPECT_EQ(packet::MacAddr{output.header.src_mac}, src);
    EXPECT_EQ(packet::MacAddr{output.header.dst_mac}, dst);
    EXPECT_EQ(output.header.ethertype, ethertype);
    EXPECT_EQ(output.payload.size(), payload.size());
}

TEST(EthernetTest, RejectShortFrame) {
    std::vector<std::byte> short_frame = { std::byte{0x01}, std::byte{0x02} };
    auto result = ethernet::parse(short_frame);
    EXPECT_FALSE(result.ok());
}

TEST(EthernetTest, RejectVLANFrame) {
    packet::MacAddr src = packet::MacAddr::from_string("00:11:22:33:44:55");
    packet::MacAddr dst = packet::MacAddr::from_string("66:77:88:99:aa:bb");
    std::uint16_t vlan_ethertype = 0x8100;

    std::vector<std::byte> frame = ethernet::build(src, dst, vlan_ethertype, {});
    auto result = ethernet::parse(frame);
    EXPECT_FALSE(result.ok());
}
