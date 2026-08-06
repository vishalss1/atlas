#include <gtest/gtest.h>
#include "atlas/ndp/ndp.hpp"

using namespace atlas::ndp;
using namespace atlas::packet;

TEST(NdpTest, CacheStoreAndRetrieve) {
    NdpCache cache(std::chrono::seconds(60));
    auto ip = Ipv6Addr::from_string("fe80::1");
    MacAddr mac{std::array<std::byte, 6>{std::byte{0x00}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}, std::byte{0x55}}};

    cache.put(ip, mac);

    auto res = cache.get(ip);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->mac, mac);
    EXPECT_TRUE(res->resolved);
}
