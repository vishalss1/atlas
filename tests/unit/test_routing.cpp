#include <gtest/gtest.h>
#include "routing/routing.hpp"

using namespace atlas::routing;
using namespace atlas::packet;

TEST(RoutingTest, LongestPrefixMatch) {
    RouteTable table;

    // Default route: 0.0.0.0/0
    table.add_route(Route{
        .destination = Ipv4Prefix::from_string("0.0.0.0/0"),
        .gateway = Ipv4Addr::from_string("192.168.1.254"),
        .interface_name = "eth0"
    });

    // Subnet route: 10.0.0.0/8
    table.add_route(Route{
        .destination = Ipv4Prefix::from_string("10.0.0.0/8"),
        .gateway = Ipv4Addr::from_string("10.0.0.1"),
        .interface_name = "eth1"
    });

    // Specific subnet route: 10.1.2.0/24
    table.add_route(Route{
        .destination = Ipv4Prefix::from_string("10.1.2.0/24"),
        .gateway = Ipv4Addr::from_string("10.1.2.1"),
        .interface_name = "eth2"
    });

    // Test 1: Matches most specific 10.1.2.0/24 route
    auto match1 = table.lookup(Ipv4Addr::from_string("10.1.2.45"));
    ASSERT_TRUE(match1.has_value());
    EXPECT_EQ(match1->interface_name, "eth2");

    // Test 2: Matches 10.0.0.0/8 route
    auto match2 = table.lookup(Ipv4Addr::from_string("10.5.6.7"));
    ASSERT_TRUE(match2.has_value());
    EXPECT_EQ(match2->interface_name, "eth1");

    // Test 3: Fallback to default route 0.0.0.0/0
    auto match3 = table.lookup(Ipv4Addr::from_string("8.8.8.8"));
    ASSERT_TRUE(match3.has_value());
    EXPECT_EQ(match3->interface_name, "eth0");
}

TEST(RoutingTest, LocalIpCheck) {
    RouteTable table;
    std::vector<Ipv4Addr> local_ips = {
        Ipv4Addr::from_string("192.168.1.1"),
        Ipv4Addr::from_string("10.0.0.1")
    };

    EXPECT_TRUE(table.is_local(Ipv4Addr::from_string("192.168.1.1"), local_ips));
    EXPECT_TRUE(table.is_local(Ipv4Addr::from_string("10.0.0.1"), local_ips));
    EXPECT_FALSE(table.is_local(Ipv4Addr::from_string("192.168.1.100"), local_ips));
}
