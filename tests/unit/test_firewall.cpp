#include <gtest/gtest.h>
#include "atlas/firewall/firewall.hpp"

using namespace atlas::firewall;
using namespace atlas::packet;

TEST(FirewallTest, DefaultDropPolicy) {
    Firewall fw(Action::Drop);
    Packet pkt;
    pkt.ipv4 = IPv4Header{
        .protocol = 6,
        .src_addr = Ipv4Addr::from_string("192.168.1.50"),
        .dst_addr = Ipv4Addr::from_string("10.0.0.1")
    };

    EXPECT_EQ(fw.evaluate(pkt, Direction::In), Action::Drop);
}

TEST(FirewallTest, MatchRuleAllow) {
    Firewall fw(Action::Drop);
    fw.add_rule(Rule{
        .action = Action::Allow,
        .protocol = "tcp",
        .dst_port = PortRange{80, 80},
        .dir = Direction::In
    });

    Packet pkt;
    pkt.ipv4 = IPv4Header{.protocol = 6};
    pkt.l4 = L4Info{.protocol = 6, .src_port = 12345, .dst_port = 80};

    // Port 80 TCP -> Allow
    EXPECT_EQ(fw.evaluate(pkt, Direction::In), Action::Allow);

    // Port 22 TCP -> Drop (fallback to default)
    pkt.l4->dst_port = 22;
    EXPECT_EQ(fw.evaluate(pkt, Direction::In), Action::Drop);
}

TEST(FirewallTest, DirectionFiltering) {
    Firewall fw(Action::Drop);
    fw.add_rule(Rule{
        .action = Action::Allow,
        .protocol = "all",
        .dir = Direction::Out
    });

    Packet pkt;
    pkt.ipv4 = IPv4Header{.protocol = 17};

    // Outbound -> Allow
    EXPECT_EQ(fw.evaluate(pkt, Direction::Out), Action::Allow);

    // Inbound -> Drop
    EXPECT_EQ(fw.evaluate(pkt, Direction::In), Action::Drop);
}
