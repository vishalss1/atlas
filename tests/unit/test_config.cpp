#include <gtest/gtest.h>
#include <fstream>
#include "config/config.hpp"

TEST(ConfigTest, LoadValidConfig) {
    const std::string test_config = R"({
        "interfaces": {
            "eth0": {
                "address": "192.168.1.1/24",
                "device": "\\Device\\NPF_Test1",
                "nat_outside": false
            },
            "eth1": {
                "address": "10.0.0.1/24",
                "device": "\\Device\\NPF_Test2",
                "nat_outside": true
            }
        },
        "routes": [
            { "destination": "0.0.0.0/0", "gateway": "192.168.1.254", "interface": "eth0" }
        ],
        "nat": {
            "enabled": true,
            "outside_ip": "203.0.113.10",
            "port_range": { "start": 1024, "end": 65535 }
        },
        "logging": { "level": "debug" }
    })";

    std::string tmp_filename = "test_temp_config.json";
    {
        std::ofstream out(tmp_filename);
        out << test_config;
    }

    auto cfg = atlas::config::load(tmp_filename);
    EXPECT_EQ(cfg.interfaces.size(), 2u);
    EXPECT_TRUE(cfg.interfaces.contains("eth0"));
    EXPECT_EQ(cfg.interfaces["eth0"].address.to_string(), "192.168.1.1/24");
    EXPECT_TRUE(cfg.nat.enabled);
    EXPECT_EQ(cfg.nat.outside_ip.to_string(), "203.0.113.10");

    std::remove(tmp_filename.c_str());
}

TEST(ConfigTest, RejectInvalidRouteInterface) {
    const std::string bad_config = R"({
        "interfaces": {
            "eth0": { "address": "192.168.1.1/24", "device": "dev0" }
        },
        "routes": [
            { "destination": "0.0.0.0/0", "gateway": "192.168.1.254", "interface": "non_existent_eth" }
        ]
    })";

    std::string tmp_filename = "test_bad_config.json";
    {
        std::ofstream out(tmp_filename);
        out << bad_config;
    }

    EXPECT_THROW(atlas::config::load(tmp_filename), std::runtime_error);
    std::remove(tmp_filename.c_str());
}
