#include <iostream>
#include <spdlog/spdlog.h>
#include "config/config.hpp"
#include "interfaces/manager.hpp"

int main(int argc, char* argv[]) {
    spdlog::info("Atlas Software Router v0.1.0 starting...");

    std::string config_path = "config.json";
    if (argc > 1) {
        config_path = argv[1];
    }

    try {
        spdlog::info("Loading configuration from {}", config_path);
        auto cfg = atlas::config::load(config_path);
        spdlog::info("Config loaded successfully. Configured interfaces: {}", cfg.interfaces.size());
    } catch (const std::exception& e) {
        spdlog::error("Initialization error: {}", e.what());
        return 1;
    }

    return 0;
}
