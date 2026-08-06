#pragma once

#include <vector>
#include <memory>
#include <string>
#include "atlas/interfaces/interface.hpp"

namespace atlas::interfaces {

class InterfaceManager {
    std::vector<std::unique_ptr<Interface>> interfaces_;

public:
    InterfaceManager() = default;

    void add_interface(std::unique_ptr<Interface> iface);
    [[nodiscard]] Interface* get_interface(const std::string& name);
    [[nodiscard]] const Interface* get_interface(const std::string& name) const;
    [[nodiscard]] const std::vector<std::unique_ptr<Interface>>& get_all() const;
};

} // namespace atlas::interfaces
