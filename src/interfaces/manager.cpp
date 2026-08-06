#include "manager.hpp"
#include <algorithm>

namespace atlas::interfaces {

void InterfaceManager::add_interface(std::unique_ptr<Interface> iface) {
    if (iface) {
        interfaces_.push_back(std::move(iface));
    }
}

Interface* InterfaceManager::get_interface(const std::string& name) {
    auto it = std::find_if(interfaces_.begin(), interfaces_.end(),
        [&name](const std::unique_ptr<Interface>& iface) {
            return iface->name() == name;
        });
    return (it != interfaces_.end()) ? it->get() : nullptr;
}

const Interface* InterfaceManager::get_interface(const std::string& name) const {
    auto it = std::find_if(interfaces_.begin(), interfaces_.end(),
        [&name](const std::unique_ptr<Interface>& iface) {
            return iface->name() == name;
        });
    return (it != interfaces_.end()) ? it->get() : nullptr;
}

const std::vector<std::unique_ptr<Interface>>& InterfaceManager::get_all() const {
    return interfaces_;
}

} // namespace atlas::interfaces
