#include <cstdint>
#include <cstddef>
#include <span>
#include "atlas/arp/arp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0;

    std::span<const std::byte> payload_span(
        reinterpret_cast<const std::byte*>(data),
        size
    );

    auto result = atlas::arp::parse_arp(payload_span);
    (void)result;

    return 0;
}
