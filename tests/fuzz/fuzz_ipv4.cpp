#include <cstdint>
#include <cstddef>
#include <span>
#include "atlas/ipv4/ipv4.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0;

    std::span<const std::byte> payload_span(
        reinterpret_cast<const std::byte*>(data),
        size
    );

    auto result = atlas::ipv4::parse(payload_span);
    if (result.ok()) {
        auto hdr = result.get().header;
        (void)atlas::ipv4::recompute_checksum(hdr);
    }

    return 0;
}
