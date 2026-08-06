#include <cstdint>
#include <cstddef>
#include <span>
#include "atlas/ethernet/ethernet.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0;

    std::span<const std::byte> frame_span(
        reinterpret_cast<const std::byte*>(data),
        size
    );

    auto result = atlas::ethernet::parse(frame_span);
    (void)result;

    return 0;
}
