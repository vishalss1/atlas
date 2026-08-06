#include "ethernet.hpp"
#include <cstring>

namespace atlas::ethernet {

packet::Result<EthernetParseOutput, std::string> parse(std::span<const std::byte> raw) {
    constexpr std::size_t kEthernetHeaderSize = 14;
    if (raw.size() < kEthernetHeaderSize) {
        return packet::Result<EthernetParseOutput, std::string>(
            std::string("Frame too short for Ethernet header (bytes: ") + std::to_string(raw.size()) + ")"
        );
    }

    packet::EthernetHeader header;
    std::memcpy(header.dst_mac.data(), raw.data(), 6);
    std::memcpy(header.src_mac.data(), raw.data() + 6, 6);

    std::uint16_t raw_ethertype = 0;
    std::memcpy(&raw_ethertype, raw.data() + 12, sizeof(raw_ethertype));
    header.ethertype = (static_cast<std::uint16_t>(raw.data()[12]) << 8) |
                        static_cast<std::uint16_t>(raw.data()[13]);

    // Check for Ethernet II vs 802.3 Length field
    if (header.ethertype < 0x0600) {
        return packet::Result<EthernetParseOutput, std::string>(
            "Unsupported 802.3 frame (length field < 0x0600)"
        );
    }

    // Check for 802.1Q VLAN tag
    if (header.ethertype == 0x8100 || header.ethertype == 0x88A8) {
        return packet::Result<EthernetParseOutput, std::string>(
            "Unsupported 802.1Q VLAN tagged frame"
        );
    }

    EthernetParseOutput output{
        .header = header,
        .payload = raw.subspan(kEthernetHeaderSize)
    };

    return packet::Result<EthernetParseOutput, std::string>(output);
}

std::vector<std::byte> build(
    packet::MacAddr src,
    packet::MacAddr dst,
    std::uint16_t ethertype,
    std::span<const std::byte> payload
) {
    constexpr std::size_t kEthernetHeaderSize = 14;
    std::vector<std::byte> frame(kEthernetHeaderSize + payload.size());

    // Copy MAC addresses
    std::memcpy(frame.data(), dst.bytes.data(), 6);
    std::memcpy(frame.data() + 6, src.bytes.data(), 6);

    // Ethertype in big-endian (network byte order)
    frame[12] = static_cast<std::byte>((ethertype >> 8) & 0xFF);
    frame[13] = static_cast<std::byte>(ethertype & 0xFF);

    // Copy payload
    if (!payload.empty()) {
        std::memcpy(frame.data() + kEthernetHeaderSize, payload.data(), payload.size());
    }

    return frame;
}

} // namespace atlas::ethernet
