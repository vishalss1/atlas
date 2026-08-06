# Core Data Structures & Error Handling

## Pipeline Packet (`src/packet/packet.hpp`)

The `Packet` struct is the primary data structure flowing through the forwarding pipeline:

```cpp
namespace atlas::packet {

using PacketID = std::uint64_t;

enum class Verdict : std::uint8_t {
    Forward,
    Drop,
    LocalDeliver
};

struct Packet {
    PacketID id;
    std::chrono::steady_clock::time_point timestamp;

    const interfaces::Interface* ingress_iface = nullptr;
    const interfaces::Interface* egress_iface  = nullptr;

    std::span<const std::byte> raw;          // Raw ingress frame bytes (non-owning view)
    std::optional<EthernetHeader> eth;
    std::optional<IPv4Header> ipv4;
    std::span<const std::byte> payload;     // Non-owning view into raw payload
    std::optional<L4Info> l4;

    // Pipeline state fields
    Ipv4Addr next_hop{};
    MacAddr next_hop_mac{};
    Verdict verdict = Verdict::Forward;
    std::string drop_reason;
};

} // namespace atlas::packet
```

---

## Address Wrappers (`src/packet/address.hpp`)

- `Ipv4Addr`: Encapsulates a 32-bit IPv4 address in host byte order. Provides string parsing (`from_string`), formatting (`to_string`), and subnet comparison operators.
- `MacAddr`: Encapsulates 6-byte Ethernet MAC hardware address (`std::array<std::byte, 6>`).
- `Ipv4Prefix`: CIDR subnet wrapper (`Ipv4Addr` + prefix length `uint8_t`). Implements `contains(Ipv4Addr)`.

---

## Error Handling: `Result<T, E>` (`src/packet/result.hpp`)

To ensure a non-throwing data path without C++23 `std::expected`, Atlas defines a custom `Result<T, E>` wrapper around `std::variant`:

```cpp
template <typename T, typename E = std::string>
class Result {
    std::variant<T, E> value_;
public:
    Result(T t) : value_(std::move(t)) {}
    Result(E e) : value_(std::move(e)) {}
    
    bool ok() const { return std::holds_alternative<T>(value_); }
    explicit operator bool() const { return ok(); }
    
    T& get() { return std::get<T>(value_); }
    const T& get() const { return std::get<T>(value_); }
    
    E& error() { return std::get<E>(value_); }
    const E& error() const { return std::get<E>(value_); }
};
```

### Exception Rules
- **Startup / Configuration Phase:** Exceptions (`std::runtime_error`) are permitted for invalid configs or interface binding failures.
- **Data Path Forwarding Phase:** Functions **must not throw**. Errors are returned as `Result<T>` or `std::optional<T>`.
