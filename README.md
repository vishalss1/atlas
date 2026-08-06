<div align="center">

# ⚡ ATLAS

### Windows-Native User-Space Software Router in C++20

A zero-overhead software router built from first principles — handling raw Ethernet II frame parsing, IPv4 validation, Longest Prefix Match (LPM) routing, ARP resolution, NAPT connection tracking, and stateless firewall filtering via a 14-stage non-throwing data path.

![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?style=flat&logo=cplusplus)
![MSVC](https://img.shields.io/badge/Compiler-MSVC_19.3x-0078D4?style=flat&logo=visualstudio)
![CMake](https://img.shields.io/badge/Build-CMake_3.21+-064F8C?style=flat&logo=cmake)
![Ninja](https://img.shields.io/badge/Generator-Ninja-FF6B00?style=flat)
![Npcap](https://img.shields.io/badge/Packet_IO-Npcap_SDK-008080?style=flat)
![GoogleTest](https://img.shields.io/badge/Testing-GoogleTest-00599C?style=flat)
![spdlog](https://img.shields.io/badge/Logging-spdlog-5B2C6F?style=flat)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat)

</div>

---

## Table of Contents

[What Is Atlas](#what-is-atlas) · [Architectural Principles](#architectural-principles) · [Forwarding Pipeline](#forwarding-pipeline) · [Core Components](#core-components) · [Data Model & Safety](#data-model--safety) · [Tech Stack](#tech-stack) · [Project Structure](#project-structure) · [Configuration](#configuration) · [Quick Start](#quick-start) · [Testing & Verification](#testing--verification) · [Implementation Roadmap](#implementation-roadmap)

---

## What Is Atlas

Most networking tutorials explain routers conceptually using high-level socket abstractions. **Atlas** goes down to the wire — bypassing the Windows kernel IP stack using **Npcap** to capture and inject raw Ethernet frames in user space. Every header field, Internet checksum, TTL decrement, routing lookup, NAT translation, and firewall verdict is calculated manually in C++20.

Built as a first-principles learning system, Atlas models how physical software routers handle packet forwarding. The data path is completely isolated from the operating system's routing table, operating with explicit zero-copy byte views (`std::span`), monadic error handling (`Result<T, E>`), and determinism across every pipeline stage.

---

## Architectural Principles

Atlas is governed by 9 core engineering invariants designed to guarantee predictability, testability, and safety:

| Principle | Invariant | Description |
|:---|:---|:---|
| **P1** | **Correctness First** | Simple, readable code over premature optimization. Zero-copy pools are added only after benchmarking proves a bottleneck. |
| **P2** | **Explicit Pipeline** | Every packet flows through a deterministic, linear 14-stage processing path without hidden side channels. |
| **P3** | **Pure Functions** | Header parsing, checksum validation, and LPM routing lookups are pure functions without global side-effects. |
| **P4** | **Immutability** | Parsed packet headers yield non-aliasing state representations. Transformations produce clear, explicit state transitions. |
| **P5** | **Pure Testability** | Components are testable in isolation using synthetic packet byte spans (`std::array<std::byte, N>`) without requiring physical network cards. |
| **P6** | **Fail Closed** | Malformed, corrupted, or ambiguous packets are dropped immediately and logged. Default firewall policy is `DROP`. |
| **P7** | **Single-Threaded Core** | Forwarding loop runs deterministically on a single thread for v1, designed cleanly for future parallel worker threads. |
| **P8** | **Config-Driven** | Interfaces, routes, subnets, and firewall policies are loaded dynamically from JSON at startup. No hardcoded topology. |
| **P9** | **RAII & No-Throw Data Path** | Resource handles use RAII (`std::unique_ptr`). Startup path may throw; **the forwarding data path never throws C++ exceptions**. |

---

## Forwarding Pipeline

Every raw frame entering an Atlas network interface is assigned a monotonic `PacketID uint64_t` and passes through this exact 14-stage sequence:

```
[Incoming Frame]
       │
       ▼
 1. Receive (interfaces::Interface::read)
       │  std::span<const std::byte>
       ▼
 2. Parse Ethernet Header          (ethernet::parse)
       │  EthernetHeader{src_mac, dst_mac, ethertype}
       ▼
 3. Filter MAC Address
       │  is DstMAC ours or broadcast? no → drop
       ▼
 4. Parse IPv4 Header              (ipv4::parse)
       │  IPv4Header{src, dst, ttl, proto, checksum, ...}
       ▼
 5. Validate Packet               (ipv4::validate)
       │  checksum ok, version=4, IHL sane, ttl > 0
       ▼
 6. Decrement TTL                 (ipv4::decrement_ttl)
       │  ttl--; if ttl == 0 → drop + log
       ▼
 7. Recalculate Header Checksum   (ipv4::recompute_checksum)
       ▼
 8. Routing Table Lookup          (routing::lookup)
       │  → Route{interface, gateway, is_local}
       ▼
 9. Local Delivery Check          (routing::is_local)
       │  destined to router IP? → LocalDeliver verdict
       ▼
10. Firewall Evaluation           (firewall::evaluate)
       │  DROP → drop + log
       ▼
11. NAT Translation               (nat::translate)
       │  rewrite src/dst IP & ports, update checksums
       ▼
12. ARP Resolution                (arp::resolve)
       │  → next-hop MAC (queue packet if pending resolution)
       ▼
13. Build Outgoing Frame          (ethernet::build)
       │  dst_mac = next-hop MAC, src_mac = egress iface MAC
       ▼
14. Transmit                      (interfaces::Interface::write)
       │
       ▼
[Outgoing Frame]
```

### Execution Rules
- **Composition Root:** `forwarding::forward(ctx, pkt)` orchestrates the stages.
- **Monotonic Tracing:** All logs emitted across any stage carry the packet's unique `PacketID`.
- **ARP Suspension:** If ARP resolution returns `Pending`, the frame is held in `arp::Engine`'s queue (capped at 64 packets/IP). Upon receiving an ARP reply, queued packets resume directly at **Stage 13 (Build Frame)** without re-running routing, firewall, or NAT.

---

## Core Components

| Component | Path | Status | Description |
|:---|:---|:---|:---|
| **Packet Data Model** | `src/packet/` | **Phase 1 Complete** | Packet struct, monadic `Result<T, E>`, IPv4 & MAC address wrappers. |
| **Configuration System** | `src/config/` | **Phase 1 Complete** | JSON schema loader and startup validator. |
| **Interface Manager** | `src/interfaces/` | **Phase 1 Complete** | Npcap `pcap_t*` handle wrapper with RAII cleanup and Windows IP Helper binding. |
| **Ethernet Layer** | `src/ethernet/` | **Phase 1 Complete** | Parses and constructs Ethernet II frames (`0x0800` IPv4, `0x0806` ARP). |
| **IPv4 Engine** | `src/ipv4/` | **Phase 1 Complete** | Header parsing, 16-bit Internet Checksum validation, TTL decrementing, and fragment rejection. |
| **Routing Engine** | `src/routing/` | Phase 2 (In Progress) | Routing table maintaining IPv4 prefixes, gateway IPs, and Longest Prefix Match (LPM) scanning. |
| **ARP Engine** | `src/arp/` | Phase 2 (In Progress) | IPv4-to-MAC resolution with thread-safe ARP cache (300s TTL) and pending request queues. |
| **Packet Forwarder** | `src/forwarding/` | Phase 2 (In Progress) | Central composition root driving the 14-stage non-throwing pipeline. |
| **Firewall** | `src/firewall/` | Phase 3 (Planned) | 5-tuple stateless packet filtering engine (default policy: `DROP`). |
| **NAT Engine** | `src/nat/` | Phase 3 (Planned) | NAPT / SNAT session tracking, port allocation (`1024-65535`), and L4 checksum recomputation. |

---

## Data Model & Safety

### Zero-Copy Packet Representation (`src/packet/packet.hpp`)

Rather than reallocating memory at every stage, `Packet` holds non-owning byte slices (`std::span<const std::byte>`) into the raw frame buffer provided by the network interface:

```cpp
namespace atlas::packet {

using PacketID = std::uint64_t;

enum class Verdict : std::uint8_t { Forward, Drop, LocalDeliver };

struct Packet {
    PacketID id;
    std::chrono::steady_clock::time_point timestamp;

    const interfaces::Interface* ingress_iface = nullptr;
    const interfaces::Interface* egress_iface  = nullptr;

    std::span<const std::byte> raw;       // Ingress buffer view
    std::optional<EthernetHeader> eth;
    std::optional<IPv4Header> ipv4;
    std::span<const std::byte> payload;   // L4+ payload view
    std::optional<L4Info> l4;

    Ipv4Addr next_hop{};
    MacAddr next_hop_mac{};
    Verdict verdict = Verdict::Forward;
    std::string drop_reason;
};

} // namespace atlas::packet
```

### Non-Throwing Error Handling (`src/packet/result.hpp`)

In compliance with Principle **P9**, C++ exceptions are banned from the forwarding path. Errors and stage results use a custom monadic type:

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

---

## Tech Stack

| Domain | Technology | Notes |
|:---|:---|:---|
| **Language** | C++20 (`/std:c++20`) | `std::span`, `std::optional`, `std::variant`, concepts |
| **Compiler** | MSVC 19.3x+ / GCC 12+ / Clang 15+ | Primary build target Visual Studio 2022 |
| **Build System** | CMake 3.21+ & Ninja | Out-of-tree preset builds (`CMakePresets.json`) |
| **Packet I/O** | Npcap SDK | Raw network frame capture & injection on Windows |
| **Package Manager**| vcpkg (Manifest Mode) | Dependency management via `vcpkg.json` |
| **JSON Parser** | `nlohmann/json` | Declarative startup configuration loading |
| **Logging** | `spdlog` + `fmt` | Structured multi-threaded logging with `PacketID` tracing |
| **Testing** | GoogleTest (`gtest`) | Unit tests and interface mock fixtures |
| **Platform** | Windows IP Helper & Winsock2 | Device enumeration and adapter MAC resolution (`src/platform/`) |

---

## Project Structure

```
atlas/
├── CMakeLists.txt                 # Top-level CMake config & target definitions
├── CMakePresets.json              # Build presets (debug, release, ninja)
├── vcpkg.json                     # Dependency manifest (gtest, spdlog, nlohmann-json)
├── CLAUDE.md                      # Canonical AI & architectural constitution
├── README.md                      # Project documentation
├── config.json                    # Sample router configuration
├── third_party/
│   └── npcap/                     # Vendored Npcap SDK headers & import libraries
├── include/atlas/                 # Public headers
├── src/                           # Source code modules
│   ├── main.cpp                   # Application entrypoint & dependency wiring
│   ├── packet/                    # Packet struct, address wrappers, Result<T, E>
│   ├── ethernet/                  # Ethernet II parser & frame builder
│   ├── arp/                       # ARP engine, cache, & request queue
│   ├── ipv4/                      # IPv4 header validation, checksum, & TTL
│   ├── routing/                   # Routing table & Longest Prefix Match (LPM)
│   ├── firewall/                  # 5-tuple stateless rule filtering engine
│   ├── nat/                       # NAPT / SNAT connection tracking & port pool
│   ├── forwarding/                # 14-stage pipeline composition root
│   ├── interfaces/                # Network interface manager abstraction
│   ├── config/                    # JSON config parser & validator
│   └── platform/                  # Windows-specific IP Helper / Winsock bindings
└── tests/
    ├── unit/                      # GoogleTest unit test suite
    └── integration/               # End-to-end packet forwarding tests
```

---

## Configuration

Atlas uses JSON for declarative network configuration (`config.json`):

```json
{
  "interfaces": {
    "eth0": {
      "address": "192.168.1.1/24",
      "device": "\\Device\\NPF_{GUID1}",
      "nat_outside": false
    },
    "eth1": {
      "address": "10.0.0.1/24",
      "device": "\\Device\\NPF_{GUID2}",
      "nat_outside": true
    }
  },
  "routes": [
    { "destination": "0.0.0.0/0", "gateway": "192.168.1.254", "interface": "eth0" },
    { "destination": "10.0.0.0/24", "gateway": "0.0.0.0", "interface": "eth1" }
  ],
  "nat": {
    "enabled": true,
    "outside_ip": "203.0.113.10",
    "port_range": { "start": 1024, "end": 65535 },
    "timeouts": { "tcp": "300s", "udp": "60s" }
  },
  "firewall": {
    "default": "drop",
    "rules": [
      { "action": "allow", "protocol": "tcp", "dst_port": "80", "dir": "in" },
      { "action": "allow", "protocol": "tcp", "dst_port": "443", "dir": "in" },
      { "action": "drop",  "protocol": "tcp", "dst_port": "22", "dir": "in" }
    ]
  },
  "arp": { "cache_ttl": "300s" },
  "logging": { "level": "info" }
}
```

---

## Quick Start

### Prerequisites
1. **Windows 10/11** with Visual Studio 2022 (Desktop development with C++ workload).
2. **Npcap Driver**: Install [Npcap](https://npcap.com/) with *"Install Npcap in WinPcap API-compatible Mode"* enabled.
3. **CMake 3.21+** & **Ninja**.
4. **vcpkg** set up and configured via `VCPKG_ROOT`.

### Build Commands

```powershell
# 1. Configure build using CMake presets
cmake --preset default

# 2. Build Debug binary
cmake --build --preset debug

# 3. Run unit tests
ctest --preset default

# 4. Execute Atlas router (Administrator privileges required for raw packet I/O)
.\build\debug\atlas.exe --config config.json
```

---

## Testing & Verification

Atlas uses a multi-tiered testing methodology:

```powershell
# Run GoogleTest Unit Test Suite
.\build\debug\tests\unit\atlas_unit_tests.exe
```

1. **Unit Tests (`tests/unit/`)**: Functional verification of packet parsing, IPv4 checksum generation, LPM route resolution, ARP state transitions, and firewall rule matching using synthetic byte arrays (`std::array<std::byte, N>`).
2. **Mock Interfaces**: Interface read/write logic is tested against loopback/fake adapters without physical wire traffic.
3. **Fuzzing Targets**: Parser entrypoints are isolated for `libFuzzer` target execution (`LLVMFuzzerTestOneInput`).
4. **Sanitizers**: ASan (AddressSanitizer) and UBSan (UndefinedBehaviorSanitizer) builds are validated in CI.

---

## Implementation Roadmap

- [x] **Phase 1: Foundations (COMPLETED)** — Core packet types (`src/packet/`), `Result<T, E>` monad, JSON configuration parser & validator (`src/config/`), Ethernet II parser/builder (`src/ethernet/`), IPv4 engine with checksum & TTL (`src/ipv4/`), interface abstraction (`src/interfaces/`).
- [ ] **Phase 2: Forwarding Core (IN PROGRESS)** — Longest Prefix Match (LPM) routing engine (`src/routing/`), thread-safe ARP cache & queueing (`src/arp/`), 14-stage forwarding pipeline integration (`src/forwarding/`).
- [ ] **Phase 3: Policy Engine (PLANNED)** — 5-tuple stateless firewall filtering (`src/firewall/`), NAPT / Source NAT with connection tracking and L4 checksum rewriting (`src/nat/`).
- [ ] **Phase 4: Hardening & Verification (PLANNED)** — High-volume synthetic frame integration tests, LLVM parser fuzzing, ASan/UBSan CI pipelines.
- [ ] **Future Milestones** — ICMP echo/time-exceeded handlers, stateful firewall conntrack integration, multi-threaded worker loop, IPv6 support.

---

<div align="center">

**Built by [Vishal Shetagar](https://github.com/vishalss1)**

*C++20 · Npcap · CMake · Windows Networking · System Architecture*

[![GitHub](https://img.shields.io/badge/GitHub-vishalss1-181717?style=flat&logo=github)](https://github.com/vishalss1)

</div>
