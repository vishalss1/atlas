# Atlas Software Router — Project Overview

## Identity & Purpose
- **Name:** Atlas
- **Tagline:** A Windows-native, user-space software router built from first principles in C++20.
- **Purpose:** Learning and understanding packet forwarding internals.
- **Target OS:** Windows (primary target). Platform abstractions (`platform/`) isolate Windows-specific calls (IP Helper, Winsock, Npcap) to allow future Linux porting.

## Current Implementation Status
- **Current Milestone:** **Phase 1 (Foundations) Complete**
- **Implemented Modules:** Packet Data Model & `Result<T, E>` monad (`src/packet/`), JSON Configuration Parser & Validator (`src/config/`), Ethernet II Parser & Builder (`src/ethernet/`), IPv4 Engine with Checksum & TTL (`src/ipv4/`), Interface Manager (`src/interfaces/`).
- **Next Up:** Phase 2 (Forwarding Core — Routing Table LPM, ARP Engine & Cache, 14-Stage Pipeline Orchestration).

## Non-Goals
- Dynamic routing protocols (RIP/OSPF/BGP) — deferred to future milestones.
- Enterprise switching, MPLS, or VLAN handling.
- IPv6 support (v1 is strictly IPv4; design must not preclude IPv6).
- Kernel bypass (DPDK / XDP) — user-space via Npcap.

---

## Architectural Principles

1. **P1: Correctness Over Performance** — Readable, correct implementation first. Zero-copy and object pools are deferred until proven necessary by benchmarks.
2. **P2: Explicit Pipeline** — Linear, deterministic 14-stage packet flow. No implicit side-channels.
3. **P3: Pure Functions Where Possible** — Parsing, validation, checksums, and LPM routing lookups are pure functions without side-effects.
4. **P4: Immutability Within the Pipeline** — Packet headers are parsed into structured representations; stage operations produce updated state without unsafe in-place mutation aliasing.
5. **P5: Testability** — Every component must be unit-testable in isolation using synthetic packet byte spans without requiring live physical network interfaces.
6. **P6: Fail Closed** — Drop malformed or ambiguous frames immediately and log the event.
7. **P7: Single-Threaded First** — Deterministic single-threaded event loop for v1; parallel worker thread design supported in layout.
8. **P8: Configuration-Driven** — Topology, IP subnets, routes, and firewall policies are parsed from configuration at startup.
9. **P9: RAII & Exception Discipline** — All resource handles are managed via RAII (`std::unique_ptr`). Startup path can throw; **data path never throws** (returns `Result<T>` or `std::optional<T>`).

---

## Toolchain & Build Environment
- **Standard:** C++20 (`/std:c++20` on MSVC).
- **Compiler:** MSVC 19.3x+ (Visual Studio 2022 17.4+).
- **Build System:** CMake 3.21+ with Ninja generator (`cmake --preset default`).
- **Dependencies:** Npcap SDK (`third_party/npcap/`), `nlohmann/json`, GoogleTest (`gtest`), `spdlog`, `fmt`.
- **Package Manager:** vcpkg (`vcpkg.json` manifest mode).
