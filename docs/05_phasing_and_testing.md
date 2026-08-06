# Implementation Phasing & Testing Strategy

## Implementation Status & Roadmap

Current Codebase Status: **Phase 4 (Hardening & Verification) Completed**

### Phase 1 — Foundations — **[COMPLETED]**
- [x] Implement `config` module (JSON loading & validation in `src/config/`).
- [x] Implement `packet` types (`Packet`, `Result<T, E>`, `Ipv4Addr`, `MacAddr` in `src/packet/`).
- [x] Implement `ethernet` header parser and builder with GoogleTest suite (`src/ethernet/`).
- [x] Implement `ipv4` header parser, checksum calculation, and TTL management with GoogleTest suite (`src/ipv4/`).
- [x] Implement `interfaces` abstraction wrapping raw packet handles (`src/interfaces/`).

### Phase 2 — Forwarding Core — **[COMPLETED]**
- [x] Implement `routing` table with Longest Prefix Match (LPM) scanning (`src/routing/`).
- [x] Implement `arp` engine (cache management, request generation, pending packet queues in `src/arp/`).
- [x] Wire basic `forwarding` pipeline: `Ethernet -> IPv4 -> Routing -> ARP -> Ethernet Build -> Transmit` (`src/forwarding/`).

### Phase 3 — Policy Engine — **[COMPLETED]**
- [x] Implement `firewall` 5-tuple stateless filtering rules (`src/firewall/`).
- [x] Wire firewall stage into forwarding pipeline.
- [x] Implement `nat` NAPT / SNAT module with connection tracking & dynamic port pool (`src/nat/`).
- [x] Wire NAT stage into forwarding pipeline.

### Phase 4 — Hardening & Verification — **[COMPLETED]**
- [x] Integrate async structured logging (`spdlog`) across all pipeline stages with monotonic `PacketID` tracing.
- [x] Add end-to-end multi-interface integration tests (`tests/integration/test_pipeline_integration.cpp`).
- [x] Set up LLVMFuzzer parser targets for Ethernet, IPv4, and ARP (`tests/fuzz/`).
- [x] Enable ASan / AddressSanitizer build options in CMake.

### Phase 5 — Control Plane Engine — **[COMPLETED]**
- [x] Implement `icmp` protocol module (`include/atlas/icmp/icmp.hpp`, `src/icmp/icmp.cpp`).
- [x] ICMP Echo Request / Reply ping handler for local router IPs.
- [x] ICMP Time Exceeded (Type 11, Code 0) generation when TTL expires.
- [x] ICMP Destination Unreachable (Type 3) error generation.
- [x] GoogleTest functional test suite (`tests/unit/test_icmp.cpp`).

### Advanced Milestones — **[COMPLETED]**
- [x] **Stateful Connection Tracking (`conntrack`)**: 5-tuple TCP/UDP state tracking table (`src/firewall/conntrack.cpp`).
- [x] **Multi-Threaded Worker Pool**: Concurrent packet processing pool (`src/forwarding/worker_pool.cpp`).
- [x] **IPv6 Protocol Engine**: 128-bit IPv6 address types & 40-byte header parser/builder (`src/ipv6/ipv6.cpp`).
- [x] **ICMPv6 NDP Cache**: Neighbor Discovery Protocol resolution table (`src/ndp/ndp.cpp`).

---

## Testing Strategy

### 1. Unit Tests (`tests/unit/`, GoogleTest)
- Pure functional test cases using hand-crafted byte arrays (`std::array<std::byte, N>`).
- Test suites active: `ConfigTest`, `EthernetTest`, `IPv4Test`, `RoutingTest`, `ArpTest`, `FirewallTest`, `ConntrackTest`, `NatTest`, `IcmpTest`, `IPv6Test`, `NdpTest`, `WorkerPoolTest`, `ForwardingTest` (26 tests passing).

### 2. Integration Tests (`tests/integration/`, GoogleTest)
- Multi-interface topology testing using `FakeInterface` pairs.
- Test suite active: `PipelineIntegrationTest` (2 tests passing). Total across project: 20 tests passing.
