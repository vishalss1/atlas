# Implementation Phasing & Testing Strategy

## Implementation Status & Roadmap

Current Codebase Status: **Phase 3 (Policy Engine) Completed**

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

### Phase 4 — Hardening & Verification — **[PLANNED / NEXT]**
- [ ] Integrate async structured logging (`spdlog`) across all pipeline stages with monotonic `PacketID` tracing.
- [ ] Add integration tests on virtual/Npcap interfaces (`tests/integration/`).
- [ ] Set up libFuzzer fuzzing targets for Ethernet and IPv4 parsers.
- [ ] Enable ASan / UBSan sanitizers in CI.

---

## Testing Strategy

### 1. Unit Tests (`tests/unit/`, GoogleTest)
- Pure functional test cases using hand-crafted byte arrays (`std::array<std::byte, N>`).
- Test suites currently active: `ConfigTest`, `EthernetTest`, `IPv4Test`, `RoutingTest`, `ArpTest`, `FirewallTest`, `NatTest`, `ForwardingTest` (18 tests passing).

### 2. Integration Tests (`tests/integration/`)
- Inject synthetic frames into virtual network interfaces.
- Assert expected MAC rewriting, TTL decrements, checksum recalculations, and egress routing decisions.
