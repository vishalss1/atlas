# Component Architecture & Specifications

This document describes the responsibilities, design decisions, and current implementation status for each core module in `src/`.

---

## 1. Network Interface Manager (`src/interfaces/`) — **[STATUS: IMPLEMENTED - Phase 1]**
- **Responsibility:** Abstraction layer wrapping raw Npcap `pcap_t*` capture handles.
- **Key Types:** `Interface`, `Manager`.
- **Behavior:**
  - Opens physical network adapters in promiscuous mode via Npcap.
  - `read()` returns raw byte buffers; `write()` injects raw Ethernet frames.
  - RAII wrapper ensures `pcap_close()` execution on shutdown.
  - Platform isolation: Windows IP Helper API calls reside under `src/platform/`.

---

## 2. Ethernet Layer (`src/ethernet/`) — **[STATUS: IMPLEMENTED - Phase 1]**
- **Responsibility:** Parse and construct Ethernet II frames (`0x0800` IPv4, `0x0806` ARP).
- **Key Functions:**
  - `parse(span<const byte>) -> Result<EthernetHeader, span<const byte>>`
  - `build(MacAddr src, MacAddr dst, uint16_t ethertype, span<const byte> payload)`
- **Behavior:** Drops non-Ethernet II frames (VLAN 802.1Q, 802.3 length headers) with diagnostic logs.

---

## 3. IPv4 Engine (`src/ipv4/`) — **[STATUS: IMPLEMENTED - Phase 1]**
- **Responsibility:** Parse IPv4 headers, validate version/length/checksum, decrement TTL, and recompute Internet Checksum.
- **Key Functions:**
  - `parse(span<const byte>) -> Result<IPv4Header>`
  - `validate(IPv4Header) -> bool`
  - `decrement_ttl(IPv4Header&) -> bool`
  - `recompute_checksum(IPv4Header&) -> void`
- **Behavior:** Drops IP fragments (v1 does not perform fragment reassembly) and expired TTL (TTL <= 1).

---

## 4. Configuration System (`src/config/`) — **[STATUS: IMPLEMENTED - Phase 1]**
- **Responsibility:** Parse and validate JSON runtime network configuration.
- **Key Types:** `Config`, `InterfaceConfig`, `RouteConfig`, `NatConfig`, `FirewallConfig`.
- **Behavior:** Verifies interface definitions, route validity, NAT port ranges, and firewall rules prior to router engine launch.

---

## 5. ARP Engine (`src/arp/`) — **[STATUS: SPECIFIED / PHASE 2 IN PROGRESS]**
- **Responsibility:** Resolve IPv4 address to MAC address; manage ARP request/reply lifecycle and ARP cache.
- **Key Components:**
  - Cache: `unordered_map<Ipv4Addr, ArpEntry>` with mutex protection.
  - Resolved TTL: 300 seconds; Pending TTL: 3 seconds.
  - Pending Queue: `unordered_map<Ipv4Addr, vector<Packet>>` (capped at 64 packets per IP).
- **Behavior:** On ARP reply, flushes queued packets and forwards them to frame construction.

---

## 6. Routing Engine (`src/routing/`) — **[STATUS: SPECIFIED / PHASE 2 IN PROGRESS]**
- **Responsibility:** Maintain routing table; perform Longest Prefix Match (LPM); select egress interface and next hop IP.
- **Key Components:** `RouteTable`, `Route` (prefix, gateway, interface name).
- **Behavior:**
  - Linear scan LPM in v1 (longest prefix length wins; fallback to default route `0.0.0.0/0`).
  - Distinguishes direct on-link targets (gateway is 0.0.0.0) from gatewayed targets.

---

## 7. Firewall (`src/firewall/`) — **[STATUS: SPECIFIED / PHASE 3 PLANNED]**
- **Responsibility:** Stateless packet filtering based on 5-tuple rules.
- **Key Components:** `RuleSet`, `Rule` (Action: Allow/Drop; Direction: In/Out; Src/Dst IP prefixes; Port ranges).
- **Behavior:** Top-down first-match rule evaluation. Default policy is **DROP** (fail closed).

---

## 8. NAT Engine (`src/nat/`) — **[STATUS: SPECIFIED / PHASE 3 PLANNED]**
- **Responsibility:** Network Address Port Translation (NAPT / Source NAT).
- **Key Components:**
  - `SessionTable`: Keyed bi-directionally for inbound and outbound traffic.
  - Port Pool: Range `[1024, 65535]` for dynamic port allocation.
- **Behavior:** Applies on outbound packets exiting `nat_outside: true` interfaces; rewrites IP and L4 (TCP/UDP) ports, recomputing header and L4 checksums.

---

## 9. Packet Forwarder (`src/forwarding/`) — **[STATUS: SPECIFIED / PHASE 2 IN PROGRESS]**
- **Responsibility:** Composition root orchestrating the 14-stage forwarding pipeline.
- **Behavior:** Accepts incoming packet context, invokes pipeline stages sequentially, hands off final payload to the target interface.
