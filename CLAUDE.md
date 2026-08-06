# CLAUDE.md — Atlas Router: Architecture & Implementation Decisions

> This file is the authoritative implementation reference for AI agents (and humans) working on Atlas.
> It exists so that every implementation decision — language, structure, data layout, concurrency,
> error handling, per-component behavior — is fixed in one place instead of re-derived per session.
> If a decision here conflicts with a request, treat this file as the source of truth unless the user
> explicitly overrides it, and update this file when they do.

---

## 0. Project Identity

- **Name:** Atlas
- **What it is:** A Windows-native, user-space software router (Ethernet → ARP → IPv4 → LPM routing →
  firewall → NAT → forwarding), built for learning, not for production use.
- **Non-goals (do not implement unless explicitly asked):** IPv6, dynamic routing protocols (RIP/OSPF/BGP),
  MPLS, enterprise switching, kernel-bypass (DPDK/XDP), VLAN tagging, hot config reload, ICMP generation.
  These are documented in the original architecture doc as future milestones — an agent should not
  pull them into scope opportunistically.

---

## 1. Language & Toolchain

- **Language: C++20.** Not Go, not Rust, not C. Rationale:
  - RAII maps directly onto the scarce OS resources this project owns (Npcap handles, sockets,
    adapter handles) — no GC, no runtime, deterministic cleanup.
  - `std::span`, `std::string_view`, and packed struct overlays give zero-copy packet parsing,
    which matters because the whole point of the project is per-packet pipeline performance.
  - Npcap, Winsock, and the IP Helper API are native C APIs — C++ interops with them directly with
    no cgo/FFI-equivalent layer.
- **Compiler:** MSVC (`cl.exe`) is primary, since the Npcap SDK and Windows headers are MSVC-native.
  clang-cl is supported secondarily for `clang-tidy`/`clang-format` tooling only.
- **Standard flags:** `/std:c++20 /W4 /WX /permissive-`. Warnings are errors — do not silence a
  warning with a cast; fix the underlying issue.
- **Build system: CMake ≥ 3.20**, Ninja generator, out-of-source builds (`build/`).
- **Dependency management: vcpkg** (manifest mode, `vcpkg.json` at repo root). Pinned dependencies:
  - `npcap-sdk` — raw capture/transmit
  - `yaml-cpp` — config parsing
  - `spdlog` — logging
  - `fmt` — formatting (spdlog dependency, used directly too)
  - `gtest` — unit/integration testing
- Do not add a dependency outside vcpkg without updating this file — no ad hoc `#include` of
  vendored single-header libraries dropped into the tree.

---

## 2. Repository Layout

C++-idiomatic, not the Go `cmd/`+`internal/` layout from the original planning doc:

```
atlas/
├── CMakeLists.txt
├── vcpkg.json
├── src/
│   ├── main.cpp
│   ├── interfaces/       # NIC enumeration, Npcap handle lifecycle
│   ├── ethernet/         # frame parsing/building
│   ├── arp/               # ARP cache, request/reply handling
│   ├── ipv4/              # header parse/validate, TTL, checksum
│   ├── routing/           # LPM trie, routing table
│   ├── forwarding/        # pipeline orchestration, MAC rewrite, tx
│   ├── firewall/          # rule evaluation
│   ├── nat/                # connection tracking, port allocation
│   ├── packet/             # buffer pool, PacketContext, header overlays
│   ├── config/             # YAML load + validation
│   └── platform/           # Windows-specific glue (Npcap, IP Helper API)
├── include/atlas/         # public headers, mirrors src/ module names
├── tests/
│   ├── unit/               # GoogleTest, per-module
│   ├── integration/        # pcap-fixture replay tests
│   └── fixtures/           # checked-in .pcap files
├── docs/                   # architecture.md, per-protocol notes (unchanged from planning doc)
└── scripts/                # build/setup helpers
```

Each `src/<module>/` has a matching `include/atlas/<module>/` — implementation files never expose
internals via headers outside that pairing.

---

## 3. Memory & Ownership

- No manual `new`/`delete`. Ownership is expressed with `std::unique_ptr` by default.
- `std::shared_ptr` is reserved for connection-tracking entries referenced by both the firewall and
  NAT engine simultaneously — this is the *only* sanctioned shared-ownership case. Do not reach for
  `shared_ptr` elsewhere; it's a signal something else is architecturally wrong.
- OS handles (`pcap_t*`, adapter `HANDLE`s) are wrapped in thin RAII types (e.g. `NpcapHandle`) with
  deleted copy constructors and move-only semantics. Never store a raw `pcap_t*` in application code.
- **No per-packet heap allocation in the hot path.** See §5 (buffer pool).

---

## 4. Packet Representation

- A packet is a non-owning `std::span<std::byte>` over a buffer drawn from the pool (§5).
- Header parsing uses an **overlay pattern**: `#pragma pack(1)` structs (`EthernetHeader`,
  `Ipv4Header`, `ArpHeader`) are `reinterpret_cast` onto the buffer *after* an explicit bounds check
  against the captured length. Never overlay before validating the buffer is long enough — this is
  the single most important safety rule in the parsing code.
- A `PacketContext` struct threads pipeline state by reference through every stage: ingress interface
  id, capture timestamp, spans for each parsed header, and decision flags (drop reason, NAT applied,
  firewall verdict). Stages mutate `PacketContext` in place; they do not copy the packet.

---

## 5. Buffer Pool

- Fixed-size slab allocator, buffer size = configured MTU (default 1518 B; jumbo frames up to 9000 B
  supported via config).
- Pool is pre-allocated at startup — sized as `(interfaces × per-interface-queue-depth) + slack`.
- Buffers are checked out on capture, checked back in after transmit or drop. A checked-out buffer
  that isn't returned within a debug-build watchdog window logs a leak warning (debug builds only —
  no runtime cost in release).

---

## 6. Concurrency Model

- **v1: single-threaded event loop per interface**, blocking on `pcap_next_ex`. Chosen deliberately
  over threading for v1 so that pipeline correctness can be reasoned about without data races —
  matches the project's stated goal (understanding, not performance).
- **Documented future extension** (do not build this unless asked): one capture thread per interface
  feeding a lock-free MPSC queue into a shared forwarding worker pool sized to
  `std::thread::hardware_concurrency()`. Routing table / ARP cache / NAT table would move to
  `std::shared_mutex` (reads vastly outnumber writes); firewall rule set would become copy-on-write
  with atomic pointer swap for lock-free reads.
- Do not introduce threading opportunistically while implementing a single component — it changes
  the locking story for every shared table at once and needs to be a deliberate, whole-pipeline change.

---

## 7. Error Handling

- **No C++ exceptions in the packet-processing hot path.** Exceptions are reserved for startup and
  config-parsing failures only (things that should halt the process, not per-packet events).
- Hot-path functions return a lightweight `Result<T, PacketError>` (minimal hand-rolled type —
  do not pull in `tl::expected` or similar just for this; the pattern is small enough to own).
- Malformed or invalid packets are counted (per-drop-reason counter) and dropped silently — never
  thrown, never logged at anything above TRACE (logging every drop at INFO would flood the log under
  normal internet background noise/scans).

---

## 8. Logging

- `spdlog`. Async sink for hot-path counters (forwarded/dropped/NAT'd, flushed on an interval),
  synchronous sink for startup/config/fatal errors.
- Levels: `TRACE` (per-packet detail — compiled out entirely in Release via macro, not just filtered
  at runtime), `DEBUG`, `INFO`, `WARN`, `ERROR`.
- Never log packet payload contents at any level above TRACE (privacy/noise).

---

## 9. Configuration

- YAML via `yaml-cpp`, parsed once at startup into an **immutable** `Config` struct (no live mutation
  — config is load-then-freeze).
- Validation happens before the router starts forwarding: reject invalid CIDRs, duplicate interface
  names, overlapping routes with identical prefix length, and out-of-range port allocations up front
  with a clear error — do not let a bad config surface as a confusing runtime forwarding bug.
- Hot-reload is explicitly out of scope for v1 (see §0 non-goals) — it would require re-deriving the
  concurrency model in §6 first.

---

## 10. Component Decisions

### 10.1 Interface Manager
- One `InterfaceManager` instance per configured interface; owns the `pcap_t*` lifetime via
  `NpcapHandle`.
- Interface MAC/IP is resolved at startup via `GetAdaptersAddresses` (IP Helper API), **not**
  hardcoded in config — config only names the interface, the manager resolves its properties.

### 10.2 Ethernet Layer
- Validate frame length ≥ 14 bytes before overlaying `EthernetHeader`.
- EtherType dispatch via `switch`: `0x0800` → IPv4, `0x0806` → ARP, everything else counted as
  `unsupported_ethertype` and dropped.
- No VLAN tag handling in v1 (would require detecting the 4-byte 802.1Q tag before the overlay —
  future extension, not a bug if frames with tags are currently dropped/mis-parsed... actually: add
  an explicit check that logs+drops tagged frames rather than mis-parsing them as untagged).

### 10.3 ARP Engine
- `ArpCache = std::unordered_map<Ipv4Address, ArpEntry>` guarded by `std::shared_mutex`.
- `ArpEntry`: MAC, last-seen timestamp, state (`INCOMPLETE` / `REACHABLE` / `STALE`).
- Default entry TTL: 1200s (mirrors common OS conventions — not arbitrary).
- On cache miss: queue **one** pending packet per unresolved IP (bounded — do not build an unbounded
  per-IP queue), send an ARP request, flush on reply. Unresolved after N retries → drop + count.
  ICMP host-unreachable is deferred (ICMP isn't implemented in v1 — see non-goals).

### 10.4 IPv4 Engine
- Validate: `version == 4`, `IHL ≥ 5`, `total_length ≤ captured_length`, checksum verified — in that
  order, before any further processing.
- TTL 0 or 1 on a packet not destined for the router itself → drop + count (ICMP time-exceeded
  deferred, same reasoning as ARP above).
- Checksum after TTL decrement is recomputed **incrementally** (RFC 1624 formula), not from scratch —
  this is a deliberate perf decision worth preserving even at this project's scale, since it's the
  kind of detail the project exists to teach.

### 10.5 Routing Engine
- LPM via a binary (radix) trie keyed on prefix bits — chosen over a linear scan for correctness/perf
  illustration, and over DIR-24-8 for v1 implementation clarity. DIR-24-8 or a Patricia trie is a
  documented future perf pass, not a v1 requirement.

### 10.6 NAT Engine
- Connection tracking table keyed by 5-tuple (`protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`),
  `std::unordered_map`.
- **Source NAT (masquerade) only** in v1 — no destination NAT / full-cone NAT (future).
- Ephemeral port range default `49152–65535` (IANA dynamic range), allocated from a free-list, not a
  linear counter, to make reuse after session close O(1).
- Session timeouts mirror common conntrack defaults rather than being invented: TCP established
  3600s idle, TCP unestablished 120s idle (simplified SYN/ESTABLISHED/FIN state, not a full TCP state
  machine), UDP 30s idle.

### 10.7 Firewall
- Rule set: `std::vector<Rule>`, evaluated top-down, **first match wins**.
- **Default-deny fallback if no ALLOW rule matches** — this must be explicit in config, never an
  implicit fallthrough, so a missing rule fails closed and visibly rather than silently.
- v1 is stateless. Stateful inspection/connection tracking integration with §10.6 is a documented
  future milestone, not a v1 requirement, even though the NAT engine already tracks connections —
  don't wire firewall statefulness through the NAT conntrack table opportunistically; it needs its
  own design pass.

### 10.8 Packet Forwarder
- Rewrites destination MAC (from ARP resolution) and source MAC (from egress interface identity).
  TTL/checksum are **not** touched here — that happened in §10.4; don't duplicate it.
- Transmits via `pcap_sendpacket`. Buffer is returned to the pool (§5) after transmit, success or
  failure alike.

---

## 11. Windows API Usage

- **Npcap** is the raw capture/transmit path. Do **not** use `SOCK_RAW` sockets as the primary
  mechanism — Npcap gives true L2 access, which is what a router needs.
- **IP Helper API** (`GetAdaptersAddresses`, `GetIpForwardTable2`) is used only at startup for
  interface enumeration — never called per-packet.
- **Windows Routing APIs** (`CreateIpForwardEntry2` etc.) are explicitly **not** used to inject
  routes into the OS routing table. Atlas maintains its own routing table entirely in user space —
  this is a deliberate decision to avoid two sources of truth for "where does this packet go," not
  an oversight. Do not add OS route injection without revisiting this section first.

---

## 12. Testing

- **Unit tests (GoogleTest):** per module — Ethernet parsing, IPv4 checksum (including the
  incremental-update path from §10.4), ARP cache expiry, LPM trie correctness, NAT port allocation.
- **Integration tests:** replay checked-in `.pcap` fixtures (`tests/fixtures/`) through the pipeline
  rather than requiring a live NIC or admin privileges — Npcap raw capture needs elevation, which
  integration tests should not depend on.
- CI (when set up) needs a self-hosted Windows runner — Npcap is Windows-only, there is no portable
  fallback.

---

## 13. Style Conventions

- Files: `snake_case.cpp` / `snake_case.hpp`
- Types: `PascalCase`
- Functions/methods: `camelCase`
- Member variables: trailing underscore (`buffer_`, `cache_`)
- Constants: `kPascalCase`; `ALL_CAPS` reserved for preprocessor macros only
- Header guards: `#pragma once`
- Never `using namespace std;` in a header

---

## 14. Change Policy

When a new implementation decision is made during development, add it to the relevant section above
in the same PR/commit as the code that depends on it. This file should never lag behind what the
codebase actually does — an agent picking up this project cold should be able to trust every line here.