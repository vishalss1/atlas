# The Forwarding Pipeline

Every packet entering the Atlas router traverses a strict 14-stage linear processing pipeline.

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

## Pipeline Execution Contract

1. **Composition Root:** `forwarding::forward(ctx, pkt)` is the sole entry point executing the stages sequentially.
2. **Non-Throwing Data Path:** Stages return `Result<T>` or a `Verdict`. Errors (`DropError`) signal packet drop as a normal control-flow outcome, never throwing C++ exceptions.
3. **Tracing & PacketID:** Every ingress frame is assigned a monotonic `PacketID uint64_t`. All logging across every pipeline stage attaches this `packet_id`.
4. **ARP Suspension:** If ARP resolution returns `Pending`, the packet is queued in `arp::Engine`'s pending queue. Upon ARP reply receipt, the packet is resumed directly at Stage 13 (frame construction & transmit) without re-running routing, firewall, or NAT.
