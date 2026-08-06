# Atlas Software Router — Documentation Index

This directory contains design specifications, architectural principles, and component breakdowns for the Atlas software router project.

## Table of Contents

1. [00. Overview & Architecture Principles](file:///d:/atlas/docs/00_overview.md)
   - Project Identity & Non-goals
   - Core Architectural Principles (P1 - P9)
   - Toolchain & Build Environment

2. [01. Forwarding Pipeline](file:///d:/atlas/docs/01_pipeline.md)
   - 14-Stage Packet Pipeline Flowchart
   - Execution Contract & Non-Throwing Data Path
   - PacketID Tracing & ARP Packet Queueing

3. [02. Component Architecture](file:///d:/atlas/docs/02_components.md)
   - Network Interface Manager (`interfaces/`)
   - Ethernet Layer (`ethernet/`)
   - ARP Engine (`arp/`)
   - IPv4 Engine (`ipv4/`)
   - Routing Engine (`routing/`)
   - NAT Engine (`nat/`)
   - Firewall (`firewall/`)
   - Forwarding Composition Root (`forwarding/`)

4. [03. Core Data Structures & Error Handling](file:///d:/atlas/docs/03_data_structures.md)
   - `Packet` Struct Layout
   - IP and MAC Address Wrappers
   - `Result<T, E>` Error Handling Type

5. [04. Configuration System](file:///d:/atlas/docs/04_configuration.md)
   - JSON Schema & Sample Configuration
   - Startup Configuration Validation

6. [05. Implementation Roadmap & Testing](file:///d:/atlas/docs/05_phasing_and_testing.md)
   - Implementation Phases (Phase 1 to Phase 4)
   - GoogleTest Unit & Integration Testing Strategy
