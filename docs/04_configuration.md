# Configuration System

Atlas uses JSON format (`nlohmann/json`) for runtime network configuration.

## Sample Configuration (`config.json`)

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

## Validation Strategy
The `config::load(path)` parser executes strict validation prior to engine startup:
1. **Interface Check:** Verifies all referenced interfaces exist and specify valid Npcap device GUIDs.
2. **Route Integrity:** Verifies routes reference declared interfaces and valid CIDR blocks.
3. **NAT Rules:** Ensures `outside_ip` is valid and port ranges are non-inverted (`start <= end`).
4. **Firewall Rules:** Verifies valid protocols (`tcp`, `udp`, `icmp`, `all`) and port bounds.
