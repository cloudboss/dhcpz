# Claude Code Instructions for dhcpz

A DHCP protocol library for Zig.

## Project Overview

- **Language**: Zig 0.15.2
- **Purpose**: DHCP message encoding/decoding

## Build Commands

```bash
zig build test    # Run unit tests
```

## Code Style

### Memory Management

- All slice data in `Option` must be heap-allocated
- `Message.deinit()` frees all option data
- When appending options with slice data, ownership transfers to the Message
- Use `errdefer` for cleanup on error paths

### API Design

- `Message.encode()` writes to a caller-provided buffer
- `Message.decode()` allocates and returns owned data
- Builder functions (`createDiscover`, `createRequest`) allocate necessary data

## File Structure

```
src/
  root.zig    # Re-exports v4 (and v6 when added)
  v4.zig      # DHCPv4 types, encode/decode, builders, tests
```

## Supported DHCP Options

| Option | Code | Description |
|--------|------|-------------|
| Subnet Mask | 1 | Network mask |
| Router | 3 | Default gateway(s) |
| DNS | 6 | DNS server(s) |
| Domain Name | 15 | Domain name string |
| Requested IP | 50 | Client's requested address |
| Message Type | 53 | DHCP message type |
| Server ID | 54 | DHCP server identifier |
| Parameter List | 55 | Requested options |
| Max Size | 57 | Maximum message size |
| Domain Search | 119 | Search domain list |

## Testing

Tests cover:
- DHCPDISCOVER encode/decode round-trip
- DHCPREQUEST encode/decode round-trip
- DHCP response parsing with multiple options
- Domain search list encode/decode
