# dhcpz

A DHCP protocol library for Zig.

## Installation

```bash
zig fetch --save git+https://github.com/cloudboss/dhcpz
```

Then in your `build.zig`:

```zig
const dhcpz = b.dependency("dhcpz", .{
    .target = target,
});
exe.root_module.addImport("dhcpz", dhcpz.module("dhcpz"));
```

## Example

```zig
const std = @import("std");
const v4 = @import("dhcpz").v4;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create DHCPDISCOVER
    const mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    var discover = try v4.createDiscover(allocator, 0x12345678, mac);
    defer discover.deinit();

    // Encode to bytes
    var buf: [1500]u8 = undefined;
    const len = try discover.encode(&buf);

    // Send buf[0..len] over UDP to port 67...

    // Decode response
    var response = try v4.Message.decode(allocator, received_data);
    defer response.deinit();

    // Check message type
    if (response.options.getMessageType()) |msg_type| {
        if (msg_type == .offer) {
            // Handle DHCPOFFER
            const offered_ip = response.yiaddr;
            const subnet = response.options.get(.subnet_mask);
            const gateway = response.options.get(.router);
            // ...
        }
    }
}
```

## API

All DHCPv4 types are under `dhcpz.v4`.

### Types

- `v4.Message` - DHCP message with header fields and options
- `v4.Option` - Tagged union of all supported option types
- `v4.MessageType` - DISCOVER, OFFER, REQUEST, ACK, NAK, etc.
- `v4.OptionCode` - Option type codes
- `v4.Ipv4Addr` - `[4]u8` alias for IPv4 addresses

### Functions

- `v4.createDiscover(allocator, xid, mac)` - Create DHCPDISCOVER message
- `v4.createRequest(allocator, xid, mac, requested_ip, server_id)` - Create DHCPREQUEST message

### Message Methods

- `Message.init(allocator)` - Create empty message
- `Message.deinit()` - Free all allocated memory
- `Message.encode(buf)` - Encode to bytes, returns length
- `Message.decode(allocator, data)` - Decode from bytes
- `Message.setXid(xid)` - Set transaction ID
- `Message.setChaddr(mac)` - Set client hardware address
- `Message.setBroadcast(bool)` - Set broadcast flag

### Options Methods

- `Options.append(option)` - Add an option (takes ownership of slice data)
- `Options.get(tag)` - Get option by tag, returns payload or null
- `Options.getMessageType()` - Convenience for getting message type

## Building

```bash
zig build test
```

## License

MIT
