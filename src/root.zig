//! DHCP protocol encoding and decoding.

/// DHCPv4 (RFC 2131, RFC 2132).
pub const v4 = @import("v4.zig");

test {
    _ = v4;
}
