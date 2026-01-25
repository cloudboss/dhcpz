//! DHCPv4 protocol encoding and decoding.
//!
//! This module provides types and functions for working with DHCPv4 messages
//! as defined in RFC 2131 and RFC 2132.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// DHCP client port (bootpc).
pub const CLIENT_PORT: u16 = 68;
/// DHCP server port (bootps).
pub const SERVER_PORT: u16 = 67;

const MAGIC_COOKIE: [4]u8 = .{ 0x63, 0x82, 0x53, 0x63 };

/// BOOTP message operation code.
pub const OpCode = enum(u8) {
    boot_request = 1,
    boot_reply = 2,
};

/// Hardware address type.
pub const HType = enum(u8) {
    ethernet = 1,
};

/// DHCP message type (option 53).
pub const MessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
};

/// DHCP option codes.
pub const OptionCode = enum(u8) {
    pad = 0,
    subnet_mask = 1,
    router = 3,
    domain_name_server = 6,
    domain_name = 15,
    requested_ip_address = 50,
    message_type = 53,
    server_identifier = 54,
    parameter_request_list = 55,
    max_message_size = 57,
    domain_search = 119,
    end = 255,
    _,
};

/// IPv4 address as 4 bytes in network order.
pub const Ipv4Addr = [4]u8;

fn freeOptionCodes(allocator: Allocator, list: []const OptionCode) void {
    const ptr: [*]const u8 = @ptrCast(list.ptr);
    allocator.free(ptr[0..list.len]);
}

/// A DHCP option value.
/// Slice fields are heap-allocated and freed by `deinit`.
pub const Option = union(enum) {
    subnet_mask: Ipv4Addr,
    router: []const Ipv4Addr,
    domain_name_server: []const Ipv4Addr,
    domain_name: []const u8,
    requested_ip_address: Ipv4Addr,
    message_type: MessageType,
    server_identifier: Ipv4Addr,
    parameter_request_list: []const OptionCode,
    max_message_size: u16,
    domain_search: []const []const u8,
    unknown: struct {
        code: u8,
        data: []const u8,
    },

    /// Free heap-allocated option data.
    pub fn deinit(self: *Option, allocator: Allocator) void {
        switch (self.*) {
            .router => |addrs| allocator.free(addrs),
            .domain_name_server => |addrs| allocator.free(addrs),
            .domain_name => |name| allocator.free(name),
            .parameter_request_list => |list| freeOptionCodes(allocator, list),
            .domain_search => |names| {
                for (names) |name| {
                    allocator.free(name);
                }
                allocator.free(names);
            },
            .unknown => |u| allocator.free(u.data),
            else => {},
        }
    }
};

/// Collection of DHCP options.
pub const Options = struct {
    items: std.ArrayList(Option) = .empty,
    allocator: Allocator,

    pub fn init(allocator: Allocator) Options {
        return .{ .allocator = allocator };
    }

    /// Free all options and their heap-allocated data.
    pub fn deinit(self: *Options) void {
        for (self.items.items) |*item| {
            item.deinit(self.allocator);
        }
        self.items.deinit(self.allocator);
    }

    /// Add an option. Takes ownership of any heap-allocated data in the option.
    pub fn append(self: *Options, option: Option) !void {
        try self.items.append(self.allocator, option);
    }

    /// Get an option by tag, returns the payload or null if not present.
    pub fn get(self: *const Options, comptime tag: std.meta.Tag(Option)) ?std.meta.TagPayload(Option, tag) {
        for (self.items.items) |item| {
            if (item == tag) {
                return @field(item, @tagName(tag));
            }
        }
        return null;
    }

    /// Get the DHCP message type option.
    pub fn getMessageType(self: *const Options) ?MessageType {
        return self.get(.message_type);
    }
};

/// A DHCPv4 message (RFC 2131).
pub const Message = struct {
    op: OpCode = .boot_request,
    htype: HType = .ethernet,
    hlen: u8 = 6,
    hops: u8 = 0,
    /// Transaction ID.
    xid: u32 = 0,
    /// Seconds elapsed since client began address acquisition.
    secs: u16 = 0,
    flags: u16 = 0,
    /// Client IP address (filled in if client has a valid IP).
    ciaddr: Ipv4Addr = .{ 0, 0, 0, 0 },
    /// "Your" IP address (assigned by server).
    yiaddr: Ipv4Addr = .{ 0, 0, 0, 0 },
    /// Server IP address.
    siaddr: Ipv4Addr = .{ 0, 0, 0, 0 },
    /// Gateway IP address (relay agent).
    giaddr: Ipv4Addr = .{ 0, 0, 0, 0 },
    /// Client hardware address.
    chaddr: [16]u8 = .{0} ** 16,
    /// Server host name.
    sname: [64]u8 = .{0} ** 64,
    /// Boot file name.
    file: [128]u8 = .{0} ** 128,
    options: Options,

    const HEADER_SIZE = 236;
    const MIN_PACKET_SIZE = HEADER_SIZE + 4;

    /// Create a new message with default values.
    pub fn init(allocator: Allocator) Message {
        return .{ .options = Options.init(allocator) };
    }

    /// Free all allocated memory.
    pub fn deinit(self: *Message) void {
        self.options.deinit();
    }

    /// Set transaction ID.
    pub fn setXid(self: *Message, xid: u32) *Message {
        self.xid = xid;
        return self;
    }

    /// Set client hardware address (MAC).
    pub fn setChaddr(self: *Message, mac: [6]u8) *Message {
        @memcpy(self.chaddr[0..6], &mac);
        return self;
    }

    /// Set or clear the broadcast flag.
    pub fn setBroadcast(self: *Message, broadcast: bool) *Message {
        if (broadcast) {
            self.flags |= 0x8000;
        } else {
            self.flags &= ~@as(u16, 0x8000);
        }
        return self;
    }

    /// Encode the message to bytes. Returns the number of bytes written.
    pub fn encode(self: *const Message, buf: []u8) !usize {
        if (buf.len < MIN_PACKET_SIZE) {
            return error.BufferTooSmall;
        }

        buf[0] = @intFromEnum(self.op);
        buf[1] = @intFromEnum(self.htype);
        buf[2] = self.hlen;
        buf[3] = self.hops;
        mem.writeInt(u32, buf[4..8], self.xid, .big);
        mem.writeInt(u16, buf[8..10], self.secs, .big);
        mem.writeInt(u16, buf[10..12], self.flags, .big);
        @memcpy(buf[12..16], &self.ciaddr);
        @memcpy(buf[16..20], &self.yiaddr);
        @memcpy(buf[20..24], &self.siaddr);
        @memcpy(buf[24..28], &self.giaddr);
        @memcpy(buf[28..44], &self.chaddr);
        @memcpy(buf[44..108], &self.sname);
        @memcpy(buf[108..236], &self.file);

        // Magic cookie
        @memcpy(buf[236..240], &MAGIC_COOKIE);

        // Options
        var pos: usize = 240;
        for (self.options.items.items) |opt| {
            pos = try encodeOption(opt, buf, pos);
        }

        // End option
        if (pos >= buf.len) {
            return error.BufferTooSmall;
        }
        buf[pos] = @intFromEnum(OptionCode.end);
        pos += 1;

        return pos;
    }

    /// Decode a message from bytes. Caller owns the returned message.
    pub fn decode(allocator: Allocator, data: []const u8) !Message {
        if (data.len < MIN_PACKET_SIZE) {
            return error.PacketTooShort;
        }

        // Verify magic cookie
        if (!mem.eql(u8, data[236..240], &MAGIC_COOKIE)) {
            return error.InvalidMagicCookie;
        }

        var msg = Message.init(allocator);
        errdefer msg.deinit();

        msg.op = @enumFromInt(data[0]);
        msg.htype = @enumFromInt(data[1]);
        msg.hlen = data[2];
        msg.hops = data[3];
        msg.xid = mem.readInt(u32, data[4..8], .big);
        msg.secs = mem.readInt(u16, data[8..10], .big);
        msg.flags = mem.readInt(u16, data[10..12], .big);
        @memcpy(&msg.ciaddr, data[12..16]);
        @memcpy(&msg.yiaddr, data[16..20]);
        @memcpy(&msg.siaddr, data[20..24]);
        @memcpy(&msg.giaddr, data[24..28]);
        @memcpy(&msg.chaddr, data[28..44]);
        @memcpy(&msg.sname, data[44..108]);
        @memcpy(&msg.file, data[108..236]);

        // Parse options
        var pos: usize = 240;
        while (pos < data.len) {
            const code: OptionCode = @enumFromInt(data[pos]);
            pos += 1;

            if (code == .end) break;
            if (code == .pad) continue;

            if (pos >= data.len) return error.TruncatedOption;
            const len = data[pos];
            pos += 1;

            if (pos + len > data.len) return error.TruncatedOption;
            const option_data = data[pos .. pos + len];
            pos += len;

            const opt = try decodeOption(allocator, code, option_data);
            try msg.options.append(opt);
        }

        return msg;
    }
};

fn encodeOption(opt: Option, buf: []u8, pos: usize) !usize {
    var p = pos;
    switch (opt) {
        .message_type => |mt| {
            if (p + 3 > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.message_type);
            buf[p + 1] = 1;
            buf[p + 2] = @intFromEnum(mt);
            p += 3;
        },
        .requested_ip_address => |addr| {
            if (p + 6 > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.requested_ip_address);
            buf[p + 1] = 4;
            @memcpy(buf[p + 2 .. p + 6], &addr);
            p += 6;
        },
        .server_identifier => |addr| {
            if (p + 6 > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.server_identifier);
            buf[p + 1] = 4;
            @memcpy(buf[p + 2 .. p + 6], &addr);
            p += 6;
        },
        .parameter_request_list => |list| {
            const len: u8 = @intCast(list.len);
            if (p + 2 + len > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.parameter_request_list);
            buf[p + 1] = len;
            for (list, 0..) |code, i| {
                buf[p + 2 + i] = @intFromEnum(code);
            }
            p += 2 + len;
        },
        .max_message_size => |size| {
            if (p + 4 > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.max_message_size);
            buf[p + 1] = 2;
            mem.writeInt(u16, buf[p + 2 .. p + 4][0..2], size, .big);
            p += 4;
        },
        .subnet_mask => |mask| {
            if (p + 6 > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.subnet_mask);
            buf[p + 1] = 4;
            @memcpy(buf[p + 2 .. p + 6], &mask);
            p += 6;
        },
        .router => |addrs| {
            const len: u8 = @intCast(addrs.len * 4);
            if (p + 2 + len > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.router);
            buf[p + 1] = len;
            for (addrs, 0..) |addr, i| {
                @memcpy(buf[p + 2 + i * 4 .. p + 2 + (i + 1) * 4], &addr);
            }
            p += 2 + len;
        },
        .domain_name_server => |addrs| {
            const len: u8 = @intCast(addrs.len * 4);
            if (p + 2 + len > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.domain_name_server);
            buf[p + 1] = len;
            for (addrs, 0..) |addr, i| {
                @memcpy(buf[p + 2 + i * 4 .. p + 2 + (i + 1) * 4], &addr);
            }
            p += 2 + len;
        },
        .domain_name => |name| {
            const len: u8 = @intCast(name.len);
            if (p + 2 + len > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.domain_name);
            buf[p + 1] = len;
            @memcpy(buf[p + 2 .. p + 2 + len], name);
            p += 2 + len;
        },
        .domain_search => |names| {
            // RFC 1035 compressed domain name encoding
            var encoded: [255]u8 = undefined;
            var encoded_len: usize = 0;
            for (names) |name| {
                var iter = mem.splitScalar(u8, name, '.');
                while (iter.next()) |label| {
                    if (label.len == 0) continue;
                    if (encoded_len + 1 + label.len > encoded.len) return error.BufferTooSmall;
                    encoded[encoded_len] = @intCast(label.len);
                    encoded_len += 1;
                    @memcpy(encoded[encoded_len .. encoded_len + label.len], label);
                    encoded_len += label.len;
                }
                if (encoded_len >= encoded.len) return error.BufferTooSmall;
                encoded[encoded_len] = 0; // null terminator for domain
                encoded_len += 1;
            }
            const len: u8 = @intCast(encoded_len);
            if (p + 2 + len > buf.len) return error.BufferTooSmall;
            buf[p] = @intFromEnum(OptionCode.domain_search);
            buf[p + 1] = len;
            @memcpy(buf[p + 2 .. p + 2 + len], encoded[0..encoded_len]);
            p += 2 + len;
        },
        .unknown => |u| {
            const len: u8 = @intCast(u.data.len);
            if (p + 2 + len > buf.len) return error.BufferTooSmall;
            buf[p] = u.code;
            buf[p + 1] = len;
            @memcpy(buf[p + 2 .. p + 2 + len], u.data);
            p += 2 + len;
        },
    }
    return p;
}

fn decodeOption(allocator: Allocator, code: OptionCode, data: []const u8) !Option {
    switch (code) {
        .message_type => {
            if (data.len < 1) return error.InvalidOptionLength;
            return .{ .message_type = @enumFromInt(data[0]) };
        },
        .subnet_mask => {
            if (data.len < 4) return error.InvalidOptionLength;
            return .{ .subnet_mask = data[0..4].* };
        },
        .router => {
            if (data.len < 4 or data.len % 4 != 0) return error.InvalidOptionLength;
            const count = data.len / 4;
            const addrs = try allocator.alloc(Ipv4Addr, count);
            for (0..count) |i| {
                addrs[i] = data[i * 4 ..][0..4].*;
            }
            return .{ .router = addrs };
        },
        .domain_name_server => {
            if (data.len < 4 or data.len % 4 != 0) return error.InvalidOptionLength;
            const count = data.len / 4;
            const addrs = try allocator.alloc(Ipv4Addr, count);
            for (0..count) |i| {
                addrs[i] = data[i * 4 ..][0..4].*;
            }
            return .{ .domain_name_server = addrs };
        },
        .domain_name => {
            const name = try allocator.dupe(u8, data);
            return .{ .domain_name = name };
        },
        .requested_ip_address => {
            if (data.len < 4) return error.InvalidOptionLength;
            return .{ .requested_ip_address = data[0..4].* };
        },
        .server_identifier => {
            if (data.len < 4) return error.InvalidOptionLength;
            return .{ .server_identifier = data[0..4].* };
        },
        .parameter_request_list => {
            const list = try allocator.alloc(OptionCode, data.len);
            for (data, 0..) |byte, i| {
                list[i] = @enumFromInt(byte);
            }
            return .{ .parameter_request_list = list };
        },
        .max_message_size => {
            if (data.len < 2) return error.InvalidOptionLength;
            return .{ .max_message_size = mem.readInt(u16, data[0..2], .big) };
        },
        .domain_search => {
            // RFC 1035 compressed domain name decoding
            var names: std.ArrayList([]const u8) = .empty;
            errdefer {
                for (names.items) |name| allocator.free(name);
                names.deinit(allocator);
            }

            var pos: usize = 0;
            while (pos < data.len) {
                var name_buf: [256]u8 = undefined;
                var name_len: usize = 0;

                while (pos < data.len and data[pos] != 0) {
                    const label_len = data[pos];
                    pos += 1;
                    if (pos + label_len > data.len) return error.InvalidDomainName;
                    if (name_len > 0) {
                        if (name_len >= name_buf.len) return error.DomainNameTooLong;
                        name_buf[name_len] = '.';
                        name_len += 1;
                    }
                    if (name_len + label_len > name_buf.len) return error.DomainNameTooLong;
                    @memcpy(name_buf[name_len .. name_len + label_len], data[pos .. pos + label_len]);
                    name_len += label_len;
                    pos += label_len;
                }
                if (pos < data.len) pos += 1; // skip null terminator

                if (name_len > 0) {
                    const name = try allocator.dupe(u8, name_buf[0..name_len]);
                    try names.append(allocator, name);
                }
            }

            return .{ .domain_search = try names.toOwnedSlice(allocator) };
        },
        else => {
            const dup = try allocator.dupe(u8, data);
            return .{ .unknown = .{ .code = @intFromEnum(code), .data = dup } };
        },
    }
}

/// Create a DHCPDISCOVER message.
pub fn createDiscover(allocator: Allocator, xid: u32, mac: [6]u8) !Message {
    var msg = Message.init(allocator);
    errdefer msg.deinit();

    _ = msg.setXid(xid).setChaddr(mac).setBroadcast(true);
    try msg.options.append(.{ .message_type = .discover });

    const param_list = try allocator.dupe(OptionCode, &[_]OptionCode{
        .subnet_mask,
        .router,
        .domain_name_server,
        .domain_name,
        .domain_search,
    });
    msg.options.append(.{ .parameter_request_list = param_list }) catch |err| {
        freeOptionCodes(allocator, param_list);
        return err;
    };
    try msg.options.append(.{ .max_message_size = 1500 });

    return msg;
}

/// Create a DHCPREQUEST message.
pub fn createRequest(
    allocator: Allocator,
    xid: u32,
    mac: [6]u8,
    requested_ip: Ipv4Addr,
    server_id: Ipv4Addr,
) !Message {
    var msg = Message.init(allocator);
    errdefer msg.deinit();

    _ = msg.setXid(xid).setChaddr(mac).setBroadcast(true);
    try msg.options.append(.{ .message_type = .request });
    try msg.options.append(.{ .requested_ip_address = requested_ip });
    try msg.options.append(.{ .server_identifier = server_id });
    try msg.options.append(.{ .max_message_size = 1500 });

    return msg;
}

test "encode and decode DHCPDISCOVER" {
    const allocator = std.testing.allocator;
    const mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

    var msg = try createDiscover(allocator, 0x12345678, mac);
    defer msg.deinit();

    var buf: [1500]u8 = undefined;
    const len = try msg.encode(&buf);

    var decoded = try Message.decode(allocator, buf[0..len]);
    defer decoded.deinit();

    try std.testing.expectEqual(@as(u32, 0x12345678), decoded.xid);
    try std.testing.expectEqual(OpCode.boot_request, decoded.op);
    try std.testing.expectEqual(HType.ethernet, decoded.htype);
    try std.testing.expectEqualSlices(u8, &mac, decoded.chaddr[0..6]);
    try std.testing.expectEqual(MessageType.discover, decoded.options.getMessageType().?);
}

test "encode and decode DHCPREQUEST" {
    const allocator = std.testing.allocator;
    const mac = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    const requested_ip = [4]u8{ 192, 168, 1, 100 };
    const server_id = [4]u8{ 192, 168, 1, 1 };

    var msg = try createRequest(allocator, 0xABCDEF01, mac, requested_ip, server_id);
    defer msg.deinit();

    var buf: [1500]u8 = undefined;
    const len = try msg.encode(&buf);

    var decoded = try Message.decode(allocator, buf[0..len]);
    defer decoded.deinit();

    try std.testing.expectEqual(@as(u32, 0xABCDEF01), decoded.xid);
    try std.testing.expectEqual(MessageType.request, decoded.options.getMessageType().?);
    try std.testing.expectEqualSlices(u8, &requested_ip, &decoded.options.get(.requested_ip_address).?);
    try std.testing.expectEqualSlices(u8, &server_id, &decoded.options.get(.server_identifier).?);
}

test "decode DHCP response with options" {
    const allocator = std.testing.allocator;

    var buf: [300]u8 = .{0} ** 300;
    buf[0] = 2; // BOOTREPLY
    buf[1] = 1; // Ethernet
    buf[2] = 6; // MAC len
    mem.writeInt(u32, buf[4..8], 0x12345678, .big);
    // yiaddr
    buf[16] = 192;
    buf[17] = 168;
    buf[18] = 1;
    buf[19] = 100;
    // magic cookie
    @memcpy(buf[236..240], &MAGIC_COOKIE);
    // options
    var pos: usize = 240;
    // message type = ACK
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = 5;
    pos += 3;
    // subnet mask
    buf[pos] = 1;
    buf[pos + 1] = 4;
    buf[pos + 2] = 255;
    buf[pos + 3] = 255;
    buf[pos + 4] = 255;
    buf[pos + 5] = 0;
    pos += 6;
    // router
    buf[pos] = 3;
    buf[pos + 1] = 4;
    buf[pos + 2] = 192;
    buf[pos + 3] = 168;
    buf[pos + 4] = 1;
    buf[pos + 5] = 1;
    pos += 6;
    // DNS server
    buf[pos] = 6;
    buf[pos + 1] = 4;
    buf[pos + 2] = 8;
    buf[pos + 3] = 8;
    buf[pos + 4] = 8;
    buf[pos + 5] = 8;
    pos += 6;
    // end
    buf[pos] = 255;

    var msg = try Message.decode(allocator, buf[0 .. pos + 1]);
    defer msg.deinit();

    try std.testing.expectEqual(OpCode.boot_reply, msg.op);
    try std.testing.expectEqual(@as(u32, 0x12345678), msg.xid);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 100 }, &msg.yiaddr);
    try std.testing.expectEqual(MessageType.ack, msg.options.getMessageType().?);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 255, 255, 255, 0 }, &msg.options.get(.subnet_mask).?);

    const routers = msg.options.get(.router).?;
    try std.testing.expectEqual(@as(usize, 1), routers.len);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 1 }, &routers[0]);

    const dns = msg.options.get(.domain_name_server).?;
    try std.testing.expectEqual(@as(usize, 1), dns.len);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 8, 8, 8, 8 }, &dns[0]);
}

test "domain search encode and decode" {
    const allocator = std.testing.allocator;

    var msg = Message.init(allocator);
    defer msg.deinit();

    // Allocate search list (ownership transfers to msg)
    const name1 = try allocator.dupe(u8, "example.com");
    const name2 = try allocator.dupe(u8, "test.local");
    var names_buf = [_][]const u8{ name1, name2 };
    const search_list = try allocator.dupe([]const u8, &names_buf);
    msg.options.append(.{ .domain_search = search_list }) catch |err| {
        allocator.free(name1);
        allocator.free(name2);
        allocator.free(search_list);
        return err;
    };

    var buf: [1500]u8 = undefined;
    const len = try msg.encode(&buf);

    var decoded = try Message.decode(allocator, buf[0..len]);
    defer decoded.deinit();

    const decoded_search = decoded.options.get(.domain_search).?;
    try std.testing.expectEqual(@as(usize, 2), decoded_search.len);
    try std.testing.expectEqualStrings("example.com", decoded_search[0]);
    try std.testing.expectEqualStrings("test.local", decoded_search[1]);
}

test "decode error: packet too short" {
    const allocator = std.testing.allocator;
    const short_packet = [_]u8{0} ** 100;
    try std.testing.expectError(error.PacketTooShort, Message.decode(allocator, &short_packet));
}

test "decode error: invalid magic cookie" {
    const allocator = std.testing.allocator;
    var buf: [300]u8 = .{0} ** 300;
    buf[0] = 1; // BOOTREQUEST
    buf[1] = 1; // Ethernet
    buf[2] = 6;
    // Wrong magic cookie
    buf[236] = 0x00;
    buf[237] = 0x00;
    buf[238] = 0x00;
    buf[239] = 0x00;
    buf[240] = 255; // end option

    try std.testing.expectError(error.InvalidMagicCookie, Message.decode(allocator, buf[0..241]));
}

test "decode error: truncated option" {
    const allocator = std.testing.allocator;
    var buf: [300]u8 = .{0} ** 300;
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    @memcpy(buf[236..240], &MAGIC_COOKIE);
    // Option with length that exceeds remaining data
    buf[240] = 53; // message type
    buf[241] = 10; // length claims 10 bytes but we only provide 1
    buf[242] = 5;
    // No end marker, packet ends here

    try std.testing.expectError(error.TruncatedOption, Message.decode(allocator, buf[0..243]));
}

test "encode error: buffer too small" {
    const allocator = std.testing.allocator;
    var msg = Message.init(allocator);
    defer msg.deinit();

    var small_buf: [100]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, msg.encode(&small_buf));
}

test "decode multiple routers and DNS servers" {
    const allocator = std.testing.allocator;

    var buf: [300]u8 = .{0} ** 300;
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    @memcpy(buf[236..240], &MAGIC_COOKIE);

    var pos: usize = 240;
    // Two routers
    buf[pos] = 3; // router
    buf[pos + 1] = 8; // 2 addresses
    buf[pos + 2] = 192;
    buf[pos + 3] = 168;
    buf[pos + 4] = 1;
    buf[pos + 5] = 1;
    buf[pos + 6] = 192;
    buf[pos + 7] = 168;
    buf[pos + 8] = 1;
    buf[pos + 9] = 2;
    pos += 10;

    // Three DNS servers
    buf[pos] = 6; // DNS
    buf[pos + 1] = 12; // 3 addresses
    buf[pos + 2] = 8;
    buf[pos + 3] = 8;
    buf[pos + 4] = 8;
    buf[pos + 5] = 8;
    buf[pos + 6] = 8;
    buf[pos + 7] = 8;
    buf[pos + 8] = 4;
    buf[pos + 9] = 4;
    buf[pos + 10] = 1;
    buf[pos + 11] = 1;
    buf[pos + 12] = 1;
    buf[pos + 13] = 1;
    pos += 14;

    buf[pos] = 255; // end

    var msg = try Message.decode(allocator, buf[0 .. pos + 1]);
    defer msg.deinit();

    const routers = msg.options.get(.router).?;
    try std.testing.expectEqual(@as(usize, 2), routers.len);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 1 }, &routers[0]);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 2 }, &routers[1]);

    const dns = msg.options.get(.domain_name_server).?;
    try std.testing.expectEqual(@as(usize, 3), dns.len);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 8, 8, 8, 8 }, &dns[0]);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 8, 8, 4, 4 }, &dns[1]);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 1, 1, 1, 1 }, &dns[2]);
}

test "decode unknown option passthrough" {
    const allocator = std.testing.allocator;

    var buf: [300]u8 = .{0} ** 300;
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    @memcpy(buf[236..240], &MAGIC_COOKIE);

    var pos: usize = 240;
    // Unknown option code 250 with some data
    buf[pos] = 250;
    buf[pos + 1] = 4;
    buf[pos + 2] = 0xDE;
    buf[pos + 3] = 0xAD;
    buf[pos + 4] = 0xBE;
    buf[pos + 5] = 0xEF;
    pos += 6;
    buf[pos] = 255;

    var msg = try Message.decode(allocator, buf[0 .. pos + 1]);
    defer msg.deinit();

    const unknown = msg.options.get(.unknown).?;
    try std.testing.expectEqual(@as(u8, 250), unknown.code);
    try std.testing.expectEqualSlices(u8, &[4]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, unknown.data);
}

test "decode with pad options" {
    const allocator = std.testing.allocator;

    var buf: [300]u8 = .{0} ** 300;
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    @memcpy(buf[236..240], &MAGIC_COOKIE);

    var pos: usize = 240;
    // Pad options (code 0, no length byte)
    buf[pos] = 0; // pad
    pos += 1;
    buf[pos] = 0; // pad
    pos += 1;
    // Message type
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = 5; // ACK
    pos += 3;
    buf[pos] = 0; // pad
    pos += 1;
    buf[pos] = 255; // end

    var msg = try Message.decode(allocator, buf[0 .. pos + 1]);
    defer msg.deinit();

    try std.testing.expectEqual(MessageType.ack, msg.options.getMessageType().?);
}

test "domain name option" {
    const allocator = std.testing.allocator;

    var buf: [300]u8 = .{0} ** 300;
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    @memcpy(buf[236..240], &MAGIC_COOKIE);

    var pos: usize = 240;
    // Domain name option
    const domain = "example.com";
    buf[pos] = 15; // domain name
    buf[pos + 1] = @intCast(domain.len);
    @memcpy(buf[pos + 2 .. pos + 2 + domain.len], domain);
    pos += 2 + domain.len;
    buf[pos] = 255;

    var msg = try Message.decode(allocator, buf[0 .. pos + 1]);
    defer msg.deinit();

    try std.testing.expectEqualStrings("example.com", msg.options.get(.domain_name).?);
}

test "minimum valid packet" {
    const allocator = std.testing.allocator;

    // Minimum: 236 byte header + 4 byte magic cookie + 1 byte end option
    var buf: [241]u8 = .{0} ** 241;
    buf[0] = 1; // BOOTREQUEST
    buf[1] = 1; // Ethernet
    buf[2] = 6;
    @memcpy(buf[236..240], &MAGIC_COOKIE);
    buf[240] = 255; // end

    var msg = try Message.decode(allocator, &buf);
    defer msg.deinit();

    try std.testing.expectEqual(OpCode.boot_request, msg.op);
    try std.testing.expectEqual(@as(?MessageType, null), msg.options.getMessageType());
}

test "max message size option" {
    const allocator = std.testing.allocator;

    var buf: [300]u8 = .{0} ** 300;
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 6;
    @memcpy(buf[236..240], &MAGIC_COOKIE);

    var pos: usize = 240;
    buf[pos] = 57; // max message size
    buf[pos + 1] = 2;
    mem.writeInt(u16, buf[pos + 2 .. pos + 4][0..2], 1500, .big);
    pos += 4;
    buf[pos] = 255;

    var msg = try Message.decode(allocator, buf[0 .. pos + 1]);
    defer msg.deinit();

    try std.testing.expectEqual(@as(u16, 1500), msg.options.get(.max_message_size).?);
}

test "broadcast flag" {
    const allocator = std.testing.allocator;

    var msg = Message.init(allocator);
    defer msg.deinit();

    try std.testing.expectEqual(@as(u16, 0), msg.flags);

    _ = msg.setBroadcast(true);
    try std.testing.expectEqual(@as(u16, 0x8000), msg.flags);

    _ = msg.setBroadcast(false);
    try std.testing.expectEqual(@as(u16, 0), msg.flags);
}
