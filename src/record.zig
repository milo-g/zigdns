const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const dns = @import("lib.zig");
const ParseError = dns.ParseError;

const TYPE_LEN = 2;
const CLASS_LEN = 2;
const TTL_LEN = 4;
const RDLEN_LEN = 2;

const FLUSH_MASK = 0x8000;
const CLASS_MASK = 0x7FFF;

pub const ResourceRecord = struct {
    name: dns.Name,
    type: dns.ResourceType,
    flush_cache: bool,
    class: dns.ResourceClass,
    ttl: u32,
    rlength: u16,
    rdata: ResourceData,

    allocator: Allocator,

    pub fn init(allocator: Allocator) ResourceRecord {
        return .{
            .allocator = allocator,
            .name = dns.Name.init(allocator),
            .type = dns.ResourceType.ALL,
            .flush_cache = false,
            .class = dns.ResourceClass.ANY,
            .ttl = 0,
            .rlength = 0,
            .rdata = ResourceData{ .UNKNOWN = {} },
        };
    }

    pub fn deinit(self: *const ResourceRecord) void {
        self.name.deinit();
        self.rdata.deinit();
    }

    pub fn parse(self: *ResourceRecord, reader: anytype) !void {
        try self.name.parse(reader);
        self.type = @enumFromInt(try reader.readInt(std.meta.Tag(dns.ResourceType), .big));

        const class_bytes = try reader.readInt(u16, .big);
        self.flush_cache = (class_bytes & FLUSH_MASK) != 0;
        self.class = @enumFromInt(@as(u15, @truncate(class_bytes & CLASS_MASK)));

        self.ttl = try reader.readInt(u32, .big);
        self.rlength = try reader.readInt(u16, .big);
        self.rdata = try ResourceData.decode(self.allocator, reader, self.type, self.rlength);
    }

    pub fn decode(allocator: Allocator, reader: anytype) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        try record.parse(reader);

        return record;
    }

    pub fn encode(self: *const ResourceRecord, writer: anytype) !void {
        try self.name.encode(writer);
        try writer.writeInt(std.meta.Tag(dns.ResourceType), @intFromEnum(self.type), .big);

        // Class bytes are | F (1) | CLASS (15) |
        const class_bytes: u16 = (@as(u16, @intFromBool(self.flush_cache)) << 15) | @as(u16, @intFromEnum(self.class));
        try writer.writeInt(u16, class_bytes, .big);

        try writer.writeInt(u32, self.ttl, .big);
        try writer.writeInt(u16, self.rlength, .big);
        try self.rdata.encode(writer);
    }

    pub fn createA(allocator: Allocator, name: []const u8, address: [4]u8, ttl: u32, flush: bool) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        record.name = try dns.Name.fromString(allocator, name);
        record.ttl = ttl;
        record.rdata = ResourceData{ .A = address };
        record.rlength = record.rdata.length();
        record.type = .A;
        record.class = .IN;
        record.flush_cache = flush;

        return record;
    }

    pub fn createAAAA(allocator: Allocator, name: []const u8, address: [16]u8, ttl: u32, flush: bool) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        record.name = try dns.Name.fromString(allocator, name);
        record.ttl = ttl;
        record.rdata = ResourceData{ .AAAA = address };
        record.rlength = record.rdata.length();
        record.type = .AAAA;
        record.class = .IN;
        record.flush_cache = flush;

        return record;
    }

    pub fn createCNAME(allocator: Allocator, name: []const u8, canonical: []const u8, ttl: u32, flush: bool) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        record.name = try dns.Name.fromString(allocator, name);
        record.ttl = ttl;
        record.rdata = ResourceData{ .CNAME = try dns.Name.fromString(allocator, canonical) };
        record.rlength = record.rdata.length();
        record.type = .CNAME;
        record.class = .IN;
        record.flush_cache = flush;

        return record;
    }

    pub fn createNS(allocator: Allocator, name: []const u8, nameserver: []const u8, ttl: u32, flush: bool) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        record.name = try dns.Name.fromString(allocator, name);
        record.ttl = ttl;
        record.rdata = ResourceData{ .NS = try dns.Name.fromString(allocator, nameserver) };
        record.rlength = record.rdata.length();
        record.type = .NS;
        record.class = .IN;
        record.flush_cache = flush;

        return record;
    }

    pub fn createPTR(allocator: Allocator, name: []const u8, ptr: []const u8, ttl: u32, flush: bool) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        record.name = try dns.Name.fromString(allocator, name);
        record.ttl = ttl;
        record.rdata = ResourceData{ .PTR = try dns.Name.fromString(allocator, ptr) };
        record.rlength = record.rdata.length();
        record.type = .PTR;
        record.class = .IN;
        record.flush_cache = flush;

        return record;
    }

    pub fn createMX(allocator: Allocator, name: []const u8, priority: u16, exchange: []const u8, ttl: u32, flush: bool) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        record.name = try dns.Name.fromString(allocator, name);
        record.ttl = ttl;

        const exchange_name = try dns.Name.fromString(allocator, exchange);
        record.rdata = ResourceData{ .MX = .{ .priority = priority, .exchange = exchange_name } };
        record.rlength = record.rdata.length();
        record.type = .MX;
        record.class = .IN;
        record.flush_cache = flush;

        return record;
    }

    pub fn createTXT(allocator: Allocator, name: []const u8, txt: []const u8, ttl: u32, flush: bool) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        record.name = try dns.Name.fromString(allocator, name);
        record.ttl = ttl;

        const txt_data = try allocator.dupe(u8, txt);
        record.rdata = ResourceData{ .TXT = .{ .data = txt_data, .allocator = allocator } };
        record.rlength = record.rdata.length();
        record.type = .TXT;
        record.class = .IN;
        record.flush_cache = flush;

        return record;
    }

    pub fn createSRV(allocator: Allocator, name: []const u8, priority: u16, weight: u16, port: u16, target: []const u8, ttl: u32, flush: bool) !ResourceRecord {
        var record = ResourceRecord.init(allocator);
        record.name = try dns.Name.fromString(allocator, name);
        record.ttl = ttl;

        const target_name = try dns.Name.fromString(allocator, target);
        record.rdata = ResourceData{ .SRV = .{ .priority = priority, .weight = weight, .port = port, .target = target_name } };
        record.rlength = record.rdata.length();
        record.type = .SRV;
        record.class = .IN;
        record.flush_cache = flush;

        return record;
    }
};

pub const ResourceData = union(dns.ResourceType) {
    pub const A_LEN: usize = 4;
    pub const AAAA_LEN: usize = 16;

    A: [4]u8,
    NS: dns.Name,
    CNAME: dns.Name,
    PTR: dns.Name,
    MX: struct {
        priority: u16,
        exchange: dns.Name,
    },
    TXT: struct {
        data: []const u8,
        allocator: Allocator,
    },
    AAAA: [16]u8,
    SRV: struct {
        priority: u16,
        weight: u16,
        port: u16,
        target: dns.Name,
    },
    ALL: void,
    UNKNOWN: void,

    pub fn deinit(self: *const ResourceData) void {
        switch (self.*) {
            .TXT => self.TXT.allocator.free(self.TXT.data),
            .MX => self.MX.exchange.deinit(),
            .NS => self.NS.deinit(),
            .PTR => self.PTR.deinit(),
            .CNAME => self.CNAME.deinit(),
            .SRV => self.SRV.target.deinit(),
            else => return,
        }
    }

    pub fn encode(self: *const ResourceData, writer: anytype) !void {
        switch (self.*) {
            .A => try writer.writeAll(&self.A),
            .AAAA => try writer.writeAll(&self.AAAA),
            .TXT => try writer.writeAll(self.TXT.data),
            .NS => try self.NS.encode(writer),
            .CNAME => try self.CNAME.encode(writer),
            .PTR => try self.PTR.encode(writer),
            .MX => {
                try writer.writeInt(u16, self.MX.priority, .big);
                try self.MX.exchange.encode(writer);
            },
            .SRV => {
                try writer.writeInt(u16, self.SRV.priority, .big);
                try writer.writeInt(u16, self.SRV.weight, .big);
                try writer.writeInt(u16, self.SRV.port, .big);
                try self.SRV.target.encode(writer);
            },
            else => return,
        }
    }

    pub fn decode(allocator: Allocator, reader: anytype, rtype: dns.ResourceType, rlen: usize) !ResourceData {
        return switch (rtype) {
            .A => try ResourceData.decodeA(reader, rlen),
            .AAAA => try ResourceData.decodeAAAA(reader, rlen),
            .TXT => try ResourceData.decodeTXT(allocator, reader, rlen),
            .CNAME => try ResourceData.decodeCNAME(allocator, reader),
            .NS => try ResourceData.decodeNS(allocator, reader),
            .PTR => try ResourceData.decodePTR(allocator, reader),
            .MX => try ResourceData.decodeMX(allocator, reader),
            .SRV => try ResourceData.decodeSRV(allocator, reader),
            else => .{ .UNKNOWN = {} },
        };
    }

    fn decodeA(reader: anytype, len: usize) !ResourceData {
        var ip: [4]u8 = undefined;
        const br = try reader.readAll(&ip);
        if (br != len) {
            return ParseError.EndOfStream;
        }

        return .{
            .A = ip,
        };
    }

    fn decodeAAAA(reader: anytype, len: usize) !ResourceData {
        var ip: [16]u8 = undefined;
        const br = try reader.readAll(&ip);
        if (br != len) {
            return ParseError.EndOfStream;
        }

        return .{
            .AAAA = ip,
        };
    }

    fn decodeTXT(allocator: Allocator, reader: anytype, len: usize) !ResourceData {
        const data = try allocator.alloc(u8, len);
        errdefer allocator.free(data);
        const br = try reader.readAll(data);
        if (br != len) {
            return ParseError.EndOfStream;
        }

        return .{
            .TXT = .{
                .data = data,
                .allocator = allocator,
            },
        };
    }

    fn decodeCNAME(allocator: Allocator, reader: anytype) !ResourceData {
        const name = try dns.Name.fromWire(allocator, reader);
        return .{
            .CNAME = name,
        };
    }

    fn decodeNS(allocator: Allocator, reader: anytype) !ResourceData {
        const name = try dns.Name.fromWire(allocator, reader);
        return .{
            .NS = name,
        };
    }

    fn decodePTR(allocator: Allocator, reader: anytype) !ResourceData {
        const name = try dns.Name.fromWire(allocator, reader);
        return .{
            .PTR = name,
        };
    }

    fn decodeMX(allocator: Allocator, reader: anytype) !ResourceData {
        const priority = try reader.readInt(u16, .big);
        const exchange = try dns.Name.fromWire(allocator, reader);

        return .{
            .MX = .{
                .priority = priority,
                .exchange = exchange,
            },
        };
    }

    fn decodeSRV(allocator: Allocator, reader: anytype) !ResourceData {
        const priority = try reader.readInt(u16, .big);
        const weight = try reader.readInt(u16, .big);
        const port = try reader.readInt(u16, .big);
        const target = try dns.Name.fromWire(allocator, reader);

        return .{
            .SRV = .{
                .priority = priority,
                .weight = weight,
                .port = port,
                .target = target,
            },
        };
    }

    pub fn length(self: *ResourceData) u16 {
        return switch (self.*) {
            .A => A_LEN,
            .AAAA => AAAA_LEN,
            .TXT => |txt| @truncate(txt.data.len),
            .CNAME => |cname| @truncate(cname.length()),
            .NS => |ns| @truncate(ns.length()),
            .PTR => |ptr| @truncate(ptr.length()),
            .MX => |mx| @sizeOf(u16) + @as(u16, @truncate(mx.exchange.length())),
            .SRV => |srv| @sizeOf(u16) * 3 + @as(u16, @truncate(srv.target.length())),
            else => 0,
        };
    }
};

const testing = std.testing;

test "ResourceData - A record encoding and decoding" {
    // Setup test data
    const ip = [4]u8{ 192, 168, 1, 1 };
    var a_record = ResourceData{ .A = ip };

    // Setup buffer for encoding
    var buffer: [4]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    // Encode
    try a_record.encode(&writer);

    // Verify encoded data
    try testing.expectEqualSlices(u8, &ip, &buffer);

    // Now decode
    var read_fbs = std.io.fixedBufferStream(&buffer);
    const reader = read_fbs.reader();

    const decoded = try ResourceData.decodeA(reader, buffer.len);

    // Verify decoded data
    try testing.expectEqual(dns.ResourceType.A, std.meta.activeTag(decoded));
    try testing.expectEqualSlices(u8, &ip, &decoded.A);
}

test "ResourceData - TXT record encoding and decoding" {
    // Setup test data
    const txt_content = "Hello, DNS!";
    var txt_record = ResourceData{ .TXT = .{
        .data = txt_content,
        .allocator = testing.allocator,
    } };

    // Setup buffer for encoding
    var buffer: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    // Encode
    try txt_record.encode(&writer);

    // Verify encoded data
    try testing.expectEqualSlices(u8, txt_content, buffer[0..txt_content.len]);

    // Now decode
    var read_fbs = std.io.fixedBufferStream(buffer[0..txt_content.len]);
    const reader = read_fbs.reader();

    var decoded = try ResourceData.decodeTXT(testing.allocator, reader, txt_content.len);
    defer decoded.deinit();

    // Verify decoded data
    try testing.expectEqual(dns.ResourceType.TXT, std.meta.activeTag(decoded));
    try testing.expectEqualSlices(u8, txt_content, decoded.TXT.data);
}

test "ResourceData - decode function with A record" {
    // Setup test data
    const ip = [4]u8{ 192, 168, 1, 1 };
    var buffer: [4]u8 = undefined;
    @memcpy(&buffer, &ip);

    var fbs = std.io.fixedBufferStream(&buffer);
    const reader = fbs.reader();

    // Decode using the generic decode function
    var decoded = try ResourceData.decode(testing.allocator, reader, .A, 4);

    // Verify decoded data
    try testing.expectEqual(dns.ResourceType.A, std.meta.activeTag(decoded));
    try testing.expectEqualSlices(u8, &ip, &decoded.A);
}

test "ResourceRecord - encode and parse A record" {
    var record = ResourceRecord.init(testing.allocator);
    defer record.deinit();

    record.type = dns.ResourceType.A;
    record.class = dns.ResourceClass.IN;
    record.ttl = 3600;
    record.rlength = ResourceData.A_LEN;
    record.rdata = .{ .A = [4]u8{ 192, 168, 1, 1 } };

    var buffer: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    try record.encode(&writer);
    const encoded_len = fbs.pos;

    var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
    const reader = read_fbs.reader();

    var parsed_record = ResourceRecord.init(testing.allocator);
    defer parsed_record.deinit();

    try parsed_record.parse(reader);

    // Verify parsed data
    try testing.expectEqual(dns.ResourceType.A, parsed_record.type);
    try testing.expectEqual(dns.ResourceClass.IN, parsed_record.class);
    try testing.expectEqual(@as(u32, 3600), parsed_record.ttl);
    try testing.expectEqual(@as(u16, 4), parsed_record.rlength);
    try testing.expectEqualSlices(u8, &[4]u8{ 192, 168, 1, 1 }, &parsed_record.rdata.A);
}

test "ResourceData - SRV record encoding and decoding" {
    const allocator = testing.allocator;

    var target_name = try dns.Name.fromString(allocator, "service.example.com");
    defer target_name.deinit();

    var srv_record = ResourceData{ .SRV = .{
        .priority = 10,
        .weight = 20,
        .port = 5060,
        .target = target_name,
    } };

    var buffer: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    try srv_record.encode(&writer);
    const encoded_len = fbs.pos;

    var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
    const reader = read_fbs.reader();

    var decoded = try ResourceData.decodeSRV(allocator, reader);
    defer decoded.deinit();

    try testing.expectEqual(dns.ResourceType.SRV, std.meta.activeTag(decoded));
    try testing.expectEqual(@as(u16, 10), decoded.SRV.priority);
    try testing.expectEqual(@as(u16, 20), decoded.SRV.weight);
    try testing.expectEqual(@as(u16, 5060), decoded.SRV.port);

    const original_target = try srv_record.SRV.target.toOwnedSlice(allocator);
    defer allocator.free(original_target);
    const decoded_target = try decoded.SRV.target.toOwnedSlice(allocator);
    defer allocator.free(decoded_target);

    try testing.expectEqualStrings(original_target, decoded_target);
}

test "ResourceData - CNAME record encoding and decoding" {
    const allocator = testing.allocator;

    var name = try dns.Name.fromString(allocator, "www.example.com");
    defer name.deinit();

    var cname_record = ResourceData{ .CNAME = name };

    var buffer: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    try cname_record.encode(&writer);
    const encoded_len = fbs.pos;

    var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
    const reader = read_fbs.reader();

    var decoded = try ResourceData.decodeCNAME(allocator, reader);
    defer decoded.deinit();

    try testing.expectEqual(dns.ResourceType.CNAME, std.meta.activeTag(decoded));

    const original_name = try cname_record.CNAME.toOwnedSlice(allocator);
    defer allocator.free(original_name);
    const decoded_name = try decoded.CNAME.toOwnedSlice(allocator);
    defer allocator.free(decoded_name);

    try testing.expectEqualStrings(original_name, decoded_name);
}

test "ResourceData - NS record encoding and decoding" {
    const allocator = testing.allocator;

    var name = try dns.Name.fromString(allocator, "ns1.example.com");
    defer name.deinit();

    var ns_record = ResourceData{ .NS = name };

    var buffer: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    try ns_record.encode(&writer);
    const encoded_len = fbs.pos;

    var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
    const reader = read_fbs.reader();

    var decoded = try ResourceData.decodeNS(allocator, reader);
    defer decoded.deinit();

    try testing.expectEqual(dns.ResourceType.NS, std.meta.activeTag(decoded));

    const original_name = try ns_record.NS.toOwnedSlice(allocator);
    defer allocator.free(original_name);
    const decoded_name = try decoded.NS.toOwnedSlice(allocator);
    defer allocator.free(decoded_name);

    try testing.expectEqualStrings(original_name, decoded_name);
}

test "ResourceData - PTR record encoding and decoding" {
    const allocator = testing.allocator;

    var name = try dns.Name.fromString(allocator, "1.0.168.192.in-addr.arpa");
    defer name.deinit();

    var ptr_record = ResourceData{ .PTR = name };

    var buffer: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    try ptr_record.encode(&writer);
    const encoded_len = fbs.pos;

    var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
    const reader = read_fbs.reader();

    var decoded = try ResourceData.decodePTR(allocator, reader);
    defer decoded.deinit();

    try testing.expectEqual(dns.ResourceType.PTR, std.meta.activeTag(decoded));

    const original_name = try ptr_record.PTR.toOwnedSlice(allocator);
    defer allocator.free(original_name);
    const decoded_name = try decoded.PTR.toOwnedSlice(allocator);
    defer allocator.free(decoded_name);

    try testing.expectEqualStrings(original_name, decoded_name);
}

test "ResourceData - MX record encoding and decoding" {
    const allocator = testing.allocator;

    var exchange = try dns.Name.fromString(allocator, "mail.example.com");
    defer exchange.deinit();

    var mx_record = ResourceData{ .MX = .{
        .priority = 10,
        .exchange = exchange,
    } };

    var buffer: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    try mx_record.encode(&writer);
    const encoded_len = fbs.pos;

    var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
    const reader = read_fbs.reader();

    var decoded = try ResourceData.decodeMX(allocator, reader);
    defer decoded.deinit();

    try testing.expectEqual(dns.ResourceType.MX, std.meta.activeTag(decoded));
    try testing.expectEqual(@as(u16, 10), decoded.MX.priority);

    const original_exchange = try mx_record.MX.exchange.toOwnedSlice(allocator);
    defer allocator.free(original_exchange);
    const decoded_exchange = try decoded.MX.exchange.toOwnedSlice(allocator);
    defer allocator.free(decoded_exchange);

    try testing.expectEqualStrings(original_exchange, decoded_exchange);
}

test "ResourceData - AAAA record encoding and decoding" {
    const ip = [16]u8{
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
    };
    var aaaa_record = ResourceData{ .AAAA = ip };

    var buffer: [16]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var writer = fbs.writer();

    try aaaa_record.encode(&writer);

    try testing.expectEqualSlices(u8, &ip, &buffer);

    var read_fbs = std.io.fixedBufferStream(&buffer);
    const reader = read_fbs.reader();

    const decoded = try ResourceData.decodeAAAA(reader, buffer.len);

    try testing.expectEqual(dns.ResourceType.AAAA, std.meta.activeTag(decoded));
    try testing.expectEqualSlices(u8, &ip, &decoded.AAAA);
}

test "ResourceRecord - createSRV function" {
    const record = try ResourceRecord.createSRV(testing.allocator, "_http._tcp.example.com", 10, 20, 80, "web.example.com", 3600, false);
    defer record.deinit();

    try testing.expectEqual(dns.ResourceType.SRV, record.type);
    try testing.expectEqual(dns.ResourceClass.IN, record.class);
    try testing.expectEqual(@as(u32, 3600), record.ttl);

    try testing.expectEqual(@as(u16, 10), record.rdata.SRV.priority);
    try testing.expectEqual(@as(u16, 20), record.rdata.SRV.weight);
    try testing.expectEqual(@as(u16, 80), record.rdata.SRV.port);

    const name = try record.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(name);
    try testing.expectEqualStrings("_http._tcp.example.com", name);

    const target = try record.rdata.SRV.target.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(target);
    try testing.expectEqualStrings("web.example.com", target);
}

test "ResourceRecord - length calculation for all record types" {
    const allocator = testing.allocator;

    var a_record = ResourceData{ .A = [4]u8{ 192, 168, 1, 1 } };
    try testing.expectEqual(@as(u16, 4), a_record.length());

    var aaaa_record = ResourceData{ .AAAA = [16]u8{
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
    } };
    try testing.expectEqual(@as(u16, 16), aaaa_record.length());

    var cname = try dns.Name.fromString(allocator, "example.com");
    defer cname.deinit();
    var cname_record = ResourceData{ .CNAME = cname };
    try testing.expectEqual(@as(u16, @truncate(cname.length())), cname_record.length());

    var ns = try dns.Name.fromString(allocator, "ns1.example.com");
    defer ns.deinit();
    var ns_record = ResourceData{ .NS = ns };
    try testing.expectEqual(@as(u16, @truncate(ns.length())), ns_record.length());

    var ptr = try dns.Name.fromString(allocator, "1.0.168.192.in-addr.arpa");
    defer ptr.deinit();
    var ptr_record = ResourceData{ .PTR = ptr };
    try testing.expectEqual(@as(u16, @truncate(ptr.length())), ptr_record.length());

    var exchange = try dns.Name.fromString(allocator, "mail.example.com");
    defer exchange.deinit();
    var mx_record = ResourceData{ .MX = .{
        .priority = 10,
        .exchange = exchange,
    } };
    try testing.expectEqual(@as(u16, @sizeOf(u16) + @as(u16, @truncate(exchange.length()))), mx_record.length());

    var target = try dns.Name.fromString(allocator, "service.example.com");
    defer target.deinit();
    var srv_record = ResourceData{ .SRV = .{
        .priority = 10,
        .weight = 20,
        .port = 5060,
        .target = target,
    } };
    try testing.expectEqual(@as(u16, @sizeOf(u16) * 3 + @as(u16, @truncate(target.length()))), srv_record.length());

    const txt_data = "v=spf1 include:_spf.example.com ~all";
    var txt_record = ResourceData{ .TXT = .{
        .data = txt_data,
        .allocator = allocator,
    } };
    try testing.expectEqual(@as(u16, @truncate(txt_data.len)), txt_record.length());
}

test "ResourceRecord - Flush cache flag parsing" {
    // Sample record with flush cache flag set (high bit of class field)
    const flush_data = [_]u8{
        0x00, // Empty domain name (root)
        0x00, 0x01, // A record
        0x80, 0x01, // IN class with flush cache bit set (0x8001)
        0x00, 0x00, 0x0E, 0x10, // TTL (3600)
        0x00, 0x04, // RDLEN (4)
        192, 168, 1, 1, // IP address
    };

    var stream = std.io.fixedBufferStream(&flush_data);
    const reader = stream.reader();

    var record = ResourceRecord.init(testing.allocator);
    defer record.deinit();

    try record.parse(reader);

    // Verify flush_cache flag is set
    try testing.expect(record.flush_cache);
    try testing.expectEqual(dns.ResourceClass.IN, record.class);
}

test "ResourceRecord - Flush cache flag not set during parsing" {
    // Sample record without flush cache flag set
    const no_flush_data = [_]u8{
        0x00, // Empty domain name (root)
        0x00, 0x01, // A record
        0x00, 0x01, // IN class without flush cache bit
        0x00, 0x00, 0x0E, 0x10, // TTL (3600)
        0x00, 0x04, // RDLEN (4)
        192, 168, 1, 1, // IP address
    };

    var stream = std.io.fixedBufferStream(&no_flush_data);
    const reader = stream.reader();

    var record = ResourceRecord.init(testing.allocator);
    defer record.deinit();

    try record.parse(reader);

    // Verify flush_cache flag is not set
    try testing.expect(!record.flush_cache);
    try testing.expectEqual(dns.ResourceClass.IN, record.class);
}

test "ResourceRecord - Encode with flush cache flag" {
    // Test both with and without flush cache flag
    const test_cases = [_]struct {
        flush_cache: bool,
        class: dns.ResourceClass,
        expected: u16,
    }{
        .{ .flush_cache = false, .class = dns.ResourceClass.IN, .expected = 0x0001 },
        .{ .flush_cache = true, .class = dns.ResourceClass.IN, .expected = 0x8001 },
        .{ .flush_cache = false, .class = dns.ResourceClass.CS, .expected = 0x0002 },
        .{ .flush_cache = true, .class = dns.ResourceClass.CS, .expected = 0x8002 },
    };

    for (test_cases) |tc| {
        // Create a minimal record with the test case settings
        var record = ResourceRecord{
            .name = dns.Name.init(testing.allocator),
            .type = dns.ResourceType.A,
            .class = tc.class,
            .flush_cache = tc.flush_cache,
            .ttl = 3600,
            .rlength = 4,
            .rdata = .{ .A = [4]u8{ 192, 168, 1, 1 } },
            .allocator = testing.allocator,
        };
        defer record.deinit();

        // Create a buffer to encode into
        var buffer: [64]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);
        const writer = fbs.writer();

        // Encode the record
        try record.encode(writer);

        // Check the class bytes (skip over the name and type bytes - with empty name, that's 3 bytes)
        const class_bytes = std.mem.readInt(u16, buffer[3..][0..2], .big);
        try testing.expectEqual(tc.expected, class_bytes);
    }
}

test "ResourceRecord - Round trip with flush cache flag" {
    // Create a full record with flush cache flag set
    var record = try ResourceRecord.createA(testing.allocator, "example.com", [4]u8{ 192, 168, 1, 1 }, 3600, true // flush_cache flag
    );
    defer record.deinit();

    // Verify the flag is set correctly in the created record
    try testing.expect(record.flush_cache);

    // Encode to wire format
    var buffer: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try record.encode(fbs.writer());
    const encoded_len = fbs.pos;

    // Parse the encoded data
    var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
    var parsed_record = try ResourceRecord.decode(testing.allocator, read_fbs.reader());
    defer parsed_record.deinit();

    // Verify flush_cache flag was preserved
    try testing.expect(parsed_record.flush_cache);
    try testing.expectEqual(record.class, parsed_record.class);
    try testing.expectEqual(record.type, parsed_record.type);
    try testing.expectEqual(record.ttl, parsed_record.ttl);
    try testing.expectEqualSlices(u8, &record.rdata.A, &parsed_record.rdata.A);

    // Verify the domain name was preserved
    const original_name = try record.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(original_name);
    const parsed_name = try parsed_record.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(parsed_name);
    try testing.expectEqualStrings(original_name, parsed_name);
}

test "ResourceRecord - Factory functions preserve flush cache flag" {
    // Test a few factory functions with flush_cache = true

    // A record
    {
        var record = try ResourceRecord.createA(testing.allocator, "example.com", [4]u8{ 192, 168, 1, 1 }, 3600, true // flush_cache flag
        );
        defer record.deinit();
        try testing.expect(record.flush_cache);
    }

    // AAAA record
    {
        var record = try ResourceRecord.createAAAA(testing.allocator, "example.com", [16]u8{
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
            0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        }, 3600, true // flush_cache flag
        );
        defer record.deinit();
        try testing.expect(record.flush_cache);
    }

    // TXT record
    {
        var record = try ResourceRecord.createTXT(testing.allocator, "example.com", "v=spf1 include:_spf.example.com ~all", 3600, true // flush_cache flag
        );
        defer record.deinit();
        try testing.expect(record.flush_cache);
    }
}

test "ResourceRecord - Mask constants for flush cache" {
    // Verify correct mask constants are defined
    try testing.expectEqual(@as(u16, 0x8000), FLUSH_MASK);
    try testing.expectEqual(@as(u16, 0x7FFF), CLASS_MASK);

    // Test masks are applied correctly
    const class_value: u16 = 0x0001; // IN class
    const with_flush: u16 = class_value | FLUSH_MASK;

    try testing.expectEqual(@as(u16, 0x8001), with_flush);
    try testing.expectEqual(@as(u16, 0x0001), with_flush & CLASS_MASK);
    try testing.expectEqual(@as(u16, 0x8000), with_flush & FLUSH_MASK);
}
