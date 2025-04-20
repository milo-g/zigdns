const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const dns = @import("lib.zig");
const ParseError = dns.ParseError;

const TYPE_LEN = 2;
const CLASS_LEN = 2;

const UNICAST_MASK = 0x8000;
const CLASS_MASK = 0x7FFF;

pub const Question = struct {
    name: dns.Name,
    ///Type of resource being queried
    type: dns.ResourceType,
    ///Class of resource being queried
    class: dns.ResourceClass,

    ///Flag used in multicast DNS indicating a unicast response is desired.
    ///(RFC 6762)
    unicast: bool,

    allocator: Allocator,

    pub fn init(allocator: Allocator) Question {
        return .{
            .allocator = allocator,
            .name = dns.Name.init(allocator),
            .type = dns.ResourceType.ALL,
            .class = dns.ResourceClass.ANY,
            .unicast = false,
        };
    }

    pub fn deinit(self: *const Question) void {
        self.name.deinit();
    }

    /// Parse DNS question
    pub fn parse(self: *Question, reader: *dns.PacketReader) !void {
        // DNS question has format of
        // | QName | QType | U (1 bit) | QClass (15 bit) |
        try self.name.parse(reader);

        const type_int = try reader.readInt(std.meta.Tag(dns.ResourceType), .big);
        self.type = dns.ResourceType.fromInt(type_int);

        const class_bytes = try reader.readInt(u16, .big);
        self.unicast = (class_bytes & UNICAST_MASK) != 0;
        self.class = dns.ResourceClass.fromInt(@as(u15, @truncate(class_bytes & CLASS_MASK)));
    }

    // Static helper methods
    /// Create a DNS question from string slice
    pub fn create(allocator: Allocator, name: []const u8, rtype: dns.ResourceType, class: dns.ResourceClass, unicast: bool) !Question {
        const qname = try dns.Name.fromString(allocator, name);

        return .{
            .name = qname,
            .type = rtype,
            .class = class,
            .unicast = unicast,
            .allocator = allocator,
        };
    }

    /// Decode from wire
    pub fn decode(allocator: Allocator, reader: *dns.PacketReader) !Question {
        var question = Question.init(allocator);
        errdefer question.deinit();

        try question.parse(reader);
        return question;
    }

    /// Encode to wire
    pub fn encode(self: *const Question, writer: anytype) !void {
        try self.name.encode(writer);
        try writer.writeInt(std.meta.Tag(dns.ResourceType), @intFromEnum(self.type), .big);

        // Class bytes are | U (1) | CLASS (15) |
        const class_bytes: u16 = (@as(u16, @intFromBool(self.unicast)) << 15) | @as(u16, @intFromEnum(self.class));
        try writer.writeInt(u16, class_bytes, .big);
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.writeAll("Question{ name: ");
        try self.name.format("", .{}, writer);
        try writer.print(", type: {}, class: {}", .{ self.type, self.class });
        if (self.unicast) {
            try writer.writeAll(", unicast: true");
        }
        try writer.writeAll(" }");
    }
};

const testing = std.testing;

test "Question.parse - Parse valid question" {
    // Sample question
    // example.com
    // A record
    // IN class
    const sample_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x01, // A record
        0x00, 0x01, // IN class
    };

    var reader = dns.PacketReader.init(&sample_data);

    var question = Question.init(testing.allocator);
    defer question.deinit();

    try question.parse(&reader);

    const name = try question.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(name);

    try testing.expectEqualStrings("example.com", name);
    try testing.expectEqual(dns.ResourceClass.IN, question.class);
    try testing.expectEqual(dns.ResourceType.A, question.type);
}

test "Question.parse - Unknown type and class values" {
    const unusual_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x12, 0x34, // Unusual type value (4660)
        0x56, 0x78, // Unusual class value (22136)
    };

    var reader = dns.PacketReader.init(&unusual_data);

    var question = Question.init(testing.allocator);
    defer question.deinit();

    try question.parse(&reader);

    try testing.expectEqual(dns.ResourceType.UNKNOWN, question.type);
    try testing.expectEqual(dns.ResourceClass.UNKNOWN, question.class);
}

test "Question.parse - Insufficient data" {
    const incomplete_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, // Only partial type data
    };

    var reader = dns.PacketReader.init(&incomplete_data);

    var question = Question.init(testing.allocator);
    defer question.deinit();

    const result = question.parse(&reader);
    try testing.expectError(error.EndOfFile, result);
}

test "Question.parse - Unicast flag set" {
    // Sample question with unicast flag set (high bit of class field)
    const unicast_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x01, // A record
        0x80, 0x01, // IN class with unicast bit set (0x8001)
    };

    var reader = dns.PacketReader.init(&unicast_data);

    var question = Question.init(testing.allocator);
    defer question.deinit();

    try question.parse(&reader);

    try testing.expect(question.unicast);
    try testing.expectEqual(dns.ResourceClass.IN, question.class);
}

test "Question.parse - Unicast flag not set" {
    // Sample question with unicast flag not set
    const regular_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x01, // A record
        0x00, 0x01, // IN class without unicast bit
    };

    var reader = dns.PacketReader.init(&regular_data);

    var question = Question.init(testing.allocator);
    defer question.deinit();

    try question.parse(&reader);

    try testing.expect(!question.unicast);
    try testing.expectEqual(dns.ResourceClass.IN, question.class);
}

test "Question.encode - Unicast flag handling" {
    // Test both with and without unicast flag
    const test_cases = [_]struct {
        unicast: bool,
        class: dns.ResourceClass,
        expected: u16,
    }{
        .{ .unicast = false, .class = dns.ResourceClass.IN, .expected = 0x0001 },
        .{ .unicast = true, .class = dns.ResourceClass.IN, .expected = 0x8001 },
        .{ .unicast = false, .class = dns.ResourceClass.CS, .expected = 0x0002 },
        .{ .unicast = true, .class = dns.ResourceClass.CS, .expected = 0x8002 },
    };

    for (test_cases) |tc| {
        // Create a question with the test case settings
        var question = Question{
            .name = try dns.Name.fromString(testing.allocator, "example.com"),
            .type = dns.ResourceType.A,
            .class = tc.class,
            .unicast = tc.unicast,
            .allocator = testing.allocator,
        };
        defer question.deinit();

        // Create a buffer to encode into
        var buffer: [64]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);
        const writer = fbs.writer();

        // Encode the question
        try question.encode(writer);

        // Check the class bytes (skip over the name and type bytes)
        const class_bytes = std.mem.readInt(u16, buffer[13 + TYPE_LEN ..][0..2], .big);
        try testing.expectEqual(tc.expected, class_bytes);
    }
}

test "Question.roundtrip - Preserve unicast flag" {
    // Create a question with unicast flag set
    var original = Question{
        .name = try dns.Name.fromString(testing.allocator, "example.com"),
        .type = dns.ResourceType.A,
        .class = dns.ResourceClass.IN,
        .unicast = true,
        .allocator = testing.allocator,
    };
    defer original.deinit();

    // Encode the question
    var buffer: [64]u8 = undefined;
    var encode_stream = std.io.fixedBufferStream(&buffer);
    try original.encode(encode_stream.writer());
    const encoded_len = encode_stream.pos;

    // Decode the question
    var reader = dns.PacketReader.init(buffer[0..encoded_len]);
    var decoded = try Question.decode(testing.allocator, &reader);
    defer decoded.deinit();

    // Verify the unicast flag is preserved
    try testing.expect(decoded.unicast);
    try testing.expectEqual(original.class, decoded.class);
    try testing.expectEqual(original.type, decoded.type);

    const original_name = try original.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(original_name);
    const decoded_name = try decoded.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(decoded_name);
    try testing.expectEqualStrings(original_name, decoded_name);
}
