const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const dns = @import("lib.zig");
const ParseError = dns.ParseError;

const TYPE_LEN = 2;
const CLASS_LEN = 2;

pub const Question = struct {
    name: dns.Name,
    type: dns.ResourceType,
    class: dns.ResourceClass,

    allocator: Allocator,

    pub fn init(allocator: Allocator) Question {
        return .{
            .allocator = allocator,
            .name = dns.Name.init(allocator),
            .type = dns.ResourceType.ALL,
            .class = dns.ResourceClass.ANY,
        };
    }

    pub fn deinit(self: *const Question) void {
        self.name.deinit();
    }

    /// Parse DNS question
    pub fn parse(self: *Question, reader: anytype) !void {
        // DNS question has format of
        // | QName | QType | QClass |
        try self.name.parse(reader);

        const type_int = try reader.readInt(std.meta.Tag(dns.ResourceType), .big);
        self.type = dns.ResourceType.fromInt(type_int);

        const class_int = try reader.readInt(std.meta.Tag(dns.ResourceClass), .big);
        self.class = dns.ResourceClass.fromInt(class_int);
    }

    // Static helper methods
    /// Create a DNS question from string slice
    pub fn create(allocator: Allocator, name: []const u8, rtype: dns.ResourceType, class: dns.ResourceClass) !Question {
        const qname = try dns.Name.fromString(allocator, name);

        return .{
            .name = qname,
            .type = rtype,
            .class = class,
            .allocator = allocator,
        };
    }

    /// Decode from wire
    pub fn decode(allocator: Allocator, reader: anytype) !Question {
        var question = Question.init(allocator);
        errdefer question.deinit();

        try question.parse(reader);
        return question;
    }

    /// Encode to wire
    pub fn encode(self: *const Question, writer: anytype) !void {
        try self.name.encode(writer);
        try writer.writeInt(std.meta.Tag(dns.ResourceType), @intFromEnum(self.type), .big);
        try writer.writeInt(std.meta.Tag(dns.ResourceClass), @intFromEnum(self.class), .big);
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

    var stream = std.io.fixedBufferStream(&sample_data);
    const reader = stream.reader();

    var question = Question.init(testing.allocator);
    defer question.deinit();

    try question.parse(reader);

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

    var stream = std.io.fixedBufferStream(&unusual_data);
    const reader = stream.reader();

    var question = Question.init(testing.allocator);
    defer question.deinit();

    try question.parse(reader);

    try testing.expectEqual(dns.ResourceType.UNKNOWN, question.type);
    try testing.expectEqual(dns.ResourceClass.UNKNOWN, question.class);
}

test "Question.parse - Insufficient data" {
    const incomplete_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, // Only partial type data
    };

    var stream = std.io.fixedBufferStream(&incomplete_data);
    const reader = stream.reader();

    var question = Question.init(testing.allocator);
    defer question.deinit();

    const result = question.parse(reader);
    try testing.expectError(error.EndOfStream, result);
}
