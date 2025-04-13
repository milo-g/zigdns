const std = @import("std");
const io = std.io;
const mem = std.mem;
const Allocator = mem.Allocator;
const ParseError = @import("lib.zig").ParseError;

pub const LABEL_MAX_LENGTH: u8 = 63;
pub const NAME_MAX_LENGTH: u8 = 255;

/// DNS Name in name encoding format.
pub const Name = struct {
    allocator: Allocator,

    labels: std.ArrayList([]u8),

    pub fn init(allocator: Allocator) Name {
        const labels = std.ArrayList([]u8).init(allocator);
        return .{
            .allocator = allocator,
            .labels = labels,
        };
    }

    pub fn deinit(self: *const Name) void {
        for (self.labels.items) |label| {
            self.allocator.free(label);
        }

        self.labels.deinit();
    }

    /// Parses DNS name from a reader, assuming the first length byte is at the beginning of reader.
    pub fn parse(self: *Name, reader: anytype) !void {
        var total: usize = 0;

        while (total < 255) {
            // read length byte
            const len = try reader.readByte();
            total += 1;

            if (len > LABEL_MAX_LENGTH) {
                return ParseError.InvalidLabelLength;
            }

            if (len == 0) {
                break;
            }

            const label = try self.allocator.alloc(u8, len);
            errdefer self.allocator.free(label);

            const label_read = try reader.readAll(label);
            if (label_read != len) {
                return error.EndOfStream;
            }
            total += label_read;

            try self.labels.append(label);
        }

        if (total > 255) {
            return ParseError.InvalidTotalLength;
        }
    }

    pub fn toOwnedSlice(self: *const Name, allocator: Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        errdefer list.deinit();

        const writer = list.writer();
        for (self.labels.items, 0..) |label, i| {
            if (i > 0) {
                try writer.writeByte('.');
            }
            try writer.writeAll(label);
        }

        return list.toOwnedSlice();
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        for (self.labels.items, 0..) |label, i| {
            if (i > 0) {
                try writer.writeByte('.');
            }
            try writer.writeAll(label);
        }
    }

    pub fn fromString(allocator: Allocator, name: []const u8) !Name {
        var stream = std.io.fixedBufferStream(name);
        const reader = stream.reader();

        var qname = Name.init(allocator);
        errdefer qname.deinit();

        while (true) {
            const label = (reader.readUntilDelimiterOrEofAlloc(allocator, '.', LABEL_MAX_LENGTH) catch |err| switch (err) {
                error.StreamTooLong => break,
                else => return err,
            }) orelse break;

            if (label.len != 0) {
                try qname.labels.append(label);
                continue;
            }
        }

        return qname;
    }

    pub fn fromWire(allocator: Allocator, reader: anytype) !Name {
        var name = Name.init(allocator);
        errdefer name.deinit();

        try name.parse(reader);
        return name;
    }

    pub fn encode(self: *const Name, writer: anytype) !void {
        for (self.labels.items) |label| {
            try writer.writeByte(@as(u8, @truncate(label.len)));
            try writer.writeAll(label);
        }

        try writer.writeByte(0);
    }

    pub fn length(self: Name) usize {
        var total: usize = 1;

        for (self.labels.items) |label| {
            total += label.len;
            total += 1;
        }

        return total;
    }
};

const testing = std.testing;

test "Name.parse - valid domain name" {
    // Test data for "example.com"
    const test_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };

    var fixed_buffer_stream = std.io.fixedBufferStream(&test_data);
    const reader = fixed_buffer_stream.reader();

    var name = Name.init(testing.allocator);
    defer name.deinit();

    try name.parse(reader);

    // Verify the correct number of labels
    try testing.expectEqual(@as(usize, 2), name.labels.items.len);

    // Verify the label contents
    try testing.expectEqualStrings("example", name.labels.items[0]);
    try testing.expectEqualStrings("com", name.labels.items[1]);
}

test "Name.parse - long domain name" {
    // Generate test data for a valid but long domain name
    // with multiple labels each with close to maximum length
    var test_data: [255]u8 = undefined;
    test_data[0] = 63; // First label length (max)

    // Fill first label with 'a's
    for (1..64) |i| {
        test_data[i] = 'a';
    }

    test_data[64] = 63; // Second label length

    // Fill second label with 'b's
    for (65..128) |i| {
        test_data[i] = 'b';
    }

    test_data[128] = 63; // Third label length

    // Fill third label with 'c's
    for (129..192) |i| {
        test_data[i] = 'c';
    }

    test_data[192] = 62; // Fourth label (slightly shorter)

    // Fill fourth label with 'd's
    for (193..255) |i| {
        test_data[i] = 'd';
    }

    var fixed_buffer_stream = std.io.fixedBufferStream(&test_data);
    const reader = fixed_buffer_stream.reader();

    var name = Name.init(testing.allocator);
    defer name.deinit();

    // Should just fit within 255 bytes
    try name.parse(reader);

    // Verify label counts
    try testing.expectEqual(@as(usize, 4), name.labels.items.len);
    try testing.expectEqual(@as(usize, 63), name.labels.items[0].len);
    try testing.expectEqual(@as(usize, 63), name.labels.items[1].len);
    try testing.expectEqual(@as(usize, 63), name.labels.items[2].len);
    try testing.expectEqual(@as(usize, 62), name.labels.items[3].len);
}

test "Name.parse - domain name too long" {
    // Create a DNS name encoding that exceeds 255 bytes
    // This is impossible in a valid DNS message, but let's test the validation
    var test_data: [260]u8 = undefined;

    // Set up multiple labels that together exceed 255 bytes
    test_data[0] = 63; // First label length
    for (1..64) |i| {
        test_data[i] = 'a';
    }

    test_data[64] = 63; // Second label length
    for (65..128) |i| {
        test_data[i] = 'b';
    }

    test_data[128] = 63; // Third label length
    for (129..192) |i| {
        test_data[i] = 'c';
    }

    test_data[192] = 63; // Fourth label length
    for (193..256) |i| {
        test_data[i] = 'd';
    }

    // Add more data to exceed 255 limit
    test_data[256] = 3;
    test_data[257] = 'c';
    test_data[258] = 'o';
    test_data[259] = 'm';

    var fixed_buffer_stream = std.io.fixedBufferStream(&test_data);
    const reader = fixed_buffer_stream.reader();

    var name = Name.init(testing.allocator);
    defer name.deinit();

    // Should fail with InvalidTotalLength
    const result = name.parse(reader);
    try testing.expectError(ParseError.InvalidTotalLength, result);
}

test "Name.toOwnedSlice" {
    // Test data for "example.com"
    const test_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };

    var fixed_buffer_stream = std.io.fixedBufferStream(&test_data);
    const reader = fixed_buffer_stream.reader();

    var name = Name.init(testing.allocator);
    defer name.deinit();

    try name.parse(reader);

    // Convert to owned slice
    const domain_str = try name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(domain_str);

    // Verify the result
    try testing.expectEqualStrings("example.com", domain_str);
}

test "Name.toOwnedSlice - root domain" {
    // Test data for root domain (just a zero byte)
    const test_data = [_]u8{0};

    var fixed_buffer_stream = std.io.fixedBufferStream(&test_data);
    const reader = fixed_buffer_stream.reader();

    var name = Name.init(testing.allocator);
    defer name.deinit();

    try name.parse(reader);

    // Convert to owned slice
    const domain_str = try name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(domain_str);

    // Verify empty string for root domain
    try testing.expectEqualStrings("", domain_str);
}

test "Name.toOwnedSlice - multiple labels" {
    // Test data for "mail.example.co.uk"
    const test_data = [_]u8{
        4,   'm', 'a', 'i', 'l',
        7,   'e', 'x', 'a', 'm',
        'p', 'l', 'e', 3,   'c',
        'o', 'm', 0,
    };

    var fixed_buffer_stream = std.io.fixedBufferStream(&test_data);
    const reader = fixed_buffer_stream.reader();

    var name = Name.init(testing.allocator);
    defer name.deinit();

    try name.parse(reader);

    // Convert to owned slice
    const domain_str = try name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(domain_str);

    // Verify the result
    try testing.expectEqualStrings("mail.example.com", domain_str);
}

test "Name.fromString - basic domain parsing" {
    const allocator = testing.allocator;

    const domain = "example.com";
    const qname = try Name.fromString(allocator, domain);
    defer qname.deinit();

    try testing.expectEqual(@as(usize, 2), qname.labels.items.len);
    try testing.expectEqualStrings("example", qname.labels.items[0]);
    try testing.expectEqualStrings("com", qname.labels.items[1]);
}
