const std = @import("std");
const io = std.io;
const mem = std.mem;
const Allocator = mem.Allocator;
const ParseError = @import("lib.zig").ParseError;
const PacketReader = @import("lib.zig").PacketReader;

const LABEL_MAX_LENGTH: u8 = 63;
const NAME_MAX_LENGTH: u8 = 255;

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

    /// Parses DNS name from a packet reader, assuming the beginning length byte is at the beginning of reader.
    /// Correctly follows pointers up to MAX_PTRS amount, set to 5.
    pub fn parse(self: *Name, reader: *PacketReader) !void {
        const PTR_FLAG: u8 = 0x3;
        const PTR_MASK: u16 = 0x3FFF;
        const MAX_PTRS = 5;

        var ptr_start: usize = 0;
        var ptr_count: usize = 0;
        var total_length: usize = 0;

        while (total_length < NAME_MAX_LENGTH) {
            var len_byte = try reader.peekByte();
            const is_ptr = (len_byte >> 6) == PTR_FLAG;

            if (is_ptr) {
                if (ptr_count >= MAX_PTRS) {
                    return ParseError.PointerLimitReached;
                }

                if (ptr_count == 0) {
                    ptr_start = reader.position();
                }

                const ptr = try reader.readInt(u16, .big) & PTR_MASK;
                if (ptr >= reader.length()) {
                    return ParseError.PointerOutOfBounds;
                }

                try reader.seekTo(@as(usize, ptr));
                total_length += 2;
                ptr_count += 1;
                continue;
            }

            len_byte = try reader.readByte();
            total_length += 1;

            if (len_byte > LABEL_MAX_LENGTH) {
                std.debug.print("length is {d}\n", .{len_byte});
                return ParseError.InvalidLabelLength;
            }

            if (len_byte == 0) {
                break;
            }

            const label = try self.allocator.alloc(u8, len_byte);
            errdefer self.allocator.free(label);

            const label_read = try reader.readAll(label);
            if (label_read != len_byte) {
                return error.EndOfStream;
            }

            total_length += label_read;
            try self.labels.append(label);
        }

        if (total_length > NAME_MAX_LENGTH) {
            return ParseError.InvalidTotalLength;
        }

        if (ptr_count > 0) {
            try reader.seekTo(ptr_start + @sizeOf(u16));
            return;
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
        var reader = PacketReader.init(name);

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

    pub fn fromWire(allocator: Allocator, reader: *PacketReader) !Name {
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

    var reader = PacketReader.init(&test_data);

    var name = Name.init(testing.allocator);
    defer name.deinit();

    try name.parse(&reader);

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

    var reader = PacketReader.init(&test_data);

    var name = Name.init(testing.allocator);
    defer name.deinit();

    // Should just fit within 255 bytes
    try name.parse(&reader);

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

    var reader = PacketReader.init(&test_data);

    var name = Name.init(testing.allocator);
    defer name.deinit();

    // Should fail with InvalidTotalLength
    const result = name.parse(&reader);
    try testing.expectError(ParseError.InvalidTotalLength, result);
}

test "Name.toOwnedSlice" {
    // Test data for "example.com"
    const test_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };

    var reader = PacketReader.init(&test_data);

    var name = Name.init(testing.allocator);
    defer name.deinit();

    try name.parse(&reader);

    // Convert to owned slice
    const domain_str = try name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(domain_str);

    // Verify the result
    try testing.expectEqualStrings("example.com", domain_str);
}

test "Name.toOwnedSlice - root domain" {
    // Test data for root domain (just a zero byte)
    const test_data = [_]u8{0};

    var reader = PacketReader.init(&test_data);

    var name = Name.init(testing.allocator);
    defer name.deinit();

    try name.parse(&reader);

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

    var reader = PacketReader.init(&test_data);

    var name = Name.init(testing.allocator);
    defer name.deinit();

    try name.parse(&reader);

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

test "Name.parse - with compression pointer" {
    const allocator = testing.allocator;

    // Create a DNS packet with a pointer
    // First name: [3]www[7]example[3]com[0]
    // Second name: [3]ftp[pointer to offset 4]
    var packet = [_]u8{
        // First name at offset 0
        3,   'w', 'w', 'w',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0,
        // Second name at offset 17 with pointer to "example.com" at offset 4
        3, 'f', 't', 'p', 0xC0, 0x04, // Pointer: 0xC4 (11000000) indicates pointer, 4 is offset
    };

    // Parse first name
    {
        var reader = PacketReader.init(&packet);
        var name = Name.init(allocator);
        defer name.deinit();

        try name.parse(&reader);

        try testing.expectEqual(@as(usize, 3), name.labels.items.len);
        try testing.expectEqualStrings("www", name.labels.items[0]);
        try testing.expectEqualStrings("example", name.labels.items[1]);
        try testing.expectEqualStrings("com", name.labels.items[2]);

        // Reader should be at position 17
        try testing.expectEqual(@as(usize, 17), reader.position());
    }

    // Parse second name with pointer
    {
        var reader = PacketReader.init(&packet);
        try reader.seekTo(17); // Start at the second name

        var name = Name.init(allocator);
        defer name.deinit();

        try name.parse(&reader);

        try testing.expectEqual(@as(usize, 3), name.labels.items.len);
        try testing.expectEqualStrings("ftp", name.labels.items[0]);
        try testing.expectEqualStrings("example", name.labels.items[1]);
        try testing.expectEqualStrings("com", name.labels.items[2]);

        // Reader should be at position 17 + 6 (after reading "ftp" and the pointer)
        try testing.expectEqual(@as(usize, 23), reader.position());
    }
}
