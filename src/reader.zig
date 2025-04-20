const std = @import("std");
const mem = std.mem;
const builtin = std.builtin;

const ReaderError = error{
    EndOfFile,
    StreamTooLong,
    SeekError,
};

pub const Reader = struct {
    data: []const u8,
    head: usize,

    pub fn init(data: []const u8) Reader {
        return .{
            .data = data,
            .head = 0,
        };
    }

    // Reading
    pub inline fn readByte(self: *Reader) !u8 {
        try self.canRead(1);

        const byte = self.data[self.head];
        self.head += 1;
        return byte;
    }

    pub inline fn readInt(self: *Reader, comptime T: type, endian: builtin.Endian) !T {
        try self.canRead(@sizeOf(T));

        var int_buffer: [@sizeOf(T)]u8 = undefined;
        @memcpy(&int_buffer, self.data[self.head .. self.head + @sizeOf(T)]);

        const int = mem.readInt(T, &int_buffer, endian);
        self.head += @sizeOf(T);
        return int;
    }

    pub fn readAll(self: *Reader, buffer: []u8) !usize {
        const to_read = @min(buffer.len, self.remaining());
        std.mem.copyForwards(u8, buffer, self.data[self.head .. self.head + to_read]);
        self.head += to_read;
        return to_read;
    }

    pub inline fn readUntilDelimiterOrEofAlloc(self: *Reader, allocator: mem.Allocator, delimiter: u8, max_size: usize) !?[]u8 {
        const start = self.head;
        var count: usize = 0;

        if (self.isEof()) {
            return null;
        }

        while (count < max_size) {
            if (self.isEof())
                break;

            const byte = try self.readByte();
            if (byte == delimiter) {
                break;
            }

            count += 1;
        }

        if (count >= max_size) {
            return ReaderError.StreamTooLong;
        }

        const buffer = try allocator.alloc(u8, count);
        mem.copyForwards(u8, buffer, self.data[start .. start + count]);

        return buffer;
    }

    // Peeking
    pub fn peekByte(self: *Reader) !u8 {
        try self.canRead(1);
        return self.data[self.head];
    }

    // Seeking
    pub fn seekBy(self: *Reader, len: usize) !void {
        try self.canRead(len);
        self.head += len;

        return;
    }

    pub fn seekTo(self: *Reader, pos: usize) !void {
        if (pos > self.data.len) {
            return ReaderError.SeekError;
        }

        self.head = pos;
    }

    pub fn reset(self: *Reader) void {
        self.head = 0;
    }

    // State
    pub fn position(self: *const Reader) usize {
        return self.head;
    }

    pub fn remaining(self: *const Reader) usize {
        return self.data.len - self.head;
    }

    pub fn isEof(self: *const Reader) bool {
        return self.head >= self.data.len;
    }

    pub fn length(self: *const Reader) usize {
        return self.data.len;
    }

    fn canRead(self: *const Reader, size: usize) !void {
        if (self.head + size > self.data.len) {
            return ReaderError.EndOfFile;
        }
    }
};

const testing = std.testing;

test "Reader initialization" {
    const data = "hello";
    const reader = Reader.init(data);

    try testing.expectEqualSlices(u8, data, reader.data);
    try testing.expectEqual(reader.head, 0);
}

test "Reader - readUntilDelimeterOrEofAlloc" {
    const allocator = testing.allocator;

    // Test case 1: Basic delimiter parsing
    {
        const data = "hello.world";
        var reader = Reader.init(data);

        // Read until the first delimiter
        const part1 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part1) |p| allocator.free(p);

        try testing.expect(part1 != null);
        try testing.expectEqualStrings("hello", part1.?);

        // Read after delimiter
        const part2 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part2) |p| allocator.free(p);

        try testing.expect(part2 != null);
        try testing.expectEqualStrings("world", part2.?);

        // Should return null at EOF
        const part3 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part3) |p| allocator.free(p);

        try testing.expect(part3 == null);
    }

    // Test case 2: Multiple delimiters
    {
        const data = "abc..def";
        var reader = Reader.init(data);

        // Read until first delimiter
        const part1 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part1) |p| allocator.free(p);

        try testing.expect(part1 != null);
        try testing.expectEqualStrings("abc", part1.?);

        // Empty segment between consecutive delimiters
        const part2 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part2) |p| allocator.free(p);

        try testing.expect(part2 != null);
        try testing.expectEqualStrings("", part2.?);

        // Third segment
        const part3 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part3) |p| allocator.free(p);

        try testing.expect(part3 != null);
        try testing.expectEqualStrings("def", part3.?);

        // EOF
        const part4 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part4) |p| allocator.free(p);

        try testing.expect(part4 == null);
    }

    // Test case 3: Empty string
    {
        const data = "";
        var reader = Reader.init(data);

        // Should return null immediately for empty string
        const part = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part) |p| allocator.free(p);

        try testing.expect(part == null);
    }

    // Test case 4: String without delimiter
    {
        const data = "nodelimiter";
        var reader = Reader.init(data);

        // Should return entire string
        const part = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part) |p| allocator.free(p);

        try testing.expect(part != null);
        try testing.expectEqualStrings("nodelimiter", part.?);

        // Then EOF
        const part2 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part2) |p| allocator.free(p);

        try testing.expect(part2 == null);
    }

    // Test case 5: Delimiter at start
    {
        const data = ".startswithdelimiter";
        var reader = Reader.init(data);

        // Should return empty string
        const part1 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part1) |p| allocator.free(p);

        try testing.expect(part1 != null);
        try testing.expectEqualStrings("", part1.?);

        // Then the rest
        const part2 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part2) |p| allocator.free(p);

        try testing.expect(part2 != null);
        try testing.expectEqualStrings("startswithdelimiter", part2.?);

        // Then EOF
        const part3 = try reader.readUntilDelimiterOrEofAlloc(allocator, '.', 100);
        defer if (part3) |p| allocator.free(p);

        try testing.expect(part3 == null);
    }

    // Test case 6: StreamTooLong error
    {
        const data = "abcdefghijklmnopqrstuvwxyz";
        var reader = Reader.init(data);

        // Max size of 5 should trigger StreamTooLong
        try testing.expectError(ReaderError.StreamTooLong, reader.readUntilDelimiterOrEofAlloc(allocator, '.', 5));
    }
}
test "Reader - readByte" {
    {
        const data = "ABC";
        var reader = Reader.init(data);

        // Read each byte individually
        try testing.expectEqual(@as(u8, 'A'), try reader.readByte());
        try testing.expectEqual(@as(usize, 1), reader.head);

        try testing.expectEqual(@as(u8, 'B'), try reader.readByte());
        try testing.expectEqual(@as(usize, 2), reader.head);

        try testing.expectEqual(@as(u8, 'C'), try reader.readByte());
        try testing.expectEqual(@as(usize, 3), reader.head);
    }

    // Test EOF error
    {
        const data = "A";
        var reader = Reader.init(data);

        // Read the only byte
        _ = try reader.readByte();

        // Next read should fail with EOF
        try testing.expectError(ReaderError.EndOfFile, reader.readByte());
    }

    // Test with empty data
    {
        const data = "";
        var reader = Reader.init(data);

        // Should immediately fail with EOF
        try testing.expectError(ReaderError.EndOfFile, reader.readByte());
    }
}

test "Reader - readAll" {
    // Test reading all available data
    {
        const data = "Hello, World!";
        var reader = Reader.init(data);

        var buffer: [13]u8 = undefined;
        const bytes_read = try reader.readAll(&buffer);

        try testing.expectEqual(@as(usize, 13), bytes_read);
        try testing.expectEqualStrings(data, buffer[0..]);
        try testing.expectEqual(@as(usize, 13), reader.head);
    }

    // Test reading with buffer larger than available data
    {
        const data = "Hello";
        var reader = Reader.init(data);

        var buffer: [10]u8 = undefined;
        const bytes_read = try reader.readAll(&buffer);

        try testing.expectEqual(@as(usize, 5), bytes_read);
        try testing.expectEqualStrings(data, buffer[0..bytes_read]);
        try testing.expectEqual(@as(usize, 5), reader.head);
    }

    // Test reading with buffer smaller than available data
    {
        const data = "Hello, World!";
        var reader = Reader.init(data);

        // Read first chunk
        var buffer1: [5]u8 = undefined;
        const bytes_read1 = reader.readAll(&buffer1);

        try testing.expectEqual(@as(usize, 5), bytes_read1);
        try testing.expectEqualStrings("Hello", buffer1[0..]);
        try testing.expectEqual(@as(usize, 5), reader.head);

        // Read second chunk
        var buffer2: [8]u8 = undefined;
        const bytes_read2 = reader.readAll(&buffer2);

        try testing.expectEqual(@as(usize, 8), bytes_read2);
        try testing.expectEqualStrings(", World!", buffer2[0..]);
        try testing.expectEqual(@as(usize, 13), reader.head);

        // Try to read more when at EOF
        var buffer3: [5]u8 = undefined;
        const bytes_read3 = reader.readAll(&buffer3);

        try testing.expectEqual(@as(usize, 0), bytes_read3);
        try testing.expectEqual(@as(usize, 13), reader.head);
    }

    // Test reading from empty data
    {
        const data = "";
        var reader = Reader.init(data);

        var buffer: [10]u8 = undefined;
        const bytes_read = try reader.readAll(&buffer);

        try testing.expectEqual(@as(usize, 0), bytes_read);
    }
}

test "Reader - combined reading operations" {
    // Test mixing different read operations
    {
        // Create test data with mixed content
        var data: [10]u8 = undefined;
        data[0] = 'A'; // Single byte
        std.mem.writeInt(u16, data[1..3], 0x1234, .little); // 2-byte integer
        data[3] = 'B'; // Single byte
        std.mem.writeInt(u32, data[4..8], 0xDEADBEEF, .big); // 4-byte integer
        data[8] = 'C'; // Single byte
        data[9] = 'D'; // Single byte

        var reader = Reader.init(&data);

        // Read first byte
        try testing.expectEqual(@as(u8, 'A'), try reader.readByte());

        // Read 16-bit integer
        try testing.expectEqual(@as(u16, 0x1234), try reader.readInt(u16, .little));

        // Read next byte
        try testing.expectEqual(@as(u8, 'B'), try reader.readByte());

        // Read 32-bit integer
        try testing.expectEqual(@as(u32, 0xDEADBEEF), try reader.readInt(u32, .big));

        // Read remaining bytes with readAll
        var buffer: [2]u8 = undefined;
        const bytes_read = try reader.readAll(&buffer);

        try testing.expectEqual(@as(usize, 2), bytes_read);
        try testing.expectEqualStrings("CD", buffer[0..]);

        // Should be at EOF now
        try testing.expectError(ReaderError.EndOfFile, reader.readByte());
    }
}

test "Reader - seekBy" {
    const data = "Hello, World!";
    var reader = Reader.init(data);

    // Seek forward a few bytes
    try reader.seekBy(5);
    try testing.expectEqual(@as(usize, 5), reader.head);

    // Read byte after seeking
    try testing.expectEqual(@as(u8, ','), try reader.readByte());

    // Seek to almost end
    try reader.seekBy(6);
    try testing.expectEqual(@as(usize, 12), reader.head);

    // Try to seek past end
    try testing.expectError(ReaderError.EndOfFile, reader.seekBy(2));
    try testing.expectEqual(@as(usize, 12), reader.head);

    // Seek by 0 should work
    try reader.seekBy(0);
    try testing.expectEqual(@as(usize, 12), reader.head);
}

test "Reader - seekTo" {
    const data = "Hello, World!";
    var reader = Reader.init(data);

    // Seek to middle
    try reader.seekTo(7);
    try testing.expectEqual(@as(usize, 7), reader.head);

    // Read byte after seeking
    try testing.expectEqual(@as(u8, 'W'), try reader.readByte());

    // Seek back to beginning
    try reader.seekTo(0);
    try testing.expectEqual(@as(usize, 0), reader.head);

    // Seek to end
    try reader.seekTo(data.len - 1);
    try testing.expectEqual(@as(usize, 12), reader.head);

    // Try to seek to eof
    try reader.seekTo(data.len);
    try testing.expectEqual(@as(usize, 13), reader.head);

    // try to seek past EndOfFile
    try testing.expectError(ReaderError.SeekError, reader.seekTo(data.len + 1));
    try testing.expectEqual(@as(usize, 13), reader.head);
}

test "Reader - reset" {
    const data = "Hello, World!";
    var reader = Reader.init(data);

    // Move to middle
    try reader.seekBy(6);
    try testing.expectEqual(@as(usize, 6), reader.head);

    // Reset to beginning
    reader.reset();
    try testing.expectEqual(@as(usize, 0), reader.head);

    // Read from beginning again
    try testing.expectEqual(@as(u8, 'H'), try reader.readByte());
}

test "Reader - position" {
    const data = "Hello, World!";
    var reader = Reader.init(data);

    // Initially at beginning
    try testing.expectEqual(@as(usize, 0), reader.position());

    // Move head and check position
    try reader.seekBy(5);
    try testing.expectEqual(@as(usize, 5), reader.position());

    // Read byte and check updated position
    _ = try reader.readByte();
    try testing.expectEqual(@as(usize, 6), reader.position());
}

test "Reader - remaining" {
    const data = "Hello, World!";
    var reader = Reader.init(data);

    // Initially all data remains
    try testing.expectEqual(@as(usize, 13), reader.remaining());

    // After moving halfway
    try reader.seekBy(6);
    try testing.expectEqual(@as(usize, 7), reader.remaining());

    // After moving to end
    try reader.seekTo(data.len - 1);
    try testing.expectEqual(@as(usize, 1), reader.remaining());

    // After reading last byte
    _ = try reader.readByte();
    try testing.expectEqual(@as(usize, 0), reader.remaining());
}

test "Reader - isEof" {
    const data = "Hello";
    var reader = Reader.init(data);

    // Initially not at EOF
    try testing.expect(!reader.isEof());

    // Still not at EOF in the middle
    try reader.seekBy(3);
    try testing.expect(!reader.isEof());

    // Not at EOF at last byte
    try reader.seekTo(data.len - 1);
    try testing.expect(!reader.isEof());

    // At EOF after reading last byte
    _ = try reader.readByte();
    try testing.expect(reader.isEof());

    // Empty reader is at EOF
    var empty_reader = Reader.init("");
    try testing.expect(empty_reader.isEof());
}
