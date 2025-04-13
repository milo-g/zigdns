const std = @import("std");
const dns = @import("zigdns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a DNS name from string
    std.debug.print("=== DNS Name Handling ===\n\n", .{});

    const domains = [_][]const u8{
        "example.com",
        "mail.example.com",
        "sub.domain.example.com",
        "localhost",
        "", // Root domain
    };

    for (domains) |domain| {
        std.debug.print("Domain: '{s}'\n", .{domain});

        // Create Name from string
        var name = try dns.Name.fromString(allocator, domain);
        defer name.deinit();

        // Demonstrate toOwnedSlice
        const name_str = try name.toOwnedSlice(allocator);
        defer allocator.free(name_str);
        std.debug.print("  Converted back: '{s}'\n", .{name_str});

        // Show labels
        std.debug.print("  Labels: {d}\n", .{name.labels.items.len});
        for (name.labels.items, 0..) |label, i| {
            std.debug.print("    {d}: '{s}'\n", .{ i, label });
        }

        // Encode to wire format
        var buffer: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);
        const writer = fbs.writer();
        try name.encode(writer);
        const encoded_len = fbs.pos;

        // Display wire format
        std.debug.print("  Wire format ({d} bytes): ", .{encoded_len});
        for (buffer[0..encoded_len]) |byte| {
            if (byte >= 32 and byte <= 126) {
                std.debug.print("{c}", .{byte});
            } else {
                std.debug.print("\\x{X:0>2}", .{byte});
            }
        }
        std.debug.print("\n\n", .{});

        // Decode from wire format
        var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
        const reader = read_fbs.reader();

        var decoded_name = dns.Name.init(allocator);
        defer decoded_name.deinit();
        try decoded_name.parse(reader);

        const decoded_str = try decoded_name.toOwnedSlice(allocator);
        defer allocator.free(decoded_str);
        std.debug.print("  Decoded from wire: '{s}'\n", .{decoded_str});
        std.debug.print("---\n\n", .{});
    }
}
