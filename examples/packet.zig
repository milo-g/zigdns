const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    // Create a simple DNS query packet
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a new DNS packet
    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    // Set up header with query parameters
    packet.header.id = 1234;
    packet.header.flags = dns.Flags{ .rd = true }; // Recursion desired

    // Add a question for example.com
    try packet.addQuestion(.{
        .name = "example.com",
        .type = .A,
        .class = .IN,
    });

    // Encode the packet into a binary buffer
    var buffer: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();
    try packet.encode(writer);
    const encoded_len = fbs.pos;

    // Output the encoded packet (hexdump)
    std.debug.print("Encoded packet ({d} bytes):\n", .{encoded_len});
    for (buffer[0..encoded_len], 0..) |byte, i| {
        if (i % 16 == 0) std.debug.print("\n{X:0>4}: ", .{i});
        std.debug.print("{X:0>2} ", .{byte});
    }
    std.debug.print("\n\n", .{});

    // Now decode the packet from the buffer
    var reader = dns.PacketReader.init(buffer[0..encoded_len]);

    var decoded = try dns.Packet.decode(allocator, &reader);
    defer decoded.deinit();

    // Print the decoded packet information
    const first_question = decoded.questions.items[0];
    const name = try first_question.name.toOwnedSlice(allocator);
    defer allocator.free(name);

    std.debug.print("Decoded Packet:\n", .{});
    std.debug.print("  ID: {d}\n", .{decoded.header.id});
    std.debug.print("  Flags: {b:0>16}\n", .{decoded.header.flags.encodeToInt()});
    std.debug.print("  Questions: {d}\n", .{decoded.header.qd});
    std.debug.print("  First question: {d} {any} {any}\n", .{ name, first_question.type, first_question.class });
}
