const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== DNS Response Construction ===\n\n", .{});

    // Create a DNS response packet
    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    // Setup header as a response
    packet.header.id = 1234;
    packet.header.flags = dns.Flags{
        .qr = true, // This is a response
        .rd = true, // Recursion desired (copied from query)
        .ra = true, // Recursion available
        .aa = true, // Authoritative answer
    };

    // Add the question (mirroring what was asked)
    try packet.addQuestion(.{
        .name = "example.com",
        .type = .A,
        .class = .IN,
    });

    // Add A record answer
    try packet.addAnswer(.{
        .A = .{
            .name = "example.com",
            .address = [_]u8{ 93, 184, 216, 34 }, // 93.184.216.34
            .ttl = 3600,
        },
    });

    // Add AAAA record answer
    try packet.addAnswer(.{
        .AAAA = .{
            .name = "example.com",
            .address = [_]u8{ 0x20, 0x01, 0x4, 0x08, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 },
            .ttl = 3600,
        },
    });

    // Add a TXT record
    try packet.addAnswer(.{
        .TXT = .{
            .name = "example.com",
            .text = "v=spf1 -all",
            .ttl = 3600,
        },
    });

    // Encode the packet
    var buffer: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try packet.encode(fbs.writer());
    const encoded_len = fbs.pos;

    // Print the packet contents
    std.debug.print("Constructed DNS Response:\n", .{});
    std.debug.print("  ID: {d}\n", .{packet.header.id});
    std.debug.print("  Flags: 0x{X:0>4} ", .{packet.header.flags.encodeToInt()});
    std.debug.print("(QR={d}, AA={d}, RD={d}, RA={d})\n", .{
        @intFromBool(packet.header.flags.qr),
        @intFromBool(packet.header.flags.aa),
        @intFromBool(packet.header.flags.rd),
        @intFromBool(packet.header.flags.ra),
    });
    std.debug.print("  Questions: {d}\n", .{packet.header.qd});
    std.debug.print("  Answers: {d}\n", .{packet.header.an});

    // Display each question
    for (packet.questions.items, 0..) |question, i| {
        const qname = try question.name.toOwnedSlice(allocator);
        defer allocator.free(qname);
        std.debug.print("  Question {d}: {s} {any} {any}\n", .{ i + 1, qname, question.type, question.class });
    }

    // Display each answer
    for (packet.answers.items, 0..) |answer, i| {
        const aname = try answer.name.toOwnedSlice(allocator);
        defer allocator.free(aname);

        std.debug.print("  Answer {d}: {s} {any} TTL={d}\n", .{ i + 1, aname, answer.type, answer.ttl });

        switch (answer.rdata) {
            .A => |ip| {
                std.debug.print("    Address: {d}.{d}.{d}.{d}\n", .{ ip[0], ip[1], ip[2], ip[3] });
            },
            .AAAA => |ip| {
                std.debug.print("    IPv6: ", .{});
                for (0..8) |j| {
                    const word: u16 = @as(u16, ip[j * 2]) << 8 | ip[j * 2 + 1];
                    std.debug.print("{x}", .{word});
                    if (j < 7) std.debug.print(":", .{});
                }
                std.debug.print("\n", .{});
            },
            .TXT => |txt| {
                std.debug.print("    Text: \"{s}\"\n", .{txt.data});
            },
            .CNAME => |cname| {
                const cn = try cname.toOwnedSlice(allocator);
                defer allocator.free(cn);
                std.debug.print("    Canonical Name: {s}\n", .{cn});
            },
            else => {
                std.debug.print("    <Other record type>\n", .{});
            },
        }
    }

    // Packet size
    std.debug.print("\nEncoded packet size: {d} bytes\n", .{encoded_len});
}
