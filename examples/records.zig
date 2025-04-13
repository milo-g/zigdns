const std = @import("std");
const dns = @import("zigdns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== DNS Record Types Example ===\n\n", .{});

    // Create a DNS packet to showcase different record types
    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    // Set up header
    packet.header.id = 1234;
    packet.header.flags = dns.Flags{
        .qr = true,
        .aa = true,
        .rd = true,
        .ra = true,
    };

    // Add question
    try packet.addQuestion(.{
        .name = "example.org",
        .type = .ALL, // Request all records
        .class = .IN,
    });

    // Add various resource records
    // A record (IPv4 address)
    try packet.addAnswer(.{
        .A = .{
            .name = "example.org",
            .address = [_]u8{ 93, 184, 216, 34 },
            .ttl = 3600,
        },
    });

    // AAAA record (IPv6 address)
    try packet.addAnswer(.{
        .AAAA = .{
            .name = "example.org",
            .address = [_]u8{
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
                0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
            },
            .ttl = 3600,
        },
    });

    // CNAME record
    try packet.addAnswer(.{
        .CNAME = .{
            .name = "www.example.org",
            .canonical = "example.org",
            .ttl = 3600,
        },
    });

    // MX record (mail exchange)
    try packet.addAnswer(.{
        .MX = .{
            .name = "example.org",
            .priority = 10,
            .exchange = "mail.example.org",
            .ttl = 3600,
        },
    });

    // NS record (nameserver)
    try packet.addAnswer(.{
        .NS = .{
            .name = "example.org",
            .nameserver = "ns1.example.org",
            .ttl = 3600,
        },
    });

    // Add another NS record
    try packet.addAnswer(.{
        .NS = .{
            .name = "example.org",
            .nameserver = "ns2.example.org",
            .ttl = 3600,
        },
    });

    // TXT record
    try packet.addAnswer(.{
        .TXT = .{
            .name = "example.org",
            .text = "v=spf1 include:_spf.example.org ~all",
            .ttl = 3600,
        },
    });

    // PTR record (reverse DNS)
    try packet.addAnswer(.{
        .PTR = .{
            .name = "34.216.184.93.in-addr.arpa",
            .pointer = "example.org",
            .ttl = 3600,
        },
    });

    // SRV record (service)
    try packet.addAnswer(.{
        .SRV = .{
            .name = "_http._tcp.example.org",
            .priority = 10,
            .weight = 60,
            .port = 80,
            .target = "web.example.org",
            .ttl = 3600,
        },
    });

    // Print summary of records
    std.debug.print("DNS Records Summary:\n", .{});
    std.debug.print("  Total Records: {d}\n", .{packet.answers.items.len});
    std.debug.print("\nIndividual Record Details:\n", .{});

    // Print each record
    for (packet.answers.items, 0..) |record, i| {
        const name = try record.name.toOwnedSlice(allocator);
        defer allocator.free(name);

        std.debug.print("\n#{d}: Type={s}, Name={s}, TTL={d}\n", .{
            i + 1,
            record.type.toString(),
            name,
            record.ttl,
        });

        switch (record.rdata) {
            .A => |ip| {
                std.debug.print("  A: {d}.{d}.{d}.{d}\n", .{ ip[0], ip[1], ip[2], ip[3] });
            },
            .AAAA => |ip| {
                std.debug.print("  AAAA: ", .{});
                for (0..8) |j| {
                    const word = @as(u16, ip[j * 2]) << 8 | ip[j * 2 + 1];
                    if (j > 0) std.debug.print(":", .{});
                    std.debug.print("{x:0>4}", .{word});
                }
                std.debug.print("\n", .{});
            },
            .CNAME => |cname| {
                const target = try cname.toOwnedSlice(allocator);
                defer allocator.free(target);
                std.debug.print("  CNAME: {s}\n", .{target});
            },
            .NS => |ns| {
                const server = try ns.toOwnedSlice(allocator);
                defer allocator.free(server);
                std.debug.print("  NS: {s}\n", .{server});
            },
            .MX => |mx| {
                const exchange = try mx.exchange.toOwnedSlice(allocator);
                defer allocator.free(exchange);
                std.debug.print("  MX: Priority={d} Exchange={s}\n", .{ mx.priority, exchange });
            },
            .TXT => |txt| {
                std.debug.print("  TXT: \"{s}\"\n", .{txt.data});
            },
            .PTR => |ptr| {
                const pointer = try ptr.toOwnedSlice(allocator);
                defer allocator.free(pointer);
                std.debug.print("  PTR: {s}\n", .{pointer});
            },
            .SRV => |srv| {
                const target = try srv.target.toOwnedSlice(allocator);
                defer allocator.free(target);
                std.debug.print("  SRV: Priority={d} Weight={d} Port={d} Target={s}\n", .{
                    srv.priority, srv.weight, srv.port, target,
                });
            },
            else => {
                std.debug.print("  <Unsupported Record Type>\n", .{});
            },
        }
    }

    // Encode the packet
    var buffer: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try packet.encode(fbs.writer());
    const encoded_len = fbs.pos;

    std.debug.print("\nTotal encoded packet size: {d} bytes\n", .{encoded_len});
}
