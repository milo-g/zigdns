# ZigDNS

A DNS protocol library for Zig, offering robust functionality for DNS packet parsing, construction, and manipulation.

## Features

- **Complete DNS packet handling**: Parse and construct DNS packets according to RFC standards.
- **Compressed name parsing**: Supports parsing compressed names.
- **Support for mDNS**: Implements mDNS query/record specific flags for unicast-desired and flush-cache.
- **Resource Record Support**: Includes comprehensive support for common DNS record types:
  - A (IPv4 addresses)
  - AAAA (IPv6 addresses)
  - CNAME (Canonical names)
  - NS (Nameserver records)
  - MX (Mail exchange records)
  - TXT (Text records)
  - PTR (Pointer records)
  - SRV (Service records)

### Limitations

- **Encoding compressed names**: Writing compressed packets is not supported at this time.
- **EDNS**: Extended DNS records OPT, SIG, and others are not supported at this time.
- **EDNS - Additional Records**: Additional EDNS record parsing is skipped.

## Installation

Add ZigDNS to your project:

```bash
zig fetch --save="dns" https://github.com/milo-g/zigdns/archive/refs/tags/0.3.1.tar.gz
```

Then in your `build.zig`:

```zig
const dns = b.dependency("dns", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("dns", dns.module("dns"));
```

## Usage

### Basic DNS Query

```zig
const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // Create a DNS packet
    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    // Set up the header with query flags and ID
    packet.header.id = 1234;
    packet.header.flags = dns.Flags{ .rd = true }; // Recursion desired

    // Add a question - lookup the A record for example.com
    try packet.addQuestion(.{
        .name = "example.com",
        .type = .A,
        .class = .IN,
    });

    // Encode the packet to a buffer
    var buffer: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try packet.encode(writer);
    const encoded_len = fbs.pos;

    // Now you can send this buffer to a DNS server...
}
```

### Creating a DNS Response

```zig
const std = @import("std");
const dns = @import("dns");

pub fn createResponse(allocator: std.mem.Allocator) !dns.Packet {
    var packet = dns.Packet.init(allocator);

    // Set up the header as a response
    packet.header.id = 1234;
    packet.header.flags = dns.Flags{
        .qr = true,  // This is a response
        .aa = true,  // Authoritative answer
        .rd = true,  // Recursion desired
        .ra = true,  // Recursion available
    };

    // Add a question
    try packet.addQuestion(.{
        .name = "example.com",
        .type = .A,
        .class = .IN,
    });

    // Add an A record answer
    try packet.addAnswer(.{
        .A = .{
            .name = "example.com",
            .address = [_]u8{ 93, 184, 216, 34 },  // Example.com IP
            .ttl = 3600,
        }
    });

    return packet;
}
```

### Parsing a DNS Packet

```zig
const std = @import("std");
const dns = @import("dns");

pub fn parseDnsPacket(allocator: std.mem.Allocator, buffer: []const u8) !void {
    var reader = dns.PacketReader.init(buffer);

    var packet = try dns.Packet.decode(allocator, &reader);
    defer packet.deinit();

    // Access header fields
    std.debug.print("DNS ID: {d}\n", .{packet.header.id});

    // Check if it's a query or response
    if (packet.header.flags.qr) {
        std.debug.print("This is a response\n", .{});
    } else {
        std.debug.print("This is a query\n", .{});
    }

    // Access questions
    for (packet.questions.items, 0..) |q, i| {
        const name = try q.name.toOwnedSlice(allocator);
        defer allocator.free(name);
        std.debug.print("Question {d}: {s} (Type: {s})\n", .{
            i + 1,
            name,
            q.type.toString(),
        });
    }

    // Access answers
    for (packet.answers.items, 0..) |a, i| {
        const name = try a.name.toOwnedSlice(allocator);
        defer allocator.free(name);
        std.debug.print("Answer {d}: {s} (Type: {s})\n", .{
            i + 1,
            name,
            a.type.toString(),
        });

        switch (a.type) {
            .A => {
                std.debug.print("Handling A record...\n", .{});

                const addr = a.rdata.A;
                std.debug.print("Address is {d}.{d}.{d}.{d}\n", .{addr[0], addr[1], addr[2], addr[3] });
            },
            .CNAME => {
                std.debug.print("Handling CNAME record...\n", .{});

                const canonical = a.rdata.CNAME.toOwnedSlice(allocator);
                defer allocator.free(canonical);
                std.debug.print("Canonical name: {s}", .{canonical});
            },
            ...
            else => break
        }
    }
}
```

### mDNS Support

```zig
...

// Creating packets
try packet.addQuestion(.{
    .name = "example.com",
    .type = .A,
    .class = .IN,
    .unicast = true, // unicast response desired.
});

try packet.addAnswer(.{
    .A = .{
        .name = "example.com",
        .address = [_]u8{ 192, 168, 1, 0 },
        .ttl = 3600,
        .flush = true, // clients should flush cache for this record.
    }
});

...

// Reading packets.
for (packet.questions.items, 0..) |q, i| {
    if (q.unicast) {
        std.debug.print("Client requesting a unicast response", .{});
    }
}

for (packet.answers.items, 0..) |a, i| {
    if (a.flush) {
        std.debug.print("Flush this record from the cache", .{});
    }
}

```

## Documentation

The library includes several examples demonstrating different aspects of the DNS protocol:

- `packet.zig`: Basic DNS packet construction and parsing
- `name.zig`: Working with DNS name format, using `toOwnedSlice` and wire format encoding
- `response.zig`: Creating complex DNS response packets with multiple record types
- `records.zig`: Demonstration of all supported DNS record types

### Building and Running Examples

Build all examples:

```bash
zig build examples
```

Run a specific example:

```bash
zig build example-packet   # Run the packet example
zig build example-name     # Run the name handling example
zig build example-response # Run the response example
zig build example-records  # Run the records example
```

## Building and Testing

```bash
zig build test
```

## License

[MIT License](LICENSE)
