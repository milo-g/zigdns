const std = @import("std");
const net = std.net;
const dns = @import("zigdns");

const ServerError = error{
    InvalidQueryFormat,
    UnknownQueryType,
};

const HandlerError = ServerError || std.mem.Allocator.Error;

const SimpleServer = struct {
    socket: net.dgram.Socket,
    allocator: std.mem.Allocator,
    buffer: []u8,

    // Records we're serving
    records: std.ArrayList(dns.ResourceRecord),

    pub fn init(allocator: std.mem.Allocator, port: u16) !SimpleServer {
        const socket = try net.dgram.openSocket(allocator, .{
            .address = net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, port),
            .flags = .{},
        });
        errdefer socket.close();

        const buffer = try allocator.alloc(u8, 1024);
        errdefer allocator.free(buffer);

        var records = std.ArrayList(dns.ResourceRecord).init(allocator);
        errdefer {
            for (records.items) |*record| {
                record.deinit();
            }
            records.deinit();
        }

        // Add our A record
        try records.append(try dns.ResourceRecord.createA(
            allocator,
            "example.org",
            [4]u8{ 127, 0, 0, 1 },
            3600,
        ));

        return SimpleServer{
            .socket = socket,
            .allocator = allocator,
            .buffer = buffer,
            .records = records,
        };
    }

    pub fn deinit(self: *SimpleServer) void {
        for (self.records.items) |*record| {
            record.deinit();
        }
        self.records.deinit();
        self.allocator.free(self.buffer);
        self.socket.close();
    }

    pub fn serve(self: *SimpleServer) !void {
        std.debug.print("DNS server listening on UDP port {}\n", .{
            self.socket.getLocalAddress().getPort(),
        });

        while (true) {
            // Receive a DNS query
            const recv_result = try self.socket.receiveFrom(self.buffer);
            const addr = recv_result.sender;
            const recv_len = recv_result.numberOfBytes;

            std.debug.print("Received {} bytes from {}:{}\n", .{
                recv_len,
                addr.getIp4().octets,
                addr.getPort(),
            });

            // Handle the query
            const response_len = self.handleQuery(self.buffer[0..recv_len], self.buffer) catch |err| {
                std.debug.print("Error handling query: {}\n", .{err});
                continue;
            };

            // Send the response
            _ = try self.socket.sendTo(addr, self.buffer[0..response_len]);
        }
    }

    fn handleQuery(self: *SimpleServer, query_data: []const u8, response_buffer: []u8) !usize {
        // Create a reader for the query data
        var query_fbs = std.io.fixedBufferStream(query_data);
        const query_reader = query_fbs.reader();

        // Decode the DNS packet
        var query_packet = dns.Packet.init(self.allocator);
        defer query_packet.deinit();
        query_packet.parse(query_reader) catch |err| {
            std.debug.print("Failed to parse DNS query: {}\n", .{err});
            return ServerError.InvalidQueryFormat;
        };

        // Create a response packet
        var response_packet = dns.Packet.init(self.allocator);
        defer response_packet.deinit();

        // Set response header fields
        response_packet.header.id = query_packet.header.id;
        response_packet.header.flags = dns.Flags{
            .qr = true, // This is a response
            .rd = query_packet.header.flags.rd, // Copy recursion desired bit
            .ra = false, // We don't support recursion
            .aa = true, // We're authoritative for our records
        };

        // Check if we have questions
        if (query_packet.questions.items.len == 0) {
            std.debug.print("Query contained no questions\n", .{});
            return ServerError.InvalidQueryFormat;
        }

        // Get the first question
        const question = query_packet.questions.items[0];
        const qname = try question.name.toOwnedSlice(self.allocator);
        defer self.allocator.free(qname);

        std.debug.print("Query for {s} {s}\n", .{qname, @tagName(question.type)});

        // Copy the question to the response
        try response_packet.addQuestion(.{
            .name = qname,
            .type = question.type,
            .class = question.class,
        });

        // Check if we have a matching record
        var found = false;
        for (self.records.items) |record| {
            const record_name = try record.name.toOwnedSlice(self.allocator);
            defer self.allocator.free(record_name);

            if (std.mem.eql(u8, record_name, qname) and record.type == question.type) {
                // Add this record to the answer section
                switch (record.type) {
                    .A => {
                        try response_packet.addAnswer(.{
                            .A = .{
                                .name = qname,
                                .address = record.rdata.A,
                                .ttl = record.ttl,
                            },
                        });
                        found = true;
                    },
                    else => {
                        std.debug.print("Unhandled record type: {}\n", .{record.type});
                    },
                }
            }
        }

        if (!found) {
            // Set NXDOMAIN if no matching records
            response_packet.header.flags.rcode = .NXDOMAIN;
        }

        // Encode the response packet
        var response_fbs = std.io.fixedBufferStream(response_buffer);
        const response_writer = response_fbs.writer();
        try response_packet.encode(response_writer);

        return response_fbs.pos;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a simple DNS server on port 5353
    var server = try SimpleServer.init(allocator, 5353);
    defer server.deinit();

    // Run the server (will run until terminated)
    try server.serve();
}