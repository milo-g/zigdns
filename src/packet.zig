const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const dns = @import("lib.zig");

const ParseError = dns.ParseError;
const DEFAULT_TTL: u32 = 3600;

// Type hint structs for configuration
pub const QuestionConfig = struct {
    name: []const u8,
    type: dns.ResourceType = .A,
    class: dns.ResourceClass = .IN,
};

pub const RecordConfig = union(enum) {
    A: struct {
        name: []const u8 = "",
        address: [4]u8,
        ttl: u32 = DEFAULT_TTL,
    },
    AAAA: struct {
        name: []const u8 = "",
        address: [16]u8,
        ttl: u32 = DEFAULT_TTL,
    },
    TXT: struct {
        name: []const u8 = "",
        text: []const u8,
        ttl: u32 = DEFAULT_TTL,
    },
    NS: struct {
        name: []const u8 = "",
        nameserver: []const u8 = "",
        ttl: u32 = DEFAULT_TTL,
    },
    CNAME: struct {
        name: []const u8 = "",
        canonical: []const u8 = "",
        ttl: u32 = DEFAULT_TTL,
    },
    PTR: struct {
        name: []const u8 = "",
        pointer: []const u8 = "",
        ttl: u32 = DEFAULT_TTL,
    },
    MX: struct {
        name: []const u8,
        priority: u16 = 0,
        exchange: []const u8 = "",
        ttl: u32 = DEFAULT_TTL,
    },
    SRV: struct {
        name: []const u8,
        priority: u16,
        weight: u16,
        port: u16,
        target: []const u8 = "",
        ttl: u32 = DEFAULT_TTL,
    },
};

pub const Packet = struct {
    header: dns.Header,
    questions: std.ArrayList(dns.Question),
    answers: std.ArrayList(dns.ResourceRecord),
    nameservers: std.ArrayList(dns.ResourceRecord),
    additional: std.ArrayList(dns.ResourceRecord),

    allocator: Allocator,

    pub fn init(allocator: Allocator) Packet {
        return .{
            .header = dns.Header{},
            .questions = std.ArrayList(dns.Question).init(allocator),
            .answers = std.ArrayList(dns.ResourceRecord).init(allocator),
            .nameservers = std.ArrayList(dns.ResourceRecord).init(allocator),
            .additional = std.ArrayList(dns.ResourceRecord).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Packet) void {
        for (self.questions.items) |q| q.deinit();
        for (self.answers.items) |a| a.deinit();
        for (self.nameservers.items) |ns| ns.deinit();
        for (self.additional.items) |ad| ad.deinit();

        self.questions.deinit();
        self.answers.deinit();
        self.nameservers.deinit();
        self.additional.deinit();
    }

    pub fn parse(self: *Packet, reader: anytype) !void {
        self.header = try dns.Header.decode(reader);

        for (0..self.header.qd) |_| {
            const question = try dns.Question.decode(self.allocator, reader);
            try self.questions.append(question);
        }

        for (0..self.header.an) |_| {
            std.debug.print("answers\n", .{});
            const answer = try dns.ResourceRecord.decode(self.allocator, reader);
            try self.answers.append(answer);
        }

        for (0..self.header.ns) |_| {
            const nameserver = try dns.ResourceRecord.decode(self.allocator, reader);
            try self.nameservers.append(nameserver);
        }

        for (0..self.header.ar) |_| {
            const additional = try dns.ResourceRecord.decode(self.allocator, reader);
            try self.additional.append(additional);
        }
    }

    pub fn decode(allocator: Allocator, reader: anytype) !Packet {
        var packet = Packet.init(allocator);
        try packet.parse(reader);

        return packet;
    }

    pub fn encode(self: *Packet, writer: anytype) !void {
        try self.header.encode(writer);

        for (self.questions.items) |q| {
            try q.encode(writer);
        }

        for (self.answers.items) |a| {
            try a.encode(writer);
        }

        for (self.nameservers.items) |ns| {
            try ns.encode(writer);
        }

        for (self.additional.items) |ad| {
            try ad.encode(writer);
        }
    }

    pub fn addQuestion(self: *Packet, config: QuestionConfig) !void {
        const question = try dns.Question.create(self.allocator, config.name, config.type, config.class);
        try self.questions.append(question);

        self.header.qd += 1;
    }

    pub fn addAnswer(self: *Packet, config: RecordConfig) !void {
        const record = try self.createRecord(config);

        self.header.an += 1;
        try self.answers.append(record);
    }

    fn createRecord(self: *Packet, config: RecordConfig) !dns.ResourceRecord {
        return switch (config) {
            .A => |a| try dns.ResourceRecord.createA(self.allocator, a.name, a.address, a.ttl),
            .AAAA => |a| try dns.ResourceRecord.createAAAA(self.allocator, a.name, a.address, a.ttl),
            .TXT => |txt| try dns.ResourceRecord.createTXT(self.allocator, txt.name, txt.text, txt.ttl),
            .CNAME => |cname| try dns.ResourceRecord.createCNAME(self.allocator, cname.name, cname.canonical, cname.ttl),
            .NS => |ns| try dns.ResourceRecord.createNS(self.allocator, ns.name, ns.nameserver, ns.ttl),
            .PTR => |ptr| try dns.ResourceRecord.createPTR(self.allocator, ptr.name, ptr.pointer, ptr.ttl),
            .MX => |mx| try dns.ResourceRecord.createMX(self.allocator, mx.name, mx.priority, mx.exchange, mx.ttl),
            .SRV => |srv| try dns.ResourceRecord.createSRV(self.allocator, srv.name, srv.priority, srv.weight, srv.port, srv.target, srv.ttl),
        };
    }
};

const testing = std.testing;

fn createTestName(allocator: Allocator, name: []const u8) !dns.Name {
    return try dns.Name.fromString(allocator, name);
}

fn createARecord(allocator: Allocator, name: []const u8, ip: [4]u8, ttl: u32) !dns.ResourceRecord {
    var record = dns.ResourceRecord.init(allocator);
    errdefer record.deinit();

    record.name = try createTestName(allocator, name);
    record.type = .A;
    record.class = .IN;
    record.ttl = ttl;
    record.rlength = 4;
    record.rdata = .{ .A = ip };

    return record;
}

test "Packet encoding and decoding - simple query" {
    var packet = Packet.init(testing.allocator);
    defer packet.deinit();

    packet.header.id = 1234;
    packet.header.flags = dns.Flags{ .rd = true };
    packet.header.qd = 1;

    var question = dns.Question.init(testing.allocator);
    question.name = try createTestName(testing.allocator, "example.com");
    question.type = .A;
    question.class = .IN;
    try packet.questions.append(question);

    var buffer: [512]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    const writer = fbs.writer();

    try packet.encode(writer);
    const encoded_len = fbs.pos;

    // Decoding
    var read_fbs = std.io.fixedBufferStream(buffer[0..encoded_len]);
    const reader = read_fbs.reader();

    var decoded_packet = try Packet.decode(testing.allocator, reader);
    defer decoded_packet.deinit();

    try testing.expectEqual(@as(u16, 1234), decoded_packet.header.id);
    try testing.expectEqual(@as(u16, 0x0100), decoded_packet.header.flags.encodeToInt());
    try testing.expectEqual(@as(u16, 1), decoded_packet.header.qd);
    try testing.expectEqual(@as(u16, 0), decoded_packet.header.an);

    try testing.expectEqual(@as(usize, 1), decoded_packet.questions.items.len);
    try testing.expectEqual(dns.ResourceType.A, decoded_packet.questions.items[0].type);
    try testing.expectEqual(dns.ResourceClass.IN, decoded_packet.questions.items[0].class);

    const q_name = decoded_packet.questions.items[0].name;
    try testing.expectEqual(@as(usize, 2), q_name.labels.items.len);
    try testing.expectEqualStrings("example", q_name.labels.items[0]);
    try testing.expectEqualStrings("com", q_name.labels.items[1]);
}

test "addQuestion - basic A record question" {
    const allocator = testing.allocator;

    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    try packet.addQuestion(.{ .name = "example.com", .type = .A, .class = .IN });

    try testing.expectEqual(@as(u16, 1), packet.header.qd);

    const question = packet.questions.items[0];
    const question_name = try question.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(question_name);

    try testing.expectEqualStrings("example.com", question_name);
    try testing.expectEqual(dns.ResourceType.A, question.type);
    try testing.expectEqual(dns.ResourceClass.IN, question.class);
}

test "addQuestion - multiple questions" {
    const allocator = testing.allocator;

    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    try packet.addQuestion(.{
        .name = "example.com",
        .type = .A,
    });

    try packet.addQuestion(.{ .name = "example.org", .type = .AAAA, .class = .IN });

    try testing.expectEqual(@as(u16, 2), packet.header.qd);

    const first_question = packet.questions.items[0];
    const first_question_name = try first_question.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(first_question_name);

    try testing.expectEqualStrings("example.com", first_question_name);
    try testing.expectEqual(dns.ResourceType.A, first_question.type);

    const second_question = packet.questions.items[1];
    const second_question_name = try second_question.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(second_question_name);

    try testing.expectEqualStrings("example.org", second_question_name);
    try testing.expectEqual(dns.ResourceType.AAAA, second_question.type);
}

test "addAnswer - A record" {
    const allocator = testing.allocator;

    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    try packet.addAnswer(.{ .A = .{ .name = "example.com", .address = [_]u8{ 192, 168, 0, 1 }, .ttl = 3600 } });

    try testing.expectEqual(@as(u16, 1), packet.header.an);

    const record = packet.answers.items[0];
    const record_name = try record.name.toOwnedSlice(testing.allocator);
    defer testing.allocator.free(record_name);

    try testing.expectEqualStrings("example.com", record_name);

    try testing.expectEqual(dns.ResourceType.A, record.type);
}

test "addAnswer - multiple record types" {
    const allocator = testing.allocator;

    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    try packet.addAnswer(.{ .A = .{ .name = "example.com", .address = [_]u8{ 192, 168, 0, 1 } } });
    try packet.addAnswer(.{ .AAAA = .{ .name = "example.com", .address = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } });
    try packet.addAnswer(.{ .TXT = .{ .name = "example.com", .text = "v=spf1 include:_spf.example.com ~all" } });

    try testing.expectEqual(@as(u16, 3), packet.header.an);
}

test "addAnswer - with optional TTL" {
    const allocator = testing.allocator;

    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    try packet.addAnswer(.{ .A = .{ .name = "example.com", .address = [_]u8{ 192, 168, 0, 1 }, .ttl = 3600 } });
    try packet.addAnswer(.{ .A = .{ .name = "example.org", .address = [_]u8{ 192, 168, 0, 2 } } });

    try testing.expectEqual(@as(u16, 2), packet.header.an);
}

test "addAnswer - with optional name" {
    const allocator = testing.allocator;

    var packet = dns.Packet.init(allocator);
    defer packet.deinit();

    try packet.addAnswer(.{ .A = .{ .name = "example.com", .address = [_]u8{ 192, 168, 0, 1 } } });
    try packet.addAnswer(.{ .A = .{ .address = [_]u8{ 192, 168, 0, 2 } } });

    try testing.expectEqual(@as(u16, 2), packet.header.an);
}
