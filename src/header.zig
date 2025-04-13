const std = @import("std");
const builtin = @import("builtin");
const cpu = builtin.cpu;
const mem = std.mem;

const ParseError = @import("lib.zig").ParseError;

pub const HeaderSize: usize = 12;

/// DNS Operation Codes (RFC 1035, 2136, 3425, 6891)
pub const OpCode = enum(u4) {
    /// Standard query
    QUERY = 0,

    /// Inverse query (obsolete)
    IQUERY = 1,

    /// Server status request
    STATUS = 2,

    /// Reserved
    RESERVED3 = 3,

    /// Zone change notification
    NOTIFY = 4,

    /// Dynamic update
    UPDATE = 5,

    /// Stateful operations
    DSO = 6,

    // 7-15 are unassigned
    _,
};

/// DNS Response Codes (RFC 1035, 2136, 2671, 2845)
pub const RCode = enum(u4) {
    /// No error
    NOERROR = 0,

    /// Format error
    FORMERR = 1,

    /// Server failure
    SERVFAIL = 2,

    /// Name error (domain doesn't exist)
    NXDOMAIN = 3,

    /// Not implemented
    NOTIMP = 4,

    /// Query refused
    REFUSED = 5,

    /// Name exists when it should not
    YXDOMAIN = 6,

    /// RR set exists when it should not
    YXRRSET = 7,

    /// RR set that should exist does not
    NXRRSET = 8,

    /// Not authorized
    NOTAUTH = 9,

    /// Name not in zone
    NOTZONE = 10,

    // 11-15 reserved
    _,
};

pub const Flags = packed struct {
    /// Query (0) or response (1)
    qr: bool = false,

    /// Query type (4 bit)
    opcode: OpCode = .QUERY,

    /// Authoritative answer
    aa: bool = false,

    /// Message truncated
    tc: bool = false,

    /// Recursion desired
    rd: bool = false,

    /// Recursion available
    ra: bool = false,

    /// Reserved bit (must be 0)
    z: u1 = 0,

    /// Authenticated data (DNSSEC)
    ad: bool = false,

    /// Checking disabled (DNSSEC)
    cd: bool = false,

    /// Response code (4 bit)
    rcode: RCode = .NOERROR,

    const QR_MASK: u16 = 0x8000; // 15
    const OPCODE_MASK: u16 = 0x7800; // 11-14
    const OPCODE_SHIFT: u4 = 11;
    const AA_MASK: u16 = 0x0400; // 10
    const TC_MASK: u16 = 0x0200; // 9
    const RD_MASK: u16 = 0x0100; // 8

    const RA_MASK: u16 = 0x0080; // 7
    const Z_MASK: u16 = 0x0040; // 6
    const Z_SHIFT: u4 = 6;
    const AD_MASK: u16 = 0x0020; // 5
    const CD_MASK: u16 = 0x0010; // 4
    const RCODE_MASK: u16 = 0x000F; // 0-3

    pub fn decodeSlice(bytes: []u8) Flags {
        const raw_flags = std.mem.readInt(u16, bytes[0..2], .big);

        return .{
            .qr = (raw_flags & QR_MASK) != 0,
            .opcode = @enumFromInt((raw_flags & OPCODE_MASK) >> OPCODE_SHIFT),
            .aa = (raw_flags & AA_MASK) != 0,
            .tc = (raw_flags & TC_MASK) != 0,
            .rd = (raw_flags & RD_MASK) != 0,
            .ra = (raw_flags & RA_MASK) != 0,
            .z = @truncate(raw_flags & Z_MASK),
            .ad = (raw_flags & AD_MASK) != 0,
            .cd = (raw_flags & CD_MASK) != 0,
            .rcode = @enumFromInt(raw_flags & RCODE_MASK),
        };
    }

    /// Encode flags to int
    pub fn encodeToInt(self: Flags) u16 {
        var raw_flags: u16 = 0x0;

        if (self.qr) raw_flags |= QR_MASK;
        raw_flags |= (@as(u16, @intFromEnum(self.opcode)) << OPCODE_SHIFT);
        if (self.aa) raw_flags |= AA_MASK;
        if (self.tc) raw_flags |= TC_MASK;
        if (self.rd) raw_flags |= RD_MASK;

        if (self.ra) raw_flags |= RA_MASK;
        raw_flags |= (@as(u16, self.z) << Z_SHIFT);
        if (self.ad) raw_flags |= AD_MASK;
        if (self.cd) raw_flags |= CD_MASK;
        raw_flags |= @intFromEnum(self.rcode);

        return raw_flags;
    }
};

/// DNS header (RFC 1035)
pub const Header = packed struct {
    /// Transaction ID
    id: u16 = 0,

    /// Flags
    flags: Flags = Flags{},

    /// Question count
    qd: u16 = 0,

    /// Answer count
    an: u16 = 0,

    /// Authority count
    ns: u16 = 0,

    /// Additional count
    ar: u16 = 0,

    pub fn decode(reader: anytype) !Header {
        var bytes: [HeaderSize]u8 = undefined;
        _ = try reader.readAll(&bytes);

        const flags = Flags.decodeSlice(bytes[2..4]);

        return .{
            .id = mem.readInt(u16, bytes[0..2], .big),
            .flags = flags,
            .qd = mem.readInt(u16, bytes[4..6], .big),
            .an = mem.readInt(u16, bytes[6..8], .big),
            .ns = mem.readInt(u16, bytes[8..10], .big),
            .ar = mem.readInt(u16, bytes[10..12], .big),
        };
    }

    pub fn encode(self: *Header, writer: anytype) !void {
        try writer.writeInt(u16, self.id, .big);

        const raw_flags = self.flags.encodeToInt();
        try writer.writeInt(u16, raw_flags, .big);

        try writer.writeInt(u16, self.qd, .big);
        try writer.writeInt(u16, self.an, .big);
        try writer.writeInt(u16, self.ns, .big);
        try writer.writeInt(u16, self.ar, .big);
    }
};

test "Parse header from slice" {
    const sample_header = [_]u8{
        0x12, 0x34, // ID: 0x1234
        0x81, 0x80, // Flags: 0x8180 (QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, Z=0, RCODE=0)
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x02, // ANCOUNT: 2
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    };

    var stream = std.io.fixedBufferStream(&sample_header);
    const reader = stream.reader();
    const header = try Header.decode(reader);

    try std.testing.expectEqual(@as(u16, 0x1234), header.id);

    try std.testing.expectEqual(true, header.flags.qr); // QR bit (bit 15) should be 1
    try std.testing.expectEqual(OpCode.QUERY, header.flags.opcode); // Opcode (bits 14-11) should be 0
    try std.testing.expectEqual(false, header.flags.aa); // AA bit (bit 10) should be 0
    try std.testing.expectEqual(false, header.flags.tc); // TC bit (bit 9) should be 0
    try std.testing.expectEqual(true, header.flags.rd); // RD bit (bit 8) should be 1
    try std.testing.expectEqual(true, header.flags.ra); // RA bit (bit 7) should be 1
    try std.testing.expectEqual(false, header.flags.ad); // AD bit (bit 5) should be 0
    try std.testing.expectEqual(false, header.flags.cd); // CD bit (bit 4) should be 0
    try std.testing.expectEqual(RCode.NOERROR, header.flags.rcode); // RCODE (bits 3-0) should be 0

    // Test the count fields
    try std.testing.expectEqual(@as(u16, 1), header.qd);
    try std.testing.expectEqual(@as(u16, 2), header.an);
    try std.testing.expectEqual(@as(u16, 0), header.ns);
    try std.testing.expectEqual(@as(u16, 0), header.ar);
}

test "Flags.encodeInt" {
    const flags = Flags{
        .qr = true,
        .opcode = .STATUS,
        .aa = true, // Authoritative answer
        .tc = false,
        .rd = false,
        .ra = false,
        .z = 0,
        .ad = false,
        .cd = false,
        .rcode = .SERVFAIL,
    };

    try std.testing.expectEqual(@as(u16, 0x9402), flags.encodeToInt());
}
