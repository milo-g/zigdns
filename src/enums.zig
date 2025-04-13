const std = @import("std");

/// DNS Resource Record Types
/// Based on IANA registry of DNS parameters
/// Inexahustive list but covers broad usage (e.g. can be set in registrars like GoDaddy)
pub const ResourceType = enum(u16) {
    /// IPv4 host address
    A = 1,
    /// Authoritative name server
    NS = 2,
    /// Canonical name for an alias
    CNAME = 5,
    /// Domain name pointer
    PTR = 12,
    /// Mail exchange
    MX = 15,
    /// Text strings
    TXT = 16,
    /// IPv6 host address
    AAAA = 28,
    /// Service record
    SRV = 33,
    /// QTYPE all records (*)
    ALL = 255,
    /// Unknown value
    UNKNOWN = 0,

    pub fn fromInt(value: u16) ResourceType {
        return switch (value) {
            1 => .A,
            2 => .NS,
            5 => .CNAME,
            12 => .PTR,
            15 => .MX,
            16 => .TXT,
            28 => .AAAA,
            33 => .SRV,
            255 => .ALL,
            else => .UNKNOWN,
        };
    }

    pub fn toString(self: ResourceType) []const u8 {
        return switch (self) {
            .A, .NS, .CNAME, .PTR, .MX, .TXT, .AAAA, .SRV, .ALL => @tagName(self),
            else => "UNKNOWN",
        };
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.writeAll(self.toString());
    }
};

/// DNS Resource Record Classes
/// Based on IANA registry of DNS parameters
pub const ResourceClass = enum(u16) {
    /// Internet
    IN = 1,
    /// CSNET (obsolete)
    CS = 2,
    /// Chaos
    CH = 3,
    /// Hesiod
    HS = 4,
    /// QCLASS NONE
    NONE = 254,
    /// QCLASS * (ANY)
    ANY = 255,

    /// Allows handling of unknown resource classes
    UNKNOWN = 0,

    pub fn fromInt(value: u16) ResourceClass {
        return switch (value) {
            1 => .IN,
            2 => .CS,
            3 => .CH,
            4 => .HS,
            254 => .NONE,
            255 => .ANY,
            else => .UNKNOWN,
        };
    }

    pub fn toString(self: ResourceClass) []const u8 {
        return switch (self) {
            .IN, .CS, .CH, .HS, .NONE, .ANY => @tagName(self),
            else => "UNKNOWN",
        };
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        try writer.writeAll(self.toString());
    }
};
