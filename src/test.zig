const std = @import("std");
const dns = @import("lib.zig");

test "all" {
    std.testing.refAllDecls(dns);
}
