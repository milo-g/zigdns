pub const Header = @import("header.zig").Header;
pub const Flags = @import("header.zig").Flags;
pub const Name = @import("name.zig").Name;
pub const ResourceType = @import("enums.zig").ResourceType;
pub const ResourceClass = @import("enums.zig").ResourceClass;
pub const Question = @import("question.zig").Question;
pub const ResourceRecord = @import("record.zig").ResourceRecord;
pub const Packet = @import("packet.zig").Packet;

pub const ParseError = @import("errors.zig").ParseError;
