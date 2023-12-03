const cbor = @import("zbor");

key: []const u8,
value: []u8,

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
    _ = options;

    try cbor.stringify(self, .{
        .from_callback = true,
        .field_settings = &.{
            .{ .name = "key", .value_options = .{ .slice_serialization_type = .TextString } },
            .{ .name = "value", .value_options = .{ .slice_serialization_type = .TextString } },
        },
    }, out);
}
