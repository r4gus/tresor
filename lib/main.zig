const std = @import("std");
const cbor = @import("zbor");

pub const VERSION: []const u8 = "0.1.1";

const ChaCha20 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const header = @import("header.zig");
pub const Data = @import("Data.zig");
pub const Entry = @import("Entry.zig");

pub const Error = error{
    OutOfMemory,
    DoesNotExist,
    DoesExist,
};

/// Tresor
///
/// Data structure for managing secrets. Each secret (also called Entry) contains
/// one or more key-value pairs (so called Fields).
///
/// A serialized key store is structured as follows:
///
/// 1. The magic string "SECRET"
/// 2. The length of the header
/// 3. A CBOR encoded header
///     * The major version number
///     * The minor version number
///     * A cipher identifier and the corresponding IV
///     * A compression algorithm identifier (currently not supported)
///     * A key derivation function identifier and corresponding parameters (e.g. number of rounds)
/// 4. The TAG of a AEAD cipher
/// 5. The AEAD encrypted CBOR data, with the header as associated data
///
/// ## Encryption algorithms
///
/// The following encryption algorithms are supported:
///     * ChaCha20
///
/// We can extend this library to support additional AEAD ciphers, if neccessary.
///
///
/// ## Key Derivation Function
///
/// The following KDFs are supported:
///     * Argon2id
///
/// We can extend this library to support additional KDFs, if neccessary.
///
/// ## Info
///
/// * The data format doesn't store the length of the encrypted body! Please
///   make sure that you store the serialized data in a way that allows you
///   to infer the length of the body (e.g. when writing to a file, make sure
///   you truncate the file to 0 byte before writing to it).
pub const Tresor = struct {
    /// Header with information about the file and how to decrypt it
    outer_header: header.OuterHeader,
    /// Encrypted, CBOR encoded data (possibly compressed)
    data: Data,
    allocator: std.mem.Allocator,
    rand: std.rand.Random,
    time: *const fn () i64,

    /// Deinitialize the given data structure
    pub fn deinit(self: *@This()) void {
        if (self.outer_header.cipher.iv) |iv| {
            self.allocator.free(iv);
        }
        self.allocator.free(self.data.generator);
        self.allocator.free(self.data.name);
        self.data.deinit();
    }

    /// Create a new entry using the allocator assigned to the key store.
    ///
    /// The caller owns the memory of the data structure until it
    /// has been added to the key store.
    pub fn createEntry(self: *@This(), id: []const u8) Error!Entry {
        var a = try self.allocator.alloc(u8, id.len);
        @memcpy(a, id);
        return Entry.new(a, self.time(), self.allocator);
    }

    /// Add a Entry to the given keystore.
    ///
    /// This will fail if the id of the Entry is already in use.
    pub fn addEntry(self: *@This(), entry: Entry) Error!void {
        try self.data.addEntry(entry, self.time());
    }

    /// Get a reference to the Entry with the given id.
    ///
    /// Returns null if the Entry doesn't exist.
    pub fn getEntry(self: *@This(), id: []const u8) ?*Entry {
        return self.data.getEntry(id, self.time());
    }

    /// Find and remove the Entry with the given id.
    ///
    /// Returns an error if the Entry doesn't exist, i.e.
    /// make sure you handle it using catch if you are not
    /// sure if the id exists.
    pub fn removeEntry(self: *@This(), id: []const u8) Error!void {
        var e = try self.data.removeEntry(id, self.time());
        e.deinit();
    }

    /// Get all Entries that math the given Filters.
    ///
    /// Each filter is string-key-value pair that is compared to the fields of each Entry.
    /// A Entry is only part of the returned slice if all Filters match Fields of the Entry.
    /// For example, you might have some Entries with the Field `"Type": "Passkey"` and
    /// others with the Field `"Type": "Password"`. You can the get all stored Passkeys
    /// by providing the `"Type": "Passkey"` Filter. If you pass `&.{}`, no Filters are
    /// applied, i.e. you get back the whole database.
    ///
    /// The caller owns the returned slice and is responsible to free it.
    pub fn getEntries(
        self: *@This(),
        filters: []const Data.Filter,
        allocator: std.mem.Allocator,
    ) ?[]const *Entry {
        return self.data.getEntries(filters, allocator, self.time());
    }

    /// Serialize the given key store, using the Writer `out` and `pw` for encryption.
    pub fn seal(self: *@This(), out: anytype, pw: []const u8) !void {
        // 1. derive key from secret using kdf.
        // 1.a) first create a random salt
        self.outer_header.kdf.params.seed(self.rand);
        var key: [32]u8 = undefined;
        defer {
            zero(key[0..]);
        }
        // 1.b) then derive the secret from our password
        try self.outer_header.kdf.params.derive(key[0..], pw, self.allocator);

        // Generate new iv
        if (self.outer_header.cipher.iv) |iv| {
            self.allocator.free(iv);
        }
        self.outer_header.cipher.iv = try self.outer_header.cipher.type.iv(self.rand, self.allocator);

        // 2. Serialize data
        var oh = std.ArrayList(u8).init(self.allocator);
        try cbor.stringify(self.outer_header, .{}, oh.writer());
        defer oh.deinit();

        var d = std.ArrayList(u8).init(self.allocator);
        try cbor.stringify(self.data, .{}, d.writer());
        defer {
            zero(d.items);
            d.deinit();
        }

        // The data layout might differ depending on the encryption scheme used
        if (self.outer_header.cipher.type == .ChaCha20) {

            // 3. Write outer header data
            const oh_len = @as(u32, @intCast(oh.items.len));

            try out.writeAll("\x53\x45\x43\x52\x45\x54"); // SECRET
            try out.writeIntLittle(u32, oh_len);
            try out.writeAll(oh.items);

            // 4. Write
            var mem = try self.allocator.alloc(u8, d.items.len + ChaCha20.tag_length);
            defer self.allocator.free(mem);
            ChaCha20.encrypt(
                mem[ChaCha20.tag_length..],
                mem[0..ChaCha20.tag_length],
                d.items,
                oh.items,
                self.outer_header.cipher.iv.?[0..12].*,
                key,
            );
            try out.writeAll(mem);
        } else unreachable;
    }

    /// Decode a the `raw' data into a key store, using `pw` for decryption.
    pub fn open(
        raw: []const u8,
        pw: []const u8,
        allocator: std.mem.Allocator,
        rand: std.rand.Random,
        time: *const fn () i64,
    ) !@This() {
        if (raw.len < 10 or !std.mem.eql(u8, "SECRET", raw[0..6])) {
            std.log.err("Unexpected magic number", .{});
            return error.UnknownFileFormat;
        }

        const header_len = @as(usize, @intCast(std.mem.bytesToValue(u32, raw[6..10])));
        const outer_header = cbor.parse(
            header.OuterHeader,
            cbor.DataItem.new(raw[10 .. header_len + 10]) catch |err| {
                std.log.err("OuterHeader: Invalid data item", .{});
                return err;
            },
            .{ .allocator = allocator },
        ) catch |err| {
            std.log.err("OuterHeader: Parsing failed", .{});
            return err;
        };

        // derive key from secret using kdf
        var key: [32]u8 = undefined;
        defer zero(key[0..]);
        try outer_header.kdf.params.derive(key[0..], pw, allocator);
        errdefer allocator.free(outer_header.cipher.iv.?);

        const data_index = header_len + 10;

        // The data layout might differ depending on the encryption scheme used
        const mem = if (outer_header.cipher.type == .ChaCha20) blk: {
            var mem = try allocator.alloc(u8, raw[data_index + 16 ..].len);
            errdefer allocator.free(mem);

            var tag: [16]u8 = undefined;
            std.mem.copy(u8, tag[0..], raw[data_index .. data_index + 16]);

            ChaCha20.decrypt(
                mem, // out
                raw[data_index + 16 ..], // cipher text
                tag, // tag
                raw[10 .. header_len + 10], // ad
                outer_header.cipher.iv.?[0..12].*, // nonce
                key,
            ) catch |err| {
                std.log.err("Unable to decrypt data", .{});
                return err;
            };

            break :blk mem;
        } else unreachable;
        defer allocator.free(mem);

        //std.debug.print("{s}\n", .{std.fmt.fmtSliceHexUpper(mem)});

        const data = cbor.parse(
            Data,
            cbor.DataItem.new(mem) catch |err| {
                std.log.err("Data: Invalid data item", .{});
                return err;
            },
            .{ .allocator = allocator },
        ) catch |err| {
            std.log.err("Data: Parsing failed", .{});
            return err;
        };

        return @This(){
            .outer_header = outer_header,
            .data = data,
            .allocator = allocator,
            .rand = rand,
            .time = time,
        };
    }

    pub fn new(
        maj: u16,
        min: u16,
        cipher: header.Cipher,
        compression: header.Compression,
        kdf: header.Kdf,
        generator: []const u8,
        name: []const u8,
        a: std.mem.Allocator,
        rand: std.rand.Random,
        time: *const fn () i64,
    ) !@This() {
        const h = header.OuterHeader{
            .version_major = maj,
            .version_minor = min,
            .cipher = .{
                .type = cipher,
            },
            .compression = compression,
            .kdf = .{
                .type = kdf,
                .params = kdf.new(),
            },
        };

        var gen = try a.alloc(u8, generator.len);
        @memcpy(gen, generator);
        var n = try a.alloc(u8, name.len);
        @memcpy(n, name);

        return @This(){
            .outer_header = h,
            .data = Data.new(gen, n, time(), a),
            .allocator = a,
            .rand = rand,
            .time = time,
        };
    }
};

inline fn zero(x: []u8) void {
    var i: usize = 0;
    while (i < x.len) : (i += 1) {
        x[i] = 0;
    }
}

test "main tests" {
    _ = header;
    _ = Data;
}

test "serialize store" {
    const allocator = std.testing.allocator;

    var store = try Tresor.new(
        1,
        0,
        .ChaCha20,
        .None,
        .Argon2id,
        "PassKeyZ",
        "DB1",
        allocator,
        std.crypto.random,
        std.time.milliTimestamp,
    );
    defer store.deinit();

    var id1 = try allocator.alloc(u8, 64);
    const time1 = std.time.milliTimestamp();
    std.crypto.random.bytes(id1[0..]);
    var e1 = Entry.new(id1, time1, allocator);
    try e1.addField("UserName", "SugarYourCoffee", time1);
    try e1.addField("URL", "https://sugaryourcoffee.de", time1);
    try store.addEntry(e1);

    var str = std.ArrayList(u8).init(allocator);
    defer str.deinit();

    try store.seal(str.writer(), "password");

    //std.debug.print("{s}\n", .{std.fmt.fmtSliceHexLower(str.items)});

    var store1 = try Tresor.open(
        str.items,
        "password",
        allocator,
        std.crypto.random,
        std.time.milliTimestamp,
    );
    defer store1.deinit();
    var e2 = store1.getEntry(id1);
    try std.testing.expect(e2 != null);
    try std.testing.expectEqualSlices(u8, "SugarYourCoffee", e2.?.getField("UserName", 0).?);
    try std.testing.expectEqualSlices(u8, "https://sugaryourcoffee.de", e2.?.getField("URL", 0).?);
}
