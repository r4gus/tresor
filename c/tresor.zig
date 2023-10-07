const std = @import("std");
const tresor = @import("tresor");
const allocator = std.heap.c_allocator;

const Tresor = tresor.Tresor;
const Entry = tresor.Entry;

// Bump those versions up with new releases
const MAJ = 0;
const MIN = 1;

pub const Error = enum(i32) {
    ERR_SUCCESS = 0,
    ERR_AOM = -1,
    ERR_DNE = -2,
    ERR_DE = -3,
    ERR_FILE = -4,
    ERR_SEAL = -5,
    ERR_FAIL = -6,
};

export fn Tresor_new(name: [*c]const u8) ?*anyopaque {
    var t = allocator.create(Tresor) catch |err| {
        std.log.err("Tresor_new: unable to allocate memory ({any})", .{err});
        return null;
    };

    t.* = Tresor.new(
        MAJ,
        MIN,
        .ChaCha20,
        .None,
        .Argon2id,
        "Tresor",
        name[0..strlen(name)],
        allocator,
        std.crypto.random,
        std.time.milliTimestamp,
    ) catch |err| {
        allocator.destroy(t);
        std.log.err("Tresor_new: unable to create new instance ({any})", .{err});
        return null;
    };

    return @ptrCast(t);
}

export fn Tresor_deinit(self: *anyopaque) void {
    var t: *Tresor = @ptrCast(@alignCast(self));
    t.deinit();
}

export fn Tresor_entry_create(self: *anyopaque, id: [*c]const u8) Error {
    var t: *Tresor = @ptrCast(@alignCast(self));
    var e = t.createEntry(id[0..strlen(id)]) catch |err| {
        return switch (err) {
            error.OutOfMemory => Error.ERR_AOM,
            error.DoesNotExist => Error.ERR_DNE,
            error.DoesExist => Error.ERR_DE,
        };
    };
    t.addEntry(e) catch |err| {
        return switch (err) {
            error.OutOfMemory => Error.ERR_AOM,
            error.DoesNotExist => Error.ERR_DNE,
            error.DoesExist => Error.ERR_DE,
        };
    };

    return Error.ERR_SUCCESS;
}

export fn Tresor_entry_get(self: *anyopaque, id: [*c]const u8) ?*anyopaque {
    var t: *Tresor = @ptrCast(@alignCast(self));
    return @ptrCast(t.getEntry(id[0..strlen(id)]));
}

export fn Tresor_entry_remove(self: *anyopaque, id: [*c]const u8) Error {
    var t: *Tresor = @ptrCast(@alignCast(self));
    t.removeEntry(id[0..strlen(id)]) catch |err| {
        return switch (err) {
            error.OutOfMemory => Error.ERR_AOM,
            error.DoesNotExist => Error.ERR_DNE,
            error.DoesExist => Error.ERR_DE,
        };
    };

    return Error.ERR_SUCCESS;
}

// Filter = KEY:VALUE { "," KEY:VALUE }*
export fn Tresor_entry_get_many(self: *anyopaque, filter: [*c]const u8) [*c]?*anyopaque {
    var t: *Tresor = @ptrCast(@alignCast(self));
    var filters = std.ArrayList(tresor.Data.Filter).init(allocator);
    defer filters.deinit();

    var iter = std.mem.splitAny(u8, filter[0..strlen(filter)], ",");
    while (iter.next()) |kv| {
        var iter2 = std.mem.splitAny(u8, kv, ":");
        const k = iter2.next();
        const v = iter2.next();
        if (k == null or v == null) continue;
        filters.append(.{
            .key = k.?,
            .value = v.?,
        }) catch {
            continue;
        };
    }

    var entries = t.getEntries(filters.items, allocator);
    if (entries == null) return null;
    defer allocator.free(entries.?);
    var ret = allocator.alloc(*tresor.Entry, entries.?.len + 1) catch {
        return null;
    };
    @memcpy(ret[0..entries.?.len], entries.?[0..]);
    var r: [*c]?*anyopaque = @ptrCast(ret);
    r[entries.?.len] = null;
    return r;
}

export fn Tresor_entry_field_add(entry: *anyopaque, key: [*c]const u8, value: [*c]const u8) Error {
    var e: *Entry = @ptrCast(@alignCast(entry));
    e.addField(
        .{
            .key = key[0..strlen(key)],
            .value = value[0..strlen(value)],
        },
        std.time.milliTimestamp(),
    ) catch {
        return Error.ERR_FAIL;
    };

    return Error.ERR_SUCCESS;
}

export fn Tresor_entry_field_get(entry: *anyopaque, key: [*c]const u8) [*c]const u8 {
    var e: *Entry = @ptrCast(@alignCast(entry));
    if (e.getField(key[0..strlen(key)], std.time.milliTimestamp())) |f| {
        return f.ptr;
    } else {
        return null;
    }
}

export fn Tresor_entry_field_update(entry: *anyopaque, key: [*c]const u8, value: [*c]const u8) Error {
    var e: *Entry = @ptrCast(@alignCast(entry));
    e.updateField(
        key[0..strlen(key)],
        value[0..strlen(value)],
        std.time.milliTimestamp(),
    ) catch {
        return Error.ERR_FAIL;
    };

    return Error.ERR_SUCCESS;
}

export fn Tresor_seal(self: *anyopaque, path: [*c]const u8, pw: [*c]const u8) Error {
    var t: *Tresor = @ptrCast(@alignCast(self));

    if (strlen(path) < 2) return Error.ERR_FILE;
    var file = openFile(path) catch {
        return Error.ERR_FILE;
    };
    defer file.close();
    t.seal(file.writer(), pw[0..strlen(pw)]) catch {
        return Error.ERR_SEAL;
    };

    return Error.ERR_SUCCESS;
}

export fn Tresor_open(path: [*c]const u8, pw: [*c]const u8) ?*anyopaque {
    var file = openFile(path) catch {
        return null;
    };
    defer file.close();

    var mem = file.readToEndAlloc(allocator, 50_000_000) catch {
        return null;
    };
    defer allocator.free(mem);

    var t = allocator.create(Tresor) catch |err| {
        std.log.err("Tresor_new: unable to allocate memory ({any})", .{err});
        return null;
    };

    t.* = Tresor.open(
        mem,
        pw[0..strlen(pw)],
        allocator,
        std.crypto.random,
        std.time.milliTimestamp,
    ) catch {
        allocator.destroy(t);
        return null;
    };

    return @ptrCast(t);
}

fn openFile(path: [*c]const u8) !std.fs.File {
    return if (path[0] == '~' and path[1] == '/') blk: {
        const home = std.os.getenv("HOME");
        if (home == null) return error.NoHome;
        var home_dir = try std.fs.openDirAbsolute(home.?, .{});
        defer home_dir.close();
        var file = try home_dir.openFile(path[2..strlen(path)], .{ .mode = .read_write });
        break :blk file;
    } else if (path[0] == '/') blk: {
        var file = try std.fs.openFileAbsolute(path[0..strlen(path)], .{ .mode = .read_write });
        break :blk file;
    } else blk: {
        var file = try std.fs.cwd().openFile(path[0..strlen(path)], .{ .mode = .read_write });
        break :blk file;
    };
}

inline fn strlen(s: [*c]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    return i;
}
