const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const zbor_dep = b.dependency("zbor", .{
        .target = target,
        .optimize = optimize,
    });
    const zbor_module = zbor_dep.module("zbor");

    const module = b.addModule("tresor", .{
        .root_source_file = .{ .path = "lib/main.zig" },
        .imports = &.{
            .{ .name = "zbor", .module = zbor_module },
        },
    });
    try b.modules.put(b.dupe("tresor"), module);

    const lib = b.addStaticLibrary(.{
        .name = "tresor",
        .root_source_file = .{ .path = "c/tresor.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.root_module.addImport("tresor", module);
    lib.linkLibC();
    lib.installHeader(b.path("c/tresor.h"), "tresor.h");
    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_source_file = .{ .path = "lib/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    main_tests.root_module.addImport("zbor", zbor_module);
    const run_main_tests = b.addRunArtifact(main_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
