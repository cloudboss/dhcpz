const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("dhcpz", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const zest = b.dependency("zest", .{});

    const mod_tests = b.addTest(.{
        .root_module = mod,
        .test_runner = .{
            .path = zest.path("src/root.zig"),
            .mode = .simple,
        },
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
}
