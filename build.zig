const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "dns",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(lib);

    const lib_tests = b.addTest(.{
        .root_source_file = b.path("src/test.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);

    const zigdns_module = b.addModule("dns", .{
        .root_source_file = b.path("src/lib.zig"),
    });

    const example_names = [_][]const u8{
        "packet",
        "name",
        "response",
        "records",
    };

    const examples_step = b.step("examples", "Build all examples");

    inline for (example_names) |name| {
        const example = b.addExecutable(.{
            .name = name,
            .root_source_file = b.path("examples/" ++ name ++ ".zig"),
            .target = target,
            .optimize = optimize,
        });

        example.root_module.addImport("dns", zigdns_module);
        b.installArtifact(example);

        const run_example = b.addRunArtifact(example);
        const run_step = b.step("example-" ++ name, "Run the " ++ name ++ " example");
        run_step.dependOn(&run_example.step);

        examples_step.dependOn(&b.addInstallArtifact(example, .{}).step);
    }
}
