load("@rules_proto//proto:defs.bzl", "ProtoInfo")

# Borrowed from https://github.com/grpc/grpc-java/blob/v1.24.1/java_grpc_library.bzl#L61
def _path_ignoring_repository(f):
    # Bazel creates a _virtual_imports directory in case the .proto source files
    # need to be accessed at a path that's different from their source path:
    # https://github.com/bazelbuild/bazel/blob/0.27.1/src/main/java/com/google/devtools/build/lib/rules/proto/ProtoCommon.java#L289
    #
    # In that case, the import path of the .proto file is the path relative to
    # the virtual imports directory of the rule in question.
    virtual_imports = "/_virtual_imports/"
    if virtual_imports in f.path:
        return f.path.split(virtual_imports)[1].split("/", 1)[1]
    elif len(f.owner.workspace_root) == 0:
        # |f| is in the main repository
        return f.short_path
    else:
        # If |f| is a generated file, it will have "bazel-out/*/genfiles" prefix
        # before "external/workspace", so we need to add the starting index of "external/workspace"
        return f.path[f.path.find(f.owner.workspace_root) + len(f.owner.workspace_root) + 1:]

# Heavily inspired by
# https://github.com/envoyproxy/envoy/blob/main/tools/api_proto_plugin/plugin.bzl
def _proto2md_compile_impl(ctx):
    """Implementation of rule `md_proto_library`."""

    if ProtoInfo not in ctx.attr.proto:
        fail("`proto` must point to a `proto_library` target.")

    proto_info = ctx.attr.proto[ProtoInfo]

    sources = []
    for f in proto_info.direct_sources:
        sources.append(f)

    if len(sources) == 0:
        fail("empty source")

    import_paths = []
    for f in proto_info.transitive_sources.to_list():
        import_paths.append("{base}={dep}".format(base = _path_ignoring_repository(f), dep = f.path))

    inputs = [proto_info.transitive_sources]

    output_dir = ctx.actions.declare_directory("md_out")

    args = ctx.actions.args()
    args.add(ctx.label.workspace_root, format = "-I./%s")
    args.add_all(import_paths, format_each = "-I%s")
    args.add(ctx.executable._proto2md_proto_plugin, format = "--plugin=protoc-gen-md=%s")
    args.add(output_dir.path, format = "--md_out=%s")
    args.add_all(proto_info.direct_sources)
    args.add_all(proto_info.transitive_sources)

    ctx.actions.run(
        executable = ctx.executable._protoc,
        arguments = [args],
        inputs = depset(transitive = inputs),
        tools = [ctx.executable._proto2md_proto_plugin],
        outputs = [output_dir],
        mnemonic = "GenMarkdown",
    )

    return [
        DefaultInfo(files = depset([output_dir])),
    ]

md_proto_library = rule(
    implementation = _proto2md_compile_impl,
    attrs = {
        "_protoc": attr.label(
            doc = "protobuf compiler",
            default = Label("@com_google_protobuf//:protoc"),
            executable = True,
            cfg = "exec",
        ),
        "_proto2md_proto_plugin": attr.label(
            doc = "proto2md protoc plugin",
            default = Label("//common/tools/proto2md:protoc-gen-md"),
            executable = True,
            cfg = "exec",
        ),
        "proto": attr.label(
            doc = "Input protobuf file",
        ),
    },
)
