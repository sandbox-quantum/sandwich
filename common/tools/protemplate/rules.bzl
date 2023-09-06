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

def _template_compile_impl(ctx):
    """Implementation of rule `template_proto_library`."""

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

    basedir = ctx.outputs.out.dirname

    inputs = depset(transitive = [proto_info.transitive_sources, ctx.attr.template.files])

    args = ctx.actions.args()
    args.add(ctx.label.workspace_root, format = "-I./%s")
    args.add_all(import_paths, format_each = "-I%s")
    args.add(ctx.executable._template_proto_plugin, format = "--plugin=protoc-gen-template=%s")
    args.add("{}:{}".format(ctx.attr.template.files.to_list()[0].path, basedir), format = "--template_out=%s")
    args.add_all(proto_info.direct_sources)
    args.add_all(proto_info.transitive_sources)

    ctx.actions.run(
        executable = ctx.executable._protoc,
        arguments = [args],
        inputs = inputs,
        tools = [ctx.executable._template_proto_plugin],
        outputs = [ctx.outputs.out],
        env = {"OUT_FILE_PATH": ctx.outputs.out.path},
        mnemonic = "GenTemplate",
    )

    return [
        DefaultInfo(files = depset([ctx.outputs.out])),
    ]

template_proto_library = rule(
    doc = "Generate a file from a template and protobuf library metadata",
    implementation = _template_compile_impl,
    attrs = {
        "_protoc": attr.label(
            doc = "protobuf compiler",
            default = Label("@com_google_protobuf//:protoc"),
            executable = True,
            cfg = "exec",
        ),
        "_template_proto_plugin": attr.label(
            doc = "protemplate protoc plugin",
            default = Label("//common/tools/protemplate:protoc-gen-template"),
            executable = True,
            cfg = "exec",
        ),
        "proto": attr.label(
            doc = "Input protobuf file",
            mandatory = True,
            providers = [ProtoInfo],
        ),
        "template": attr.label(
            doc = "Template file",
            allow_single_file = True,
            mandatory = True,
        ),
        "out": attr.output(
            doc = "Output file",
            mandatory = True,
        ),
    },
)
