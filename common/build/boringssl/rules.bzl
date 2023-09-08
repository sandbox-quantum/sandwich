load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

def _merge_liboqs_into_boringssl_code(ctx):
    """Implements the `merge_liboqs_into_boringssl` rule."""
    boringssl_srcs = ctx.actions.declare_directory("boringssl_with_oqs")
    args = ctx.actions.args()
    args.add(ctx.attr.liboqs[OutputGroupInfo].gen_dir.to_list()[0].path)
    args.add(ctx.attr.boringssl_srcs.label.workspace_root)
    args.add(boringssl_srcs.path)
    ctx.actions.run_shell(
        outputs = [boringssl_srcs],
        inputs = ctx.attr.boringssl_srcs.files.to_list() +
                 ctx.attr.liboqs[OutputGroupInfo].gen_dir.to_list(),
        command = """rm -rf "$3" && cp -rL "$2" "$3" && cp -r "$1" "$3/oqs"; """,
        arguments = [args],
    )

    default_info = DefaultInfo(
        files = depset([boringssl_srcs]),
    )

    return [
        default_info,
    ]

"""Rule to merge the liboqs install directory inside the BoringSSL source code,
under the `oqs/` directory."""
merge_liboqs_into_boringssl = rule(
    implementation = _merge_liboqs_into_boringssl_code,
    output_to_genfiles = False,
    attrs = {
        "boringssl_srcs": attr.label(mandatory = True, doc = "BoringSSL source code"),
        "liboqs": attr.label(mandatory = True, doc = "liboqs"),
    },
)

def boringssl_build(name, boringssl_srcs, liboqs, *kargs, **kwargs):
    """Builds BoringSSL with liboqs.

    Attributes:
      name:
        Name of the target.
      boringssl_srcs:
        Source of BoringSSL.
      liboqs:
        Compiled liboqs.

    Output:
      a `cc_library`.
    """
    merge_liboqs_into_boringssl(
        name = "{name}_merge".format(name = name),
        boringssl_srcs = boringssl_srcs,
        liboqs = liboqs,
    )
    cmake(
        name = "{name}_boringssl".format(name = name),
        build_data = ["//common/rules/go:go_sdk"],
        generate_args = [
            "-GNinja",
            "-DGO_EXECUTABLE=$$EXT_BUILD_ROOT$$/external/go_sdk/bin/go",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        ],
        env = {
            "GOCACHE": "$$PWD/gocache",
            "GOPATH": "$$PWD/external/go_sdk/bin/go",
        },
        linkopts = select({
            # liboqs uses `SecRandomCopyBytes` for the iPhones,
            # but forgot to link against `Security` Framework.
            "@platforms//os:ios": [
                "-Wl,-framework,Security",
            ],
            "//conditions:default": [],
        }),
        lib_source = ":{name}_merge".format(name = name),
        working_directory = "boringssl_with_oqs",
        out_static_libs = ["libssl.a", "libcrypto.a"],
        tags = ["requires-network"],
    )
    native.cc_library(
        name = name,
        deps = [
            liboqs,
            ":{name}_boringssl".format(name = name),
        ],
        *kargs,
        **kwargs
    )
