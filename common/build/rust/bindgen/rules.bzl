load("@rules_rust//bindgen:bindgen.bzl", "rust_bindgen_toolchain")
load(":repositories.bzl", "rust_bindgen_get_component")

def rust_bindgen_register_toolchain(os, arch):
    """Registers the Rust bindgen toolchain for a given OS and architecture."""
    name = "bindgen_toolchain_{os}_{arch}".format(
        os = os,
        arch = arch,
    )
    impl_name = "{name}_impl".format(
        name = name,
    )
    rust_bindgen_toolchain(
        name = impl_name,
        bindgen = "@rules_rust//bindgen/3rdparty:bindgen",
        clang = rust_bindgen_get_component(os, arch, "clang"),
        libclang = rust_bindgen_get_component(os, arch, "libclang"),
    )
    native.toolchain(
        name = name,
        toolchain = impl_name,
        toolchain_type = "@rules_rust//bindgen:toolchain_type",
        exec_compatible_with = [
            "@platforms//os:{}".format(os),
            "@platforms//cpu:{}".format(arch),
        ],
        visibility = ["//visibility:public"],
    )

def rust_bindgen_register_toolchains():
    """Register all the Rust bindgen toolchains."""
    for os, arch in (
        ("linux", "aarch64"),
        ("linux", "x86_64"),
        ("macos", "aarch64"),
        ("macos", "x86_64"),
    ):
        native.register_toolchains("//common/build/rust/bindgen:bindgen_toolchain_{os}_{arch}".format(
            os = os,
            arch = arch,
        ))
