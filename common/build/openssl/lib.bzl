load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain")

# Map between cpu name and OpenSSL platform name.
# See `https://www.openssl.org/policies/general-supplemental/platforms.html`.
# The cpu name is provided by the toolchain:
# `bazel cquery --output=jsonproto '@local_config_cc//:toolchain' --starlark:expr="providers(target)['CcToolchainConfigInfo']"`
_OPENSSL_OS_MAP = {
    "ios_arm64": "ios64-xcrun",
    "ios_arm64e": "ios64-xcrun",
    "ios_armv7": "ios-xcrun",
    "darwin_x86_64": "darwin64-x86_64-cc",
    "darwin_arm64": "darwin64-arm64-cc",
    "darwin_arm64e": "darwin64-arm64-cc",
    "k8": "linux-x86_64-clang",
    "aarch64": "linux-aarch64",
}

def pick_openssl_Configure_os(ctx):
    """Returns the most suitable OpenSSL platform name, depending on the current
    target platform.

    Args:
      ctx:
        Current Bazel target context.

    Returns:
      The OpenSSL platform name.
    """
    cc_toolchain = find_cpp_toolchain(ctx) or fail("Failed to find the cpp toolchain")

    if cc_toolchain.cpu in _OPENSSL_OS_MAP:
        return _OPENSSL_OS_MAP[cc_toolchain.cpu]
    else:
        return "linux-x86_64"

def is_target_apple(ctx):
    """Returns true if the current target is Apple.

    Args:
      ctx:
        Current Bazel target context.

    Returns:
      True if the target platform is Apple, else False.
    """
    for ac in ctx.attr._apple_constraints:
        if ctx.target_platform_has_constraint(ac[platform_common.ConstraintValueInfo]):
            return True
    return False

def copy_openssl_cli(ctx, install_dir):
    """Declares and copies the file `openssl`, which is the OpenSSL cli binary.

    Args:
      ctx:
        Current Bazel target context.
      install_dir:
        File object pointing to the TreeArtifact install directory.

    Returns:
      File object pointing to the OpenSSL cli binary.
    """
    openssl_cli = ctx.actions.declare_file("openssl")
    args = ctx.actions.args()
    args.add("{install_dir}/bin/openssl".format(install_dir = install_dir.path))
    args.add(openssl_cli.path)
    ctx.actions.run(
        outputs = [openssl_cli],
        inputs = [install_dir],
        mnemonic = "exportopensslcli",
        executable = "cp",
        arguments = [args],
    )

    return openssl_cli

def copy_openssl_conf(ctx, install_dir):
    """Declares and copies the file `openssl.cnf`, which is the OpenSSL
    configuration, needed by the OpenSSL cli.

    Args:
      ctx:
        Current Bazel target context.
      install_dir:
        File object pointing to the TreeArtifact install directory.

    Returns:
      File object pointing to the OpenSSL configuration file.
    """
    openssl_conf = ctx.actions.declare_file("openssl.cnf")
    args = ctx.actions.args()
    args.add("{install_dir}/bin/openssl.cnf".format(install_dir = install_dir.path))
    args.add(openssl_conf.path)
    ctx.actions.run(
        outputs = [openssl_conf],
        inputs = [install_dir],
        mnemonic = "exportopensslconf",
        executable = "cp",
        arguments = [args],
    )

    return openssl_conf

def create_linker_input(ctx, install_dir, libname):
    """Creates a LinkerInput object for a given library.

    Args:
      ctx:
        Current Bazel target context.
      install_dir:
        File object pointing to the TreeArtifact install directory.
      libname:
        Name of the library.

    The library specified by `libname` MUST exist under the directory
    `install_dir/lib`.

    Returns:
      The LinkerInput object describing the library `libname`.
    """
    lib = ctx.actions.declare_file(libname)
    args = ctx.actions.args()
    args.add("{install_dir}/lib/{libname}".format(install_dir = install_dir.path, libname = libname))
    args.add(lib.path)

    ctx.actions.run(
        outputs = [lib],
        inputs = [install_dir],
        mnemonic = "export{l}".format(l = libname.replace(".", "")),
        executable = "cp",
        arguments = [args],
    )
    lib = cc_common.create_library_to_link(
        actions = ctx.actions,
        pic_static_library = lib,
    )

    user_link_flags = ["-lpthread", "-ldl"]
    if is_target_apple(ctx):
        user_link_flags += ["-framework", "Security"]
    linker_input = cc_common.create_linker_input(
        owner = ctx.label,
        libraries = depset([lib]),
        user_link_flags = user_link_flags,
    )

    return linker_input

def create_linking_context(ctx, install_dir, libs = ["libcrypto.a", "libssl.a"], deps = []):
    """Creates the LinkingContext object.

    Args:
      ctx:
        Current Bazel target context.
      install_dir:
        File object pointing to the TreeArtifact install directory.
      libs:
        Filenames of the libraries.
      deps:
        External dependencies.

    The LinkingContext returned by this function describes the following
    libraries:
      * `libssl.a`
      * `libcrypto.a`

    Returns:
      LinkingContext objects for OpenSSL and liboqs.
    """
    linker_inputs = []
    for l in libs:
        linker_inputs.append(create_linker_input(
            ctx = ctx,
            install_dir = install_dir,
            libname = l,
        ))

    linker_input_deps = []
    for dep in deps:
        linker_input_deps.append(dep[CcInfo].linking_context.linker_inputs)

    return cc_common.create_linking_context(
        linker_inputs = depset(
            direct = linker_inputs,
            transitive = linker_input_deps,
        ),
    )

def create_cc_info(linking_context, include_dir, deps = None):
    """Creates the CcInfo provider.

    Args:
      linking_context:
        LinkingContext object describing the OpenSSL libraries.
      include_dir:
        File object pointing to the TreeArtifact include directory.
      deps:
        External dependencies.

    Returns:
      CcInfo object.
    """
    compilation_contexts = []
    compilation_contexts.append(cc_common.create_compilation_context(
        system_includes = depset(["{include_dir}/".format(include_dir = include_dir.path)]),
        headers = depset([include_dir]),
    ))
    for dep in deps:
        compilation_contexts.append(dep[CcInfo].compilation_context)

    compilation_context = cc_common.merge_compilation_contexts(
        compilation_contexts = compilation_contexts,
    )

    return CcInfo(
        compilation_context = compilation_context,
        linking_context = linking_context,
    )
