load("@bazel_skylib//lib:shell.bzl", "shell")
load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain")
load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "C_COMPILE_ACTION_NAME")

_DEFAULT_OPENSSL_CONFIGURE_FLAGS = [
    "no-comp",
    "no-dtls",
    "no-idea",
    "no-psk",
    "no-shared",
    "no-srp",
    "no-ssl2",
    "no-ssl3",
    "no-tests",
    "no-weak-ssl-ciphers",
    "-Wno-bitwise-instead-of-logical",
    "-Wno-unknown-warning-option",
    "-Wno-unused-but-set-variable",
]

def _generate_build_command(ctx, cmake, ninja, compiler, openssl_target, liboqs_target, install_dir):
    """Generates the build command for OpenSSL and liboqs.

    Args:
      ctx:
        Bazel rule context.
      cmake:
        File object pointing to the cmake binary.
      ninja:
        File object pointing to the ninja binary.
      compiler:
        Path to the compiler used by the current toolchain.
      openssl_target:
        Target object to the OpenSSL sources.
      liboqs_target:
        Target object to the liboqs sources.
      install_dir:
        File object pointing to the TreeArtifact install directory.

    Returns:
      The tuple (cmd, args), where `cmd` is the string command, and `args` is
      the Args object for the command `cmd`.
    """

    cmd = """
  set -e
  export BASE_DIR="$PWD/"

  export CMAKE="$BASE_DIR/$1"
  export NINJA="$BASE_DIR/$2"
  export CC="$(realpath "$3")"
  export CXX="$CC"


  export OPENSSL_SRC_DIR="$BASE_DIR/$4"
  export OPENSSL_BUILD_DIR="$PWD/openssl_build"
  export OPENSSL_CONFIGURE_ARGS="$5"

  export LIBOQS_SRC_DIR="$BASE_DIR/$6"
  export LIBOQS_BUILD_DIR="$PWD/liboqs_build"
  export LIBOQS_CONFIGURE_ARGS="$7"

  export INSTALL_DIR="$BASE_DIR/$8"

  export DEVELOPER_DIR="$(/usr/bin/xcode-select -p)" || echo "nevermind"
  export SDKROOT="$(/usr/bin/xcrun --show-sdk-path)" || echo "nevermind"

  export NCORES=$(nproc) || export NCORES=$(sysctl -n hw.logicalcpu) || export NCORES=1

  mkdir -p "$OPENSSL_BUILD_DIR"
  (
    cd "$OPENSSL_BUILD_DIR"
    mkdir lib/
    mkdir -p include/openssl/
    touch include/openssl/ssl.h
    touch lib/libssl.a lib/libcrypto.a
  )
  mkdir -p "$LIBOQS_BUILD_DIR"
  (
    "$CMAKE"  -S "$LIBOQS_SRC_DIR" \
              -B "$LIBOQS_BUILD_DIR" \
              -G Ninja \
              "-DCMAKE_C_COMPILER=$CC" \
              "-DCMAKE_ASM_COMPILER=$CC" \
              "-DCMAKE_MAKE_PROGRAM=$NINJA" \
              "-DCMAKE_INSTALL_PREFIX=$INSTALL_DIR" \
              "-DOPENSSL_ROOT_DIR=$OPENSSL_BUILD_DIR" \
              -DOQS_BUILD_ONLY_LIB=ON \
              "-DCMAKE_C_FLAGS=-isystem $OPENSSL_SRC_DIR/include" \
              $LIBOQS_CONFIGURE_ARGS
  )
  (
    cd "$OPENSSL_BUILD_DIR"
    rm -rf lib include/
    "$OPENSSL_SRC_DIR/config" \
        "--openssldir=$INSTALL_DIR" \
        "--prefix=$INSTALL_DIR" \
        $OPENSSL_CONFIGURE_ARGS \
        "-L$INSTALL_DIR/lib" \
        "-isystem $LIBOQS_BUILD_DIR/include"
    make build_generated
  )
  (
    "$CMAKE" --build "$LIBOQS_BUILD_DIR" -j$NCORES
    "$CMAKE" --install "$LIBOQS_BUILD_DIR"
  )
  (
    cd "$OPENSSL_BUILD_DIR"
    mkdir -p oqs/lib oqs/lib64
    make -j$NCORES -o test || make -j$NCORES 1 -o test
    make install_sw
  )
  cp $OPENSSL_SRC_DIR/apps/openssl.cnf $INSTALL_DIR/bin/
  """

    args = ctx.actions.args()

    args.add(cmake)  # $1
    args.add(ninja)  # $2
    args.add(compiler)  # $3

    args.add(openssl_target.label.workspace_root)  # $4
    openssl_configure_flags = ctx.attr.configure_flags[:]
    if ctx.var["COMPILATION_MODE"] != "opt":
        openssl_configure_flags.insert(0, "-d")

    for flag in ctx.attr.additional_configure_flags:
        openssl_configure_flags.append(flag)
    args.add(" ".join(openssl_configure_flags))  # $5

    args.add(liboqs_target.label.workspace_root)  # $6
    if ctx.var["COMPILATION_MODE"] == "opt":
        args.add("-DCMAKE_BUILD_TYPE=Release")  # $7
    else:
        args.add("")  # $7

    args.add(install_dir.path)  # $8

    return cmd, args

def _copy_openssl_cli(ctx, install_dir):
    """Declares and copies the file `openssl`, which is the OpenSSL cli binary.

    Args:
      ctx:
        Bazel rule context.
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

def _copy_openssl_conf(ctx, install_dir):
    """Declares and copies the file `openssl.cnf`, which is the OpenSSL
    configuration, needed by the OpenSSL cli.

    Args:
      ctx:
        Bazel rule context.
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

def _create_linker_input(ctx, install_dir, libname):
    """Creates a LinkerInput object for a given library.

    Args:
      ctx:
        Bazel rule context.
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
    linker_input = cc_common.create_linker_input(
        owner = ctx.label,
        libraries = depset([lib]),
        user_link_flags = ["-lpthread", "-ldl"],
    )

    return linker_input

def _create_linking_context(ctx, install_dir):
    """Creates the LinkingContext object.

    Args:
      ctx:
        Bazel rule context.
      install_dir:
        File object pointing to the TreeArtifact install directory.

    The LinkingContext returned by this function describes the following
    libraries:
      * `libssl.a`
      * `libcrypto.a`
      * `liboqs.a`.

    Returns:
      LinkingContext objects for OpenSSL and liboqs.
    """
    linker_inputs = []
    for l in ("liboqs.a", "libcrypto.a", "libssl.a"):
        linker_inputs.append(_create_linker_input(
            ctx = ctx,
            install_dir = install_dir,
            libname = l,
        ))

    return cc_common.create_linking_context(
        linker_inputs = depset(linker_inputs),
    )

def _create_cc_info(linking_context, include_dir):
    """Creates the CcInfo provider.

    Args:
      linking_context:
        LinkingContext object describing the OpenSSL and liboqs libraries.
      include_dir:
        File object pointing to the TreeArtifact include directory.

    Returns:
      CcInfo object.
    """
    return CcInfo(
        compilation_context = cc_common.create_compilation_context(
            system_includes = depset(["{include_dir}/".format(include_dir = include_dir.path)]),
            headers = depset([include_dir]),
        ),
        linking_context = linking_context,
    )

def _find_cc_compiler(ctx):
    """Finds the C/C++ compiler used by Bazel.

    Args:
      ctx:
        Bazel rule context.

    This routines find the cc compiler using the default cc_toolchain.

    Returns:
      File object pointing to the compiler, or None if not found.
    """
    cc_toolchain = find_cpp_toolchain(ctx) or fail("Failed to find the cpp toolchain")
    for f in cc_toolchain.all_files.to_list():
        if f.path == cc_toolchain.compiler_executable:
            return f

    return cc_toolchain.compiler_executable

def _find_cmake(ctx):
    """Finds the CMake binary used by Bazel.

    Args:
      ctx:
        Bazel rule context.

    This routines find the CMake binary fetched by Bazel through the default
    toolchain `@rules_foreign_cc//toolchains:cmake_toolchain`.

    Returns:
      File object pointing to the CMake binary, or None if not found.
    """
    cmake_toolchain = ctx.toolchains["@rules_foreign_cc//toolchains:cmake_toolchain"]
    cmake_path = "{}/{}".format(cmake_toolchain.data.target.label.workspace_root, cmake_toolchain.data.path)

    for f in cmake_toolchain.data.target.files.to_list():
        if f.path == cmake_path:
            return f

    return None

def _find_ninja(ctx):
    """Finds the ninjabuild binary used by Bazel.

    Args:
      ctx:
        Bazel rule context.

    This routines find the ninjabuild binary fetched by Bazel through the default
    toolchain `@rules_foreign_cc//toolchains:ninja_toolchain`.

    Returns:
      File object pointing to the ninjabuild binary, or None if not found.
    """
    ninja_toolchain = ctx.toolchains["@rules_foreign_cc//toolchains:ninja_toolchain"]
    ninja_path = ninja_toolchain.data.path

    for f in ninja_toolchain.data.target.files.to_list():
        if f.path == ninja_path:
            return f

    if ninja_path.endswith("/bin/ninja"):
        return ninja_path

    return None

def _openssl_build_impl(ctx):
    """Implements the `openssl_build` rule.

    This rule configures and compiles OpenSSL and liboqs, together.

    The output providers are the following:
      * CcInfo: it allows users to use it to compile against OpenSSL+liboqs.
        It also allows them to use the OpenSSL cli through the `executable`
        property.
      * DefaultInfo: runfiles, needed for the OpenSSL cli. It is the OpenSSL
        configuration.
    """
    compiler = _find_cc_compiler(ctx) or fail("Failed to find the cc compiler")
    cmake = _find_cmake(ctx) or fail("Failed to find the `cmake` binary.")
    ninja = _find_ninja(ctx) or fail("Failed to find the `ninja` binary.")

    install_dir = ctx.actions.declare_directory("install/")
    include_dir = ctx.actions.declare_directory("install/include")

    cmd, args = _generate_build_command(
        ctx = ctx,
        cmake = cmake,
        ninja = ninja,
        compiler = compiler,
        openssl_target = ctx.attr.openssl_srcs,
        liboqs_target = ctx.attr.liboqs_srcs,
        install_dir = install_dir,
    )

    ctx.actions.run_shell(
        outputs = [install_dir, include_dir],
        inputs = ctx.attr.openssl_srcs.files.to_list() + ctx.attr.liboqs_srcs.files.to_list(),
        tools = [
            cmake,
            ctx.toolchains["@rules_foreign_cc//toolchains:ninja_toolchain"].data.target.files,
            ctx.toolchains["@rules_foreign_cc//toolchains:cmake_toolchain"].data.target.files,
        ],
        mnemonic = "opensslliboqsbuild",
        progress_message = "%{label}: Building OpenSSL to %{output}",
        use_default_shell_env = True,
        arguments = [args],
        command = cmd,
    )

    openssl_cli = _copy_openssl_cli(
        ctx = ctx,
        install_dir = install_dir,
    )
    openssl_conf = _copy_openssl_conf(
        ctx = ctx,
        install_dir = install_dir,
    )

    linking_context = _create_linking_context(
        ctx = ctx,
        install_dir = install_dir,
    )
    cc_info = _create_cc_info(
        linking_context = linking_context,
        include_dir = include_dir,
    )

    default_info = DefaultInfo(
        files = depset(),
        runfiles = ctx.runfiles([openssl_conf]),
        executable = openssl_cli,
    )

    return [
        default_info,
        cc_info,
    ]

"""Builds OpenSSL and liboqs.

Attributes:
  openssl_srcs:
    Target to the source code of OpenSSL. Mandatory.
  liboqs_srcs:
    Target to the source code of liboqs. Mandatory.
  configure_flags:
    Configure flags for OpenSSL. See `_DEFAULT_OPENSSL_CONFIGURE_FLAGS`
    for the default flags. Optional.
  additional_configure_flags:
    Additional configure flags for OpenSSL. These flags will be added
    to the end of the configure flags list. Optional.

Output:
  A target, usable by all the `cc_*` rules, and an executable target, which
  corresponds to the OpenSSL cli binary.
"""
openssl_build = rule(
    implementation = _openssl_build_impl,
    output_to_genfiles = True,
    toolchains = [
        "@rules_foreign_cc//toolchains:cmake_toolchain",
        "@rules_foreign_cc//toolchains:ninja_toolchain",
        "@rules_foreign_cc//toolchains:make_toolchain",
    ],
    attrs = {
        "openssl_srcs": attr.label(mandatory = True, doc = "OpenSSL source code"),
        "liboqs_srcs": attr.label(mandatory = True, doc = "liboqs source code"),
        "configure_flags": attr.string_list(
            mandatory = False,
            doc = "OpenSSL configure flags",
            default = _DEFAULT_OPENSSL_CONFIGURE_FLAGS,
        ),
        "additional_configure_flags": attr.string_list(
            mandatory = False,
            doc = "OpenSSL additional flags",
        ),
        "_cc_toolchain": attr.label(
            default = Label("@bazel_tools//tools/cpp:current_cc_toolchain"),
        ),
    },
    executable = True,
    fragments = ["cpp"],
)

def gen_cert_key(name, alg, out_cert, out_key, out_format = "PEM", subject = "/CN=SandboxAQ TEST CA", expiration_days = "365", **kwargs):
    if out_format.lower() not in ("pem", "der"):
        fail("Invalid out format: '{}'. Supported out format are 'pem' and 'der'".format(out_format))
    cmd = [
        "./$(execpath //vendor/github.com/open-quantum-safe/liboqs-openssl:openssl)",
        "req",
        "-x509",
        "-new",
        "-newkey",
        shell.quote(alg),
        "-keyout",
        "$(location {})".format(out_key),
        "-out",
        "$(location {})".format(out_cert),
        "-outform",
        out_format,
        "-nodes",
        "-subj",
        shell.quote(subject),
        "-days",
        "{}".format(expiration_days),
        "-config",
        "$(execpath //vendor/github.com/open-quantum-safe/liboqs-openssl:openssl).runfiles/$$(basename $$PWD)/$(rootpath //vendor/github.com/open-quantum-safe/liboqs-openssl:openssl).cnf",
    ]

    native.genrule(
        name = name,
        srcs = ["//vendor/github.com/open-quantum-safe/liboqs-openssl:openssl"],
        outs = [out_cert, out_key],
        cmd = " ".join(cmd),
        tools = [
            "//vendor/github.com/open-quantum-safe/liboqs-openssl:openssl",
            "@bazel_tools//tools/bash/runfiles",
        ],
        **kwargs
    )
