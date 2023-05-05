load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain")
load(
    "@rules_foreign_cc//foreign_cc/private:cc_toolchain_util.bzl",
    "get_env_vars",
    "get_flags_info",
    "get_tools_info",
    "is_debug_mode",
)
load(
    ":lib.bzl",
    "copy_openssl_cli",
    "copy_openssl_conf",
    "create_cc_info",
    "create_linker_input",
    "create_linking_context",
    "is_target_apple",
    "pick_openssl_Configure_os",
)

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

_CMAKE_TOOLCHAIN = "@rules_foreign_cc//toolchains:cmake_toolchain"
_NINJA_TOOLCHAIN = "@rules_foreign_cc//toolchains:ninja_toolchain"
_MAKE_TOOLCHAIN = "@rules_foreign_cc//toolchains:make_toolchain"

_BUILD_BASH_COMMAND = """
set -e
export BASE_DIR="${PWD}/"

function _realpath() {
  echo "$(cd "$(dirname "$1")" && echo "${PWD}")/$(basename "$1")"
}

export CMAKE="$(_realpath "${CMAKE}")"
export NINJA="$(_realpath "${NINJA}")"
export CC="$(_realpath "${CC}")"
export CXX="$(_realpath "${CXX}")"
export AR="$(_realpath "${AR}")"
export MAKE="$(_realpath "${MAKE}")"

export OPENSSL_SRC_DIR="$(_realpath "${OPENSSL_SRC_DIR}")"
export OPENSSL_BUILD_DIR="$(_realpath "./openssl_build")"
export LIBOQS_SRC_DIR="$(_realpath "${LIBOQS_SRC_DIR}")"
export LIBOQS_BUILD_DIR="$(_realpath "./liboqs_build")"
export INSTALL_DIR="$(_realpath "${INSTALL_DIR}")"

if [[ "$(uname -s)" == "Darwin" ]]; then
  # Needed for macOS. See https://github.com/bazelbuild/bazel/blob/master/tools/objc/xcrunwrapper.sh
  WRAPPER_DEVDIR="${DEVELOPER_DIR:-}"
  if [[ -z "${WRAPPER_DEVDIR}" ]] ; then
      WRAPPER_DEVDIR="$(xcode-select -p)"
  fi
  for ARG in CFLAGS CXXFLAGS ASFLAGS OPENSSL_CFLAGS; do
      value="$(eval "echo \\$${ARG}")"
      export ${ARG}="${value//__BAZEL_XCODE_DEVELOPER_DIR__/${WRAPPER_DEVDIR}}"
      value="$(eval "echo \\$${ARG}")"
      export ${ARG}="${value//__BAZEL_XCODE_SDKROOT__/${SDKROOT}}"
  done
fi

export NCORES=$(nproc 2>/dev/null) || export NCORES=$(sysctl -n hw.logicalcpu) || export NCORES=1
mkdir -p "${OPENSSL_BUILD_DIR}"
(
  cd "${OPENSSL_BUILD_DIR}"
  mkdir lib/
  mkdir -p include/openssl/
  for f in include/openssl/ssl.h lib/libssl.a lib/libcrypto.a; do
    echo "" > "$f"
  done
)
mkdir -p "${LIBOQS_BUILD_DIR}"
(
  echo "set(CMAKE_SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR})" > cross.cmake
  echo "set(CMAKE_SYSTEM_NAME ${CMAKE_SYSTEM_NAME})" >> cross.cmake
  export CMAKE_TOOLCHAIN_FILE="${PWD}/cross.cmake"
  "$CMAKE"  -S "${LIBOQS_SRC_DIR}" \
            -B "${LIBOQS_BUILD_DIR}" \
            -G Ninja \
            -Wno-dev \
            --toolchain "${PWD}/cross.cmake" \
            "-DCMAKE_C_COMPILER=${CC}" \
            "-DCMAKE_AR=${AR}" \
            "-DCMAKE_ASM_FLAGS=${ASFLAGS}" \
            "-DCMAKE_ASM_COMPILER=${CC}" \
            "-DCMAKE_MAKE_PROGRAM=${NINJA}" \
            "-DCMAKE_INSTALL_PREFIX=${INSTALL_DIR}" \
            "-DOPENSSL_ROOT_DIR=${OPENSSL_BUILD_DIR}" \
            "-DOQS_BUILD_ONLY_LIB=ON" \
            "-DCMAKE_HAVE_POSIX_MEMALIGN=ON" \
            "-DCMAKE_C_FLAGS_INIT=${CFLAGS}" \
            "-DCMAKE_EXE_LINKER_FLAGS_INIT=${LDFLAGS}" \
            "-DCMAKE_SHARED_LINKER_FLAGS_INIT=${LDFLAGS}" \
            "-DCMAKE_C_FLAGS=-isystem ${OPENSSL_SRC_DIR}/include" \
            "-DCMAKE_C_ARCHIVE_CREATE=<CMAKE_AR> ${ARFLAGS} <TARGET> <OBJECTS>" \
            ${LIBOQS_CONFIGURE_ARGS}
)
(
  echo "${OPENSSL_SRC_DIR}"
  echo "${OPENSSL_BUILD_DIR}"
  cd "${OPENSSL_BUILD_DIR}"
  rm -rf lib include/
  unset AR
  unset CFLAGS
  export LDFLAGS="${OPENSSL_LDFLAGS}"
  "${OPENSSL_SRC_DIR}/Configure" ${OPENSSL_OS_TARGET} \
      "--openssldir=${INSTALL_DIR}" \
      "--prefix=${INSTALL_DIR}" \
      ${OPENSSL_CONFIGURE_ARGS} \
      "-L${INSTALL_DIR}/lib" \
      "-isystem ${LIBOQS_BUILD_DIR}/include" ${DEPS_FLAGS} ${OPENSSL_CFLAGS}
  "${MAKE}" build_generated || "${MAKE}" build_generated
)
(
  "$CMAKE" --build "${LIBOQS_BUILD_DIR}" "-j${NCORES}"
  "$CMAKE" --install "${LIBOQS_BUILD_DIR}"
)
(
  cd "${OPENSSL_BUILD_DIR}"
  mkdir -p oqs/lib oqs/lib64
  "${MAKE}" "-j${NCORES}" -o test || "${MAKE}" "-j${NCORES}" -o test
  "${MAKE}" install_sw
)
cp "${OPENSSL_SRC_DIR}/apps/openssl.cnf" "${INSTALL_DIR}/bin/"
"""

# Map between cpu name and Cmake system name/processor.
# See https://cmake.org/cmake/help/latest/variable/CMAKE_HOST_SYSTEM_PROCESSOR.html#variable:CMAKE_HOST_SYSTEM_PROCESSOR
_CMAKE_OS_MAP = {
    "ios_arm64": ("Darwin", "arm64"),
    "ios_arm64e": ("Darwin", "arm64"),
    "ios_armv7": ("Darwin", "arm"),
    "darwin_x86_64": ("Darwin", "x86_64"),
    "darwin_arm64": ("Darwin", "arm64"),
    "darwin_arm64e": ("Darwin", "arm64"),
    "k8": ("Linux", "x86_64"),
}

"""`LibraryToLink` attributes that define static libraries."""
_STATIC_LIBRARIES_ATTRS = ("static_library", "pic_static_library")

def _generate_link_flags_deps(ctx):
    """Generates link flags for dependencies

    Args:
      ctx:
        Bazel rule context.

    Returns:
      String for link flags, and additional files to include to the main
      action.
    """
    outs = []
    for dep in ctx.attr.deps:
        lc = dep[CcInfo].linking_context
        for linker_input in lc.linker_inputs.to_list():
            for library in linker_input.libraries:
                for a in _STATIC_LIBRARIES_ATTRS:
                    l = getattr(library, a)
                    if l != None and l not in outs:
                        outs.append(l)

    flags = []
    for o in outs:
        flags.append("-L../{}".format(o.dirname))
        flags.append("-l{}".format(o.basename.replace("lib", "").replace(".a", "")))

    return (flags, outs)

def _generate_openssl_configure_args(ctx):
    """Generates the arguments for the `configure` step of OpenSSL.

    Args:
      ctx:
        Bazel rule context.

    Returns:
      List of OpenSSL configure arguments.
    """

    args = ctx.attr.configure_flags[:]

    if is_debug_mode(ctx):
        args.insert(0, "-d")

    for flag in ctx.attr.additional_configure_flags:
        args.append(flag)

    return args

def _pick_cmake_system_processor(ctx):
    cc_toolchain = find_cpp_toolchain(ctx) or fail("Failed to find the cpp toolchain")

    if cc_toolchain.cpu in _CMAKE_OS_MAP:
        return _CMAKE_OS_MAP[cc_toolchain.cpu]
    else:
        return ("Linux", "x86_64")

def _generate_liboqs_configure_args(ctx):
    """Generates the arguments for the `cmake` step of liboqs.

    Args:
      ctx:
        Bazel rule context.

    Returns:
      List of liboqs CMake arguments.
    """

    args = []

    if not is_debug_mode(ctx):
        args.append("-DCMAKE_BUILD_TYPE=Release")

    if ctx.attr.fpemu:
        args += ["-DOQS_ENABLE_SIG_falcon_1024_avx2=OFF", "-DOQS_ENABLE_SIG_falcon_512_avx2=OFF"]

    return args

def _generate_compilers_env(ctx):
    """Generates the environment variables related to the compiler, aka the
    cc toolchain.

    This function exports at least the following variables:
      * `CC`
      * `CXX`
      * `LD`
      * `AR`
      * `CFLAGS`
      * `CXXFLAGS`
      * 'ASFLAGS'
      * `LDFLAGS`
      * `PATH`

    Args:
      ctx:
        Bazel rule context.

    Returns:
      Dictionary of environment variables for the compiler.
    """

    env = {
        "CC": "",
        "CXX": "",
        "LD": "",
        "AR": "",
        "ASFLAGS": "",
        "CFLAGS": "",
        "CXXFLAGS": "",
        "LDFLAGS": "",
        "PATH": "/bin:/usr/bin:/usr/local/bin:/sbin:/usr/local/sbin",
    }

    # Set PATH if available in ctx.configuration.default_shell_env.
    # PATH is used for coreutils like `touch`.
    if "PATH" in ctx.configuration.default_shell_env and \
       ctx.configuration.default_shell_env["PATH"] != "":
        env["PATH"] = ctx.configuration.default_shell_env["PATH"]

    # Merge with environment variables required by the cc toolchain.
    env.update(get_env_vars(ctx))

    # Get paths to compilers
    tinfo = get_tools_info(ctx)

    env["CC"] = tinfo.cc
    env["CXX"] = tinfo.cxx
    env["LD"] = tinfo.cxx_linker_executable
    env["AR"] = tinfo.cxx_linker_static

    flags = get_flags_info(ctx)

    ar_flags = flags.cxx_linker_static[:]
    if env["AR"].endswith("libtool"):
        # If libtool is used, `-o` has to be set.
        # See https://github.com/bazelbuild/rules_foreign_cc/blob/main/foreign_cc/built_tools/make_build.bzl#L65
        ar_flags += ["-D", "-static", "-o"]

    env["ASFLAGS"] = " ".join(flags.assemble)
    env["CFLAGS"] = " ".join(flags.cc)
    env["CXXFLAGS"] = " ".join(flags.cxx)

    ldflags = []
    blacklist = ["-shared"]
    for f in flags.cxx_linker_shared:
        if f in blacklist:
            continue
        ldflags.append(f)

    env["LDFLAGS"] = " ".join(ldflags)
    env["ARFLAGS"] = " ".join(ar_flags)

    openssl_cflags = []
    blacklist = ["-no-canonical-prefixes"]
    target = ""
    for i in range(len(flags.cc)):
        f = flags.cc[i]
        if f in openssl_cflags:
            continue
        if f in blacklist:
            continue
        if f == "-target":
            target = flags.cc[i + 1]
            i += 1
            continue
        openssl_cflags.append(f)

    if target in openssl_cflags:
        openssl_cflags.remove(target)

    env["OPENSSL_CFLAGS"] = " ".join(openssl_cflags)

    env["OPENSSL_LDFLAGS"] = env["LDFLAGS"]
    if is_target_apple(ctx):
        env["OPENSSL_LDFLAGS"] += " -Wl,-framework,Security"

    return env

def _generate_environ(ctx, openssl_target, liboqs_target, install_dir):
    """Generates the environment variables dictionary for the command.

    Args:
      ctx:
        Bazel rule context.
      openssl_target:
        Target object to the OpenSSL sources.
      liboqs_target:
        Target object to the liboqs sources.
      install_dir:
        File object pointing to the TreeArtifact install directory.

    Returns:
      The environment variables dictionary.
    """

    env = {}

    env.update(_generate_compilers_env(ctx))

    env["OPENSSL_SRC_DIR"] = openssl_target.label.workspace_root
    env["LIBOQS_SRC_DIR"] = liboqs_target.label.workspace_root
    env["INSTALL_DIR"] = install_dir.path

    env["OPENSSL_CONFIGURE_ARGS"] = " ".join(_generate_openssl_configure_args(ctx))

    liboqs_args = _generate_liboqs_configure_args(ctx)
    env["CMAKE_SYSTEM_NAME"], env["CMAKE_SYSTEM_PROCESSOR"] = _pick_cmake_system_processor(ctx)

    if is_target_apple(ctx):
        # see https://github.com/bazelbuild/rules_foreign_cc/blob/9acbb356916760192d4c16301a69267fe44e6dec/foreign_cc/private/framework.bzl#L307
        liboqs_args.append("-DCMAKE_OSX_ARCHITECTURES={}".format(ctx.fragments.apple.single_arch_cpu))

        # liboqs uses `SecRandomCopyBytes` for the iPhones, but forget to link against `Security` Framework
        env["LDFLAGS"] += " -framework Security"
        env["OPENSSL_CFLAGS"] += " -framework Security"

    env["LIBOQS_CONFIGURE_ARGS"] = " ".join(liboqs_args)

    env["MAKE"] = ctx.toolchains[_MAKE_TOOLCHAIN].data.path
    env["NINJA"] = ctx.toolchains[_NINJA_TOOLCHAIN].data.path

    env["CMAKE"] = None
    for f in ctx.toolchains[_CMAKE_TOOLCHAIN].data.target.files.to_list():
        if f.path.endswith(ctx.toolchains[_CMAKE_TOOLCHAIN].data.path):
            env["CMAKE"] = f.path
            break

    env["CMAKE"] or fail("failed to find the cmake binary")
    env["OPENSSL_OS_TARGET"] = pick_openssl_Configure_os(ctx)

    return env

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
    cc_toolchain = find_cpp_toolchain(ctx) or fail("Failed to find the cpp toolchain")

    install_dir = ctx.actions.declare_directory("install/")
    include_dir = ctx.actions.declare_directory("install/include")

    env = _generate_environ(
        ctx = ctx,
        openssl_target = ctx.attr.openssl_srcs,
        liboqs_target = ctx.attr.liboqs_srcs,
        install_dir = install_dir,
    )

    (deps_flags, deps_files) = _generate_link_flags_deps(ctx)
    env["DEPS_FLAGS"] = " ".join(deps_flags)

    ctx.actions.run_shell(
        outputs = [install_dir, include_dir],
        inputs = ctx.attr.openssl_srcs.files.to_list() + ctx.attr.liboqs_srcs.files.to_list() + deps_files,
        tools = [
            ctx.toolchains[_NINJA_TOOLCHAIN].data.target.files,
            ctx.toolchains[_CMAKE_TOOLCHAIN].data.target.files,
            ctx.toolchains[_MAKE_TOOLCHAIN].data.target.files,
            cc_toolchain.all_files,
        ],
        mnemonic = "opensslliboqsbuild",
        progress_message = "%{label}: Building OpenSSL to %{output}",
        use_default_shell_env = False,
        env = env,
        arguments = [],
        command = _BUILD_BASH_COMMAND,
    )

    openssl_cli = copy_openssl_cli(
        ctx = ctx,
        install_dir = install_dir,
    )
    openssl_conf = copy_openssl_conf(
        ctx = ctx,
        install_dir = install_dir,
    )

    linking_context = create_linking_context(
        ctx = ctx,
        install_dir = install_dir,
        libs = ["liboqs.a", "libssl.a", "libcrypto.a"],
        deps = ctx.attr.deps,
    )
    cc_info = create_cc_info(
        linking_context = linking_context,
        include_dir = include_dir,
        deps = ctx.attr.deps,
    )

    default_info = DefaultInfo(
        files = depset([openssl_conf]),
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
        _CMAKE_TOOLCHAIN,
        _NINJA_TOOLCHAIN,
        _MAKE_TOOLCHAIN,
        "@bazel_tools//tools/cpp:toolchain_type",
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
        "deps": attr.label_list(
            mandatory = False,
            doc = "Libraries to link OpenSSL with",
        ),
        "fpemu": attr.bool(mandatory = False, default = False, doc = "disable fpemu in liboqs"),
        "_cc_toolchain": attr.label(
            default = Label("@bazel_tools//tools/cpp:current_cc_toolchain"),
        ),
        "_apple_constraints": attr.label_list(default = ["@platforms//os:macos", "@platforms//os:ios"]),
    },
    executable = True,
    fragments = ["apple", "cpp"],
)
