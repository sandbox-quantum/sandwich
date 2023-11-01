load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain")
load(
    "@rules_foreign_cc//foreign_cc/private:cc_toolchain_util.bzl",
    "get_env_vars",
    "get_flags_info",
    "get_tools_info",
    "is_debug_mode",
)
load(
    "//common/build/openssl:lib.bzl",
    "copy_openssl_cli",
    "copy_openssl_conf",
    "create_cc_info",
    "create_linking_context",
    "is_target_apple",
    "pick_openssl_Configure_os",
)

# The GNUMake toolchain.
_MAKE_TOOLCHAIN = "@rules_foreign_cc//toolchains:make_toolchain"

def _env_string(value):
    return struct(
        value = value,
        path = False,
    )

def _env_path(value):
    return struct(
        value = value,
        path = True,
    )

def _get_linker_env(ctx):
    """Returns the environment variables related to the linker."""
    tools_info = get_tools_info(ctx)
    flags = get_flags_info(ctx)

    ldflags = []
    blacklist = ["-shared"]
    for flag in flags.cxx_linker_shared:
        if flag in blacklist:
            continue
        ldflags.append(flag)

    return {
        "LD": _env_path(tools_info.cxx_linker_executable),
        "LDFLAGS": _env_string(" ".join(ldflags)),
    }

def _get_archiver_env(ctx):
    """Returns the environment variables related to the archiver."""
    tools_info = get_tools_info(ctx)
    flags = get_flags_info(ctx)

    ar = tools_info.cxx_linker_static

    ar_flags = flags.cxx_linker_static[:]
    if ar.endswith("libtool"):
        # libtool used, `-static -D -c -o` has to be set:
        #   * `-static`: produce a static library
        #   * `-D`: deterministic mode
        #   * `-o`: output
        #   * `-c`: keep common symbols (BSS)
        ar_flags += ["-static", "-D", "-c", "-o"]

    ar_flags = " ".join(ar_flags)
    return {
        "AR": _env_path(ar),
        "ARFLAGS": _env_string(ar_flags),
    }

def _get_compiler_env(ctx):
    """Returns the environment variables related to the compiler."""
    tools_info = get_tools_info(ctx)
    flags = get_flags_info(ctx)

    cflags = []
    blacklist = ["-no-canonical-prefixes"]
    target = ""
    for i in range(len(flags.cc)):
        f = flags.cc[i]
        if f in cflags:
            continue
        if f in blacklist:
            continue
        if f == "-target":
            target = flags.cc[i + 1]
            i += 1
            continue
        cflags.append(f)
    if target in cflags:
        cflags.remove(target)
    if is_target_apple(ctx):
        cflags.append("-Wno-overriding-t-option")

    return {
        "CC": _env_path(tools_info.cc),
        "CXX": _env_path(tools_info.cxx),
        "ASFLAGS": _env_string(" ".join(flags.assemble)),
        "OPENSSL_CFLAGS": _env_string(" ".join(cflags)),
        "CFLAGS": _env_string(" ".join(flags.cc)),
        "CXXFLAGS": _env_string(" ".join(flags.cxx)),
    }

def _get_cpp_env(ctx):
    """Returns the environment variable necessary to use the compiler."""
    env_strings = get_env_vars(ctx)
    env = {}
    for var in env_strings:
        env[var] = _env_string(env_strings[var])
    env["PATH"] = _env_string(ctx.configuration.default_shell_env.get("PATH", "/bin:/usr/bin:/usr/local/bin:/sbin:/usr/local/sbin"))

    env.update(_get_linker_env(ctx))
    env.update(_get_archiver_env(ctx))
    env.update(_get_compiler_env(ctx))

    return env

def _write_env_file(ctx, env):
    """Writes the environment file that defines the various environment
    variables.

    Args:
      ctx:
        Current Bazel target context.
      env:
        The environment variables to export.

    Returns:
      The file object.
    """

    prologue = """
function _realpath() {
  echo "$(cd "$(dirname "$1")" && echo "${PWD}")/$(basename "$1")"
}
export -f _realpath
    """
    lines = []
    for var in env:
        st = env[var]
        if st.path:
            lines.append("""export {var}="$(_realpath "{path}")" """.format(var = var, path = st.value))
        else:
            lines.append("""export {var}="{value}" """.format(var = var, value = st.value))
    epilogue = """
export NCORES=$(nproc 2>/dev/null) || export NCORES=$(sysctl -n hw.logicalcpu) || export NCORES=1
    """

    content = "{prologue}\n{exports}\n{epilogue}\n".format(
        prologue = prologue,
        exports = "\n".join(lines),
        epilogue = epilogue,
    )

    configuration = ctx.actions.declare_file("config_env")
    ctx.actions.write(
        output = configuration,
        content = content,
        is_executable = False,
    )
    return configuration

def _openssl3_build_impl(ctx):
    """Implementation for `openssl3_build` rule."""
    cc_toolchain = find_cpp_toolchain(ctx) or fail("failed to find the cpp toolchain")

    install_dir = ctx.actions.declare_directory("install")
    include_dir = ctx.actions.declare_directory("install/include")

    env = _get_cpp_env(ctx)
    env["MAKE"] = _env_path(ctx.toolchains[_MAKE_TOOLCHAIN].data.path)
    env["OPENSSL_OS_TARGET"] = _env_string(pick_openssl_Configure_os(ctx))

    args = ctx.actions.args()
    args.add(ctx.attr.srcs.label.workspace_root)
    args.add(install_dir.path)

    openssl_configure_args = []
    if is_debug_mode(ctx):
        openssl_configure_args.append("--debug")
    else:
        openssl_configure_args.append("--release")
    openssl_configure_args += ctx.attr.configure_args

    args.add(" ".join(openssl_configure_args))

    configuration_file = _write_env_file(ctx, env)
    env_strings = {}
    for var in env:
        env_strings[var] = env[var].value
    env_strings["CONFIG_FILE"] = configuration_file.path
    ctx.actions.run_shell(
        outputs = [install_dir, include_dir],
        inputs = depset(transitive = [ctx.attr.srcs.files], direct = [configuration_file]),
        mnemonic = "ConfigureAndBuildStep",
        env = env_strings,
        arguments = [args],
        tools = [
            ctx.toolchains[_MAKE_TOOLCHAIN].data.target.files,
            cc_toolchain.all_files,
        ],
        command =
            """
set -e
source "${CONFIG_FILE}"

export SRCS="$(_realpath "$1")"
export INSTALL_DIR="$(_realpath "$2")"
export OPENSSL_CONFIGURE_ARGS="$3"

if [[ "$(uname -s)" == "Darwin" ]]; then
  # Needed for macOS. See https://github.com/bazelbuild/bazel/blob/master/tools/objc/xcrunwrapper.sh
  WRAPPER_DEVDIR="${DEVELOPER_DIR:-}"
  if [[ -z "${WRAPPER_DEVDIR}" ]] ; then
      WRAPPER_DEVDIR="$(xcode-select -p)"
  fi
  for ARG in CFLAGS OPENSSL_CFLAGS CXXFLAGS ASFLAGS; do
      value="$(eval "echo \\$${ARG}")"
      export ${ARG}="${value//__BAZEL_XCODE_DEVELOPER_DIR__/${WRAPPER_DEVDIR}}"
      value="$(eval "echo \\$${ARG}")"
      export ${ARG}="${value//__BAZEL_XCODE_SDKROOT__/${SDKROOT}}"
  done

  # `libtool` is broken: it strips all symbols when creating an archive with
  # `cpusubtype = ARM64_ALL.
  unset AR
fi

cp -r "${SRCS}/" tmp/
cd tmp

./Configure "${OPENSSL_OS_TARGET}" \
  --prefix="${INSTALL_DIR}" \
  --openssldir="${INSTALL_DIR}" \
  no-tests ${OPENSSL_CONFIGURE_ARGS} \
  ${OPENSSL_CFLAGS}
"${MAKE}" -j"${NCORES}"
"${MAKE}" -j"${NCORES}" install_sw
cd ..
cp "${SRCS}/apps/openssl.cnf" "${INSTALL_DIR}/bin/"
if [ -d "${INSTALL_DIR}/lib64" ]; then
  mv "${INSTALL_DIR}/lib64" "${INSTALL_DIR}/lib"
fi
""",
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
        libs = ["libcrypto.a", "libssl.a"],
        deps = ctx.attr.deps,
    )
    cc_info = create_cc_info(
        linking_context = linking_context,
        include_dir = include_dir,
        deps = ctx.attr.deps,
    )

    default_info = DefaultInfo(
        files = depset([openssl_conf, install_dir]),
        runfiles = ctx.runfiles([openssl_conf]),
        executable = openssl_cli,
    )

    return [
        default_info,
        cc_info,
    ]

"""Builds OpenSSL 3."""
openssl3_build = rule(
    doc = "Build OpenSSL 3.",
    implementation = _openssl3_build_impl,
    output_to_genfiles = True,
    toolchains = [
        _MAKE_TOOLCHAIN,
        "@bazel_tools//tools/cpp:toolchain_type",
    ],
    attrs = {
        "srcs": attr.label(doc = "OpenSSL 3 source code", mandatory = True),
        "configure_args": attr.string_list(doc = "OpenSSL 3 configure args", mandatory = True),
        "_cc_toolchain": attr.label(
            default = Label("@bazel_tools//tools/cpp:current_cc_toolchain"),
        ),
        "_apple_constraints": attr.label_list(default = ["@platforms//os:macos", "@platforms//os:ios"]),
        "deps": attr.label_list(
            mandatory = False,
            doc = "Libraries to link OpenSSL with",
        ),
    },
    executable = False,
    fragments = ["apple", "cpp"],
)
