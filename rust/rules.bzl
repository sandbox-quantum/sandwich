# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

load("@rules_rust//rust:defs.bzl", "rust_clippy", "rust_doc", "rust_library", "rust_test")


# Rust dependencies for unit tests.
_SANDWICH_RUNFILES_DEPS = [
    "@rules_rust//tools/runfiles",
]

# Data for tests
_SANDWICH_TESTDATA = [
    "//testdata",
]

# Common flags for rustdoc.
_RUSTDOC_FLAGS = [
    "-A",
    "rustdoc::private_intra_doc_links",
    "-A",
    "rustdoc::broken_intra_doc_links",
]

# Default features.
_DEFAULT_FEATURES = [
    "tunnel",
]

def sandwich_variant(
        name,
        srcs,
        generate_ffi = False,
        generate_doc = False,
        **kwargs):
    """Defines a build variant of Sandwich.

    Args:
      name:
        Name of this variant.
      generate_ffi:
        Generate the ffi variant.
      generate_coverage:
        Generate the code coverage.
      generate_doc:
        Generate the documentation.
      srcs:
        Source files for this variant.
      crate_features:
        Crate features to enable for this variant.
      crate_name:
        Crate name.
      deps:
        Dependencies for this variant.

    Outputs:
      This macro outputs the following rules, where '${name}' corresponds to
      the `name` argument:
        - `sandwich_${name}` - `rust_library`: the actual library.
        - `sandwich_${name}_test` - `rust_test`: the test suite.
        - `sandwich_${name}_clippy` - `rust_clippy`: Clippy over the variant.
        - `sandwich_${name}_doc` - `rust_doc`: rustdoc of the variant.
        - `sandwich_${name}_internal_doc` - `rust_doc`: rustdoc of the variant (internal only).
        - `sandwich_${name}_rustfmt_test` - `rustfmt_test`: rust format test (internal only).
        - `sandwich_${name}_coverage` - `rust_code_coverage`: rust code coverage (internal only).

      If `gen_ffi` is set to true, then the same rule are generated again, but
      with the crate feature "ffi" enabled.
    """

    name = "sandwich_{name}".format(name = name)
    crate_name = kwargs.get("crate_name", "sandwich")

    deps = kwargs.get("deps", [])
    deps_test = deps + _SANDWICH_RUNFILES_DEPS

    crate_features = kwargs.get("crate_features", []) + _DEFAULT_FEATURES
    crate_features_test = crate_features + ["bazel"] + _DEFAULT_FEATURES

    [kwargs.pop(k) for k in ("deps", "crate_features")]

    targets = [(name, False)]
    if generate_ffi:
        targets.append(("{name}_ffi".format(name = name), True))

    for (name, is_ffi) in targets:
        named_target = ":{name}".format(name = name)
        features = crate_features
        features_test = crate_features_test
        if is_ffi:
            features.append("ffi")
            features_test.append("ffi")

        rust_library(
            name = name,
            srcs = srcs,
            crate_features = features,
            crate_name = crate_name,
            deps = deps,
            **kwargs
        )

        rust_test(
            name = "{name}_test".format(name = name),
            timeout = "short",
            crate = named_target,
            crate_features = features_test,
            data = _SANDWICH_TESTDATA,
            deps = deps_test,
        )

        rust_clippy(
            name = "{name}_clippy".format(name = name),
            testonly = True,
            deps = [
                named_target,
                ":{name}_test".format(name = name),
            ],
        )

        if generate_doc:
            rust_doc(
                name = "{name}_doc".format(name = name),
                crate = named_target,
                rustdoc_flags = _RUSTDOC_FLAGS,
            )


