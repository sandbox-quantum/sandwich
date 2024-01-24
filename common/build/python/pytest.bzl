load("@rules_python//python:defs.bzl", _py_test = "py_test")

def py_test(name, srcs = [], args = [], deps = [], data = [], **kwargs):
    """Runs Python tests using pytest.

    This is a helper macro that wraps builtin py_test test rule by using pytest
    as the test executor.

    Args:
        name: Name of the target.
        srcs: List of test source files.
        args: List of additional arguments to be passed to pytest.
        deps: List of test target dependencies.
        data: List of runtime data required during the test.
        **kwargs: Additional keyworded arguments to be passed to py_test rule.
    """

    _py_test(
        name = name,
        srcs = srcs + ["//common/build/python:pytest_wrapper.py"],
        main = "//common/build/python:pytest_wrapper.py",
        args = [
            "-c",
            "$(location //common/build/python:pyproject.toml)",
        ] + args + [
            "$(location :%s)" % x
            for x in srcs
        ],
        deps = deps + [
            "@pypi_pytest//:pkg",
            "@pypi_pytest_asyncio//:pkg",
            "@pypi_pytest_dependency//:pkg",
        ],
        data = data + ["//common/build/python:pyproject.toml"],
        python_version = "PY3",
        srcs_version = "PY3",
        **kwargs
    )
