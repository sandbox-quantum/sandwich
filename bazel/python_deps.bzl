load("@rules_python//python:pip.bzl", "pip_parse")
load("@python3//:defs.bzl", "interpreter")

def sandwich_python_deps():
    pip_parse(
        name = "pypi",
        python_interpreter_target = interpreter,
        requirements_lock = "@sandwich//common/build/python:requirements_lock.txt",
    )
