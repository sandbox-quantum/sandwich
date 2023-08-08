# Copyright (c) SandboxAQ. All rights reserved.
# SPDX-License-Identifier: AGPL-3.0-only

import os
from pathlib import Path

from grpc_tools import protoc
from setuptools import setup
from setuptools.command.build_py import build_py
from wheel.bdist_wheel import bdist_wheel

SCRIPT_DIR = Path(os.path.realpath(__file__)).parent.resolve()


def generate_protos():
    cwd = os.getcwd()
    os.chdir(SCRIPT_DIR)
    for proto in Path("pysandwich").rglob("*.proto"):
        protoc.main(["-I.", str(proto), "--python_out=."])
    os.chdir(cwd)


class BuildPyCommand(build_py):
    def run(self):
        generate_protos()
        build_py.run(self)


class BDistWheelCommand(bdist_wheel):
    def run(self):
        generate_protos()
        bdist_wheel.run(self)


setup(
    name="pysandwich",
    packages=["pysandwich", "pysandwich.proto", "pysandwich.proto.api.v1"],
    cmdclass={"build_py": BuildPyCommand, "bdist_wheel": BDistWheelCommand},
)
