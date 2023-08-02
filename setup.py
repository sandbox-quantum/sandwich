import os
from distutils.command.build_py import build_py
from distutils.core import setup
from pathlib import Path

from grpc_tools import protoc

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
    version="0.1.0",
    description="Sandwich Python bindings",
    author="SandboxAQ",
    author_email="sandwich@sandboxaq.com",
    url="https://github.com/sandbox-quantum/sandwich",
    packages=["pysandwich", "pysandwich.proto", "pysandwich.proto.api.v1"],
    cmdclass={"build_py": BuildPyCommand, "bdist_wheel": BDistWheelCommand},
)
