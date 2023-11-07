#!/usr/bin/env python3

import dataclasses
import json
import logging
import pathlib
import sys


@dataclasses.dataclass
class Tree:
    package: str
    name: str
    path: pathlib.Path
    files: list[pathlib.Path]

    @classmethod
    def from_json(cls, data):
        path = data.pop("path")
        files = data.pop("files")

        tree = cls(
            path=pathlib.Path(path),
            files=[pathlib.Path.cwd() / file for file in files],
            **data,
        )

        for file in tree.files:
            assert file.exists()

        return tree


@dataclasses.dataclass
class Manifest:
    package: str
    name: str
    srcs: list[Tree]
    deps: list[Tree]

    @classmethod
    def from_json(cls, data):
        srcs = data.pop("srcs")
        deps = data.pop("deps")
        return cls(
            srcs=[Tree.from_json(tree) for tree in srcs],
            deps=[Tree.from_json(tree) for tree in deps],
            **data,
        )


if __name__ == "__main__":
    root = pathlib.Path.cwd()
    with pathlib.Path(sys.argv[1]).open() as f:
        data = json.load(f)
        manifest = Manifest.from_json(data)
        for tree in manifest.srcs:
            if tree.package == manifest.package:
                continue
            subdir = root / manifest.package / manifest.name / tree.path
            for file in tree.files:
                new_path = subdir / file.name
                logging.debug("symlinking %s to %s", file, new_path)
                new_path.parent.mkdir(parents=True, exist_ok=True)
                new_path.symlink_to(file)
        for tree in manifest.deps:
            if tree.package == manifest.package:
                continue
            subdir = root / manifest.package / tree.path
            for file in tree.files:
                new_path = subdir / file.relative_to(root / tree.package)
                logging.debug("symlinking %s to %s", file, new_path)
                new_path.parent.mkdir(parents=True, exist_ok=True)
                new_path.symlink_to(file)
