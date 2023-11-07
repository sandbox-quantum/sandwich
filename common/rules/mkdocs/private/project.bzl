# Copyright 2023 SandboxAQ
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("//common/rules/mkdocs:providers.bzl", "MkDocsProjectInfo", "MkDocsTreeInfo")

def _mkdocs_project_impl(ctx):
    out = ctx.actions.declare_directory(ctx.label.name)
    manifest = ctx.actions.declare_file("manifest.json")
    ctx.actions.write(
        output = manifest,
        content = json.encode_indent(
            {
                "package": ctx.label.package,
                "name": ctx.label.name,
                "srcs": [
                    {
                        "package": tree.label.package,
                        "name": tree.label.name,
                        "path": tree[MkDocsTreeInfo].path,
                        "files": [file.path for file in tree[MkDocsTreeInfo].files.to_list()],
                    }
                    for tree in ctx.attr.srcs
                ],
                "deps": [
                    {
                        "package": tree.label.package,
                        "name": tree.label.name,
                        "path": tree[MkDocsTreeInfo].path,
                        "files": [file.path for file in tree[MkDocsTreeInfo].files.to_list()],
                    }
                    for tree in ctx.attr.deps
                ],
            },
        ),
    )

    inputs = depset(
        direct = [ctx.file.config, manifest],
        transitive = [tree[MkDocsTreeInfo].files for tree in ctx.attr.srcs] + [tree[MkDocsTreeInfo].files for tree in ctx.attr.deps],
    )

    ctx.actions.run_shell(
        inputs = inputs,
        outputs = [out],
        command = """
        set -euo pipefail
        mkdir -p {OUTPUT_DIR}
        ROOT="$PWD"
        export PATH="$(dirname $ROOT/{DOXYGEN}):$PATH"
        {LAYOUT} {MANIFEST}
        cd {PACKAGE}
        "$ROOT/{MKDOCS}" build \
            --strict \
            --site-dir "$ROOT/{OUTPUT_DIR}" \
            --config-file "$ROOT/{CONFIG_FILE}"
        """.format(
            CONFIG_FILE = ctx.file.config.path,
            DOXYGEN = ctx.executable._doxygen.path,
            LAYOUT = ctx.executable._layout_binary.path,
            MANIFEST = manifest.path,
            MKDOCS = ctx.executable._mkdocs_binary.path,
            OUTPUT_DIR = out.path,
            PACKAGE = "{}".format(ctx.label.package),
        ),
        mnemonic = "MkDocsBuild",
        tools = [
            ctx.executable._layout_binary,
            ctx.executable._mkdocs_binary,
            ctx.executable._doxygen,
        ],
    )

    return [
        DefaultInfo(
            files = depset([out]),
        ),
        MkDocsProjectInfo(
            yaml_configuration = ctx.file.config,
            files = depset([out]),
        ),
    ]

"""Declares a documentation project of type MkDocs."""
mkdocs_project = rule(
    implementation = _mkdocs_project_impl,
    attrs = {
        "srcs": attr.label_list(
            doc = "Trees that are referenced directly by this project",
            allow_empty = False,
            allow_files = False,
            providers = [MkDocsTreeInfo],
            mandatory = True,
        ),
        "deps": attr.label_list(
            doc = "Trees that are included by this project",
            allow_empty = True,
            allow_files = False,
            providers = [MkDocsTreeInfo],
            mandatory = False,
        ),
        "config": attr.label(
            doc = "MkDocs configuration file",
            allow_single_file = True,
            mandatory = False,
        ),
        "_layout_binary": attr.label(
            default = Label("//common/rules/mkdocs/private:layout"),
            cfg = "exec",
            executable = True,
        ),
        "_mkdocs_binary": attr.label(
            doc = "MkDocs executable to use",
            default = Label("//common/rules/mkdocs:mkdocs"),
            cfg = "exec",
            executable = True,
        ),
        "_doxygen": attr.label(
            default = "//vendor/github.com/doxygen/doxygen",
            cfg = "exec",
            executable = True,
        ),
    },
)
