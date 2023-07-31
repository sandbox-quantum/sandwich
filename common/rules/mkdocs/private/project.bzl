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
load(
    "@rules_foreign_cc//foreign_cc/private:cc_toolchain_util.bzl",
    "is_debug_mode",
)

def _compile_project(ctx, project):
    """Build the MkDocs project. `project` must be a MkDocsProjectInfo."""

    output_directory_name = "{}_html".format(ctx.label.name)

    out = ctx.actions.declare_directory(output_directory_name)
    inputs = depset([project.yaml_configuration], transitive = [project.files, ctx.attr._doxygen_binary.files])
    args = ctx.actions.args()
    args.add(ctx.executable._mkdocs_binary.path)
    args.add(output_directory_name)
    args.add(project.yaml_configuration)

    ctx.actions.run_shell(
        inputs = inputs,
        outputs = [out],
        command = 'export PATH=$PATH:"$PWD/{doxygen_bin_path}" && export WK="$PWD" && cd "{project_path}" && "$WK/$1" build --site-dir "$2" --config-file "$WK/$3" --clean'.format(project_path = project.yaml_configuration.dirname, doxygen_bin_path = ctx.attr._doxygen_binary.files.to_list()[0].dirname),
        arguments = [args],
        mnemonic = "RunMkDocs",
        tools = [ctx.executable._mkdocs_binary],
    )

    return depset([out])

def _compute_out_filepath(tree, file):
    if tree.path == None or len(tree.path) == 0:
        return file.basename
    return "{}/{}".format(tree.path, file.basename)

def _project_impl(ctx):
    """Implementation of the `mkdocs_project` rule."""

    outs = []
    for tree in ctx.attr.trees:
        tree = tree[MkDocsTreeInfo]
        for f in tree.files.to_list():
            outpath = _compute_out_filepath(tree, f)
            outpath = "docs/{}".format(outpath)

            out = None
            if f.is_directory:
                out = ctx.actions.declare_directory(outpath)
            else:
                out = ctx.actions.declare_file(outpath)
            ctx.actions.symlink(
                output = out,
                target_file = f,
            )
            outs.append(out)

    yaml_configuration = ctx.actions.declare_file("mkdocs.yml")
    ctx.actions.symlink(
        output = yaml_configuration,
        target_file = ctx.file.config,
    )

    project = MkDocsProjectInfo(
        yaml_configuration = yaml_configuration,
        files = depset(outs),
    )

    compiled_doc = _compile_project(ctx, project)

    return [
        DefaultInfo(
            files = compiled_doc,
        ),
        project,
    ]

"""Declares a documentation project of type MkDocs."""
mkdocs_project = rule(
    implementation = _project_impl,
    attrs = {
        "trees": attr.label_list(
            doc = "Trees that belong to this project",
            allow_empty = False,
            allow_files = False,
            providers = [MkDocsTreeInfo],
            mandatory = True,
        ),
        "config": attr.label(
            doc = "MkDocs configuration file",
            allow_single_file = True,
            mandatory = False,
        ),
        "_mkdocs_binary": attr.label(
            doc = "MkDocs executable to use",
            default = Label("//common/rules/mkdocs:mkdocs"),
            cfg = "exec",
            executable = True,
        ),
        "_doxygen_binary": attr.label(
            doc = "Doxygen executable",
            default = Label("//vendor/github.com/doxygen/doxygen"),
            cfg = "exec",
        ),
    },
)
