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

load("//common/rules/mkdocs:providers.bzl", "MkDocsTreeInfo")

def _tree_impl(ctx):
    """Implementation of the `mkdocs_tree` rule."""

    transitives = []
    for target in ctx.attr.srcs:
        transitives.append(target.files)

    return [
        MkDocsTreeInfo(
            files = depset(transitive = transitives),
            path = ctx.attr.path,
        ),
    ]

"""Declares a piece of documentation that belongs to a MkDocs documentation project."""
mkdocs_tree = rule(
    implementation = _tree_impl,
    attrs = {
        "srcs": attr.label_list(
            doc = "Input files",
            allow_empty = False,
            allow_files = True,
            mandatory = True,
        ),
        "path": attr.string(
            doc = "Path in the final documentation structure",
            mandatory = False,
        ),
    },
)
