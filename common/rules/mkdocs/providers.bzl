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

MkDocsTreeInfo = provider(
    doc = "A provider containing information about a tree of documentation inside a project",
    fields = {
        "files": "depset[Files]: files belonging to the piece of documentation",
        "path": "str: path in the final documentation structure where to places files in field `files`",
    },
)

MkDocsProjectInfo = provider(
    doc = "A provider containing the general information about a MkDocs documentation project",
    fields = {
        "yaml_configuration": "File: the yaml configuration file",
        "files": "depset[File]: all files",
    },
)
