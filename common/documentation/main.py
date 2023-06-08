#!/usr/bin/env python3

import os

from mkdocs.__main__ import cli

# HACK: change current directory to the workspace root, so that we use the root
# mkdocs*.yml files.
os.chdir(os.getenv("BUILD_WORKSPACE_DIRECTORY"))
cli()
