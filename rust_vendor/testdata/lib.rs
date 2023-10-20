// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test data.

use std::path::Path;

/// Base path for testdata files.
const BASE_PATH: &str = env!("OUT_DIR");

/// Returns the path of a file in the testdata.
pub fn resolve_file(file: impl AsRef<Path>) -> Result<String, String> {
    let path = Path::new(BASE_PATH).join(
        file.as_ref()
            .strip_prefix("testdata")
            .unwrap_or(file.as_ref()),
    );
    if path.is_file() {
        Ok(path.to_string_lossy().into_owned())
    } else {
        Err(format!("{} does not exist in testdata", path.display()))
    }
}
