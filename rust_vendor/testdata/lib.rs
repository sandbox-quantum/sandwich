// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test data.

/// Base path for testdata files.
const BASE_PATH: &str = env!("OUT_DIR");

/// Returns the path of a file in the testdata.
pub fn resolve_file(file: impl std::convert::AsRef<std::path::Path>) -> Result<String, String> {
    let p = std::path::Path::new(BASE_PATH).join(file.as_ref());
    if p.is_file() {
        Ok(p.to_string_lossy().into_owned())
    } else {
        Err(format!(
            "{} does not exist in testdata",
            file.as_ref().to_string_lossy()
        ))
    }
}
