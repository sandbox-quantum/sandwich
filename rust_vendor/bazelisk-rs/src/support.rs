// Copyright 2023 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Support module.
//! This module implements various support functions.

extern crate reqwest;
extern crate sha2;

use super::Buffer;

/// Size of a SHA-384 digest.
pub(crate) const SHA384_DIGEST_LEN: usize = 0x30;

/// _read_ and _execute_ owner permissions mask.
pub(crate) const MASK_RX_OWNER: u32 = 0o500;

/// Performs an HTTP GET request and returns the content.
fn http_get(uri: impl std::convert::AsRef<str>) -> Result<Buffer, String> {
    let r = reqwest::blocking::get(uri.as_ref())
        .map_err(|e| format!("HTTP GET request failed on {}: {e}", uri.as_ref()))?;
    if !r.status().is_success() {
        return Err(format!("URI {} returned {}", uri.as_ref(), r.status()));
    }
    r.bytes()
        .map(Buffer::from)
        .map_err(|e| format!("failed to read bytes from URI {}: {e}", uri.as_ref()))
}

/// Opens a file in w+a mode, and also returns the actual size.
pub(crate) fn fs_open_file_wa(
    path: impl std::convert::AsRef<std::path::Path>,
) -> Result<(std::fs::File, usize), String> {
    let path_str = path
        .as_ref()
        .to_str()
        .map(std::borrow::Cow::from)
        .unwrap_or(path.as_ref().to_string_lossy());
    let file = std::fs::File::options()
        .create(true)
        .read(true)
        .write(true)
        .open(path.as_ref())
        .map_err(|e| format!("failed to open {path_str}: {e}"))?;

    file.metadata()
        .map_err(|e| format!("failed to read metadata of {path_str}: {e}"))
        .and_then(|me| {
            <_ as std::convert::TryInto<usize>>::try_into(me.len())
                .map_err(|e| format!("{} cannot be converted into a size_t: {e}", me.len()))
        })
        .map(|n| (file, n))
}

/// Reads a certain amount of bytes from a file.
pub(crate) fn read_file(file: &mut std::fs::File, n: usize) -> Result<Buffer, String> {
    let mut data = vec![0u8; n];
    <_ as std::io::Read>::read(file, data.as_mut())
        .map_err(|e| format!("failed to read {n} byte(s) from file: {e}"))
        .and_then(|r| {
            if r != n {
                Err(format!("{r} byte(s) read, expected {n} byte(s)"))
            } else {
                Ok(Buffer::from(data))
            }
        })
}

/// Downloads a file from an URI and writes the content to the given file.
pub(crate) fn http_download_to(
    uri: impl std::convert::AsRef<str>,
    file: &mut std::fs::File,
) -> Result<Buffer, String> {
    let data = http_get(uri)?;

    <_ as std::io::Write>::write(file, data.as_ref())
        .map_err(|e| format!("failed to write {} byte(s): {e}", data.len()))
        .and_then(|w| {
            if w != data.len() {
                Err(format!(
                    "{w} byte(s) written, expected {} byte(s)",
                    data.len()
                ))
            } else {
                Ok(())
            }
        })
        .and_then(|_| {
            file.sync_all()
                .map_err(|e| format!("failed to sync file: {e}"))
        })
        .map(|_| data)
}

/// Makes a file readable and executable.
pub(crate) fn file_set_rx(file: &mut std::fs::File) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = file
        .metadata()
        .map_err(|e| format!("cannot read metadata: {e}"))
        .map(|me| me.permissions())?;
    // +rx
    perms.set_mode(perms.mode() | MASK_RX_OWNER);
    file.set_permissions(perms)
        .map_err(|e| format!("failed to apply new permissions: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("failed to synchronize metadata with the filesystem: {e}"))
}

/// Verifies the integrity of some data using SHA-384.
pub(crate) fn sha384_verify_integrity(
    payload: impl std::convert::AsRef<[u8]>,
    expected_digest: &[u8; SHA384_DIGEST_LEN],
) -> Result<(), String> {
    let mut ax = <sha2::Sha384 as sha2::Digest>::new();
    <_ as sha2::Digest>::update(&mut ax, payload.as_ref());
    let digest = <_ as sha2::Digest>::finalize(ax);
    assert_eq!(digest.len(), SHA384_DIGEST_LEN);

    let digest_slice: &[u8] = digest.as_ref();
    if digest_slice != expected_digest.as_slice() {
        Err(format!("failed to verify integrity because SHA-384 digests don't match: expected {expected_digest:?}, got {digest_slice:?}"))
    } else {
        Ok(())
    }
}

/// Canonicalizes a path. If the path does not exists, it tries to canonicalizes
/// the parent, and so on.
pub(crate) fn fs_canonicalize(
    path: impl std::convert::AsRef<std::path::Path>,
) -> Result<std::path::PathBuf, String> {
    let p = path.as_ref();
    if p.exists() {
        std::fs::canonicalize(p)
            .map_err(|e| format!("failed to canonicalize {}: {e}", p.to_string_lossy()))
    } else if let (Some(file_name), Some(parent)) = (p.file_name(), p.parent()) {
        let parent = fs_canonicalize(parent)?;
        Ok(parent.as_path().join(file_name))
    } else {
        Err(format!(
            "cannot canonicalize {}: no parent found",
            p.to_string_lossy()
        ))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Tests [`sha384_verify_integrity`].
    #[test]
    fn test_sha384_integrity() {
        let expected_digest : [u8; SHA384_DIGEST_LEN] = hex_literal::hex!("ad14aaf25020bef2fd4e3eb5ec0c50272cdfd66074b0ed037c9a11254321aac0729985374beeaa5b80a504d048be1864");
        sha384_verify_integrity(b"A", &expected_digest).expect("verification must succeed");

        sha384_verify_integrity(b"B", &expected_digest).expect_err("verification must fail");
    }
}
