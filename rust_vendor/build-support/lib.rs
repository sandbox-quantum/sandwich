// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Utilities commonly used in build.rs files.

extern crate bazelisk;
extern crate log;
extern crate shlex;

/// Constructs a path relative to the `OUT_DIR` directory.
/// If the environment variable `OUT_DIR` is not set, an error is returned.
/// This function does not create the final path.
pub fn out_dir_path(
    path: impl std::convert::AsRef<std::path::Path>,
) -> Result<std::path::PathBuf, String> {
    std::env::var("OUT_DIR")
        .map(|s| std::path::Path::new(&s).join(path))
        .map_err(|e| format!("cannot read the environment variable `OUT_DIR`: {e}"))
}

/// Support methods related to the filesystem.
pub mod fs {
    /// _read_ and _write_ owner permissions mask.
    const MASK_RW_OWNER: u32 = 0o600;

    /// Applies a OR-bitwise to the permissions of a file.
    pub fn file_perms_or(
        path: impl std::convert::AsRef<std::path::Path>,
        mask: u32,
    ) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;

        let path = path.as_ref();

        let file = std::fs::File::open(path)
            .map_err(|e| format!("failed to open {}: {e}", path.display()))?;

        let mut perms = file
            .metadata()
            .map(|m| m.permissions())
            .map_err(|e| format!("failed to read metadata of {}: {e}", path.display()))?;

        let new_mode = perms.mode() | mask;
        perms.set_mode(new_mode);
        file.set_permissions(perms).map_err(|e| {
            format!(
                "failed to apply the permission {new_mode:o} to {}: {e}",
                path.display()
            )
        })
    }

    /// Applies +rw to a file or a directory.
    pub fn file_perms_add_rw(
        path: impl std::convert::AsRef<std::path::Path>,
    ) -> Result<(), String> {
        file_perms_or(path, MASK_RW_OWNER)
    }

    /// Verifies that a the name of a file matches a pattern.
    pub fn file_name_matches(
        path: impl std::convert::AsRef<std::path::Path>,
        pattern: impl std::convert::AsRef<std::ffi::OsStr>,
    ) -> bool {
        path.as_ref().file_name() == Some(pattern.as_ref())
    }

    /// Verifies that a path points to a file with a given extension.
    /// The given extension must not contain a leading dot.
    pub fn file_matches_extension(
        path: impl std::convert::AsRef<std::path::Path>,
        ext: impl std::convert::AsRef<std::ffi::OsStr>,
    ) -> bool {
        let path = path.as_ref();
        if !path.is_file() {
            return false;
        }
        if let Some(e) = path.extension() {
            e == ext.as_ref()
        } else {
            false
        }
    }

    /// Compares the parent of a given path against a given pattern.
    pub fn parent_matches(
        path: impl std::convert::AsRef<std::path::Path>,
        pattern: impl std::convert::AsRef<std::ffi::OsStr>,
    ) -> bool {
        path.as_ref().parent().and_then(|p| p.file_name()) == Some(pattern.as_ref())
    }

    /// Copies a file to a destination.
    pub fn copy_file(
        src: impl std::convert::AsRef<std::path::Path>,
        dst: impl std::convert::AsRef<std::path::Path>,
    ) -> Result<(), String> {
        let src = src.as_ref();
        let dst = dst.as_ref();

        let file_name = src.file_name().ok_or_else(|| {
            format!(
                "cannot copy {src} to {dst}: {src} does not have a name",
                src = src.display(),
                dst = dst.display(),
            )
        })?;

        let dst = if dst.is_dir() {
            dst.join(file_name)
        } else {
            dst.to_path_buf()
        };

        if dst.is_dir() {
            return Err(format!(
                "cannot copy {src} to {dst}: {dst} exists and is a directory",
                src = src.display(),
                dst = dst.display()
            ));
        }
        if dst.is_file() {
            log::info!(
                "file {dst} already exists. Removing it.",
                dst = dst.display()
            );
            file_perms_add_rw(&dst)?;
            std::fs::remove_file(&dst)
                .map_err(|e| format!("cannot remove {dst}: {e}", dst = dst.display()))?;
        }

        log::info!(
            "copying {src} to {dst}",
            src = src.display(),
            dst = dst.display()
        );
        std::fs::copy(src, &dst).map_err(|e| {
            format!(
                "failed to copy {src} to {dst}: {e}",
                src = src.display(),
                dst = dst.display()
            )
        })?;
        file_perms_add_rw(&dst)
    }

    #[cfg(test)]
    mod test {
        /// Tests [`super::file_matches_extension`].
        #[test]
        fn test_file_matches_extension() {
            extern crate tempfile;

            let dir = tempfile::tempdir().expect("cannot create temporary directory");
            let f = dir.path().join("file.a");
            std::fs::File::options()
                .create(true)
                .write(true)
                .open(&f)
                .expect("failed to create file");

            assert!(super::file_matches_extension(&f, "a"));
            assert!(!super::file_matches_extension(&f, "b"));
            assert!(!super::file_matches_extension(
                "non-existent.a",
                "libcrypto"
            ));
        }

        /// Test [`super::file_name_matches`].
        #[test]
        fn test_file_name_matches() {
            assert!(super::file_name_matches("path/to/file.a", "file.a"));
            assert!(!super::file_name_matches("path/to/file.a", "file.b"));
        }

        /// Tests [`super::parent_matches`].
        #[test]
        fn test_parent_matches() {
            assert!(super::parent_matches("path/to/lib.a", "to"));
            assert!(!super::parent_matches("path/to/lib.a", "path"));
            assert!(!super::parent_matches("lib.a", ""));
        }
    }
}

/// Support methods related to protobuf files.
pub mod protobuf {
    /// Removes `//!` and `#!` directives from a Rust file generated from a
    /// a protobuf.
    pub fn sanitize(
        src: impl std::convert::AsRef<std::path::Path>,
        dst: impl std::convert::AsRef<std::path::Path>,
    ) -> Result<(), String> {
        let src = src.as_ref();
        let dst = dst.as_ref();

        let rx = std::io::BufReader::new(
            std::fs::File::open(src)
                .map_err(|e| format!("failed to open {src}: {e}", src = src.display()))?,
        );

        let mut wx = std::io::BufWriter::new(
            std::fs::File::options()
                .create(true)
                .read(false)
                .write(true)
                .truncate(true)
                .open(dst)
                .map_err(|e| format!("cannot open {dst} for writing: {e}", dst = dst.display()))?,
        );

        use std::io::{BufRead, Write};
        for line in rx.lines().filter(|line| {
            if let Ok(line) = line.as_ref() {
                !line.starts_with("#![") && !line.starts_with("//!")
            } else {
                true
            }
        }) {
            let line = line.map_err(|e| {
                format!("failed to read lines from {src}: {e}", src = src.display())
            })?;
            wx.write_all(line.as_bytes())
                .and_then(|_| wx.write_all(&[b'\n']))
                .map_err(|e| format!("failed to write bytes to {dst}: {e}", dst = dst.display()))?;
        }
        Ok(())
    }

    #[cfg(test)]
    mod test {
        /// Tests [`super::sanitize`].
        #[test]
        fn test_sanitize() {
            extern crate tempfile;

            let dir = tempfile::tempdir().expect("failed to create a temporary directory.");
            let src = dir.path().join("src.rs");
            let dst = dir.path().join("dst.rs");
            std::fs::write(
                &src,
                br#"//! should be removed!
not removed
again, not removed
#![must_be_removed]
"#,
            )
            .expect("failed to write few bytes to the temporary file");
            super::sanitize(&src, &dst).expect("failed to sanitize");
            let result =
                std::fs::read(&dst).expect("failed to read few bytes from the temporary file");
            assert_eq!(&result[..], b"not removed\nagain, not removed\n");
        }
    }
}

/// Support methods related to Bazel and Bazelisk.
pub mod bazel {
    use bazelisk::Bazelisk;
    use bazelisk::ConfigurableCommand;

    /// Environment variable that may contains additional flags for bazelisk.
    const ADDITIONAL_BAZELISK_FLAGS_ENV_VAR_NAME: &str = "CARGO_BAZELISK_EXTRA_ARGS";

    /// Reads the environment variable `CARGO_BAZELISK_EXTRA_ARGS` and returns
    /// additional flags to use when compiling targets, if any.
    fn get_extra_flags_from_env() -> Vec<String> {
        std::env::var(ADDITIONAL_BAZELISK_FLAGS_ENV_VAR_NAME)
            .map(|v| shlex::split(&v).unwrap_or_default())
            .unwrap_or_default()
    }

    /// Builds a list of targets and copies some output files based on a predicate.
    /// If the predicate returns a path for a given artifact, then the latter
    /// is copied to the former.
    pub fn build_targets<S, P>(
        bazelisk: &Bazelisk,
        targets: impl std::iter::IntoIterator<Item = S>,
        p: P,
    ) -> Result<(), String>
    where
        S: std::convert::AsRef<str>,
        P: std::ops::FnOnce(&std::path::Path) -> Option<std::path::PathBuf> + Copy,
    {
        let targets: Vec<S> = targets.into_iter().collect();

        let extra_args = get_extra_flags_from_env();

        let is_release = super::cargo::is_release();
        bazelisk
            .build()
            .targets(targets.iter())
            .arg("-c")
            .arg(if is_release { "opt" } else { "fastbuild" })
            .args(extra_args.iter())
            .run()?;

        for ar in bazelisk
            .action_graph()
            .targets(targets.iter())
            .arg("-c")
            .arg(if is_release { "opt" } else { "fastbuild" })
            .args(extra_args.iter())
            .run()?
        {
            if let Some(out_path) = p(&ar) {
                if let Some(dir) = out_path.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| {
                        format!("failed to create parent directory {}: {e}", dir.display())
                    })?;
                }
                super::fs::copy_file(ar, &out_path)?;
            }
        }
        Ok(())
    }
}

/// Support methods related to Cargo.
pub mod cargo {
    /// Reports an error to cargo.
    /// This function reports an error to cargo, and then panics.
    pub fn report_error(e: impl std::fmt::Display) {
        println!("cargo:warning=ERROR: {}", e);
        panic!("an error occured");
    }

    /// Checks that we run in release mode inside a build script.
    pub fn is_release() -> bool {
        std::env::var("OPT_LEVEL")
            .map(|value| value == "3")
            .unwrap_or(false)
    }

    /// Macro rule to unwrap a Result or to report the error.
    #[macro_export]
    macro_rules! cargo_unwrap {
        ($r:expr, $s:expr) => {{
            if let Err(e) = $r {
                ::build_support::cargo::report_error(format!("{}: {e}", $s));
            };
            $r.unwrap()
        }};
    }

    /// Tells cargo to link the current crate against the given library.
    /// On success, the library's name is returned, i.e. the name given to the
    /// compiler. For instance, `crypto` is returned when this function is called
    /// with the file `libcrypto.a`.
    pub fn link_against(lib: impl std::convert::AsRef<std::path::Path>) -> Result<String, String> {
        let lib = lib.as_ref();

        let file_name = lib.file_name().ok_or_else(|| {
            format!(
                "cannot link against {lib}: no file name",
                lib = lib.display()
            )
        })?;
        let parent = lib.parent().ok_or_else(|| {
            format!(
                "cannot link against {lib}: no parent directory",
                lib = lib.display()
            )
        })?;

        let ext = lib.extension().ok_or_else(|| {
            format!(
                "cannot link against {fname}: no extension found",
                fname = file_name.to_string_lossy()
            )
        })?;
        if ext != "dylib" && ext != "so" && ext != "a" {
            return Err(format!("cannot link against {lib}: not a library (extension does not match .so, .dylib or .a)", lib = lib.display()));
        }

        let file_name_str = file_name.to_string_lossy().into_owned();

        let lib_name = file_name_str.strip_prefix("lib").ok_or_else(|| {
            format!(
                "cannot link against {lib}: file name '{file_name_str}' must starts with `lib`",
                lib = lib.display(),
            )
        })?;

        let lib_name = lib_name
            .strip_suffix(&format!(".{}", ext.to_string_lossy()))
            .ok_or_else(|| {
                format!(
                    "cannot link against {}: failed to strip extension",
                    lib_name
                )
            })?;

        log::info!("linking against {lib_name}");
        println!("cargo:rustc-link-search={}", parent.display());
        println!("cargo:rustc-link-lib={lib_name}");
        Ok(lib_name.into())
    }

    #[cfg(test)]
    mod test {
        /// Tests [`super::link_against`].
        #[test]
        fn test_link_against() {
            assert_eq!(
                super::link_against("path/to/libcrypto.a").as_deref(),
                Ok("crypto")
            );
            assert_eq!(
                super::link_against("path/to/libcrypto.so").as_deref(),
                Ok("crypto")
            );
            assert_eq!(
                super::link_against("path/to/libcrypto.dylib").as_deref(),
                Ok("crypto")
            );
            assert_eq!(
                super::link_against("path/to/libcrypto.dylib.so").as_deref(),
                Ok("crypto.dylib")
            );

            super::link_against("path/to/crypto.so").expect_err("must fail with a no prefix 'lib'");
            super::link_against("path/to/libcrypto")
                .expect_err("must fail with a library without extension");
            super::link_against("path/to/libcrypto.zadig")
                .expect_err("must fail with an illegal extension");
        }
    }
}
