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

//! A build dependency for running `bazelisk` to build native libraries and
//! more.
//!
//! This crate brings some support for running the `bazelisk` command to build
//! native libraries and other non-Rust dependencies. It takes care of retrieving
//! the Bazelisk binary that matches the current architecture and operating
//! system.
//!
//! Supported architectures and OS are the same as those supported by Bazelisk.
//! Developers can still provide their own Bazelisk binary by setting the
//! `BAZELISK_BIN_PATH` environment variable.
//!
//! Supported triples:
//!   - `linux-amd64`: Linux running amd64 or x86_64
//!   - `linux-aarch64`: Linux running aarch64
//!   - `darwin-amd64`: Darwin/macOS running amd64 or x86_64
//!   - `darwin-aarch64`: Darwin/macOS running aarch64
//!
//! Links to the Bazelisk binaries used in this project are pulled from the
//! release page of the Bazelisk repository on GitHub: <https://github.com/bazelbuild/bazelisk/releases>.
//!
//! ## Installation
//!
//! Add this to your `Cargo.toml`:
//!
//! ```toml
//! [build-dependencies]
//! bazelisk = "0.1.0"
//! ```
//!
//! ## Examples
//!
//! Simple and straightforward usage:
//!
//! ```no_run
//! extern crate bazelisk;
//!
//! // Instantiates a Bazelisk object. If it does not exist yet, the binary will
//! // be downloaded and stored in the current working directory.
//! let bazel = bazelisk::Builder::new()
//!     .build()
//!     .expect("failed to use Bazelisk");
//!
//! // Builds a specific Bazel target. If not specified using
//! // [`Builder::working_dir`], the Bazel workspace is expected to be in the
//! // current working directory.
//! use bazelisk::ConfigurableCommand;
//!
//! bazel.build_target("//a/target:name")
//!     .run()
//!     .expect("failed to build the given target");
//!
//! // Locates the artifacts produced by the target that has been built above:
//! let artifacts = bazel.action_graph_target("//a/target:name").run()
//!     .expect("failed to retrieve the artifacts produced by //a/target:name");
//! for artifact in artifacts.iter() {
//!     println!("artifact: {}", artifact.display());
//! }
//! ```
//!
//! Advanced configuration of the Bazelisk object.
//!
//! ```no_run
//! extern crate bazelisk;
//!
//! // Instantiates a Bazelisk object with advanced configuration.
//! let bazel = bazelisk::Builder()::new()
//!     .working_dir("path/to/a/bazel/workspace")   // Sets the working directory.
//!     .expect("failed to set the working directory")
//!     .env("CC", "/usr/bin/clang-13")             // Sets an env variable to be used
//!                                                 // when Bazelisk is called.
//!     .output_user_root("/tmp/build/")            // Sets the output user root
//!                                                 // directory. This value
//!                                                 // is the value argument to
//!                                                 // the `--output_user_root`
//!                                                 // Bazel option.
//!     .expect("failed to set the `output_user_root` directory")
//!     .sandbox_path("/writable/directory")        // Sets the sandbox directory.
//!     .expect("failed to set the sandbox directory")
//!     .build()
//!     .expect("failed to use Bazelisk");
//! ```
//!
//! Advanced usage of [`Bazelisk::build`].
//!
//! ```no_run
//! use bazelisk::ConfigurableCommand;
//!
//! let bazel = bazelisk::Builder::new().unwrap();
//!
//! bazel.build()
//!     .target("//target/to:build")
//!     .args(["-c", "opt"])                 // Compiles in optimized mode, a.k.a. release mode.
//!     .run().unwrap();
//! ```

#![deny(missing_docs)]

extern crate hex_literal;
extern crate tempfile;

use std::path::Path;

mod platform;
pub use platform::{get_current_platform, Platform};

mod buffer;
use buffer::Buffer;

mod builder;
pub use builder::Builder;

mod command;
pub use command::Command;
pub use command::{ArtifactCommand, BuildCommand, ConfigurableCommand};

mod config;
pub(crate) use config::Configuration;

mod support;

pub(crate) mod action_graph;

/// Hash map storing environment variables.
pub(crate) type EnvVars = std::collections::HashMap<String, String>;

/// Base URI for Bazelisk releases.
const BAZELISK_GITHUB_RELEASES_URI: &str =
    "https://github.com/bazelbuild/bazelisk/releases/download/";

/// Returns the URI to the Bazelisk binary for a given version and platform.
fn bazelisk_uri(version: impl std::convert::AsRef<str>, platform: Platform) -> String {
    format!(
        "{BAZELISK_GITHUB_RELEASES_URI}/v{version}/bazelisk-{os}-{arch}",
        version = version.as_ref(),
        os = platform.os_str(),
        arch = platform.arch_str(),
    )
}

/// Calls `bazel info execution_root` to retrieve the execution path.
fn bazelisk_determine_exec_root(bazelisk: &mut Bazelisk) {
    let mut cmd = Command::from(&*bazelisk)
        .arg("execution_root")
        .prepare_command("info");
    cmd.stdout(std::process::Stdio::piped());
    let res = cmd.output();
    if res.is_err() {
        bazelisk.exec_root = bazelisk.configuration.working_dir.to_path_buf();
        return;
    }

    let res = res.unwrap();
    if !res.status.success() {
        bazelisk.exec_root = bazelisk.configuration.working_dir.to_path_buf();
        return;
    }
    bazelisk.exec_root = String::from_utf8(res.stdout)
        .map_err(|e| format!("failed to parse stdout as an UTF-* string: {e}"))
        .map(|s| std::path::PathBuf::from(s.trim()))
        .unwrap_or(bazelisk.configuration.working_dir.to_path_buf());
}

/// A [`Bazelisk`] handle.
pub struct Bazelisk {
    /// Configuration. Values come from [`Builder`].
    configuration: Configuration,

    /// Temporary directory. Can be used for hosting the user_base, output_user_root
    /// and sandbox writable paths.
    _tmpdir: tempfile::TempDir,

    /// Execution root path.
    exec_root: std::path::PathBuf,
}

/// Instantiates a [`Bazelisk`] from a [`Builder`].
impl std::convert::TryFrom<Builder> for Bazelisk {
    type Error = String;

    fn try_from(mut builder: Builder) -> Result<Self, Self::Error> {
        let (mut file, file_size) =
            support::fs_open_file_wa(&builder.configuration.bazelisk_bin_path)?;

        let data = if file_size == 0 {
            support::http_download_to(bazelisk_uri(&builder.version, builder.platform), &mut file)
        } else {
            support::read_file(&mut file, file_size)
        }?;

        if !builder.ignore_integrity_verification {
            support::sha384_verify_integrity(&data, &builder.sha384_digest)?;
        }
        support::file_set_rx(&mut file)?;

        drop(file);

        let tmpdir = tempfile::tempdir()
            .map_err(|e| format!("failed to create a temporary directory: {e}"))?;

        builder.configuration.bazelisk_bin_path =
            support::fs_canonicalize(&builder.configuration.bazelisk_bin_path)
                .map_err(|e| format!("failed to canonicalize the path to Bazelisk: {e}"))?;

        let mut bazelisk = Self {
            configuration: builder.configuration,
            _tmpdir: tmpdir,
            exec_root: std::path::PathBuf::from("."),
        };
        bazelisk_determine_exec_root(&mut bazelisk);

        Ok(bazelisk)
    }
}

/// Shutdowns the Bazel server, unless [`Builder::no_shutdown`] was used.
impl std::ops::Drop for Bazelisk {
    fn drop(&mut self) {
        if !self.configuration.no_shutdown {
            let _ = Command::from(&*self)
                .prepare_command("shutdown")
                .stderr(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .status();
        }
    }
}

/// Implements [`Bazelisk`].
impl Bazelisk {
    /// Instantiates a new build command.
    ///
    /// A build command starts with "build". Then, if a custom sandbox directory
    /// was specified using [`Builder::sandbox_path`], then the following Bazel
    /// options are set:
    ///     - `--sandbox_base` <https://bazel.build/reference/command-line-reference#flag--sandbox_base>
    ///     - `--sandbox_witable_path` <https://bazel.build/reference/command-line-reference#flag--sandbox_writable_path>
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bazelisk;
    /// use bazelisk::Builder;
    ///
    /// // Instantiates a Bazelisk object.
    /// let bazel = Builder::new().build().unwrap();
    ///
    /// bazel.build()
    ///     .target("//target/to:build")
    ///     .run()
    ///     .expect("failed to build //target/to:build");
    /// ```
    pub fn build(&self) -> BuildCommand<'_> {
        BuildCommand(self.into())
    }

    /// Instantiates a new `build` command with a target.
    ///
    /// Like [`Bazelisk::build`], this method instantiates a new build command
    /// with a pre-filled target specified by the `target` argument.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bazelisk;
    /// use bazelisk::Builder;
    ///
    /// // Instantiates a Bazelisk object.
    /// let bazel = Builder::new().build().unwrap();
    ///
    /// // State of the build command here: `bazel build '//target/to:build'`.
    /// bazel.build_target("//target/to:build")
    ///     .run()
    ///     .expect("failed to build //target/to:build");
    /// ```
    ///
    /// See [`Bazelisk::build`] for more information regarding the sandbox.
    pub fn build_target(&self, target: impl std::convert::AsRef<str>) -> BuildCommand<'_> {
        let mut cmd = self.build();
        cmd.0.target(target);
        cmd
    }

    /// Instantiates a new query command on the action graph, to retrieve the
    /// artifacts produced by some targets.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bazelisk;
    /// use bazelisk::Builder;
    ///
    /// // Instantiates a Bazelisk object.
    /// let bazel = Builder::new().build().unwrap();
    ///
    /// // State of the aquery command here: `bazel aquery '//target/to:inspect'`.
    /// let artifacts = bazel.action_graph()
    ///     .target("//target/to:inspect")
    ///     .run()
    ///     .expect("failed to analyze //target/to:build");
    /// ```
    ///
    /// See [`Bazelisk::build`] for more information regarding the sandbox.
    pub fn action_graph(&self) -> ArtifactCommand<'_> {
        ArtifactCommand(self.into())
    }

    /// Instantiates a new query command on the action graph, with a target.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bazelisk;
    /// use bazelisk::Builder;
    ///
    /// // Instantiates a Bazelisk object.
    /// let bazel = Builder::new().build().unwrap();
    ///
    /// // State of the aquery command here: `bazel aquery '//target/to:inspect'`.
    /// let artifacts = bazel.action_graph_target("//target/to:inspect")
    ///     .run()
    ///     .expect("failed to analyze //target/to:build");
    /// ```
    ///
    /// See [`Bazelisk::build`] for more information regarding the sandbox.
    pub fn action_graph_target(
        &self,
        target: impl std::convert::AsRef<str>,
    ) -> ArtifactCommand<'_> {
        let mut cmd = self.action_graph();
        cmd.0.target(target);
        cmd
    }

    /// Returns the execution root directory of the current bazel instance.
    ///
    /// This path can be obtained by calling `bazel info execution_root`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use bazelisk;
    /// use bazelisk::Builder;
    ///
    /// let bazel  = Builder::new().build().unwrap();
    /// let exec_root = bazel.exec_root();
    /// println!("exec_root is {}", exec_root.display());
    /// ```
    pub fn exec_root(&self) -> &Path {
        self.exec_root.as_path()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Resolves the path to a runfile (data attributes).
    #[allow(dead_code)]
    pub(crate) fn resolve_runfiles(
        path: impl std::convert::AsRef<std::path::Path>,
    ) -> std::path::PathBuf {
        let r = runfiles::Runfiles::create().expect("failed to create a `Runfiles` object");

        let mut path_in_workspace = std::path::PathBuf::from(r.current_repository());
        path_in_workspace.push(path.as_ref());
        let file = r.rlocation(path_in_workspace);
        if !file.exists() {
            panic!(
                "failed to find file '{}' in runfiles",
                path.as_ref().to_string_lossy()
            );
        }
        file
    }

    /// Returns the path to the fake Bazel workspace.
    pub(crate) fn create_fake_bazel_workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("cannot create a temporary directory");
        let (file, _) = support::fs_open_file_wa(dir.path().join("WORKSPACE"))
            .expect("cannot create the WORKSPACE file");
        drop(file);

        let (mut file, _) = support::fs_open_file_wa(dir.path().join("BUILD"))
            .expect("cannot create the BUILD file");
        <_ as std::io::Write>::write(&mut file, br#"cc_library(name = "lib", srcs = ["lib.c"])"#)
            .expect("cannot write the BUILD file");
        drop(file);

        let (file, _) = support::fs_open_file_wa(dir.path().join("lib.c"))
            .expect("cannot create the lib.c file");
        drop(file);

        dir
    }

    /// Tests the constructor of [`Bazelisk`] using a [`Builder`].
    #[test]
    fn test_constructor() {
        Builder::new()
            .env("HOME", "/tmp")
            .build()
            .expect("constructor must succeed");
    }
}
