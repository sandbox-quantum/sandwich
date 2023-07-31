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

//! Defines the [`Configuration`] structure.

/// Default path on filesystem for Bazelisk.
const BAZELISK_DEFAULT_PATH: &str = "bazelisk";

use super::EnvVars;

/// Configuration for Bazelisk.
#[derive(Clone)]
pub(crate) struct Configuration {
    /// Path to the Bazelisk binary.
    pub(crate) bazelisk_bin_path: std::path::PathBuf,

    /// Working directory.
    /// The value is the absolute path to the working directory.
    pub(crate) working_dir: std::path::PathBuf,

    /// Environment variables to set.
    pub(crate) env: EnvVars,

    /// Output base.
    /// This argument is forwarded to Bazel with `--output_base`.
    pub(crate) output_base: Option<std::path::PathBuf>,

    /// Output user root.
    /// This argument is forwarded to Bazel with `--output_user_root`.
    pub(crate) output_user_root: Option<std::path::PathBuf>,

    /// Sandbox path.
    /// This argument is forwarded to Bazel with `--sandbox_writable_path`.
    pub(crate) sandbox_path: Option<std::path::PathBuf>,

    /// Enable client/server mode.
    /// By default, Bazelisk is run in batch mode.
    /// See <https://bazel.build/docs/user-manual#batch>.
    pub(crate) cliserv_mode: bool,

    /// Prevent Bazelisk from shutting down the Bazel server when it gets
    /// destroyed.
    /// By default, when Bazel is destroyed, `bazelisk shutdown` is called.
    /// Use this option to disable this behavior.
    pub(crate) no_shutdown: bool,
}

/// Implements [`std::fmt::Debug`] for [`Configuration`].
impl std::fmt::Debug for Configuration {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Configuration {{bazelisk_bin_path={bazelisk_bin_path}, working_dir={working_dir}, output_base={output_base:?}, output_user_root={output_user_root:?}, sandbox_path={sandbox_path:?}, cliserv_mode={cliserv_mode}, no_shutdown={no_shutdown}}}",
            bazelisk_bin_path = self.bazelisk_bin_path.to_string_lossy(),
            working_dir = self.working_dir.to_string_lossy(),
            output_base = self.output_base.as_ref().map(|p| p.to_string_lossy()),
            output_user_root = self.output_user_root.as_ref().map(|p| p.to_string_lossy()),
            sandbox_path = self.sandbox_path.as_ref().map(|p| p.to_string_lossy()),
            cliserv_mode = self.cliserv_mode,
            no_shutdown = self.no_shutdown,
        )
    }
}

/// Implements [`std::default::Default`] for [`Configuration`].
impl std::default::Default for Configuration {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements [`Configuration`].
impl Configuration {
    /// Instantiates a new [`Configuration`] using default values.
    pub(crate) fn new() -> Self {
        Self {
            bazelisk_bin_path: BAZELISK_DEFAULT_PATH.into(),
            working_dir: std::env::current_dir().unwrap_or(".".into()),
            output_base: None,
            output_user_root: None,
            sandbox_path: None,
            cliserv_mode: false,
            no_shutdown: false,
            env: EnvVars::new(),
        }
    }
}
