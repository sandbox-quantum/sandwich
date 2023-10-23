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

//! Defines the [`Command`] structure.
//!
//! [`Command`] conveniently wraps a [`std::process::Command`] object.
//!
//! Given a [`Bazelisk`] object, [`Command`] pre-fills several startup options:
//!
//!     - `--batch` if [`super::Builder::cliserv_mode`] is **not** used. See <https://bazel.build/reference/command-line-reference#flag--batch>.
//!     - `--output_user_root` if [`super::Builder::output_user_root`] is set. See <https://bazel.build/reference/command-line-reference#flag--output_user_root>.
//!     - `--output_base` if [`super::Builder::output_base`] is set. See <https://bazel.build/reference/command-line-reference#flag--output_base>.

use super::Bazelisk;
use super::EnvVars;

use super::action_graph;

/// A command.
pub struct Command<'a> {
    /// Reference to the [`Bazelisk`] object that created the current [`Command`].
    pub(crate) bazelisk: &'a Bazelisk,

    /// Targets concerned by the command.
    pub(crate) targets: Vec<String>,

    /// Additional environment variables.
    pub(crate) env: EnvVars,

    /// Environment variables to use for actions.
    pub(crate) action_env: EnvVars,

    /// Arguments.
    pub(crate) args: Vec<String>,

    /// No output.
    /// If set, `stdout` and `stderr` will be redirected to `/dev/null`.
    pub(crate) no_output: bool,

    /// Verbose mode.
    pub(crate) verbose: bool,
}

/// Instantiates a [`Command`] from a reference to a [`Bazelisk`] object.
impl<'a> std::convert::From<&'a Bazelisk> for Command<'a> {
    fn from(bazelisk: &'a Bazelisk) -> Self {
        Self {
            bazelisk,
            targets: Vec::new(),
            env: EnvVars::new(),
            action_env: EnvVars::new(),
            args: Vec::new(),
            no_output: false,
            verbose: false,
        }
    }
}

/// Implements [`Command`].
impl<'a> Command<'a> {
    /// Adds a target to the list of targets to build.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    pub fn target(&mut self, t: impl std::convert::AsRef<str>) -> &mut Self {
        self.targets.push(t.as_ref().to_string());
        self
    }

    /// Adds several targets at once.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .targets(["//target/to:build", "//another/target/to:build"])
    ///     .build()
    ///     .expect("failed to build two targets");
    /// ```
    pub fn targets<S>(&mut self, targets: impl std::iter::IntoIterator<Item = S>) -> &mut Self
    where
        S: std::convert::AsRef<str>,
    {
        self.targets
            .extend(targets.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Defines an environment variable.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .env("CC", "/usr/bin/clang++")
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    pub fn env(
        &mut self,
        name: impl std::convert::AsRef<str>,
        value: impl std::convert::AsRef<str>,
    ) -> &mut Self {
        self.env
            .insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Defines an environment variable to use in Bazel actions.
    ///
    /// This environment variable will be passed using `--action_env`.
    /// See <https://bazel.build/reference/command-line-reference#flag--action_env>.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .action_env("CC", "/usr/bin/clang++")
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    pub fn action_env(
        &mut self,
        name: impl std::convert::AsRef<str>,
        value: impl std::convert::AsRef<str>,
    ) -> &mut Self {
        self.action_env
            .insert(name.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Adds an argument.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .arg("-c")
    ///     .arg("opt")
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    pub fn arg(&mut self, arg: impl std::convert::AsRef<str>) -> &mut Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    /// Adds several arguments at once.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .args(["-c", "opt"])
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    pub fn args<S>(&mut self, args: impl std::iter::IntoIterator<Item = S>) -> &mut Self
    where
        S: std::convert::AsRef<str>,
    {
        self.args
            .extend(args.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Enable verbose mode when building.
    ///
    /// When called, the `--subcommands` flag is set.
    /// See <https://bazel.build/reference/command-line-reference#flag--subcommands>.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .verbose()
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    pub fn verbose(&mut self) -> &mut Self {
        self.verbose = true;
        self
    }

    /// Prepares a [`std::process::Command`] with a given sub-command.
    ///
    /// This method takes care of setting the startup commands, the environment
    /// variables as well as the environment variables for actions.
    pub fn prepare_command(
        &mut self,
        subcommand: impl std::convert::AsRef<str>,
    ) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.bazelisk.configuration.bazelisk_bin_path);

        cmd.current_dir(&self.bazelisk.configuration.working_dir);

        if self.no_output {
            cmd.stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
        }

        for (n, v) in self.env.iter() {
            cmd.env(n, v);
        }

        for (n, v) in self.bazelisk.configuration.env.iter() {
            cmd.env(n, v);
        }

        // Startup flags.
        if let Some(dir) = self.bazelisk.configuration.output_user_root.as_ref() {
            cmd.arg(format!("--output_user_root={}", dir.display()));
        }

        if let Some(dir) = self.bazelisk.configuration.output_base.as_ref() {
            cmd.arg(format!("--output_base={}", dir.display()));
        }

        if !self.bazelisk.configuration.cliserv_mode {
            cmd.arg("--batch");
        }

        if self.verbose {
            cmd.arg("--subcommands");
        }

        // Subcommand flags.
        cmd.arg(subcommand.as_ref());

        if let Some(sandbox_path) = self.bazelisk.configuration.sandbox_path.as_ref() {
            cmd.args([
                format!("--sandbox_base={}", sandbox_path.display()),
                format!("--sandbox_writable_path={}", sandbox_path.display()),
            ]);
        }

        for (n, v) in self.action_env.iter() {
            cmd.arg(format!("--action_env={n}={v}"));
        }

        cmd.args(self.args.iter());

        cmd
    }
}

/// Trait to mirror [`Command`].
pub trait ConfigurableCommand<'a>: std::borrow::BorrowMut<Command<'a>> {
    /// Adds a target to the list of targets to build.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    fn target(&mut self, t: impl std::convert::AsRef<str>) -> &mut Self {
        self.borrow_mut().target(t);
        self
    }

    /// Adds several targets at once.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .targets(["//target/to:build", "//another/target/to:build"])
    ///     .build()
    ///     .expect("failed to build two targets");
    /// ```
    fn targets<S>(&mut self, targets: impl std::iter::IntoIterator<Item = S>) -> &mut Self
    where
        S: std::convert::AsRef<str>,
    {
        self.borrow_mut().targets(targets);
        self
    }

    /// Defines an environment variable.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .env("CC", "/usr/bin/clang++")
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    fn env(
        &mut self,
        name: impl std::convert::AsRef<str>,
        value: impl std::convert::AsRef<str>,
    ) -> &mut Self {
        self.borrow_mut().env(name, value);
        self
    }

    /// Defines an environment variable to use in Bazel actions.
    ///
    /// This environment variable will be passed using `--action_env`.
    /// See <https://bazel.build/reference/command-line-reference#flag--action_env>.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .action_env("CC", "/usr/bin/clang++")
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    fn action_env(
        &mut self,
        name: impl std::convert::AsRef<str>,
        value: impl std::convert::AsRef<str>,
    ) -> &mut Self {
        self.borrow_mut().action_env(name, value);
        self
    }

    /// Adds an argument.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .arg("-c")
    ///     .arg("opt")
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    fn arg(&mut self, arg: impl std::convert::AsRef<str>) -> &mut Self {
        self.borrow_mut().arg(arg);
        self
    }

    /// Adds several arguments at once.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .args(["-c", "opt"])
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    fn args<S>(&mut self, args: impl std::iter::IntoIterator<Item = S>) -> &mut Self
    where
        S: std::convert::AsRef<str>,
    {
        self.borrow_mut().args(args);
        self
    }

    /// Enable verbose mode when building.
    ///
    /// When called, the `--subcommands` flag is set.
    /// See <https://bazel.build/reference/command-line-reference#flag--subcommands>.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .verbose()
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    fn verbose(&mut self) -> &mut Self {
        self.borrow_mut().verbose();
        self
    }
}

/// A build command.
pub struct BuildCommand<'a>(pub(crate) Command<'a>);

/// Implements [`std::borrow::Borrow`] for [`BuildCommand`].
impl<'a> std::borrow::Borrow<Command<'a>> for BuildCommand<'a> {
    fn borrow(&self) -> &Command<'a> {
        &self.0
    }
}

/// Implements [`std::borrow::BorrowMut`] for [`BuildCommand`].
impl<'a> std::borrow::BorrowMut<Command<'a>> for BuildCommand<'a> {
    fn borrow_mut(&mut self) -> &mut Command<'a> {
        &mut self.0
    }
}

/// Implements [`ConfigurableCommand`] for [`BuildCommand`].
impl<'a> ConfigurableCommand<'a> for BuildCommand<'a> {}

/// Implements [`BuildCommand`].
impl BuildCommand<'_> {
    /// Disable the output of the bazel command.
    ///
    /// When called, `stdout` and `stderr` will be redirected to `/dev/null`.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// let cmd = bazel.build()
    ///     .target("//target/to:build")
    ///     .no_output()
    ///     .build()
    ///     .expect("failed to build //target/to:build");
    /// ```
    pub fn no_output(&mut self) -> &mut Self {
        self.0.no_output = true;
        self
    }

    /// Runs the build command.
    pub fn run(&mut self) -> Result<(), String> {
        let mut cmd = self.0.prepare_command("build");
        cmd.args(self.0.targets.iter());
        let r = cmd.status().map_err(|e| {
            format!("cannot execute bazelisk with the following command: {cmd:?}: {e}")
        })?;
        if r.success() {
            Ok(())
        } else {
            Err(format!("bazelisk returned a non-zero exit status: {r}"))
        }
    }
}

/// A aquery command.
pub struct ArtifactCommand<'a>(pub(crate) Command<'a>);

/// Implements [`std::borrow::Borrow`] for [`ArtifactCommand`].
impl<'a> std::borrow::Borrow<Command<'a>> for ArtifactCommand<'a> {
    fn borrow(&self) -> &Command<'a> {
        &self.0
    }
}

/// Implements [`std::borrow::BorrowMut`] for [`ArtifactCommand`].
impl<'a> std::borrow::BorrowMut<Command<'a>> for ArtifactCommand<'a> {
    fn borrow_mut(&mut self) -> &mut Command<'a> {
        &mut self.0
    }
}

/// Implements [`ConfigurableCommand`] for [`ArtifactCommand`].
impl<'a> ConfigurableCommand<'a> for ArtifactCommand<'a> {}

/// Implements [`BuildCommand`].
impl ArtifactCommand<'_> {
    /// Runs the command and returns the artifacts.
    pub fn run(&mut self) -> Result<Vec<std::path::PathBuf>, String> {
        self.arg("--output=proto");
        let mut cmd = self.0.prepare_command("aquery");
        cmd.arg(
            self.0
                .targets
                .iter()
                .map(|d| d.as_str())
                .collect::<Vec<&str>>()
                .join("+"),
        );
        cmd.stdout(std::process::Stdio::piped());

        let output = cmd.output().map_err(|e| {
            format!("cannot execute bazelisk with the following command: {cmd:?}: {e}")
        })?;
        if !output.status.success() {
            return Err(format!(
                "bazelisk returned a non-zero exit status: {}",
                output.status
            ));
        }

        action_graph::get_artifacts_from_protobuf(&output.stdout, &self.0.bazelisk.exec_root)
    }
}

#[cfg(test)]
mod test {
    use crate::test;
    use crate::Builder;

    /// Tests [`Build`].
    #[test]
    fn test_build() {
        let workspace = test::create_fake_bazel_workspace();
        let output_user_root =
            tempfile::tempdir().expect("cannot create a temporary directory for output_user_root");
        let output_base =
            tempfile::tempdir().expect("cannot create a temporary directory for output_base");
        let sb = tempfile::tempdir().expect("cannot create a temporary directory for the sandbox");
        let home = tempfile::tempdir().expect("cannot create temporary directory for HOME");
        let bazelisk = Builder::new()
            .working_dir(workspace.path())
            .expect("cannot set the working directory")
            .env("HOME", home.path().to_string_lossy().as_ref())
            .output_user_root(output_user_root.path())
            .expect("cannot set the output_user_root directory")
            .output_base(output_base.path())
            .expect("cannot set the output_base directory")
            .sandbox_path(sb.path())
            .expect("cannot set the sandbox directory")
            .build()
            .expect("failed to create a Bazelisk handle");
        bazelisk
            .build_target("//:lib")
            .run()
            .expect("build should be successful");

        let artifacts = bazelisk
            .action_graph_target("//:lib")
            .run()
            .expect("aquery must work");
        let mut path: Option<&std::path::PathBuf> = None;
        for o in artifacts.iter() {
            if let Some(file_name) = o.file_name() {
                if file_name.eq("liblib.a") {
                    path = Some(o);
                    break;
                }
            }
        }
        assert!(path.is_some());
        assert!(path.unwrap().is_file());
    }
}
