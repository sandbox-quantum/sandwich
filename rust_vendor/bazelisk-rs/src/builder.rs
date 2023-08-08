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

//! Defines the struct [`Builder`] for building a [`Bazelisk`].

use super::platform;
use super::platform::Platform;

use super::{Bazelisk, Configuration};

use super::support;

/// Length of a SHA-384 digest.
const SHA384_DIGEST_LENGTH: usize = 0x30;

/// A SHA-384 digest.
pub type SHA384Digest = [u8; SHA384_DIGEST_LENGTH];

/// Default version of Bazelisk to use.
const BAZELISK_VERSION: &str = "1.17.0";

/// SHA-384 digest of the Bazelisk binary of the default version, for [`Platform::Aarch64Darwin`].
const BAZELISK_VARIANT_AARCH64_DARWIN_SHA384: SHA384Digest = hex_literal::hex!("0b02d3676881e4cb051fb1c729dd4879a391fe4136c5c17da354b4e851216cf538ad63696069f0add9b3160c08b197ad");

/// SHA-384 digest of the Bazelisk binary of the default version, for [`Platform::Aarch64Linux`].
const BAZELISK_VARIANT_AARCH64_LINUX_SHA384: SHA384Digest = hex_literal::hex!("12cca0fc1f49a3ecea8a9e2a3a603dbe2662fac3988caee87a193f6fae896587c794a0761fb22a6ae29954ac3f7aa48b");

/// SHA-384 digest of the Bazelisk binary of the default version, for [`Platform::X8664Darwin`].
const BAZELISK_VARIANT_X8664_DARWIN_SHA384: SHA384Digest = hex_literal::hex!("9b4a6288ca0660bd530e91f59d5a49a65c1f11d65ac811b3ac48340c004e4bc01a1fa20750d7753d50f3ba9dc187f014");

/// SHA-384 digest of the Bazelisk binary of the default version, for [`Platform::X8664Linux`].
const BAZELISK_VARIANT_X8664_LINUX_SHA384: SHA384Digest = hex_literal::hex!("e7f19e78d3e449d95535313506563b5d0cda854ecb6a4b3c6fb34cb4b69867bed74b74f3d22d0aa6ae828f5f29e1ce21");

/// Copies the SHA-384 digest corresponding to a given [`Platform`] to the given buffer.
fn get_sha384_digest_for_platform(platform: Platform, dest: &mut SHA384Digest) {
    *dest = match platform {
        Platform::Aarch64Darwin => BAZELISK_VARIANT_AARCH64_DARWIN_SHA384,
        Platform::Aarch64Linux => BAZELISK_VARIANT_AARCH64_LINUX_SHA384,
        Platform::X8664Darwin => BAZELISK_VARIANT_X8664_DARWIN_SHA384,
        Platform::X8664Linux => BAZELISK_VARIANT_X8664_LINUX_SHA384,
    };
}

/// Builder.
#[derive(Clone)]
pub struct Builder {
    /// The version of Bazelisk to use.
    pub(crate) version: String,

    /// The SHA-384 digest of the Bazelisk binary.
    pub(crate) sha384_digest: SHA384Digest,

    /// The platform of the Bazelisk binary.
    pub(crate) platform: Platform,

    /// Ignore the integrity verification.
    pub(crate) ignore_integrity_verification: bool,

    /// Configuration.
    pub(crate) configuration: Configuration,
}

/// Implements [`std::fmt::Debug`] for [`Builder`].
impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "Builder{{")?;
        writeln!(f, "\tBazelisk version: {}", self.version)?;
        write!(f, "\tExpected SHA-384 digest: ")?;
        for c in self.sha384_digest.iter() {
            write!(f, "{c:x}")?;
        }
        writeln!(f, "\n\tPlatform: {:?}", self.platform)?;
        writeln!(
            f,
            "\tignore_integrity_verification: {}",
            self.ignore_integrity_verification
        )?;
        writeln!(f, "\tconfiguration: {:?}", self.configuration)?;
        writeln!(f, "}}")
    }
}

/// Implements [`std::default::Default`] for [`Builder`].
impl std::default::Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements [`Builder`].
impl Builder {
    /// Instantiates a new [`Builder`] with the default values.
    pub fn new() -> Self {
        let mut builder = Self {
            version: BAZELISK_VERSION.into(),
            sha384_digest: [0u8; SHA384_DIGEST_LENGTH],
            platform: platform::get_current_platform(),
            ignore_integrity_verification: false,
            configuration: Configuration::new(),
        };
        get_sha384_digest_for_platform(builder.platform, &mut builder.sha384_digest);
        builder
    }

    /// Sets the version.
    pub fn version(&mut self, version: impl std::convert::Into<String>) -> &mut Self {
        self.version = version.into();
        self
    }

    /// Sets the expected SHA-384 digest.
    pub fn digest(&mut self, digest: impl std::convert::AsRef<[u8]>) -> &mut Self {
        self.sha384_digest.copy_from_slice(digest.as_ref());
        self
    }

    /// Sets the platform.
    pub fn platform(&mut self, platform: Platform) -> &mut Self {
        self.platform = platform;
        self
    }

    /// Ignores the integrity verification.
    pub fn ignore_integrity_verification(&mut self) -> &mut Self {
        self.ignore_integrity_verification = true;
        self
    }

    /// Sets the path to the Bazelisk binary.
    pub fn bazelisk_bin_path(
        &mut self,
        path: impl std::convert::AsRef<std::path::Path>,
    ) -> Result<&mut Self, String> {
        self.configuration.bazelisk_bin_path = support::fs_canonicalize(path)?;
        Ok(self)
    }

    /// Sets the working directory.
    pub fn working_dir(
        &mut self,
        path: impl std::convert::AsRef<std::path::Path>,
    ) -> Result<&mut Self, String> {
        self.configuration.working_dir = support::fs_canonicalize(path)?;
        Ok(self)
    }

    /// Sets the output base.
    pub fn output_base(
        &mut self,
        path: impl std::convert::AsRef<std::path::Path>,
    ) -> Result<&mut Self, String> {
        self.configuration.output_base = Some(support::fs_canonicalize(path)?);
        Ok(self)
    }

    /// Sets the output user root.
    pub fn output_user_root(
        &mut self,
        path: impl std::convert::AsRef<std::path::Path>,
    ) -> Result<&mut Self, String> {
        self.configuration.output_user_root = Some(support::fs_canonicalize(path)?);
        Ok(self)
    }

    /// Sets the sandbox path.
    pub fn sandbox_path(
        &mut self,
        path: impl std::convert::AsRef<std::path::Path>,
    ) -> Result<&mut Self, String> {
        self.configuration.sandbox_path = Some(support::fs_canonicalize(path)?);
        Ok(self)
    }

    /// Enables the client/server mode.
    pub fn client_server_mode(&mut self) -> &mut Self {
        self.configuration.cliserv_mode = true;
        self
    }

    /// Disables shutting down the Bazel server when [`Bazelisk`] is destroyed.
    pub fn no_shutdown(&mut self) -> &mut Self {
        self.configuration.no_shutdown = true;
        self
    }

    /// Sets a environment variable.
    pub fn env<S, T>(&mut self, name: S, value: T) -> &mut Self
    where
        S: std::convert::Into<String>,
        T: std::convert::Into<String>,
    {
        self.configuration.env.insert(name.into(), value.into());
        self
    }

    /// Builds a [`Bazelisk`] handle.
    #[allow(unused_imports)]
    pub fn build(&mut self) -> Result<Bazelisk, String> {
        use std::convert::TryFrom;
        Bazelisk::try_from(self.clone())
    }
}
