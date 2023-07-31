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

//! Enumeration of supported platforms.

/// Supported platforms.
#[derive(Copy, Clone, PartialEq)]
pub enum Platform {
    /// aarch64-darwin.
    Aarch64Darwin,

    /// aarch64-linux.
    Aarch64Linux,

    /// x86_64-darwin.
    X8664Darwin,

    /// x86_64-linux.
    X8664Linux,
}

/// Implements [`std::fmt::Debug`] for [`Platform`].
impl std::fmt::Debug for Platform {
    #[allow(unreachable_patterns)]
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Aarch64Darwin => "aarch64-darwin",
                Self::Aarch64Linux => "aarch64-linux",
                Self::X8664Darwin => "x86_64-darwin",
                Self::X8664Linux => "x86_64-linux",
                _ => unreachable!(),
            }
        )
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
const CURRENT_PLATFORM: Platform = Platform::Aarch64Linux;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
const CURRENT_PLATFORM: Platform = Platform::Aarch64Darwin;

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
const CURRENT_PLATFORM: Platform = Platform::X8664Linux;

#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
const CURRENT_PLATFORM: Platform = Platform::X8664Darwin;

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
std::compile_error!("unsupported architecture");

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
std::compile_error!("unsupported OS");

/// Returns the current platform.
pub const fn get_current_platform() -> Platform {
    CURRENT_PLATFORM
}

/// Implements [`Platform`].
impl Platform {
    /// Returns the OS as a string.
    #[allow(unreachable_patterns)]
    pub fn os_str(&self) -> &'static str {
        match self {
            Self::Aarch64Darwin | Self::X8664Darwin => "darwin",
            Self::Aarch64Linux | Self::X8664Linux => "linux",
            _ => unreachable!("unsupported platform"),
        }
    }

    /// Returns the architecture as a string.
    #[allow(unreachable_patterns)]
    pub fn arch_str(&self) -> &'static str {
        match self {
            Self::Aarch64Darwin | Self::Aarch64Linux => "arm64",
            Self::X8664Darwin | Self::X8664Linux => "amd64",
            _ => unreachable!("unsupported platform"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Tests the [`Platform::os_str`] and [`Platform::arch_str`] methods.
    #[test]
    fn test_str() {
        assert_eq!(Platform::Aarch64Linux.os_str(), "linux");
        assert_eq!(Platform::Aarch64Linux.arch_str(), "arm64");

        assert_eq!(Platform::Aarch64Darwin.os_str(), "darwin");
        assert_eq!(Platform::Aarch64Darwin.arch_str(), "arm64");

        assert_eq!(Platform::X8664Linux.os_str(), "linux");
        assert_eq!(Platform::X8664Linux.arch_str(), "amd64");

        assert_eq!(Platform::X8664Darwin.os_str(), "darwin");
        assert_eq!(Platform::X8664Darwin.arch_str(), "amd64");
    }
}
