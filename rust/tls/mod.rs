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

//! TLS module.

mod security;

pub(crate) use security::assert_compliance;

/// Security requirements to enforce on TLS tunnels.
/// These requirements are described by the verifiers that comes with the
/// `TLSOptions` configuration message.
#[derive(Clone)]
pub(crate) struct TunnelSecurityRequirements {
    /// Allows expired certificates.
    /// This switch comes from the X.509 verifier `X509Verifier`.
    #[allow(dead_code)]
    pub(crate) allow_expired_certificate: bool,
}

/// Instantiates a [`TunnelSecurityRequirements`] from a [`pb_api::X509Verifier`].
impl std::convert::From<&pb_api::X509Verifier> for TunnelSecurityRequirements {
    fn from(x509_verifier: &pb_api::X509Verifier) -> Self {
        Self {
            allow_expired_certificate: x509_verifier.allow_expired_certificate,
        }
    }
}

/// Implements [`std::default::Default`] for [`TunnelSecurityRequirements`].
impl std::default::Default for TunnelSecurityRequirements {
    fn default() -> Self {
        Self::new()
    }
}

/// Implements [`TunnelSecurityRequirements`].
impl TunnelSecurityRequirements {
    /// Instantiates a [`TunnelSecurityRequirements`].
    fn new() -> Self {
        Self {
            allow_expired_certificate: false,
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    /// Path to a valid PEM certificate.
    pub(crate) const CERT_PEM_PATH: &str = "testdata/cert.pem";

    /// Path to an invalid DER certificate.
    pub(crate) const CERT_INVALID_UNKNOWN_SIG_ALG_DER_PATH: &str =
        "testdata/cert_unknown_sig_alg.der";

    /// Path to an expired PEM certificate.
    pub(crate) const CERT_EXPIRED_PEM_PATH: &str = "testdata/cert_expired.pem";

    /// Path to a valid DER certificate.
    pub(crate) const CERT_DER_PATH: &str = "testdata/cert.der";

    /// Path to a valid PEM private key.
    pub(crate) const SK_PATH: &str = "testdata/key.pem";

    /// Path to a valid DER private key.
    pub(crate) const SK_DER_PATH: &str = "testdata/key.der";
}
