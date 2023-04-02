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

#[cfg(test)]
pub(crate) mod test {
    /// Path to a valid PEM certificate.
    pub(crate) const CERT_PEM_PATH: &str = "testdata/cert.pem";

    /// Path to an invalid PEM certificate.
    pub(crate) const CERT_INVALID_UNKNOWN_SIG_ALG_DER_PATH: &str =
        "testdata/cert_unknown_sig_alg.der";

    /// Path to a valid DER certificate.
    pub(crate) const CERT_DER_PATH: &str = "testdata/cert.der";

    /// Path to a valid PEM private key.
    pub(crate) const SK_PATH: &str = "testdata/key.pem";

    /// Path to a valid DER private key.
    pub(crate) const SK_DER_PATH: &str = "testdata/key.der";
}
