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

//! Sandwich OpenSSL implementation module.
//!
//! Author: thb-sb

pub(self) mod bio;
pub(self) mod certificate;
pub(self) mod client;
pub(self) mod io;
pub(self) mod private_key;
pub(self) mod server;
pub(self) mod tunnel;

pub(self) use bio::Bio;
pub(self) use certificate::Certificate;
pub(in crate::openssl) use context::Context;
pub(self) use io::BIO_METH;
pub(self) use private_key::PrivateKey;

pub(crate) mod context;

#[cfg(test)]
pub(crate) mod test {
    /// Path to a valid PEM certificate.
    pub(crate) const CERT_PEM_PATH: &str = "testdata/cert.pem";

    /// Path to a valid DER certificate.
    pub(crate) const CERT_DER_PATH: &str = "testdata/cert.der";

    /// Path to a valid PEM private key.
    pub(crate) const SK_PATH: &str = "testdata/key.pem";
}
