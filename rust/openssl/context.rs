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

//! Defines [`SSLContext`] enum and [`Context`] struct.
//!
//! This context is instanciated for protobuf messages that specified
//! `IMPL_OPENSSL1_1_1_OQS`.
//!
//! Author: thb-sb

extern crate openssl;

/// Wrapper around `SSL_CTX*`.
pub(super) enum SSLContext<'pimpl> {
    Client(crate::Pimpl<'pimpl, openssl::SSL_CTX>),
    Server(crate::Pimpl<'pimpl, openssl::SSL_CTX>),
}

/// Implements [`std::fmt::Debug`] for [`SSLContext`].
impl<'pimpl> std::fmt::Debug for SSLContext<'pimpl> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} OpenSSL SSL_CTX* object",
            match *self {
                SSLContext::Client(_) => "client",
                SSLContext::Server(_) => "client",
            }
        )
    }
}

/// Returns a reference to the [`crate::Pimpl`] of `openssl::SSL_CTX` from a [`SSLContext`].
impl<'pimpl> std::convert::AsRef<crate::Pimpl<'pimpl, openssl::SSL_CTX>> for SSLContext<'pimpl> {
    fn as_ref(&self) -> &crate::Pimpl<'pimpl, openssl::SSL_CTX> {
        match *self {
            SSLContext::Client(ref e) => e,
            SSLContext::Server(ref e) => e,
        }
    }
}

/// Returns the raw pointer to `openssl::SSL_CTX` from a [`SSLContext`].
impl<'pimpl> std::convert::From<&SSLContext<'pimpl>> for *const openssl::SSL_CTX {
    fn from(ssl_ctx: &SSLContext<'pimpl>) -> Self {
        match *ssl_ctx {
            SSLContext::Client(ref e) => e.as_ptr(),
            SSLContext::Server(ref e) => e.as_ptr(),
        }
    }
}

/// Returns the raw pointer as mutable to `openssl::SSL_CTX` from a [`SSLContext`].
impl<'pimpl> std::convert::From<&mut SSLContext<'pimpl>> for *mut openssl::SSL_CTX {
    fn from(ssl_ctx: &mut SSLContext<'pimpl>) -> Self {
        match *ssl_ctx {
            SSLContext::Client(ref mut e) => e.as_mut_ptr(),
            SSLContext::Server(ref mut e) => e.as_mut_ptr(),
        }
    }
}

/// Implements [`SSLContext`].
#[allow(dead_code)]
impl<'pimpl> SSLContext<'pimpl> {
    fn as_raw(&self) -> *const openssl::SSL_CTX {
        self.into()
    }
}

/// Instantiates a [`SSLContext`] from a [`crate::Mode`].
impl<'pimpl> std::convert::TryFrom<crate::Mode> for SSLContext<'pimpl> {
    type Error = crate::Error;

    fn try_from(m: crate::Mode) -> crate::Result<Self> {
        let ctx = unsafe {
            openssl::SSL_CTX_new(match m {
                crate::Mode::Client => openssl::TLS_client_method(),
                crate::Mode::Server => openssl::TLS_server_method(),
            })
        };
        if ctx.is_null() {
            return Err(pb::SystemError::SYSTEMERROR_MEMORY)?;
        }
        let ctx = crate::Pimpl::<openssl::SSL_CTX>::from_raw(
            ctx,
            Some(|x| unsafe {
                openssl::SSL_CTX_free(x);
            }),
        );

        match m {
            crate::Mode::Client => Ok(Self::Client(ctx)),
            crate::Mode::Server => Ok(Self::Server(ctx)),
        }
    }
}

/// An OpenSSL context.
pub(in crate::openssl) struct Context<'pimpl>(pub(in crate::openssl) SSLContext<'pimpl>);

/// Instantiates a [`Context`] from a [`SSLContext`].
impl<'pimpl> std::convert::From<SSLContext<'pimpl>> for Context<'pimpl> {
    fn from(ctx: SSLContext<'pimpl>) -> Self {
        Self(ctx)
    }
}

/// Instantiates a [`Context`] from a [`crate::Mode`].
impl<'pimpl> std::convert::TryFrom<crate::Mode> for Context<'pimpl> {
    type Error = crate::Error;

    fn try_from(m: crate::Mode) -> crate::Result<Self> {
        Ok(Self(SSLContext::try_from(m)?))
    }
}

/// Returns the raw pointer to `openssl::SSL_CTX` from a [`Context`].
impl<'pimpl> std::convert::From<&Context<'pimpl>> for *const openssl::SSL_CTX {
    fn from(ctx: &Context<'pimpl>) -> Self {
        (&ctx.0).into()
    }
}

/// Returns the raw pointer as mutable to `openssl::SSL_CTX` from a [`Context`].
impl<'pimpl> std::convert::From<&mut Context<'pimpl>> for *mut openssl::SSL_CTX {
    fn from(ctx: &mut Context<'pimpl>) -> Self {
        (&mut ctx.0).into()
    }
}

/// Instantiates a [`Context`] from a protobuf configuration message.
impl<'pimpl> std::convert::TryFrom<&pb_api::Configuration> for Context<'pimpl> {
    type Error = crate::Error;

    fn try_from(configuration: &pb_api::Configuration) -> crate::Result<Self> {
        use pb_api::configuration::client_options as pb_client_options;
        use pb_api::configuration::configuration as pb_configuration;
        use pb_api::configuration::server_options as pb_server_options;
        let (mode, ssl_ctx, co) = configuration
            .opts
            .as_ref()
            .ok_or(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY)
            .and_then(|oneof| match oneof {
                pb_configuration::Opts::Client(co) => co
                    .opts
                    .as_ref()
                    .ok_or(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY)
                    .and_then(|oneof| match oneof {
                        pb_client_options::Opts::Tls(tls) => Ok((
                            crate::Mode::Client,
                            SSLContext::try_from(crate::Mode::Client),
                            tls.common_options.as_ref(),
                        )),
                        _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY),
                    }),
                pb_configuration::Opts::Server(co) => co
                    .opts
                    .as_ref()
                    .ok_or(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY)
                    .and_then(|oneof| match oneof {
                        pb_server_options::Opts::Tls(tls) => Ok((
                            crate::Mode::Server,
                            SSLContext::try_from(crate::Mode::Server),
                            tls.common_options.as_ref(),
                        )),
                        _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY),
                    }),
                _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_EMPTY),
            })?;
        let mut ssl_ctx = ssl_ctx.map_err(|e|
                e >> match mode {
                    crate::Mode::Client => crate::ErrorCode::from(pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_SSL_CTX_FAILED),
                    crate::Mode::Server => crate::ErrorCode::from(pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_SSL_CTX_FAILED),
                }
        )?;

        unsafe {
            openssl::SSL_CTX_set_options(
                (&mut ssl_ctx).into(),
                (openssl::SSL_OP_NO_SSLv3
                    | openssl::SSL_OP_NO_TLSv1
                    | openssl::SSL_OP_NO_TLSv1_1
                    | openssl::SSL_OP_NO_TLSv1_2
                    | openssl::SSL_OP_NO_DTLSv1
                    | openssl::SSL_OP_NO_DTLSv1_2)
                    .into(),
            );
        }

        match unsafe { openssl::SSL_CTX_ctrl((&mut ssl_ctx).into(), openssl::SSL_CTRL_SET_MIN_PROTO_VERSION as i32, openssl::TLS1_3_VERSION.into(), std::ptr::null_mut()) } {
            1 => Ok(()),
            _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_UNSUPPORTED_PROTOCOL_VERSION)
        }?;

        let flags = co.map(|co| co.flags).unwrap_or(0);

        if mode == crate::Mode::Client {
            unsafe {
                openssl::SSL_CTX_set_verify(
                    (&mut ssl_ctx).into(),
                    if (flags
                        & <pb_api::TLSFlags as protobuf::Enum>::value(
                            &pb_api::TLSFlags::TLSFLAGS_SKIP_VERIFY,
                        ))
                        != 0
                    {
                        openssl::SSL_VERIFY_NONE
                    } else {
                        openssl::SSL_VERIFY_PEER
                    } as i32,
                    None,
                );
            }
        }
        unsafe {
            openssl::SSL_CTX_set_quiet_shutdown((&mut ssl_ctx).into(), 0);
            openssl::SSL_CTX_ctrl(
                (&mut ssl_ctx).into(),
                openssl::SSL_CTRL_SET_SESS_CACHE_MODE as i32,
                openssl::SSL_SESS_CACHE_OFF.into(),
                std::ptr::null_mut(),
            );
        }
        unsafe {
            openssl::SSL_CTX_ctrl(
                (&mut ssl_ctx).into(),
                openssl::SSL_CTRL_SET_GROUPS as i32,
                0,
                std::ptr::null_mut(),
            );
        }

        let mut ctx = Self(ssl_ctx);
        if let Some(co) = co {
            if let Err(r) = ctx.set_kems(co.kem.iter()) {
                return Err(r >> match mode {
                    crate::Mode::Client => crate::ErrorCode::from(
                        pb::OpenSSLClientConfigurationError::OPENSSLCLIENTCONFIGURATIONERROR_KEM,
                    ),
                    crate::Mode::Server => crate::ErrorCode::from(
                        pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_KEM,
                    ),
                });
            }
        }
        Ok(ctx)
    }
}

/// Implements [`Context`].
impl<'pimpl> Context<'pimpl> {
    /// Adds a certificate to the trusted certificate store, or set the
    /// certificate for the server.
    pub(super) fn push_cert(&mut self, cert: &pb_api::Certificate) -> crate::Result<()> {
        let mut cert = super::Certificate::try_from(cert)?;
        match &mut self.0 {
            SSLContext::Client(_) => {
                let store = unsafe { openssl::SSL_CTX_get_cert_store((&self.0).into()) };
                if store.is_null() {
                    Err(
                        errors! {pb::SystemError::SYSTEMERROR_MEMORY => pb::CertificateError::CERTIFICATEERROR_UNKNOWN},
                    )
                } else {
                    unsafe {
                        openssl::X509_STORE_add_cert(store, cert.as_mut_ptr());
                    };
                    Ok(())
                }
            }
            SSLContext::Server(_) => {
                match unsafe {
                    openssl::SSL_CTX_use_certificate((&mut self.0).into(), cert.as_mut_ptr())
                } {
                    1 => Ok(()),
                    _ => Err(pb::CertificateError::CERTIFICATEERROR_UNSUPPORTED)?,
                }
            }
        }
    }

    /// Sets KEMs.
    pub(super) fn set_kems<'it, T: 'it>(&mut self, it: T) -> crate::Result<()>
    where
        T: std::iter::Iterator<Item = &'it std::string::String>,
    {
        let mut nids = std::vec::Vec::<i32>::new();
        for s in it {
            let nid = match std::ffi::CString::new(s.as_bytes()) {
                Ok(cstr) => Ok(unsafe { openssl::OBJ_txt2nid(cstr.as_c_str().as_ptr()) }),
                Err(_) => Err(
                    errors! {pb::SystemError::SYSTEMERROR_MEMORY => pb::KEMError::KEMERROR_INVALID},
                ),
            }?;
            if nid == (openssl::NID_undef as i32) {
                return Err(pb::KEMError::KEMERROR_INVALID)?;
            }
            nids.push(nid);
            if nids.len() > (std::i32::MAX as usize) {
                return Err(pb::KEMError::KEMERROR_TOO_MANY)?;
            }
        }
        if !nids.is_empty() {
            match unsafe {
                openssl::SSL_CTX_ctrl(
                    (&mut self.0).into(),
                    openssl::SSL_CTRL_SET_GROUPS as i32,
                    nids.len() as i64,
                    nids.as_ptr() as *mut std::ffi::c_void,
                )
            } {
                1 => Ok(()),
                _ => Err(pb::KEMError::KEMERROR_INVALID)?,
            }
        } else {
            Ok(())
        }
    }
}

/// Instantiates a [`Context`] from a protobuf configuration message.
pub(crate) fn try_from<'ctx>(
    configuration: &pb_api::Configuration,
) -> crate::Result<Box<dyn crate::Context<'ctx> + 'ctx>> {
    use pb_api::configuration::configuration as pb_configuration;
    assert_compliance(configuration)?;
    configuration
        .opts
        .as_ref()
        .ok_or_else(|| pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into())
        .and_then::<Box<dyn crate::Context<'ctx> + 'ctx>, _>(|oneof| match oneof {
            pb_configuration::Opts::Client(_) => Ok(Box::new(unwrap_or!(
                super::client::Context::try_from(configuration),
                pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID
            ))),
            pb_configuration::Opts::Server(_) => Ok(Box::new(unwrap_or!(
                super::server::Context::try_from(configuration),
                pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID
            ))),
            _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into()),
        })
}

/// Extracts the list of allowed key exchange mechanisms (KEM) from the Configuration.
fn get_kems(cfg: &pb_api::Configuration) -> crate::Result<&std::vec::Vec<std::string::String>> {
    use pb_api::configuration::configuration as pb_configuration;
    cfg.opts
        .as_ref()
        .ok_or_else(|| pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into())
        .and_then(|oneof| match oneof {
            pb_configuration::Opts::Client(c) => Ok(&c.tls().common_options.kem),
            pb_configuration::Opts::Server(s) => Ok(&s.tls().common_options.kem),
            _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into()),
        })
}

/// A cryptographic algorithm: is it safe to attack from quantum computer, unsafe, or a hybrid.
#[derive(Copy, Clone, PartialEq, Eq)]
enum AlgorithmQuantumness {
    Classical,
    QuantumSafe,
    QuantumSafeClassicalHybrid,
}

impl std::convert::TryFrom<&str> for AlgorithmQuantumness {
    type Error = crate::Error;

    fn try_from(alg: &str) -> crate::Result<Self> {
        match alg {
            "brainpoolP384r1" => Ok(AlgorithmQuantumness::Classical),
            "brainpoolP512r1" => Ok(AlgorithmQuantumness::Classical),
            "prime256v1" => Ok(AlgorithmQuantumness::Classical),
            "secp160k1" => Ok(AlgorithmQuantumness::Classical),
            "secp160r1" => Ok(AlgorithmQuantumness::Classical),
            "secp160r2" => Ok(AlgorithmQuantumness::Classical),
            "secp192k1" => Ok(AlgorithmQuantumness::Classical),
            "secp224k1" => Ok(AlgorithmQuantumness::Classical),
            "secp224r1" => Ok(AlgorithmQuantumness::Classical),
            "secp256k1" => Ok(AlgorithmQuantumness::Classical),
            "secp384r1" => Ok(AlgorithmQuantumness::Classical),
            "secp521r1" => Ok(AlgorithmQuantumness::Classical),
            "sect163k1" => Ok(AlgorithmQuantumness::Classical),
            "sect163r1" => Ok(AlgorithmQuantumness::Classical),
            "sect163r2" => Ok(AlgorithmQuantumness::Classical),
            "sect193r1" => Ok(AlgorithmQuantumness::Classical),
            "sect193r2" => Ok(AlgorithmQuantumness::Classical),
            "sect233k1" => Ok(AlgorithmQuantumness::Classical),
            "sect233r1" => Ok(AlgorithmQuantumness::Classical),
            "sect239k1" => Ok(AlgorithmQuantumness::Classical),
            "sect283k1" => Ok(AlgorithmQuantumness::Classical),
            "sect283r1" => Ok(AlgorithmQuantumness::Classical),
            "sect409k1" => Ok(AlgorithmQuantumness::Classical),
            "sect409r1" => Ok(AlgorithmQuantumness::Classical),
            "sect571k1" => Ok(AlgorithmQuantumness::Classical),
            "sect571r1" => Ok(AlgorithmQuantumness::Classical),
            "bikel1" => Ok(AlgorithmQuantumness::QuantumSafe),
            "bikel3" => Ok(AlgorithmQuantumness::QuantumSafe),
            "frodo1344aes" => Ok(AlgorithmQuantumness::QuantumSafe),
            "frodo1344shake" => Ok(AlgorithmQuantumness::QuantumSafe),
            "frodo640aes" => Ok(AlgorithmQuantumness::QuantumSafe),
            "frodo640shake" => Ok(AlgorithmQuantumness::QuantumSafe),
            "frodo976aes" => Ok(AlgorithmQuantumness::QuantumSafe),
            "frodo976shake" => Ok(AlgorithmQuantumness::QuantumSafe),
            "hqc128" => Ok(AlgorithmQuantumness::QuantumSafe),
            "hqc192" => Ok(AlgorithmQuantumness::QuantumSafe),
            "hqc256" => Ok(AlgorithmQuantumness::QuantumSafe),
            "kyber1024" => Ok(AlgorithmQuantumness::QuantumSafe),
            "kyber512" => Ok(AlgorithmQuantumness::QuantumSafe),
            "kyber768" => Ok(AlgorithmQuantumness::QuantumSafe),
            "kyber90s1024" => Ok(AlgorithmQuantumness::QuantumSafe),
            "kyber90s512" => Ok(AlgorithmQuantumness::QuantumSafe),
            "kyber90s768" => Ok(AlgorithmQuantumness::QuantumSafe),
            "p256_bikel1" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p256_frodo640aes" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p256_frodo640shake" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p256_hqc128" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p256_kyber512" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p256_kyber90s512" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p384_bikel3" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p384_frodo976aes" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p384_frodo976shake" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p384_hqc192" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p384_kyber768" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p384_kyber90s768" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p521_frodo1344aes" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p521_frodo1344shake" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p521_hqc256" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p521_kyber1024" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            "p521_kyber90s1024" => Ok(AlgorithmQuantumness::QuantumSafeClassicalHybrid),
            _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into()),
        }
    }
}

/// Represents the AES bit size equivalent hardness of breaking an algorithm.
#[derive(Copy, Clone, PartialEq, PartialOrd, Eq)]
enum BitStrength {
    Bits128,
    Bits192,
    Bits256,
}

/// Returns the bit strength for an algorithm.
fn bit_strength(alg: &str) -> crate::Result<BitStrength> {
    match alg {
        "brainpoolP384r1" => Ok(BitStrength::Bits192),
        "brainpoolP512r1" => Ok(BitStrength::Bits256),
        "prime256v1" => Ok(BitStrength::Bits256),
        "secp160k1" => Ok(BitStrength::Bits128),
        "secp160r1" => Ok(BitStrength::Bits128),
        "secp160r2" => Ok(BitStrength::Bits128),
        "secp192k1" => Ok(BitStrength::Bits192),
        "secp224k1" => Ok(BitStrength::Bits192),
        "secp224r1" => Ok(BitStrength::Bits192),
        "secp256k1" => Ok(BitStrength::Bits256),
        "secp384r1" => Ok(BitStrength::Bits256),
        "secp521r1" => Ok(BitStrength::Bits256),
        "sect163k1" => Ok(BitStrength::Bits128),
        "sect163r1" => Ok(BitStrength::Bits128),
        "sect163r2" => Ok(BitStrength::Bits128),
        "sect193r1" => Ok(BitStrength::Bits192),
        "sect193r2" => Ok(BitStrength::Bits192),
        "sect233k1" => Ok(BitStrength::Bits192),
        "sect233r1" => Ok(BitStrength::Bits192),
        "sect239k1" => Ok(BitStrength::Bits192),
        "sect283k1" => Ok(BitStrength::Bits256),
        "sect283r1" => Ok(BitStrength::Bits256),
        "sect409k1" => Ok(BitStrength::Bits128),
        "sect409r1" => Ok(BitStrength::Bits256),
        "sect571k1" => Ok(BitStrength::Bits256),
        "sect571r1" => Ok(BitStrength::Bits256),
        "bikel1" => Ok(BitStrength::Bits128),
        "bikel3" => Ok(BitStrength::Bits128),
        "frodo1344aes" => Ok(BitStrength::Bits128),
        "frodo1344shake" => Ok(BitStrength::Bits128),
        "frodo640aes" => Ok(BitStrength::Bits128),
        "frodo640shake" => Ok(BitStrength::Bits128),
        "frodo976aes" => Ok(BitStrength::Bits128),
        "frodo976shake" => Ok(BitStrength::Bits128),
        "hqc128" => Ok(BitStrength::Bits128),
        "hqc192" => Ok(BitStrength::Bits192),
        "hqc256" => Ok(BitStrength::Bits256),
        "kyber1024" => Ok(BitStrength::Bits128),
        "kyber512" => Ok(BitStrength::Bits128),
        "kyber768" => Ok(BitStrength::Bits128),
        "kyber90s1024" => Ok(BitStrength::Bits128),
        "kyber90s512" => Ok(BitStrength::Bits128),
        "kyber90s768" => Ok(BitStrength::Bits128),
        "p256_bikel1" => Ok(BitStrength::Bits256),
        "p256_frodo640aes" => Ok(BitStrength::Bits128),
        "p256_frodo640shake" => Ok(BitStrength::Bits128),
        "p256_hqc128" => Ok(BitStrength::Bits128),
        "p256_kyber512" => Ok(BitStrength::Bits256),
        "p256_kyber90s512" => Ok(BitStrength::Bits128),
        "p384_bikel3" => Ok(BitStrength::Bits128),
        "p384_frodo976aes" => Ok(BitStrength::Bits128),
        "p384_frodo976shake" => Ok(BitStrength::Bits128),
        "p384_hqc192" => Ok(BitStrength::Bits128),
        "p384_kyber768" => Ok(BitStrength::Bits128),
        "p384_kyber90s768" => Ok(BitStrength::Bits128),
        "p521_frodo1344aes" => Ok(BitStrength::Bits128),
        "p521_frodo1344shake" => Ok(BitStrength::Bits128),
        "p521_hqc256" => Ok(BitStrength::Bits128),
        "p521_kyber1024" => Ok(BitStrength::Bits128),
        "p521_kyber90s1024" => Ok(BitStrength::Bits128),
        _ => Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE.into()),
    }
}

/// Verifies that the selected algorithm comply with the desired compliance in the configuration.
fn assert_compliance(cfg: &pb_api::Configuration) -> crate::Result<()> {
    let kems = get_kems(cfg)?;
    let compliance = cfg.compliance.as_ref().unwrap_or_default();
    let hybrid_choice = compliance.hybrid_choice.enum_value_or_default();
    let classical_choice = compliance.classical_choice.enum_value_or_default();
    let quantum_choice = compliance.quantum_safe_choice.enum_value_or_default();
    let desired_strength = compliance.bit_strength_choice.enum_value_or_default();
    for k in kems.iter() {
        match AlgorithmQuantumness::try_from(k.as_str())? {
            AlgorithmQuantumness::QuantumSafeClassicalHybrid => {
                if hybrid_choice == pb_api::HybridAlgoChoice::HYBRID_ALGORITHMS_FORBID {
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
            }
            AlgorithmQuantumness::Classical => {
                if classical_choice == pb_api::ClassicalAlgoChoice::CLASSICAL_ALGORITHMS_FORBID {
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
            }
            AlgorithmQuantumness::QuantumSafe => {
                if quantum_choice == pb_api::QuantumSafeAlgoChoice::QUANTUM_SAFE_ALGORITHMS_FORBID {
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
            }
        }
        let bs = bit_strength(k)?;
        match desired_strength {
            pb_api::NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_128 => {
                if bs < BitStrength::Bits128 {
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
            }
            pb_api::NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_192 => {
                if bs < BitStrength::Bits192 {
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
            }
            pb_api::NISTSecurityStrengthBits::BIT_STRENGTH_AT_LEAST_256 => {
                if bs < BitStrength::Bits256 {
                    Err(pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID_CASE)?
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{Context, SSLContext};

    /// Tests constructor of [`SSLContext`] from a [`crate::Mode`].
    #[test]
    fn test_constructor_ssl_context() {
        let r = SSLContext::try_from(crate::Mode::Client);
        assert!(r.is_ok());
        assert!(!r.unwrap().as_raw().is_null());

        let r = SSLContext::try_from(crate::Mode::Server);
        assert!(r.is_ok());
        assert!(!r.unwrap().as_raw().is_null());
    }

    /// Tests constructor of [`Context`] from a [`SSLContext`].
    #[test]
    fn test_constructor_context_from_ssl_context() {
        let r = SSLContext::try_from(crate::Mode::Client);
        assert!(r.is_ok());
        let r = Context::from(r.unwrap());
        assert!(!r.0.as_raw().is_null());
    }

    /// Tests constructor of [`Context`] from a [`crate::Mode`].
    #[test]
    fn test_constructor_context_from_mode() {
        let r = Context::try_from(crate::Mode::Client);
        assert!(r.is_ok());
        assert!(!r.unwrap().0.as_raw().is_null());
    }

    /// Tests `Into<*const SSL_CTX>` for [`SSLContext<'pimpl>`].
    #[test]
    fn test_into_ptr() {
        let r = SSLContext::try_from(crate::Mode::Client);
        assert!(r.is_ok());
        let r = r.unwrap();
        let ptr: *const openssl::SSL_CTX = (&r).into();
        assert!(!ptr.is_null());
    }

    /// Tests `Into<*mut SSL_CTX>` for [`SSLContext<'pimpl>`].
    #[test]
    fn test_into_ptr_mut() {
        let r = SSLContext::try_from(crate::Mode::Client);
        assert!(r.is_ok());
        let mut r = r.unwrap();
        let ptr: *mut openssl::SSL_CTX = (&mut r).into();
        assert!(!ptr.is_null());
    }

    /// Tests push cert to server.
    #[test]
    fn test_push_cert_server() {
        let ctx = Context::try_from(crate::Mode::Server);
        assert!(ctx.is_ok());
        let mut ctx = ctx.unwrap();

        let cert = super::super::certificate::test::create_cert(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
        );
        assert!(ctx.push_cert(&cert).is_ok());
    }

    /// Tests push cert to client.
    #[test]
    fn test_push_cert_client() {
        let ctx = Context::try_from(crate::Mode::Client);
        assert!(ctx.is_ok());
        let mut ctx = ctx.unwrap();

        let cert = super::super::certificate::test::create_cert(
            crate::openssl::test::CERT_DER_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
        );
        assert!(ctx.push_cert(&cert).is_ok());
    }

    /// Tests push cert to client with invalid certificate.
    #[test]
    fn test_push_cert_client_invalid() {
        let ctx = Context::try_from(crate::Mode::Client);
        assert!(ctx.is_ok());
        let mut ctx = ctx.unwrap();

        let cert = super::super::certificate::test::create_cert(
            crate::openssl::test::CERT_DER_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
        );
        let r = ctx.push_cert(&cert);
        assert!(r.is_err());
        let e = r.unwrap_err();
        assert_eq!(
            e,
            errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED}
        );
    }

    /// Tests set KEM and invalid KEM.
    #[test]
    fn test_set_kem() {
        let ctx = Context::try_from(crate::Mode::Client);
        assert!(ctx.is_ok());
        let mut ctx = ctx.unwrap();

        assert!(ctx.set_kems(vec!["kyber1024".to_string()].iter()).is_ok());
        assert!(ctx.set_kems(vec!["kyber1023".to_string()].iter()).is_err());
    }

    /// Tests `try_from` with a client.
    #[test]
    fn test_try_from_client() {
        let ctx = super::super::client::test::create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1024",
        );
        let r = super::try_from(&ctx);
        assert!(r.is_ok());
    }

    /// Tests `try_from` with a server.
    #[test]
    fn test_try_from_server() {
        let ctx = super::super::server::test::create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1024",
        );
        let r = super::try_from(&ctx);
        assert!(r.is_ok());
    }

    /// Tests `try_from` with a server and an invalid cert format.
    #[test]
    fn test_try_from_server_invalid_cert() {
        let ctx = super::super::server::test::create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            "kyber1024",
        );
        let r = super::try_from(&ctx);
        assert!(r.is_err());
        assert_eq!(
            r.unwrap_err(),
            errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::CertificateError::CERTIFICATEERROR_MALFORMED => pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_CERTIFICATE => pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID}
        );
    }

    /// Tests `try_from` with a server and an invalid private key format.
    #[test]
    fn test_try_from_server_invalid_pkey() {
        let ctx = super::super::server::test::create_basic_configuration(
            crate::openssl::test::CERT_PEM_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_PEM),
            crate::openssl::test::PKEY_PATH,
            Some(pb_api::encoding_format::ASN1EncodingFormat::ENCODING_FORMAT_DER),
            "kyber1024",
        );
        let r = super::try_from(&ctx);
        assert!(r.is_err());
        assert_eq!(
            r.unwrap_err(),
            errors! {pb::ASN1Error::ASN1ERROR_MALFORMED => pb::PrivateKeyError::PRIVATEKEYERROR_MALFORMED => pb::OpenSSLServerConfigurationError::OPENSSLSERVERCONFIGURATIONERROR_PRIVATE_KEY => pb::OpenSSLConfigurationError::OPENSSLCONFIGURATIONERROR_INVALID}
        );
    }

    /// Tests the default compliance: it accepts post quantum and hybrid.
    #[test]
    fn test_default_compliance() {
        use super::assert_compliance;
        let cfg = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            "client <
              tls <
                common_options <
                  kem: \"kyber512\"
                  kem: \"p256_kyber512\"
                >
              >
            >
            ",
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_ok());
    }

    /// Tests the default compliance: it forbids purely classical kems.
    #[test]
    fn test_default_compliance_no_classical() {
        use super::assert_compliance;
        let cfg = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            "client <
              tls <
                common_options <
                  kem: \"prime256v1\"
                  kem: \"kyber512\"
                  kem: \"p256_kyber512\"
                >
              >
            >
            ",
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_err());
    }

    #[test]
    fn test_compliance_no_hybrid() {
        use super::assert_compliance;
        let cfg = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            "client <
              tls <
                common_options <
                  kem: \"p256_kyber512\"
                >
              >
            >
            compliance <
              hybrid_choice: HYBRID_ALGORITHMS_FORBID
            >
            ",
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_err());
    }

    #[test]
    fn test_compliance_bit_strength() {
        use super::assert_compliance;
        let cfg = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            "client <
              tls <
                common_options <
                  kem: \"p256_kyber512\"
                >
              >
            >
            compliance <
              bit_strength_choice: BIT_STRENGTH_AT_LEAST_256
            >
            ",
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_ok());
    }

    #[test]
    fn test_compliance_insufficient_bit_strength() {
        use super::assert_compliance;
        let cfg = protobuf::text_format::parse_from_str::<pb_api::Configuration>(
            "client <
              tls <
                common_options <
                  kem: \"hqc192\"
                >
              >
            >
            compliance <
              bit_strength_choice: BIT_STRENGTH_AT_LEAST_256
            >
            ",
        )
        .unwrap();
        assert!(assert_compliance(&cfg).is_err());
    }
}
