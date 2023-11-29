// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

//! Support for OpenSSL 3 errors.

#![allow(non_snake_case)]
#![allow(unused_variables)]

use std::ffi::{c_int, c_ulong};

use crate::ossl3::support;

macro_rules! gen_enum_from_openssl {
    ( $name:ident, $doc:expr, $( ($sym:ident, $value:ident)$(,)? )* ) => {
        #[derive(Debug, PartialEq, Eq, Copy, Clone)]
        #[doc=$doc]
        #[allow(dead_code)]
        #[repr(isize)]
        pub(crate) enum $name {
            $(
                $sym = ::openssl3::$value as isize,
            )*
        }

        impl TryFrom<::std::ffi::c_int> for $name {
            type Error = ();

            fn try_from(err: ::std::ffi::c_int) -> Result<Self, Self::Error> {
                #[allow(unreachable_patterns)]
                match err as u32 {
                    $(
                        openssl3::$value => Ok(Self::$sym),
                    )*
                        _ => Err(())
                }
            }
        }
    };
}

gen_enum_from_openssl!(
    ErrorLibrary,
    "Library where an error can occur",
    (None, ERR_LIB_NONE),
    (Sys, ERR_LIB_SYS),
    (Bn, ERR_LIB_BN),
    (Rsa, ERR_LIB_RSA),
    (Dh, ERR_LIB_DH),
    (Evp, ERR_LIB_EVP),
    (Buf, ERR_LIB_BUF),
    (Obj, ERR_LIB_OBJ),
    (Pem, ERR_LIB_PEM),
    (Dsa, ERR_LIB_DSA),
    (X509, ERR_LIB_X509),
    (Asn1, ERR_LIB_ASN1),
    (Conf, ERR_LIB_CONF),
    (Crypto, ERR_LIB_CRYPTO),
    (Ec, ERR_LIB_EC),
    (Ssl, ERR_LIB_SSL),
    (Bio, ERR_LIB_BIO),
    (Pkcs7, ERR_LIB_PKCS7),
    (X509v3, ERR_LIB_X509V3),
    (Pkcs12, ERR_LIB_PKCS12),
    (Rand, ERR_LIB_RAND),
    (Dso, ERR_LIB_DSO),
    (Engine, ERR_LIB_ENGINE),
    (Ocsp, ERR_LIB_OCSP),
    (Ui, ERR_LIB_UI),
    (Comp, ERR_LIB_COMP),
    (Ecdsa, ERR_LIB_ECDSA),
    (Ecdh, ERR_LIB_ECDH),
    (OsslStore, ERR_LIB_OSSL_STORE),
    (Fips, ERR_LIB_FIPS),
    (Cms, ERR_LIB_CMS),
    (Ts, ERR_LIB_TS),
    (Hmac, ERR_LIB_HMAC),
    (Ct, ERR_LIB_CT),
    (Async, ERR_LIB_ASYNC),
    (Kdf, ERR_LIB_KDF),
    (Sm2, ERR_LIB_SM2),
    (Ess, ERR_LIB_ESS),
    (Prop, ERR_LIB_PROP),
    (Crmf, ERR_LIB_CRMF),
    (Prov, ERR_LIB_PROV),
    (Cmp, ERR_LIB_CMP),
    (OsslEncoder, ERR_LIB_OSSL_ENCODER),
    (OsslDecoder, ERR_LIB_OSSL_DECODER),
    (Http, ERR_LIB_HTTP),
    (User, ERR_LIB_USER),
);

/// An OpenSSL error.
pub(crate) struct Error {
    /// The library where the error has occurred.
    library: ErrorLibrary,

    /// The reason.
    reason: c_int,
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "OpenSSL3Error(lib={:?}, reason={})",
            self.library, self.reason
        )
    }
}

impl From<c_ulong> for Error {
    fn from(err: c_ulong) -> Self {
        Self {
            library: support::err_get_lib(err)
                .try_into()
                .unwrap_or(ErrorLibrary::None),
            reason: support::err_get_reason(err),
        }
    }
}

impl Error {
    /// Returns the library where the error has occurred.
    pub(crate) fn library(&self) -> ErrorLibrary {
        self.library
    }

    /// Returns the reason of the error.
    pub(crate) fn reason(&self) -> u32 {
        self.reason as u32
    }
}
