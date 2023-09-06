// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief List of `#include` for BoringSSL rust bindgen.

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <oqs/rand.h>

// Because boringssl upstream has delete this constant,
// so this is a workaround to keep boringssl::BIO_get_ssl continue working
#define BIO_C_GET_SSL 110
