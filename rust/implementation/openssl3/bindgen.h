// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief List of `#include` for rust bindgen.

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <oqs/rand.h>

/// \brief Custom BIO method for Sandwich.
///
/// \warning `bio_method_st` is an internal structure of OpenSSL, defined in
///          `include/internal/bio.h`. It means we shouldn't access its
///          definition. Instead, we should use `BIO_meth_new` and
///          its setters `BIO_meth_set_*`. However, in order not to use
///          an ELF/PIE constructor (using __attribute__((constructor))), we
///          copy the `bio_method_st` definition.
///          This copy is from OpenSSL 3.2 alpha 2.
struct bio_method_st {
  int type;
  char *name;
  int (*bwrite)(BIO *, const char *, size_t, size_t *);
  int (*bwrite_old)(BIO *, const char *, int);
  int (*bread)(BIO *, char *, size_t, size_t *);
  int (*bread_old)(BIO *, char *, int);
  int (*bputs)(BIO *, const char *);
  int (*bgets)(BIO *, char *, int);
  long (*ctrl)(BIO *, int, long, void *);
  int (*create)(BIO *);
  int (*destroy)(BIO *);
  long (*callback_ctrl)(BIO *, int, BIO_info_cb *);
  int (*bsendmmsg)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *);
  int (*brecvmmsg)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *);
};

OSSL_provider_init_fn oqs_provider_init;
