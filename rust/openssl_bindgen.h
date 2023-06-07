/*
 * Copyright 2023 SandboxAQ
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

///
/// \file
/// \brief List of `#include` for rust bindgen.

#include <openssl/err.h>
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
///          This copy is from OpenSSL 1.1.1. If we upgrade OpenSSL,
///          we MUST check and update its definition.
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
};
