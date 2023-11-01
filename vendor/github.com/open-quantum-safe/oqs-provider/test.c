/**
 * \file
 * \brief Test the oqs provider builtin integration.
 *
 * \author thb-sb */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <oqs/sig.h>

extern OSSL_provider_init_fn oqs_provider_init;

/** \brief Try to load a post-quantum private key.
 *
 * \return 0 if the private key has been successfully digested, else -1. */
static int try_load_pqc_private_key(void) {
  BIO *bio = NULL;
  EVP_PKEY *private_key = NULL;
  int ret = -1;

  bio = BIO_new(BIO_s_file());
  assert(bio != NULL);
  assert(BIO_read_filename(bio, "vendor/github.com/open-quantum-safe/"
                                "oqs-provider/dilithium5.key.pem") == 1);

  if ((private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) != NULL) {
    ret = 0;
    EVP_PKEY_free(private_key);
  } else {
    ERR_print_errors_fp(stderr);
  }
  BIO_free_all(bio);

  return ret;
}

/** \brief Try to use a post-quantum KEM algorithm.
 *
 * \return 0 if post-quantum KEMs are understood by OpenSSL, else -1. */
static int try_use_pqc_KEMs(void) {
  SSL_CTX *ctx = NULL;
  int ret = -1;

  ctx = SSL_CTX_new(TLS_server_method());
  assert(ctx != NULL);
  if (SSL_CTX_set1_groups_list(ctx, "kyber512:kyber768:kyber1024") == 1) {
    ret = 0;
  }
  SSL_CTX_free(ctx);

  return ret;
}

/** \brief Try EVP_PKEY_new_raw_private_key_ex and
 * EVP_PKEY_new_raw_public_key_ex.
 *
 * \return 0 on success, else -1. */
static int try_EVP_PKEY_new_raw_private_public_key_ex(void) {
  uint8_t *raw_public_key;
  EVP_PKEY *raw_public_key_evp;
  EVP_PKEY *raw_private_key_evp;
  uint8_t *raw_private_key;
  OQS_SIG *oqs_sig;
  int ret = -1;

  if ((oqs_sig = OQS_SIG_new("Dilithium5")) == NULL) {
    return -1;
  }
  if ((raw_public_key = malloc(oqs_sig->length_public_key)) == NULL) {
    goto fail1;
  }
  if ((raw_private_key = malloc(oqs_sig->length_secret_key)) == NULL) {
    goto fail2;
  }
  if (OQS_SIG_keypair(oqs_sig, raw_public_key, raw_private_key) !=
      OQS_SUCCESS) {
    goto fail3;
  }

  if ((raw_private_key_evp = EVP_PKEY_new_raw_private_key_ex(
           OSSL_LIB_CTX_get0_global_default(), "Dilithium5", NULL,
           raw_private_key, oqs_sig->length_secret_key)) == NULL) {
    ERR_print_errors_fp(stderr);
    goto fail3;
  }

  if ((raw_public_key_evp = EVP_PKEY_new_raw_public_key_ex(
           OSSL_LIB_CTX_get0_global_default(), "Dilithium5", NULL,
           raw_public_key, oqs_sig->length_public_key)) == NULL) {
    ERR_print_errors_fp(stderr);
    goto fail4;
  }
  EVP_PKEY_free(raw_public_key_evp);
  ret = 0;

fail4:
  EVP_PKEY_free(raw_private_key_evp);

fail3:
  free(raw_private_key);

fail2:
  free(raw_public_key);

fail1:
  OQS_SIG_free(oqs_sig);
  return ret;
}

/** \brief Try building EVP_PKEY from a private key buffer
 *         and a private key buffer
 *
 * \return 0 on success, else -1. */
static int try_EVP_PKEY_two_buffers(void) {
  uint8_t *raw_public_key = NULL;
  uint8_t *raw_private_key = NULL;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  OQS_SIG *oqs_sig = NULL;
  OSSL_PARAM_BLD *param_bld = NULL;
  OSSL_PARAM *params = NULL;
  int ret = -1;
  if ((oqs_sig = OQS_SIG_new("Dilithium5")) == NULL) {
    return -1;
  }
  if ((raw_public_key = malloc(oqs_sig->length_public_key)) == NULL) {
    goto fail1;
  }
  if ((raw_private_key = malloc(oqs_sig->length_secret_key)) == NULL) {
    goto fail2;
  }
  if (OQS_SIG_keypair(oqs_sig, raw_public_key, raw_private_key) !=
      OQS_SUCCESS) {
    goto fail3;
  }
  if ((param_bld = OSSL_PARAM_BLD_new()) == NULL ||
      !OSSL_PARAM_BLD_push_octet_string(param_bld, "priv", raw_private_key,
                                        oqs_sig->length_secret_key) ||
      !OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", raw_public_key,
                                        oqs_sig->length_public_key)) {
    goto fail4;
  }
  params = OSSL_PARAM_BLD_to_param(param_bld);
  if (params == NULL) {
    goto fail5;
  }
  ctx = EVP_PKEY_CTX_new_from_name(NULL, "Dilithium5", NULL);
  if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
      EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEY_PARAMETERS, params) <= 0) {
    goto fail6;
  }
  if (pkey == NULL) {
    goto fail7;
  }
  ret = 0;

fail7:
  EVP_PKEY_free(pkey);

fail6:
  EVP_PKEY_CTX_free(ctx);

fail5:
  OSSL_PARAM_free(params);

fail4:
  OSSL_PARAM_BLD_free(param_bld);

fail3:
  free(raw_private_key);

fail2:
  free(raw_public_key);

fail1:
  OQS_SIG_free(oqs_sig);
  return ret;
}

int main() {
  OSSL_PROVIDER *prov = NULL;

  // Before loading the OQS provider, the following function calls must fail.
  assert(try_load_pqc_private_key() == -1);
  assert(try_use_pqc_KEMs() == -1);
  assert(try_EVP_PKEY_new_raw_private_public_key_ex() == -1);
  assert(try_EVP_PKEY_two_buffers() == -1);

  // Now, loads the OQS provider.

  // Enable debug log in oqs-provider.
  setenv("OQSPROV", "1", 1);

  assert(OSSL_PROVIDER_add_builtin(OSSL_LIB_CTX_get0_global_default(),
                                   "oqs-provider", oqs_provider_init) == 1);
  assert((prov = OSSL_PROVIDER_load(OSSL_LIB_CTX_get0_global_default(),
                                    "oqs-provider")) != NULL);
  assert(strcmp(OSSL_PROVIDER_get0_name(prov), "oqs-provider") == 0);
  assert(OSSL_PROVIDER_self_test(prov) == 1);

  // Now that the OQS provider is loaded, the following function calls must
  // succeed.
  assert(try_load_pqc_private_key() == 0);
  assert(try_use_pqc_KEMs() == 0);
  assert(try_EVP_PKEY_new_raw_private_public_key_ex() == 0);
  assert(try_EVP_PKEY_two_buffers() == 0);
  return EXIT_SUCCESS;
}
