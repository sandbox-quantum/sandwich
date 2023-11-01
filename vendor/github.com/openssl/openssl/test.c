/**
 * \file
 * \brief Test the build of `openssl`.
 *
 * \author thb-sb */

#include <assert.h>
#include <stdlib.h>

#include <openssl/ssl.h>

int main() {
  void *ctx = SSL_CTX_new(TLS_client_method());
  assert(ctx != NULL);
  SSL_CTX_free(ctx);

  return EXIT_SUCCESS;
}
