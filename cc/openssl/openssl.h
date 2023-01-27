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
/// \brief OpenSSL, specification
///
/// \author thb-sb

#pragma once

#include <span>
#include <string>
#include <unordered_set>
#include <vector>

extern "C" {

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

} // end extern "C"

#include "cc/error.h"
#include "cc/result.h"
#include "proto/sandwich.pb.h"

#include "proto/api/v1/configuration.pb.h"

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
  int (*bwrite)(::BIO *, const char *, size_t, size_t *);
  int (*bwrite_old)(::BIO *, const char *, int);
  int (*bread)(::BIO *, char *, size_t, size_t *);
  int (*bread_old)(::BIO *, char *, int);
  int (*bputs)(::BIO *, const char *);
  int (*bgets)(::BIO *, char *, int);
  long (*ctrl)(::BIO *, int, long, void *);
  int (*create)(::BIO *);
  int (*destroy)(::BIO *);
  long (*callback_ctrl)(::BIO *, int, ::BIO_info_cb *);
};

namespace saq::sandwich::openssl {

/// \brief Wrapper for SSL*.
class TLSHandle {
 public:
  /// \brief Alias for a TLSHandle result.
  using TLSHandleResult = Result<TLSHandle, error::Error>;

  /// \brief Copy constructor, deleted.
  TLSHandle(const TLSHandle &) noexcept = delete;

  /// \brief Move constructor.
  TLSHandle(TLSHandle &&) noexcept;

  /// \brief Copy assignment, deleted.
  auto operator=(const TLSHandle &) noexcept -> TLSHandle & = delete;

  /// \brief Move assignment.
  auto operator=(TLSHandle &&) noexcept -> TLSHandle &;

  /// \brief Destructor.
  ~TLSHandle() noexcept;

  /// \brief Casts to a ::SSL*.
  inline operator ::SSL *() noexcept { return ssl_; }

  /// \brief Casts to a ::SSL*.
  inline operator const ::SSL *() const noexcept { return ssl_; }

  /// \brief Returns the context.
  ///
  /// \return The context.
  [[nodiscard]] inline auto Get() noexcept -> ::SSL * { return ssl_; }

  /// \brief Returns the context.
  ///
  /// \return The context.
  [[nodiscard]] inline auto Get() const noexcept -> const ::SSL * {
    return ssl_;
  }

  /// \brief Close the :SSL*.
  inline auto Close() noexcept -> int { return ::SSL_shutdown(ssl_); }

  /// \brief Get the error from SSL.
  ///
  /// \param err Error.
  ///
  /// \return The error, from SSL_get_error.
  [[nodiscard]] inline auto GetSSLError(const int err) const noexcept -> int {
    return ::SSL_get_error(ssl_, err);
  }

  /// \brief Get the OpenSSL state.
  ///
  /// \return The OpenSSL state.
  [[nodiscard]] inline auto GetState() const noexcept -> OSSL_HANDSHAKE_STATE {
    return ::SSL_get_state(ssl_);
  }

 private:
  /// \brief Construct a TLSHandle from a SSL*.
  ///
  /// \param[in] ssl SSL handle.
  /// \param mode Mode.
  TLSHandle(::SSL *ssl, proto::Mode mode) noexcept;

  friend class TLSContext;

  /// \brief SSL* handle.
  ::SSL *ssl_;

  /// \brief Mode.
  proto::Mode mode_ = proto::Mode::MODE_UNSPECIFIED;
};

/// \brief Wrapper for SSL_CTX*.
class TLSContext {
 public:
  /// \brief Alias for a TLSContext result.
  using TLSContextResult = Result<TLSContext, error::Error>;

  /// \brief Factory for an SSL_CTX.
  ///
  /// \param mode Mode.
  ///
  /// \return An TLSContext, or an error.
  [[nodiscard]] static auto New(proto::Mode mode) -> TLSContextResult;

  /// \brief Copy constructor, deleted.
  TLSContext(const TLSContext &) noexcept = delete;

  /// \brief Move constructor.
  TLSContext(TLSContext &&) noexcept;

  /// \brief Copy assignment, deleted.
  auto operator=(const TLSContext &) noexcept -> TLSContext & = delete;

  /// \brief Move assignment, deleted.
  auto operator=(TLSContext &&) noexcept -> TLSContext &;

  /// \brief Destructor.
  ~TLSContext() noexcept;

  /// \brief Appends or sets the certificate.
  ///
  /// If the mode is server, the certificate is going to be used with a private
  /// key.
  /// If the mode is client, the certificate is pushed to the certificate store.
  ///
  /// \param[in] pathname Path to the certificate.
  /// \param fmt Encoding format.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto AddOrSetCertificate(const std::string_view pathname,
                                         proto::api::v1::ASN1EncodingFormat fmt)
      -> error::Error;

  /// \brief Appends or sets the certificate using a buffer.
  ///
  /// \param[in] buffer Buffer.
  /// \param fmt Encoding format.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto AddOrSetCertificate(std::span<const std::byte> buffer,
                                         proto::api::v1::ASN1EncodingFormat fmt)
      -> error::Error;

  /// \brief Appends or sets the certificate using the protobuf type.
  ///
  /// \param[in] cert Certificate.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto AddOrSetCertificate(
      const proto::api::v1::Certificate &cert) -> error::Error;

  /// \brief Appends or sets the certificate using an OpenSSL BIO object.
  ///
  /// \param[in] bio BIO oject.
  /// \param fmt Encoding format.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto AddOrSetCertificate(::BIO *bio,
                                         proto::api::v1::ASN1EncodingFormat fmt)
      -> error::Error;

  /// \brief Sets the private key.
  ///
  /// If the mode is client, returns an error.
  ///
  /// \param[in] pathname Path to the private key.
  /// \param fmt Encoding format.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto SetPrivateKey(const std::string_view pathname,
                                   proto::api::v1::ASN1EncodingFormat fmt)
      -> error::Error;

  /// \brief Sets the private key using a buffer.
  ///
  /// \param[in] buffer Buffer
  /// \param fmt Encoding format.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto SetPrivateKey(std::span<const std::byte> buffer,
                                   proto::api::v1::ASN1EncodingFormat fmt)
      -> error::Error;

  /// \brief Sets the private key using the protobuf type.
  ///
  /// \param[in] pkey Private key.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto SetPrivateKey(const proto::api::v1::PrivateKey &pkey)
      -> error::Error;

  /// \brief Sets the private key using an OpenSSL BIO object.
  ///
  /// \param[in] bio BIO oject.
  /// \param fmt Encoding format.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto SetPrivateKey(::BIO *bio,
                                   proto::api::v1::ASN1EncodingFormat fmt)
      -> error::Error;

  /// \brief Adds a supported key encapsulation mechanism (KEM).
  ///
  /// \param[in] kem Key encapsulation mechanism to add.
  ///
  /// Note: A call to `ApplyKems` is mandatory.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto AddSupportedKem(const std::string &kem) noexcept
      -> error::Error;

  /// \brief Apply the list of key encapsulation mechanisms (KEM)
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto ApplyKems() noexcept -> error::Error;

  /// \brief Casts to a ::SSL_CTX*.
  inline operator ::SSL_CTX *() noexcept { return ctx_; }

  /// \brief Casts to a ::SSL_CTX*.
  inline operator const ::SSL_CTX *() const noexcept { return ctx_; }

  /// \brief Returns the context.
  ///
  /// \return The context.
  [[nodiscard]] inline auto Get() noexcept -> ::SSL_CTX * { return ctx_; }

  /// \brief Returns the context.
  ///
  /// \return The context.
  [[nodiscard]] inline auto Get() const noexcept -> const ::SSL_CTX * {
    return ctx_;
  }

  /// \brief Creates a new SSL session.
  ///
  /// \return New SSL* session, or an error.
  [[nodiscard]] auto NewSession() noexcept -> TLSHandle::TLSHandleResult;

  /// \brief Set the verify mode, using `SSL_CTX_set_verify`.
  ///
  /// \param mode Mode.
  void SetVerifyMode(int mode) noexcept;

 private:
  /// \brief Constructs a TLSContext from a SSL_CTX*.
  ///
  /// \param[in] ctx Context to wrap.
  /// \param mode Mode.
  TLSContext(::SSL_CTX *ctx, proto::Mode mode) noexcept;

  /// \brief Wrapped context.
  SSL_CTX *ctx_;

  /// \brief List of NIDs for key encapsulation mechanisms.
  std::unordered_set<int> kem_nids_;

  /// \brief Mode.
  proto::Mode mode_ = proto::Mode::MODE_UNSPECIFIED;
};

/// \brief Returns a BIO method for OpenSSL.
///
/// \return The BIO method for OpenSSL.
[[nodiscard]] auto GetBIOMethod() noexcept -> const ::BIO_METHOD *;

/// \brief Get the common options from a protobuf configuration.
///
/// \param configuration Protobuf configuration.
///
/// \return The common options if exist, or an error code if the configuration
/// is invalid.
[[nodiscard]] auto GetCommonOptionsFromConfiguration(
    const proto::api::v1::Configuration &configuration)
    -> Result<
        std::optional<std::reference_wrapper<const proto::api::v1::TLSOptions>>,
        error::Error>;

} // end namespace saq::sandwich::openssl
