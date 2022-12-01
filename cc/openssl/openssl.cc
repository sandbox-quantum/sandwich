///
/// \file
/// \brief OpenSSL, implementation
///
/// \author thb-sb

#include "cc/openssl/openssl.h"

#include <cassert>
#include <memory>

#include "cc/data_source.h"
#include "cc/io/io.h"
#include "cc/tunnel.h"

extern "C" {

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

} // end extern "C"

namespace saq::sandwich::openssl {

namespace {

/// \brief Free a SSL_CTX.
///
/// \param[in] ctx Context to free.
void FreeSSLCtx(::SSL_CTX *ctx) {
  ::SSL_CTX_free(ctx);
}

/// \brief Free a SSL*.
///
/// \param[in] ssl SSL* to free.
void FreeSSL(::SSL *ssl) {
  ::SSL_free(ssl);
}

/// \brief Free an OpenSSL BIO object.
///
/// \param[in] bio BIO to free.
void BIODeleter(::BIO *bio) {
  ::BIO_free_all(bio);
}

/// \brief A wrapped BIO.
using OpenSSLBIO = std::unique_ptr<::BIO, decltype(&BIODeleter)>;

/// \brief Free an OpenSSL X509* object.
///
/// \param[in] x509 X509 to free.
void X509Deleter(::X509 *x509) {
  ::X509_free(x509);
}

/// \brief A wrapped X509.
using OpenSSLX509 = std::unique_ptr<::X509, decltype(&X509Deleter)>;

/// \brief Free an OpenSSL EVP_PKEY* object.
///
/// \param[in] evp_pkey EVP_PKEY to free.
void EVPPKEYDeleter(::EVP_PKEY *evp_pkey) {
  ::EVP_PKEY_free(evp_pkey);
}

/// \brief A wrapped EVP_PKEY.
using OpenSSLEVPPKEY = std::unique_ptr<::EVP_PKEY, decltype(&EVPPKEYDeleter)>;

} // end anonymous namespace

TLSHandle::TLSHandle(::SSL *ssl, const proto::Mode mode) noexcept
    : ssl_{ssl}, mode_{mode} {}

TLSHandle::TLSHandle(TLSHandle &&other) noexcept
    : ssl_{other.ssl_}, mode_{other.mode_} {
  other.ssl_ = nullptr;
}

auto TLSHandle::operator=(TLSHandle &&other) noexcept -> TLSHandle & {
  FreeSSL(ssl_);
  ssl_ = other.ssl_;
  other.ssl_ = nullptr;
  mode_ = other.mode_;
  return *this;
}

TLSHandle::~TLSHandle() noexcept {
  FreeSSL(ssl_);
}

TLSContext::TLSContext(::SSL_CTX *ctx, const proto::Mode mode) noexcept
    : ctx_{ctx}, mode_{mode} {}

auto TLSContext::New(const proto::Mode mode) -> TLSContextResult {
  auto ctx = [mode]() -> std::optional<::SSL_CTX *> {
    if (mode == proto::Mode::MODE_CLIENT) {
      return ::SSL_CTX_new(TLS_client_method());
    }
    if (mode == proto::Mode::MODE_SERVER) {
      return ::SSL_CTX_new(TLS_server_method());
    }
    return std::nullopt;
  }();

  if (!ctx.has_value()) {
    return Error::kInvalidConfiguration;
  }

  if (*ctx == nullptr) {
    return Error::kMemory;
  }

  TLSContext tls_ctx(*ctx, mode);

  ::SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 |
                                     SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 |
                                     // NOLINTNEXTLINE
                                     SSL_OP_NO_DTLSv1 | SSL_OP_NO_DTLSv1_2);

  if (::SSL_CTX_set_min_proto_version(tls_ctx, TLS1_3_VERSION) != 1) {
    return Error::kUnsupportedProtocolVersion;
  }

  if (mode == proto::Mode::MODE_CLIENT) {
    ::SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_PEER, nullptr);
  }
  ::SSL_CTX_set_quiet_shutdown(tls_ctx, 0);
  ::SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_OFF);
  ::SSL_CTX_set1_groups(tls_ctx, nullptr, 0);

  if (mode == proto::Mode::MODE_CLIENT) {
    if (auto *store = ::X509_STORE_new(); store != nullptr) {
      ::SSL_CTX_set1_cert_store(tls_ctx, store);
      ::X509_STORE_set_trust(store, 1);
    } else {
      return Error::kMemory;
    }
  }

  return tls_ctx;
}

TLSContext::TLSContext(TLSContext &&other) noexcept
    : ctx_{other.ctx_}, mode_{other.mode_} {
  other.ctx_ = nullptr;
}

auto TLSContext::operator=(TLSContext &&other) noexcept -> TLSContext & {
  FreeSSLCtx(ctx_);
  ctx_ = other.ctx_;
  mode_ = other.mode_;
  other.ctx_ = nullptr;
  return *this;
}

TLSContext::~TLSContext() noexcept {
  FreeSSLCtx(ctx_);
  ctx_ = nullptr;
}

auto TLSContext::AddOrSetCertificate(
    const std::string_view pathname,
    const proto::api::v1::ASN1EncodingFormat fmt) -> Error {
  if (!proto::api::v1::ASN1EncodingFormat_IsValid(fmt)) {
    return Error::kInvalidConfiguration;
  }

  if (auto bio = OpenSSLBIO(::BIO_new(::BIO_s_file()), BIODeleter);
      bio != nullptr) {
    // NOLINTNEXTLINE
    if (BIO_read_filename(bio.get(), std::string{pathname}.c_str()) == 1) {
      return AddOrSetCertificate(bio.get(), fmt);
    }
    return Error::kInvalidCertificate;
  }
  return Error::kImplementation;
}

auto TLSContext::AddOrSetCertificate(
    std::span<const std::byte> buffer,
    const proto::api::v1::ASN1EncodingFormat fmt) -> Error {
  if (!ASN1EncodingFormat_IsValid(fmt)) {
    return Error::kInvalidConfiguration;
  }

  if (buffer.size() > INT_MAX) {
    return Error::kIntegerOverflow;
  }

  auto len = static_cast<int>(buffer.size());
  if (auto bio = OpenSSLBIO(::BIO_new_mem_buf(buffer.data(), len), BIODeleter);
      bio != nullptr) {
    return AddOrSetCertificate(bio.get(), fmt);
  }
  return Error::kImplementation;
}

auto TLSContext::AddOrSetCertificate(const proto::api::v1::Certificate &cert)
    -> Error {
  if (!cert.has_static_()) {
    return Error::kInvalidConfiguration;
  }
  const auto &cert_static = cert.static_();
  const auto fmt = cert_static.format();

  if (!proto::api::v1::ASN1EncodingFormat_IsValid(fmt)) {
    return Error::kInvalidConfiguration;
  }

  const auto dataOrErr = DataSource::fromProto(cert_static.data());
  if (!dataOrErr) {
    return dataOrErr.GetError();
  }

  const auto &data = dataOrErr.Get();
  if (const auto optPath = data.path()) {
    return AddOrSetCertificate(*optPath, fmt);
  }
  if (const auto optRawData = data.rawData()) {
    return AddOrSetCertificate(*optRawData, fmt);
  }
  return Error::kInvalidConfiguration;
}

auto TLSContext::AddOrSetCertificate(
    ::BIO *bio, const proto::api::v1::ASN1EncodingFormat fmt) -> Error {
  if (!proto::api::v1::ASN1EncodingFormat_IsValid(fmt)) {
    return Error::kInvalidConfiguration;
  }

  OpenSSLX509 cert(nullptr, X509Deleter);
  if (fmt == proto::api::v1::ASN1EncodingFormat::ENCODING_FORMAT_PEM) {
    cert.reset(::PEM_read_bio_X509(bio, nullptr, nullptr, nullptr));
  } else if (fmt == proto::api::v1::ASN1EncodingFormat::ENCODING_FORMAT_DER) {
    cert.reset(::d2i_X509_bio(bio, nullptr));
  } else {
    return Error::kInvalidCertificate;
  }
  if (cert == nullptr) {
    return Error::kInvalidCertificate;
  }

  if (mode_ == proto::Mode::MODE_CLIENT) {
    if (auto *store = ::SSL_CTX_get_cert_store(ctx_); store != nullptr) {
      ::X509_STORE_add_cert(store, cert.get());
    } else {
      return Error::kImplementation;
    }
  } else if (mode_ == proto::Mode::MODE_SERVER) {
    if (::SSL_CTX_use_certificate(ctx_, cert.get()) != 1) {
      return Error::kUnsupportedCertificate;
    }
  } else {
    __builtin_unreachable();
  }
  return Error::kOk;
}

auto TLSContext::SetPrivateKey(const std::string_view pathname,
                               const proto::api::v1::ASN1EncodingFormat fmt)
    -> Error {
  if (!proto::api::v1::ASN1EncodingFormat_IsValid(fmt)) {
    return Error::kInvalidConfiguration;
  }

  if (auto bio = OpenSSLBIO(::BIO_new(::BIO_s_file()), BIODeleter);
      bio != nullptr) {
    // NOLINTNEXTLINE
    if (BIO_read_filename(bio.get(), std::string{pathname}.c_str()) == 1) {
      return SetPrivateKey(bio.get(), fmt);
    }
    return Error::kInvalidPrivateKey;
  }
  return Error::kImplementation;
}

auto TLSContext::SetPrivateKey(std::span<const std::byte> buffer,
                               const proto::api::v1::ASN1EncodingFormat fmt)
    -> Error {
  if (!ASN1EncodingFormat_IsValid(fmt)) {
    return Error::kInvalidConfiguration;
  }

  if (buffer.size() > INT_MAX) {
    return Error::kIntegerOverflow;
  }

  auto len = static_cast<int>(buffer.size());
  if (auto bio = OpenSSLBIO(::BIO_new_mem_buf(buffer.data(), len), BIODeleter);
      bio != nullptr) {
    return SetPrivateKey(bio.get(), fmt);
  }
  return Error::kImplementation;
}

auto TLSContext::SetPrivateKey(const proto::api::v1::PrivateKey &pkey)
    -> Error {
  if (!pkey.has_static_()) {
    return Error::kInvalidConfiguration;
  }

  const auto &pkey_static = pkey.static_();
  const auto fmt = pkey_static.format();

  if (!ASN1EncodingFormat_IsValid(fmt)) {
    return Error::kInvalidConfiguration;
  }

  const auto dataOrErr = DataSource::fromProto(pkey_static.data());
  if (!dataOrErr) {
    return dataOrErr.GetError();
  }

  const auto &data = dataOrErr.Get();
  if (const auto optPath = data.path()) {
    return SetPrivateKey(*optPath, fmt);
  }
  if (const auto optData = data.rawData()) {
    return SetPrivateKey(*optData, fmt);
  }
  return Error::kInvalidConfiguration;
}

auto TLSContext::SetPrivateKey(::BIO *bio,
                               const proto::api::v1::ASN1EncodingFormat fmt)
    -> Error {
  if (!ASN1EncodingFormat_IsValid(fmt)) {
    return Error::kInvalidConfiguration;
  }
  if (mode_ != proto::Mode::MODE_SERVER) {
    return Error::kInvalidContext;
  }

  OpenSSLEVPPKEY pkey(nullptr, EVPPKEYDeleter);
  if (fmt == proto::api::v1::ASN1EncodingFormat::ENCODING_FORMAT_PEM) {
    pkey.reset(::PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr));
  } else if (fmt == proto::api::v1::ASN1EncodingFormat::ENCODING_FORMAT_DER) {
    pkey.reset(::d2i_PrivateKey_bio(bio, nullptr));
  } else {
    return Error::kInvalidPrivateKey;
  }
  if (pkey == nullptr) {
    return Error::kInvalidPrivateKey;
  }

  if (::SSL_CTX_use_PrivateKey(ctx_, pkey.get()) != 1) {
    return Error::kUnsupportedPrivateKey;
  }
  return Error::kOk;
}

auto TLSContext::AddSupportedKem(const std::string &kem) noexcept -> Error {
  if (kem_nids_.size() >= INT_MAX) {
    return Error::kIntegerOverflow;
  }
  if (const auto nid = ::OBJ_txt2nid(kem.c_str()); nid != NID_undef) {
    kem_nids_.insert(nid);
    return Error::kOk;
  }
  return Error::kInvalidKem;
}

auto TLSContext::ApplyKems() noexcept -> Error {
  if (kem_nids_.size() >= INT_MAX) {
    return Error::kIntegerOverflow;
  }
  std::vector<decltype(kem_nids_)::value_type> kems(kem_nids_.begin(),
                                                    kem_nids_.end());
  if (::SSL_CTX_set1_groups(ctx_, kems.data(),
                            static_cast<int>(kem_nids_.size())) == 1) {
    return Error::kOk;
  }
  return Error::kImplementation;
}

auto TLSContext::NewSession() noexcept -> Result<TLSHandle, Error> {
  if (auto *ssl = ::SSL_new(ctx_); ssl != nullptr) {
    return {{ssl, mode_}};
  }
  return Error::kImplementation;
}

void TLSContext::SetVerifyMode(const int mode) noexcept {
  ::SSL_CTX_set_verify(ctx_, mode, nullptr);
}

namespace {

auto SandwichBIOWrite(::BIO *bio, const char *data, const size_t len,
                      size_t *written) -> int {
  // NOLINTNEXTLINE
  ::BIO_clear_retry_flags(bio);
  auto *tun = static_cast<Tunnel *>(::BIO_get_data(bio));
  auto &ioint = tun->GetIO();

  // NOLINTNEXTLINE
  const auto opres = ioint.Write(
      {reinterpret_cast<const std::byte *>(data), len}, tun->GetState());
  *written = opres.count;
  if (opres.err == io::IO::Error::kOk) {
    return 1;
  }
  switch (opres.err) {
    case io::IO::Error::kInProgress:
    case io::IO::Error::kWouldBlock: {
      // NOLINTNEXTLINE
      ::BIO_set_retry_write(bio);
    } break;
    case io::IO::Error::kClosed:
    case io::IO::Error::kRefused: {
      BIO_set_close(bio, 1);
    } break;
    default: {
    }
  }
  return -1;
}

auto SandwichBIORead(::BIO *bio, char *data, const size_t len, size_t *read)
    -> int {
  // NOLINTNEXTLINE
  ::BIO_clear_retry_flags(bio);
  auto *tun = static_cast<Tunnel *>(::BIO_get_data(bio));
  auto &ioint = tun->GetIO();

  // NOLINTNEXTLINE
  const auto opres =
      ioint.Read({reinterpret_cast<std::byte *>(data), len}, tun->GetState());
  *read = opres.count;
  if (opres.err == io::IO::Error::kOk) {
    return 1;
  }
  switch (opres.err) {
    case io::IO::Error::kInProgress:
    case io::IO::Error::kWouldBlock: {
      // NOLINTNEXTLINE
      ::BIO_set_retry_read(bio);
    } break;
    case io::IO::Error::kClosed:
    case io::IO::Error::kRefused: {
      BIO_set_close(bio, 1);
    } break;
    default: {
    }
  }
  return -1;
}

auto SandwichBIOCtrl(::BIO *bio, const int cmd, const long larg,
                     [[maybe_unused]] void *pargs) -> long {
  switch (cmd) {
    case BIO_CTRL_SET_CLOSE: {
      ::BIO_set_shutdown(bio, static_cast<int>(larg));
      return 1;
    }
    case BIO_CTRL_GET_CLOSE: {
      return ::BIO_get_shutdown(bio);
    }
    case BIO_CTRL_FLUSH: {
      return 1;
    }
    default: {
      return 0;
    }
  }
}

auto SandwichBIOCreate([[maybe_unused]] ::BIO *bio) -> int {
  return 1;
}

auto SandwichBIODestroy([[maybe_unused]] ::BIO *bio) -> int {
  return 1;
}

constexpr ::bio_method_st SandwichBIOMethod = {.type = BIO_TYPE_SOCKET,
                                               .name = "sandwich_bio",
                                               .bwrite = SandwichBIOWrite,
                                               .bwrite_old = nullptr,
                                               .bread = SandwichBIORead,
                                               .bread_old = nullptr,
                                               .bputs = nullptr,
                                               .bgets = nullptr,
                                               .ctrl = SandwichBIOCtrl,
                                               .create = SandwichBIOCreate,
                                               .destroy = SandwichBIODestroy,
                                               .callback_ctrl = nullptr};

} // end anonymous namespace

/// \brief Create custom BIO_METHOD
///
/// \param[in] tunnel Tunnel
[[nodiscard]] auto GetBIOMethod() noexcept -> const ::BIO_METHOD * {
  return &SandwichBIOMethod;
}

[[nodiscard]] auto GetCommonOptionsFromConfiguration(
    const proto::api::v1::Configuration &configuration)
    -> Result<
        std::optional<std::reference_wrapper<const proto::api::v1::TLSOptions>>,
        Error> {
  switch (configuration.opts_case()) {
    case proto::api::v1::Configuration::OptsCase::kClient: {
      if (!configuration.client().has_tls()) {
        return Error::kInvalidConfiguration;
      }
      if (!configuration.client().tls().has_common_options()) {
        return {std::nullopt};
      }
      return {configuration.client().tls().common_options()};
    }
    case proto::api::v1::Configuration::OptsCase::kServer: {
      if (!configuration.server().has_tls()) {
        return Error::kInvalidConfiguration;
      }
      if (!configuration.server().tls().has_common_options()) {
        return {std::nullopt};
      }
      return {configuration.server().tls().common_options()};
    }
    case proto::api::v1::Configuration::OptsCase::OPTS_NOT_SET:
    default: {
      return Error::kInvalidConfiguration;
    }
  }
}

} // end namespace saq::sandwich::openssl
