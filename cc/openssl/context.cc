///
/// \file
/// \brief Sandwich Context for OpenSSL implementation, implementation
///
/// \author thb-sb

#include "cc/openssl/context.h"

#include <array>
#include <functional>
#include <optional>

namespace saq::sandwich::openssl {

Context::Context(const ProtoConfiguration &config, TLSContext tls_ctx)
    : sandwich::Context{config}, tls_ctx_{std::move(tls_ctx)} {}

Context::~Context() = default;

auto Context::NativeContext() noexcept -> void * {
  return static_cast<void *>(tls_ctx_.Get());
}

auto Context::NativeContext() const noexcept -> const void * {
  return static_cast<const void *>(tls_ctx_.Get());
}

auto Context::SetKems(const ProtoConfiguration &config) -> Error {
  auto common_opts = GetCommonOptionsFromConfiguration(config);
  if (!common_opts) {
    return common_opts.GetError();
  }
  {
    const auto &opts = common_opts.Get();
    if (!opts.has_value()) {
      return Error::kInvalidConfiguration;
    }
  }
  const auto &opts = common_opts->value().get();

  const auto kem_count = opts.kem_size();
  int kem_index = 0;

  // NOLINTNEXTLINE
  for (; kem_index < kem_count; ++kem_index) {
    if (auto err = tls_ctx_.AddSupportedKem(opts.kem(kem_index));
        err != Error::kOk) {
      return err;
    }
  }
  if (kem_index > 0) {
    if (auto err = tls_ctx_.ApplyKems(); err != Error::kOk) {
      return err;
    }
  }
  return Error::kOk;
}

auto Context::ApplyFlags(const ProtoConfiguration &config) -> Error {
  auto common_opts = GetCommonOptionsFromConfiguration(config);
  if (!common_opts) {
    return common_opts.GetError();
  }
  const auto &opts = common_opts.Get();
  if (!opts.has_value()) {
    return Error::kOk;
  }
  const auto flags = opts->get().flags();

  if ((flags & proto::api::v1::TLSFlags::TLSFLAGS_SKIP_VERIFY) != 0) {
    tls_ctx_.SetVerifyMode(SSL_VERIFY_NONE);
  }
  return Error::kOk;
}

} // end namespace saq::sandwich::openssl
