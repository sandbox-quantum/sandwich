/*
 * Copyright 2022 SandboxAQ
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
/// \brief Sandwich Context for OpenSSL implementation, specification
///
/// \author thb-sb

#pragma once

#include "cc/context.h"
#include "cc/io/io.h"
#include "cc/openssl/openssl.h"

namespace saq::sandwich::openssl {

/// \brief Generic OpenSSL context.
class Context : protected sandwich::Context {
 public:
  [[nodiscard]] auto NativeContext() noexcept -> void * override;
  [[nodiscard]] auto NativeContext() const noexcept -> const void * override;

  Context(const Context &) noexcept = delete;
  Context(Context &&) noexcept = default;
  auto operator=(const Context &) noexcept -> Context & = delete;
  auto operator=(Context &&) noexcept -> Context & = default;
  ~Context() override;

  /// \brief Factory for an OpenSSL context.
  ///
  /// \param[in] config Configuration to use.
  ///
  /// \return An OpenSSL context, or an error.
  [[nodiscard]] static auto FromConfiguration(const ProtoConfiguration &config)
      -> ContextResult;

 protected:
  /// \brief Returns the TLS context.
  ///
  /// \return The TLS context.
  [[nodiscard]] inline auto GetTLSContext() noexcept -> TLSContext & {
    return tls_ctx_;
  }

  /// \brief Returns the TLS context.
  ///
  /// \return The TLS context.
  [[nodiscard]] inline auto GetTLSContext() const noexcept
      -> const TLSContext & {
    return tls_ctx_;
  }

  /// \brief Set and apply KEMs from configuration.
  ///
  /// \param config Configuration.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto SetKems(const ProtoConfiguration &config) -> Error;

  /// \brief Apply flags from configuration (see `proto::TLSFlags`).
  ///
  /// \param config Configuration.
  ///
  /// \return Error::ERROR_OK if success, else an error code.
  [[nodiscard]] auto ApplyFlags(const ProtoConfiguration &config) -> Error;

  /// \brief Constructor from a configuration and a SSL_CTX object.
  ///
  /// \param[in] config Configuration to use.
  /// \param[in] tls_ctx OpenSSL context to use.
  Context(const ProtoConfiguration &config, TLSContext tls_ctx);

 private:
  /// \brief TLS context.
  TLSContext tls_ctx_;
};

} // end namespace saq::sandwich::openssl
