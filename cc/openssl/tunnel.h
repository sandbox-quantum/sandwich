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
/// \brief Tunnel implemented by OpenSSL, specification.
///
/// \author thb-sb

#pragma once

#include "cc/io/io.h"
#include "cc/tunnel.h"

#include "cc/openssl/openssl.h"

namespace saq::sandwich::openssl {

/// \brief Generic OpenSSL tunnel.
class Tunnel : public sandwich::Tunnel {
 public:
  Tunnel(const Tunnel&) noexcept = delete;
  Tunnel(Tunnel&&) noexcept = default;
  auto operator=(const Tunnel&) noexcept -> Tunnel& = delete;
  auto operator=(Tunnel&&) noexcept -> Tunnel& = default;
  ~Tunnel() override;

  [[nodiscard]] auto Close() -> State override;
  [[nodiscard]] auto Read(std::span<std::byte> buffer) -> RecordResult override;
  [[nodiscard]] auto Write(std::span<const std::byte> buffer)
      -> RecordResult override;

 protected:
  /// \brief Returns the TLS handle.
  ///
  /// \return The TLS handle.
 [[nodiscard]] inline auto GetTLS() noexcept -> TLSHandle & { return tls_; }

 /// \brief Returns the TLS handle.
 ///
 /// \return The TLS handle.
 [[nodiscard]] inline auto GetTLS() const noexcept -> const TLSHandle & {
   return tls_;
 }

  /// \brief Construct an OpenSSL tunnel.
  ///
  /// \param ioint I/O object.
  /// \param tls TLS handle.
 explicit Tunnel(std::unique_ptr<io::IO> ioint, TLSHandle tls,
                 ::BIO *bio) noexcept;

 /// \brief Check the shutdown state, and update the tunnel's if necessary.
 ///
 /// This method will set the `kBeingShutdown` state if a shutdown alert
 /// has been received.
 ///
 /// \return The new state of the tunnel.
 [[nodiscard]] auto CheckShutdownAndUpdateState() -> State;

 /// \brief Get the TLSHandle.
 ///
 /// \return The TLS handle.
 [[nodiscard]] inline auto GetTLSHandle() noexcept -> TLSHandle & {
   return tls_;
 }

 /// \brief Get the TLSHandle.
 ///
 /// \return The TLS handle.
 [[nodiscard]] inline auto GetTLSHandle() const noexcept -> const TLSHandle & {
   return tls_;
 }

private:
 /// \brief The TLS handle.
 TLSHandle tls_;
};

} // end namespace saq::sandwich::openssl
