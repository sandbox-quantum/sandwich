///
/// \file
/// \brief Sandwich server Context for OpenSSL implementation, specification
///
/// \author thb-sb

#pragma once

#include "cc/openssl/context.h"
#include "cc/openssl/tunnel.h"

namespace saq::sandwich::openssl {

/// \brief OpenSSL context for client mode.
class ClientContext final : protected openssl::Context {
 public:
  [[nodiscard]] auto NewTunnel(std::unique_ptr<io::IO> ioint)
      -> TunnelResult override;

  [[nodiscard]] inline auto Mode() const noexcept -> proto::Mode override {
    return proto::Mode::MODE_CLIENT;
  }
  ClientContext(const ClientContext &) noexcept = delete;
  ClientContext(ClientContext &&) noexcept = default;
  auto operator=(const ClientContext &) noexcept -> ClientContext & = delete;
  auto operator=(ClientContext &&) noexcept -> ClientContext & = default;
  ~ClientContext() override;

  /// \brief Factory for an OpenSSL client context.
  ///
  /// \param[in] config Configuration to use.
  ///
  /// \return An OpenSSL context, or an error.
  [[nodiscard]] static auto FromConfiguration(const ProtoConfiguration &config)
      -> ContextResult;

 private:
  /// \brief Constructor from a configuration and a SSL_CTX object.
  ///
  /// \param[in] config Configuration to use.
  /// \param[in] tls_ctx OpenSSL context to use.
  ClientContext(const ProtoConfiguration &config, TLSContext &&tls_ctx);
};

/// \brief OpenSSL tunnel for client mode.
class ClientTunnel : public openssl::Tunnel {
 public:
  template <typename... Args>
  explicit ClientTunnel(Args... args) noexcept
      : openssl::Tunnel{std::forward<Args>(args)...} {}
  ClientTunnel(std::unique_ptr<io::IO> ioint, TLSHandle tls) noexcept;
  ClientTunnel(const ClientTunnel &) noexcept = delete;
  ClientTunnel(ClientTunnel &&) noexcept = default;
  auto operator=(const ClientTunnel &) noexcept -> ClientTunnel & = delete;
  auto operator=(ClientTunnel &&) noexcept -> ClientTunnel & = default;
  ~ClientTunnel() override = default;

  [[nodiscard]] auto Handshake() -> HandshakeState override;
};

} // end namespace saq::sandwich::openssl
