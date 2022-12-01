///
/// \file
/// \brief Sandwich server Context for OpenSSL implementation, specification
///
/// \author thb-sb

#pragma once

#include "cc/openssl/context.h"
#include "cc/openssl/tunnel.h"

namespace saq::sandwich::openssl {

/// \brief OpenSSL context for server mode.
class ServerContext final : protected openssl::Context {
 public:
  [[nodiscard]] auto NewTunnel(std::unique_ptr<io::IO> ioint)
      -> TunnelResult override;

  [[nodiscard]] inline auto Mode() const noexcept -> proto::Mode override {
    return proto::Mode::MODE_SERVER;
  }
  ServerContext(const ServerContext &) noexcept = delete;
  ServerContext(ServerContext &&) noexcept = default;
  auto operator=(const ServerContext &) noexcept -> ServerContext & = delete;
  auto operator=(ServerContext &&) noexcept -> ServerContext & = default;
  ~ServerContext() override;

  /// \brief Factory for an OpenSSL server context.
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
  ServerContext(const ProtoConfiguration &config, TLSContext &&tls_ctx);
};

/// \brief OpenSSL tunnel for server mode.
class ServerTunnel : public openssl::Tunnel {
 public:
  template <typename... Args>
  explicit ServerTunnel(Args... args) noexcept
      : openssl::Tunnel{std::forward<Args>(args)...} {}
  ServerTunnel(const ServerTunnel &) noexcept = delete;
  ServerTunnel(ServerTunnel &&) noexcept = default;
  auto operator=(const ServerTunnel &) noexcept -> ServerTunnel & = delete;
  auto operator=(ServerTunnel &&) noexcept -> ServerTunnel & = default;
  ~ServerTunnel() override = default;

  [[nodiscard]] auto Handshake() -> HandshakeState override;
};

} // end namespace saq::sandwich::openssl
