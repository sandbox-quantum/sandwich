///
/// \file
/// \brief Sandwich context specification.
///
/// \author thb-sb

#pragma once

#include <memory>
#include <span>

#include "cc/errors.h"
#include "cc/io/io.h"
#include "cc/result.h"
#include "cc/tunnel.h"
#include "proto/sandwich.pb.h"

#include "proto/api/v1/configuration.pb.h"

/// Namespace for the Sandwich project.
namespace saq::sandwich {

/// A Sandwich context.
///
/// A context is a configuration for tunnels. It holds cryptography materials
/// such as certificates, private keys.
///
/// Tunnels are created from a context.
class Context {
 public:
  /// \brief A result, wrapping a Context or an error.
  using ContextResult = Result<std::unique_ptr<Context>, Error>;

  /// \brief A result, wrapping a Tunnel or an error.
  using TunnelResult = Result<std::unique_ptr<Tunnel>, Error>;

  /// \brief Alias for the configuration in Protobuf.
  using ProtoConfiguration = proto::api::v1::Configuration;

  /// \brief Factory function, from a configuration.
  ///
  /// \param[in] config Configuration.
  ///
  /// \return A context if successful, or an error.
  [[nodiscard]] static auto FromConfiguration(const ProtoConfiguration &config)
      -> ContextResult;

  /// \brief Factory function, from a serialized configuration.
  ///
  /// \tparam Byte Byte type.
  ///
  /// \param[in] sconfig Serialized configuration.
  ///
  /// \return A context if successful, or an error.
  template <typename Byte = std::byte>
  [[nodiscard]] static auto FromSerializedConfiguration(
      std::span<const Byte> sconfig) -> ContextResult {
    if (sconfig.empty()) {
      return Error::kInvalidConfiguration;
    }

    if (sconfig.size() > INT_MAX) {
      return Error::kIntegerOverflow;
    }

    ProtoConfiguration proto;
    if (!proto.ParseFromArray(static_cast<const void *>(sconfig.data()),
                              static_cast<int>(sconfig.size()))) {
      return Error::kProtobuf;
    }
    return Context::FromConfiguration(proto);
  }

  /// \brief Returns the current mode.
  ///
  /// \return The current mode.
  [[nodiscard]] virtual auto Mode() const noexcept -> proto::Mode = 0;

  /// \brief Returns the current protocol.
  ///
  /// \return The current mode.
  [[nodiscard]] inline auto Protocol() const noexcept
      -> proto::api::v1::Protocol {
    return protocol_;
  }

  /// \brief Returns the current implementation.
  ///
  /// \return The current mode.
  [[nodiscard]] inline auto Implementation() const noexcept
      -> proto::api::v1::Implementation {
    return implementation_;
  }

  /// \brief Returns the native context.
  ///
  /// \return The native context.
  [[nodiscard]] virtual auto NativeContext() noexcept -> void * = 0;

  /// \brief Returns the native context.
  ///
  /// \return The native context.
  [[nodiscard]] virtual auto NativeContext() const noexcept -> const void * = 0;

  /// \brief Creates a tunnel from an I/O interface.
  ///
  /// The returned tunnel has not started the handshake yet. To do so, there is
  /// `Tunnel::Handshake`.
  ///
  /// \param ioint I/O interface.
  ///
  /// \return A new tunnel, or an error.
  [[nodiscard]] virtual auto NewTunnel(std::unique_ptr<io::IO> ioint)
      -> TunnelResult = 0;

  /// \brief Copy constructor, deleted.
  Context(const Context &) noexcept = delete;

  /// \brief Move constructor.
  Context(Context &&) = default;

  /// \brief Copy assignment.
  auto operator=(const Context &) noexcept -> Context & = delete;

  /// \brief Move assignment.
  auto operator=(Context &&) -> Context & = default;

  /// \brief Destructor.
  virtual ~Context();

 protected:
  /// \brief Constructor, with a valid configuration.
  ///
  /// \param[in] config Configuration.
  explicit Context(const ProtoConfiguration &config);

 private:
  /// \brief Protocol.
  proto::api::v1::Protocol protocol_ =
      proto::api::v1::Protocol::PROTO_UNSPECIFIED;

  /// \brief Implementation.
  proto::api::v1::Implementation implementation_ =
      proto::api::v1::Implementation::IMPL_UNSPECIFIED;
};

} // end namespace saq::sandwich
