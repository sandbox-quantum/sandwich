///
/// \file
/// \brief Unit tests for OpenSSL tunnels.
///
/// \author thb-sb

#include <thread>

#include "cc/context.h"
#include "cc/io/io.h"
#include "cc/io/socket.h"
#include "cc/tests_utils.h"
#include "cc/tunnel.h"

extern "C" {

#include <sys/socket.h>
#include <sys/types.h>

} // end extern "C"

namespace {

/// \brief Simple message buffer.
using MsgBuffer = std::array<std::byte, 4>;
/// \brief « Ping » message.
constexpr MsgBuffer kPingMsg{std::byte{'P'}, std::byte{'i'}, std::byte{'n'},
                             std::byte{'g'}};

/// \brief « Pong » message.
constexpr MsgBuffer kPongMsg{std::byte{'P'}, std::byte{'o'}, std::byte{'n'},
                             std::byte{'g'}};

/// \brief Create a configuration.
///
/// \param mode Mode.
/// \param impl Implementation.
/// \param proto Protocol.
///
/// \return The configuration.
auto NewConfiguration(
    const saq::sandwich::proto::Mode mode,
    const saq::sandwich::proto::api::v1::Implementation impl,
    const saq::sandwich::proto::api::v1::Protocol proto)
    -> saq::sandwich::proto::api::v1::Configuration {
  saq::sandwich::proto::api::v1::Configuration config{};

  config.set_protocol(proto);
  config.set_impl(impl);

  if (mode == saq::sandwich::proto::Mode::MODE_CLIENT) {
    config.mutable_client()->mutable_tls()->mutable_common_options();
  } else if (mode == saq::sandwich::proto::Mode::MODE_SERVER) {
    config.mutable_server()->mutable_tls()->mutable_common_options();
  }

  return config;
}

/// \brief Create a Sandwich context for the client.
///
/// \return A Sandwich context for the client.
auto CreateClientContext() -> std::unique_ptr<saq::sandwich::Context> {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_CLIENT,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  config.mutable_client()->mutable_tls()->mutable_common_options()->add_kem(
      "kyber1024");

  auto *cert = config.mutable_client()
                   ->mutable_tls()
                   ->add_trusted_certificates()
                   ->mutable_static_();
  cert->mutable_data()->set_filename("testdata/cert.pem");
  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_PEM);

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == true);
  auto ctx = std::move(res.Get());
  sandwich_assert(ctx != nullptr);
  sandwich_assert(ctx->Implementation() == config.impl());
  sandwich_assert(ctx->Protocol() == config.protocol());

  return ctx;
}

/// \brief Create a Sandwich context for the server.
///
/// \return A Sandwich context for the server.
auto CreateServerContext() -> std::unique_ptr<saq::sandwich::Context> {
  auto config{NewConfiguration(
      saq::sandwich::proto::Mode::MODE_SERVER,
      saq::sandwich::proto::api::v1::Implementation::IMPL_OPENSSL1_1_1_OQS,
      saq::sandwich::proto::api::v1::Protocol::PROTO_TLS_13)};

  config.mutable_server()->mutable_tls()->mutable_common_options()->add_kem(
      "kyber1024");

  auto *cert = config.mutable_server()
                   ->mutable_tls()
                   ->mutable_certificate()
                   ->mutable_static_();
  cert->mutable_data()->set_filename("testdata/cert.pem");
  cert->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                       ENCODING_FORMAT_PEM);

  auto *key = config.mutable_server()
                  ->mutable_tls()
                  ->mutable_private_key()
                  ->mutable_static_();
  key->mutable_data()->set_filename("testdata/key.pem");
  key->set_format(saq::sandwich::proto::api::v1::ASN1EncodingFormat::
                      ENCODING_FORMAT_PEM);

  auto res = saq::sandwich::Context::FromConfiguration(config);
  sandwich_assert(res == true);
  auto ctx = std::move(res.Get());
  sandwich_assert(ctx != nullptr);
  sandwich_assert(ctx->Implementation() == config.impl());
  sandwich_assert(ctx->Protocol() == config.protocol());

  return ctx;
}

/// \brief Pair of I/O interfaces, one for the client, one for the server.
struct IOPair {
  /// \brief Client I/O interface.
  std::unique_ptr<saq::sandwich::io::IO> client;

  /// \brief Server I/O interface.
  std::unique_ptr<saq::sandwich::io::IO> server;
};

/// \brief Create two connected I/O interfaces using
/// saq::sandwich::io::Socket.
///
/// \param fds File descriptors.
///
/// The first file descriptor in `fds` is the client's.
/// and last file descriptor in `fds` is the server's
///
/// This function succeed.
[[nodiscard]] auto CreateIOs(const std::array<int, 2> &fds) -> IOPair {
  IOPair pair;

  auto res = saq::sandwich::io::Socket::FromFd(fds[0]);
  sandwich_assert(res != false);
  pair.client = std::move(res.Get());

  res = saq::sandwich::io::Socket::FromFd(fds[1]);
  sandwich_assert(res != false);
  pair.server = std::move(res.Get());

  return pair;
}

/// \brief Create a tunnel from a context and an I/O interface.
///
/// \param ctx Context.
/// \param ioint IO interface
///
/// This function succeed.
///
/// \return The tunnel.
[[nodiscard]] auto CreateTunnel(
    saq::sandwich::Context *ctx,
    std::unique_ptr<saq::sandwich::io::IO> ioint)
    -> std::unique_ptr<saq::sandwich::Tunnel> {
  auto res = ctx->NewTunnel(std::move(ioint));
  sandwich_assert(res != false);
  return std::move(res.Get());
}

/// \brief 1. Start the handshake from the client.
///
/// This function checks the following assertion:
///   * Asynchronous tunnels: the client starts the handshake. At this point,
///     the tunnel' state MUST be `kHandshakeInProgress`. The returned value
///     from `Tunnel::Handshake` MUST be `kWantRead`, because the client
///     sent the Hello,Key,Share part of the TLS1.3 handshake, and it waits
///     for the server's response (« wants to read from the socket»).
///
/// \param client Client's tunnel.
void ClientInitiateHandshake(saq::sandwich::Tunnel *client) {
  auto state{client->Handshake()};
  sandwich_assert(state ==
                  saq::sandwich::Tunnel::HandshakeState::kWantRead);

  sandwich_assert(client->GetState() ==
                  saq::sandwich::Tunnel::State::kHandshakeInProgress);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 2. The server reads the beginning of the handshake, and answers to
///        the client, by sending the second part of the handshake. At this
///        pointer, the tunnel' state MUST be `kHandshakeInProgress`. The
///        returned value from `Tunnel::Handshake` MUST be `kWantRead`, the
///        client may have to notify the server about an change or an alert.
///
/// \param server Server's tunnel.
void ServerAnswerHandshake(saq::sandwich::Tunnel *server) {
  sandwich_assert(server->GetState() ==
                  saq::sandwich::Tunnel::State::kNotConnected);
  auto state{server->Handshake()};
  sandwich_assert(state ==
                  saq::sandwich::Tunnel::HandshakeState::kWantRead);

  sandwich_assert(server->GetState() ==
                  saq::sandwich::Tunnel::State::kHandshakeInProgress);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 3. The client acknowledges the handshake by verifying the transcript'
///        signature. Now, the tunnel' state MUST be `kDone`: the record layer
///        is now available to the client. The returned value from
///        `Tunnel::Handshake` therefore MUST be `kHandshakeDone`.
///
/// \param client Client's tunnel.
void ClientCompleteHandshake(saq::sandwich::Tunnel *client) {
  auto state{client->Handshake()};
  sandwich_assert(state == saq::sandwich::Tunnel::HandshakeState::kDone);

  sandwich_assert(client->GetState() ==
                  saq::sandwich::Tunnel::State::kHandshakeDone);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 4. The server acknowledges the handshake too. Now, the tunnel' state
///        MUST be `kDone`: the record layer is now also available to the
///        server. The returned value from `Tunnel::Handshake` MUST be
///        `kHandshakeDone`.
///
/// \param server Server's tunnel.
void ServerCompleteHandshake(saq::sandwich::Tunnel *server) {
  auto state{server->Handshake()};
  sandwich_assert(state == saq::sandwich::Tunnel::HandshakeState::kDone);

  sandwich_assert(server->GetState() ==
                  saq::sandwich::Tunnel::State::kHandshakeDone);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 5. The client sends a « Ping » message to the server.
///
/// \param client Client's tunnel.
void ClientSendPing(saq::sandwich::Tunnel *client) {
  auto ioop{client->Write(kPingMsg)};
  sandwich_assert(ioop);
  sandwich_assert(ioop.Get() == kPingMsg.size());

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 6. The server reads the « Ping » message, and sends back a
///           « Pong » message.
///
/// \param server Server's tunnel.
void ServerReadPingSendPong(saq::sandwich::Tunnel *server) {
  MsgBuffer buffer{};

  auto ioop{server->Read(buffer)};
  sandwich_assert(ioop);
  sandwich_assert(ioop.Get() == kPingMsg.size());
  sandwich_assert(buffer == kPingMsg);

  ioop = server->Write(kPongMsg);
  sandwich_assert(ioop);
  sandwich_assert(ioop.Get() == kPongMsg.size());

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 7. Client reads « Pong » message.
///
/// \param client Client's tunnel.
void ClientReadPong(saq::sandwich::Tunnel *client) {
  MsgBuffer buffer{};

  auto ioop{client->Read(buffer)};
  sandwich_assert(ioop);
  sandwich_assert(ioop.Get() == kPingMsg.size());
  sandwich_assert(buffer == kPongMsg);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 8. Server tries to read something.
///
/// At this stage, the client hasn't written anything. The socket is
/// non-blocking, so the server MUST receive a `kWantRead`, and
/// `RecordResult::WouldBlock` MUST return true.
void ServerTriesRead(saq::sandwich::Tunnel *server) {
  MsgBuffer buffer{};

  auto ioop{server->Read(buffer)};
  sandwich_assert(!ioop);
  sandwich_assert(ioop.GetError() ==
                  saq::sandwich::Tunnel::RecordError::kWantRead);
  sandwich_assert(ioop.WouldBlock());

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 9. Server closes the tunnel.
///
/// At this stage, the server sent a TLS alert `SHUTDOWN`. The tunnel is now
/// closed to the server side.
void ServerClosesTunnel(saq::sandwich::Tunnel *server) {
  const auto state = server->Close();
  sandwich_assert(state == saq::sandwich::Tunnel::State::kBeingShutdown);

  auto ioop{server->Write(kPingMsg)};
  sandwich_assert(!ioop);
  sandwich_assert(ioop.GetError() ==
                  saq::sandwich::Tunnel::RecordError::kClosed);

  server->Close();
  sandwich_assert(server->GetState() ==
                  saq::sandwich::Tunnel::State::kDisconnected);
  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 10. The client tries to write something, but the server asked for
/// closing the tunnel. Therefore, the error `RecordError::kBeingShutdown` is
/// returned.
void ClientTriesWriteAfterClose(saq::sandwich::Tunnel *client) {
  auto ioop{client->Write(kPingMsg)};

  sandwich_assert(ioop);

  MsgBuffer buffer{};
  ioop = client->Read(buffer);
  sandwich_assert(!ioop);

  sandwich_assert(ioop.GetError() ==
                  saq::sandwich::Tunnel::RecordError::kBeingShutdown);
  sandwich_assert(client->Close() ==
                  saq::sandwich::Tunnel::State::kDisconnected);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';
}

/// \brief 11. Create a new tunnel using the existing I/O interface from an
/// old tunnel.
auto RecycleIOToNewTunnel(saq::sandwich::Context *ctx,
                          std::unique_ptr<saq::sandwich::Tunnel> old_tun)
    -> std::unique_ptr<saq::sandwich::Tunnel> {
  auto io = old_tun->ReleaseIO();
  sandwich_assert(io != nullptr);
  auto tun = CreateTunnel(ctx, std::move(io));
  sandwich_assert(tun != nullptr);

  std::cout << "OK for " << __builtin_FUNCTION() << '\n';

  return tun;
}

} // end anonymous namespace

int main() {
  auto client = CreateClientContext();
  auto server = CreateServerContext();

  // Create two connected sockets, to use with saq::sandwich::io::Socket.
  std::array<int, 2> fds{0};
  auto err{::socketpair(PF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK, 0, fds.data())};
  sandwich_assert(err == 0);

  // Create I/O interfaces for client and server.
  auto ios{CreateIOs(fds)};

  // Create tunnels.
  auto client_tunnel = CreateTunnel(&*client, std::move(ios.client));
  auto server_tunnel = CreateTunnel(&*server, std::move(ios.server));

  // Client initiates the handshake.
  ClientInitiateHandshake(&*client_tunnel);

  // Server answers.
  ServerAnswerHandshake(&*server_tunnel);

  // Client is okay with the signature, the handshake is done.
  ClientCompleteHandshake(&*client_tunnel);

  // The server accesses to the record layer.
  ServerCompleteHandshake(&*server_tunnel);

  // Client sends « Ping ».
  ClientSendPing(&*client_tunnel);

  // Server receives « Ping » and sends « Pong ».
  ServerReadPingSendPong(&*server_tunnel);

  // Client receives « Pong ».
  ClientReadPong(&*client_tunnel);

  // Server tries to read, it triggers a `WANT_READ`, and WouldBlock returns
  // true.
  ServerTriesRead(&*server_tunnel);

  // Server closes the tunnel  by calling `Close`. It triggers a `SHUTDOWN`
  // TLS alert.
  ServerClosesTunnel(&*server_tunnel);

  // Client tries to write to the tunnel.
  // Because the server sent a `SHUTDOWN` TLS alert, the read after
  // the write fails and return `RecordState::kBeingShutdown`.
  ClientTriesWriteAfterClose(&*client_tunnel);

  {
    // Flushing client and server sockets
    saq::sandwich::io::IO::OpResult ioop{};
    do {
      MsgBuffer buf{};
      ioop = client_tunnel->GetIO().Read(
          buf, saq::sandwich::tunnel::State::kDisconnected);
    } while (ioop.count > 0);
    do {
      MsgBuffer buf{};
      ioop = server_tunnel->GetIO().Read(
          buf, saq::sandwich::tunnel::State::kDisconnected);
    } while (ioop.count > 0);
  }

  // Create a new server tunnel using the existing I/O interface from the
  // old client tunnel.
  server_tunnel = RecycleIOToNewTunnel(&*server, std::move(server_tunnel));

  // Create a new client tunnel using the existing I/O interface from the
  // old client tunnel.
  client_tunnel = RecycleIOToNewTunnel(&*client, std::move(client_tunnel));

  // Redo: client initiates the handshake.
  ClientInitiateHandshake(&*client_tunnel);

  // Redo: server answers.
  ServerAnswerHandshake(&*server_tunnel);

  // Redo: client is okay with the signature, the handshake is done.
  ClientCompleteHandshake(&*client_tunnel);

  // Redo: the server accesses to the record layer.
  ServerCompleteHandshake(&*server_tunnel);

  client_tunnel->Close();
  server_tunnel->Close();

  return 0;
}
