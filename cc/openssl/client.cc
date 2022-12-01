///
/// \brief
/// \file OpenSSL Sandwich client implementation.
///
/// \author thb-sb

#include "cc/openssl/client.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <atomic>

#include "cc/io/io.h"
#include "cc/openssl/openssl.h"
#include "cc/tunnel.h"

namespace saq::sandwich::openssl {

/*******************************************************************************
 *                                  Context                                    *
 ******************************************************************************/

auto ClientContext::FromConfiguration(const ProtoConfiguration &config)
    -> ContextResult {
  if (!config.client().has_tls()) {
    return Error::kInvalidConfiguration;
  }
  auto result = TLSContext::New(proto::Mode::MODE_CLIENT);
  if (!result) {
    return result.GetError();
  }

  auto tls_ctx = std::move(result.Get());

  const auto &tls_client = config.client().tls();

  const auto certs_count = tls_client.trusted_certificates_size();
  // NOLINTNEXTLINE
  for (int cert_index = 0; cert_index < certs_count; ++cert_index) {
    if (auto err = tls_ctx.AddOrSetCertificate(
            tls_client.trusted_certificates(cert_index));
        err != Error::kOk) {
      return err;
    }
  }

  std::unique_ptr<ClientContext> ctx{
      new ClientContext(config, std::move(tls_ctx))};
  if (auto err = ctx->SetKems(config); err != Error::kOk) {
    return err;
  }
  if (auto err = ctx->ApplyFlags(config); err != Error::kOk) {
    return err;
  }

  return std::unique_ptr<sandwich::Context>(ctx.release());
}

ClientContext::ClientContext(const ProtoConfiguration &config,
                             TLSContext &&tls_ctx)
    : openssl::Context{config, std::move(tls_ctx)} {}

ClientContext::~ClientContext() = default;

auto ClientContext::NewTunnel(std::unique_ptr<io::IO> ioint) -> TunnelResult {
  auto res = GetTLSContext().NewSession();
  if (!res) {
    return res.GetError();
  }
  auto tls_handle = std::move(res.Get());

  ::BIO *bio = nullptr;
  if (const auto *meth = GetBIOMethod(); meth != nullptr) {
    bio = ::BIO_new(meth);
  } else {
    return Error::kImplementation;
  }
  if (bio == nullptr) {
    return Error::kImplementation;
  }

  return std::unique_ptr<sandwich::Tunnel>{
      new ClientTunnel{std::move(ioint), std::move(tls_handle), bio}};
}

/*******************************************************************************
 *                                  Tunnel                                     *
 ******************************************************************************/

auto ClientTunnel::Handshake() -> HandshakeState {
  if (GetState() == State::kHandshakeDone) {
    return HandshakeState::kDone;
  }

  auto &tls = GetTLS();
  auto state = tls.GetState();

  if (state == TLS_ST_OK) {
    SetState(State::kHandshakeDone);
    return HandshakeState::kDone;
  }

  auto err = ::SSL_connect(tls);
  if (err == 1) {
    SetState(State::kHandshakeDone);
    return HandshakeState::kDone;
  }
  err = tls.GetSSLError(err);
  switch (err) {
    case SSL_ERROR_WANT_READ: {
      SetState(State::kHandshakeInProgress);
      return HandshakeState::kWantRead;
    }
    case SSL_ERROR_WANT_WRITE: {
      SetState(State::kHandshakeInProgress);
      return HandshakeState::kWantWrite;
    }
    case SSL_ERROR_ZERO_RETURN: {
      SetState(State::kHandshakeInProgress);
      return HandshakeState::kInProgress;
    }
    case SSL_ERROR_WANT_ACCEPT:
    case SSL_ERROR_WANT_CONNECT: {
      SetState(State::kNotConnected);
      return HandshakeState::kInProgress;
    }
    default: {
      SetState(State::kError);
      return HandshakeState::kError;
    }
  }
}

} // end namespace saq::sandwich::openssl
