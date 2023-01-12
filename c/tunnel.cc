// Copyright 2022 SandboxAQ
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

///
/// \file
/// \brief Frontend for tunnels, implementation
///
/// \author thb-sb

#include "cc/tunnel.h"
#include "c/sandwich.h"
#include "cc/context.h"

#ifdef __cplusplus
extern "C" {
#endif

SANDWICH_API enum ::SandwichError sandwich_tunnel_new(
    struct SandwichContext *ctx, struct SandwichCIO *cio,
    struct SandwichTunnel **tun) {
  auto *ctx_cc = reinterpret_cast<saq::sandwich::Context *>(ctx);
  auto *io_cc = reinterpret_cast<saq::sandwich::io::IO *>(cio);

  auto res =
      ctx_cc->NewTunnel(std::unique_ptr<saq::sandwich::io::IO>(io_cc));
  if (res) {
    *tun = reinterpret_cast<std::remove_pointer_t<decltype(tun)>>(
        res.Get().release());
    return SANDWICH_ERROR_OK;
  }
  return static_cast<enum ::SandwichError>(res.GetError());
}

SANDWICH_API enum ::SandwichTunnelHandshakeState sandwich_tunnel_handshake(
    struct SandwichTunnel *tun) {
  return static_cast<enum ::SandwichTunnelHandshakeState>(
      reinterpret_cast<saq::sandwich::Tunnel *>(tun)->Handshake());
}

SANDWICH_API enum ::SandwichTunnelRecordError sandwich_tunnel_read(
    struct SandwichTunnel *tun, void *dst, const size_t n, size_t *r) {
  size_t rb = 0;
  if (r == nullptr) {
    r = &rb;
  }
  *r = 0;

  const std::span<std::byte> buf(reinterpret_cast<std::byte *>(dst), n);
  auto res = reinterpret_cast<saq::sandwich::Tunnel *>(tun)->Read(buf);
  if (!res) {
    return static_cast<enum ::SandwichTunnelRecordError>(res.GetError());
  }
  *r = res.Get();
  return SANDWICH_TUNNEL_RECORDERROR_OK;
}

SANDWICH_API enum ::SandwichTunnelRecordError sandwich_tunnel_write(
    struct SandwichTunnel *tun, const void *src, const size_t n, size_t *w) {
  size_t wb = 0;
  if (w == nullptr) {
    w = &wb;
  }
  *w = 0;

  const std::span<const std::byte> buf(reinterpret_cast<const std::byte *>(src),
                                       n);
  auto res = reinterpret_cast<saq::sandwich::Tunnel *>(tun)->Write(buf);
  if (!res) {
    return static_cast<enum ::SandwichTunnelRecordError>(res.GetError());
  }
  *w = res.Get();
  return SANDWICH_TUNNEL_RECORDERROR_OK;
}

SANDWICH_API void sandwich_tunnel_close(struct SandwichTunnel *tun) {
  reinterpret_cast<saq::sandwich::Tunnel *>(tun)->Close();
}

SANDWICH_API enum ::SandwichTunnelState sandwich_tunnel_state(
    const struct SandwichTunnel *tun) {
  return static_cast<enum ::SandwichTunnelState>(
      reinterpret_cast<const saq::sandwich::Tunnel *>(tun)->GetState());
}

SANDWICH_API enum ::SandwichError sandwich_tunnel_last_error(
    const struct SandwichTunnel *tun) {
  return static_cast<enum ::SandwichError>(
      reinterpret_cast<const saq::sandwich::Tunnel *>(tun)->GetError());
}

SANDWICH_API struct SandwichCIO *sandwich_tunnel_io_release(
    struct SandwichTunnel *tun) {
  auto *tun_cc = reinterpret_cast<saq::sandwich::Tunnel *>(tun);
  auto io = tun_cc->ReleaseIO();
  return reinterpret_cast<struct SandwichCIO *>(io.release());
}

SANDWICH_API void sandwich_tunnel_free(struct SandwichTunnel *tun) {
  delete reinterpret_cast<saq::sandwich::Tunnel *>(tun);
}

#ifdef __cplusplus
} // end extern "C"
#endif
