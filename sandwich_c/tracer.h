// Copyright (c) SandboxAQ. All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-only

///
/// \file
/// \brief Sandwich Tracer API.

#pragma once

#include <sys/types.h>

#include "sandwich_c/export.h"
#include "sandwich_c/tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \brief Adds a tracer object to a tunnel, allows for context propagation.
///
/// \param[in] tun Tunnel to associate tracer with.
/// \param[in] context_cstr A string representing the context from OpenTelemetry.
/// \param[in] fd File Descriptor where the tracer will write to.
SANDWICH_API void sandwich_tunnel_add_tracer(struct SandwichTunnel *tun, const char *context_cstr, int fd);

#ifdef __cplusplus
} // end extern "C"
#endif
